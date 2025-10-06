#include <iostream>
#include <sstream>
#include <future>
#include <mutex>
#include <set>
#include <vector>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <stdexcept>

#include "../core/logger.hpp"
#include "../core/api.hpp"
#include "mempool.hpp"
#include "blockchain.hpp"

// Tune for your block/tx sizes; this prevents runaway memory use.
static constexpr size_t FRD_MAX_MEMPOOL_TXS = 50'000;
static constexpr int    TX_BRANCH_FACTOR    = 10;
static constexpr uint64_t MIN_FEE_TO_ENTER_MEMPOOL = 1;

MemPool::MemPool(HostManager& h, BlockChain& b)
    : hosts(h), blockchain(b) {
    shutdown = false;
}

MemPool::~MemPool() {
    shutdown = true;
    for (auto &t : syncThread) {
        if (t.joinable()) t.join();
    }
}

void MemPool::mempool_sync() {
    while (!shutdown) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // Pull a batch to send
        std::vector<Transaction> txs;
        {
            std::unique_lock<std::mutex> lock(toSend_mutex);
            if (toSend.empty()) continue;
            txs = std::vector<Transaction>(std::make_move_iterator(toSend.begin()),
                                           std::make_move_iterator(toSend.end()));
            toSend.clear();
        }

        // Cull any invalids still lingering in the queue
        {
            std::unique_lock<std::mutex> lock(mempool_mutex);
            for (auto it = transactionQueue.begin(); it != transactionQueue.end(); ) {
                try {
                    if (blockchain.verifyTransaction(*it) != SUCCESS) {
                        it = transactionQueue.erase(it);
                    } else {
                        ++it;
                    }
                } catch (...) {
                    it = transactionQueue.erase(it);
                }
            }
        }

        if (txs.empty()) continue;

        // Gossip to neighbors
        std::vector<std::future<bool>> reqs;
        std::set<std::string> neighbors = hosts.sampleFreshHosts(TX_BRANCH_FACTOR);
        bool all_sent = true;

        for (const auto& neighbor : neighbors) {
            for (const auto& tx : txs) {
                reqs.push_back(std::async(std::launch::async, [neighbor, tx]() -> bool {
                    try {
                        sendTransaction(neighbor, tx);
                        return true;
                    } catch (...) {
                        Logger::logError("MemPool::mempool_sync", "Could not send tx to " + neighbor);
                        return false;
                    }
                }));
            }
        }

        for (auto& req : reqs) {
            if (!req.get()) all_sent = false;
        }

        // Re-queue if needed
        if (!all_sent) {
            std::unique_lock<std::mutex> lock(toSend_mutex);
            for (const auto& tx : txs) toSend.push_back(tx);
        }
    }
}

void MemPool::sync() {
    syncThread.push_back(std::thread(&MemPool::mempool_sync, this));
}

bool MemPool::hasTransaction(Transaction t) {
    std::unique_lock<std::mutex> lock(mempool_mutex);
    return transactionQueue.count(t) > 0;
}

ExecutionStatus MemPool::addTransaction(Transaction t) {
    std::unique_lock<std::mutex> lock(mempool_mutex);

    if (transactionQueue.count(t) > 0) {
        return ALREADY_IN_QUEUE;
    }

    if (t.getFee() < MIN_FEE_TO_ENTER_MEMPOOL) {
        return TRANSACTION_FEE_TOO_LOW;
    }

    ExecutionStatus status = blockchain.verifyTransaction(t);
    if (status != SUCCESS) {
        return status;
    }

    TransactionAmount outgoing = 0;
    TransactionAmount totalTxAmount = t.getAmount() + t.getFee();

    if (!t.isFee()) {
        outgoing = mempoolOutgoing[t.fromWallet()];
    }

    if (!t.isFee() && outgoing + totalTxAmount > blockchain.getWalletValue(t.fromWallet())) {
        return BALANCE_TOO_LOW;
    }

    if (transactionQueue.size() >= FRD_MAX_MEMPOOL_TXS) {
        return QUEUE_FULL;
    }

    transactionQueue.insert(t);
    if (!t.isFee()) {
        mempoolOutgoing[t.fromWallet()] += totalTxAmount;
    }

    {
        std::unique_lock<std::mutex> toSend_lock(toSend_mutex);
        toSend.push_back(t);
    }

    return SUCCESS;
}

size_t MemPool::size() {
    std::unique_lock<std::mutex> lock(mempool_mutex);
    return transactionQueue.size();
}

std::vector<Transaction> MemPool::getTransactions() const {
    std::unique_lock<std::mutex> lock(mempool_mutex);
    std::vector<Transaction> transactions;
    transactions.reserve(transactionQueue.size());
    for (const auto& tx : transactionQueue) {
        transactions.push_back(tx);
    }
    return transactions;
}

std::pair<char*, size_t> MemPool::getRaw() const {
    std::unique_lock<std::mutex> lock(mempool_mutex);
    size_t n = transactionQueue.size();
    if (n == 0) return { nullptr, 0 };

    size_t len = n * TRANSACTIONINFO_BUFFER_SIZE;
    char* buf = static_cast<char*>(std::malloc(len));
    if (!buf) throw std::bad_alloc();

    size_t offset = 0;
    for (const auto& tx : transactionQueue) {
        TransactionInfo t = tx.serialize();
        transactionInfoToBuffer(t, buf + offset, TRANSACTIONINFO_BUFFER_SIZE);
        offset += TRANSACTIONINFO_BUFFER_SIZE;
    }

    return { buf, len };
}

void MemPool::finishBlock(Block& block) {
    std::unique_lock<std::mutex> lock(mempool_mutex);
    for (const auto& tx : block.getTransactions()) {
        auto it = transactionQueue.find(tx);
        if (it != transactionQueue.end()) {
            transactionQueue.erase(it);

            if (!tx.isFee()) {
                mempoolOutgoing[tx.fromWallet()] -= (tx.getAmount() + tx.getFee());
                if (mempoolOutgoing[tx.fromWallet()] == 0) {
                    mempoolOutgoing.erase(tx.fromWallet());
                }
            }
        }
    }
}
