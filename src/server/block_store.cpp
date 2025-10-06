#include <iostream>
#include <thread>
#include <cstring>     // memcpy, memset
#include <memory>
#include "../core/crypto.hpp"
#include "../core/transaction.hpp"
#include "../core/logger.hpp"
#include "block_store.hpp"

using namespace std;

#define BLOCK_COUNT_KEY "BLOCK_COUNT"
#define TOTAL_WORK_KEY  "TOTAL_WORK"

BlockStore::BlockStore() {}

/* -------------------------- Counters / totals -------------------------- */

void BlockStore::setBlockCount(size_t count) {
    const string countKey = BLOCK_COUNT_KEY;
    const size_t num = count;
    leveldb::Slice key(countKey);
    leveldb::Slice slice(reinterpret_cast<const char*>(&num), sizeof(size_t));
    leveldb::WriteOptions write_options;
    write_options.sync = true;
    leveldb::Status status = db->Put(write_options, key, slice);
    if(!status.ok()) throw std::runtime_error("Could not write block count to DB : " + status.ToString());
}

size_t BlockStore::getBlockCount() const {
    const string countKey = BLOCK_COUNT_KEY;
    leveldb::Slice key(countKey);
    string value;
    leveldb::Status status = db->Get(leveldb::ReadOptions(), key, &value);
    if(!status.ok()) throw std::runtime_error("Could not read block count from DB : " + status.ToString());
    if (value.size() < sizeof(size_t)) throw std::runtime_error("block count blob too small");
    size_t ret;
    std::memcpy(&ret, value.data(), sizeof(size_t));
    return ret;
}

bool BlockStore::hasBlockCount() {
    const string countKey = BLOCK_COUNT_KEY;
    leveldb::Slice key(countKey);
    string value;
    leveldb::Status status = db->Get(leveldb::ReadOptions(), key, &value);
    return status.ok();
}

void BlockStore::setTotalWork(Bigint count) {
    const string countKey = TOTAL_WORK_KEY;
    const string sz = to_string(count);
    leveldb::Slice key(countKey);
    leveldb::Slice slice(sz.data(), sz.size());
    leveldb::WriteOptions write_options;
    write_options.sync = true;
    leveldb::Status status = db->Put(write_options, key, slice);
    if(!status.ok()) throw std::runtime_error("Could not write total work to DB : " + status.ToString());
}

Bigint BlockStore::getTotalWork() const {
    const string countKey = TOTAL_WORK_KEY;
    leveldb::Slice key(countKey);
    string value;
    leveldb::Status status = db->Get(leveldb::ReadOptions(), key, &value);
    if(!status.ok()) throw std::runtime_error("Could not read total work from DB : " + status.ToString());
    Bigint b(value);
    return b;
}

/* -------------------------- Block presence / headers -------------------------- */

bool BlockStore::hasBlock(uint32_t blockId) {
    leveldb::Slice key(reinterpret_cast<const char*>(&blockId), sizeof(uint32_t));
    string value;
    leveldb::Status status = db->Get(leveldb::ReadOptions(), key, &value);
    return status.ok();
}

BlockHeader BlockStore::getBlockHeader(uint32_t blockId) const {
    leveldb::Slice key(reinterpret_cast<const char*>(&blockId), sizeof(uint32_t));
    string valueStr;
    leveldb::Status status = db->Get(leveldb::ReadOptions(), key, &valueStr);
    if(!status.ok())
        throw std::runtime_error("Could not read block header " + to_string(blockId) + " from BlockStore db : " + status.ToString());

    if (valueStr.size() < sizeof(BlockHeader))
        throw std::runtime_error("block header blob too small");

    BlockHeader value{};
    std::memcpy(&value, valueStr.data(), sizeof(BlockHeader));
    return value;
}

/* -------------------------- Transactions in a block -------------------------- */

vector<TransactionInfo> BlockStore::getBlockTransactions(BlockHeader& block) const {
    vector<TransactionInfo> transactions;
    transactions.reserve(block.numTransactions);

    for (int i = 0; i < block.numTransactions; i++) {
        uint32_t transactionId[2] = { block.id, static_cast<uint32_t>(i) };
        leveldb::Slice key(reinterpret_cast<const char*>(transactionId), 2 * sizeof(uint32_t));
        string valueStr;
        leveldb::Status status = db->Get(leveldb::ReadOptions(), key, &valueStr);
        if(!status.ok())
            throw std::runtime_error("Could not read transaction from BlockStore db : " + status.ToString());

        if (valueStr.size() < sizeof(TransactionInfo))
            throw std::runtime_error("tx blob too small");

        TransactionInfo t{};
        std::memcpy(&t, valueStr.data(), sizeof(TransactionInfo));
        transactions.push_back(t);
    }

    return transactions;
}

/* -------------------------- Raw export (header + txs) -------------------------- */

std::pair<uint8_t*, size_t> BlockStore::getRawData(uint32_t blockId) const {
    BlockHeader block = this->getBlockHeader(blockId);
    const size_t numBytes = BLOCKHEADER_BUFFER_SIZE + (TRANSACTIONINFO_BUFFER_SIZE * block.numTransactions);
    if (numBytes == 0) return { nullptr, 0 };

    char* buffer = static_cast<char*>(std::malloc(numBytes));
    if (!buffer) throw std::bad_alloc();

    // Header
    blockHeaderToBuffer(block, buffer);

    // Transactions
    char* curr = buffer + BLOCKHEADER_BUFFER_SIZE;
    for (int i = 0; i < block.numTransactions; i++) {
        uint32_t transactionId[2] = { blockId, static_cast<uint32_t>(i) };
        leveldb::Slice key(reinterpret_cast<const char*>(transactionId), 2 * sizeof(uint32_t));
        string value;
        leveldb::Status status = db->Get(leveldb::ReadOptions(), key, &value);
        if (!status.ok())
            throw std::runtime_error("Could not read transaction from BlockStore db : " + status.ToString());

        if (value.size() < sizeof(TransactionInfo))
            throw std::runtime_error("tx blob too small");

        TransactionInfo txinfo{};
        std::memcpy(&txinfo, value.data(), sizeof(TransactionInfo));

        // Use safe serializer (requires length)
        transactionInfoToBuffer(txinfo, curr, TRANSACTIONINFO_BUFFER_SIZE);
        curr += TRANSACTIONINFO_BUFFER_SIZE;
    }

    return { reinterpret_cast<uint8_t*>(buffer), numBytes };
}

/* -------------------------- Full block (header + parsed txs) -------------------------- */

Block BlockStore::getBlock(uint32_t blockId) const {
    BlockHeader block = this->getBlockHeader(blockId);
    vector<TransactionInfo> txInfos = this->getBlockTransactions(block);

    vector<Transaction> transactions;
    transactions.reserve(txInfos.size());
    for (const auto& t : txInfos) {
        transactions.emplace_back(Transaction(t));
    }

    Block ret(block, transactions);
    return ret;
}

/* -------------------------- Wallet transaction index -------------------------- */

vector<SHA256Hash> BlockStore::getTransactionsForWallet(PublicWalletAddress& wallet) const {
    struct { uint8_t addr[25]; uint8_t txId[32]; } startKey{};
    struct { uint8_t addr[25]; uint8_t txId[32]; } endKey{};

    std::memcpy(startKey.addr, wallet.data(), 25);
    std::memset(startKey.txId, 0x00, 32);
    std::memcpy(endKey.addr,   wallet.data(), 25);
    std::memset(endKey.txId,   0xFF, 32);

    auto startSlice = leveldb::Slice(reinterpret_cast<const char*>(&startKey), sizeof(startKey));
    auto endSlice   = leveldb::Slice(reinterpret_cast<const char*>(&endKey),   sizeof(endKey));

    std::shared_ptr<leveldb::Iterator> it(db->NewIterator(leveldb::ReadOptions()));

    vector<SHA256Hash> ret;
    for (it->Seek(startSlice); it->Valid() && it->key().compare(endSlice) < 0; it->Next()) {
        leveldb::Slice keySlice(it->key());
        if (keySlice.size() < 25 + 32) continue; // guard against corrupt entries
        SHA256Hash txid{};
        std::memcpy(txid.data(), keySlice.data() + 25, 32);
        ret.push_back(txid);
    }
    return ret;
}

void BlockStore::removeBlockWalletTransactions(Block& block) {
    for (const auto& t : block.getTransactions()) {
        SHA256Hash txid = t.hashContents();

        struct { uint8_t addr[25]; uint8_t txId[32]; } w1Key{};
        struct { uint8_t addr[25]; uint8_t txId[32]; } w2Key{};

        std::memcpy(w1Key.addr, t.fromWallet().data(), 25);
        std::memcpy(w1Key.txId, txid.data(), 32);
        std::memcpy(w2Key.addr, t.toWallet().data(), 25);
        std::memcpy(w2Key.txId, txid.data(), 32);

        leveldb::Slice key(reinterpret_cast<const char*>(&w1Key), sizeof(w1Key));
        leveldb::Status status = db->Delete(leveldb::WriteOptions(), key);
        if(!status.ok()) throw std::runtime_error("Could not remove transaction from sender wallet in blockstore db : " + status.ToString());

        key = leveldb::Slice(reinterpret_cast<const char*>(&w2Key), sizeof(w2Key));
        status = db->Delete(leveldb::WriteOptions(), key);
        if(!status.ok()) throw std::runtime_error("Could not remove transaction from receiver wallet in blockstore db : " + status.ToString());
    }
}

/* -------------------------- Store a block (+ wallet index) -------------------------- */

void BlockStore::setBlock(Block& block) {
    const uint32_t blockId = block.getId();
    leveldb::Slice key(reinterpret_cast<const char*>(&blockId), sizeof(uint32_t));
    BlockHeader blockStruct = block.serialize();
    leveldb::Slice slice(reinterpret_cast<const char*>(&blockStruct), sizeof(BlockHeader));
    leveldb::Status status = db->Put(leveldb::WriteOptions(), key, slice);
    if(!status.ok()) throw std::runtime_error("Could not write block to BlockStore db : " + status.ToString());

    for (size_t i = 0; i < block.getTransactions().size(); i++) {
        uint32_t transactionId[2] = { blockId, static_cast<uint32_t>(i) };
        TransactionInfo t = block.getTransactions()[i].serialize();

        leveldb::Slice tkey(reinterpret_cast<const char*>(transactionId), 2 * sizeof(uint32_t));
        leveldb::Slice tslice(reinterpret_cast<const char*>(&t), sizeof(TransactionInfo));
        leveldb::Status st = db->Put(leveldb::WriteOptions(), tkey, tslice);
        if(!st.ok()) throw std::runtime_error("Could not write transaction to BlockStore db : " + st.ToString());

        // Wallet index entries (from and to)
        SHA256Hash txid = block.getTransactions()[i].hashContents();

        struct { uint8_t addr[25]; uint8_t txId[32]; } w1Key{};
        struct { uint8_t addr[25]; uint8_t txId[32]; } w2Key{};

        std::memcpy(w1Key.addr, t.from.data(), 25);
        std::memcpy(w1Key.txId, txid.data(), 32);
        std::memcpy(w2Key.addr, t.to.data(), 25);
        std::memcpy(w2Key.txId, txid.data(), 32);

        leveldb::Slice wkey(reinterpret_cast<const char*>(&w1Key), sizeof(w1Key));
        leveldb::Slice empty("", 0);
        st = db->Put(leveldb::WriteOptions(), wkey, empty);
        if(!st.ok()) throw std::runtime_error("Could not write sender wallet index to BlockStore db : " + st.ToString());

        wkey = leveldb::Slice(reinterpret_cast<const char*>(&w2Key), sizeof(w2Key));
        st = db->Put(leveldb::WriteOptions(), wkey, empty);
        if(!st.ok()) throw std::runtime_error("Could not write receiver wallet index to BlockStore db : " + st.ToString());
    }
}
