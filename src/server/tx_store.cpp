#include "tx_store.hpp"
#include <cstring>   // memcpy
#include <thread>
#include <stdexcept>

bool TransactionStore::hasTransaction(const Transaction &t) {
    SHA256Hash txHash = t.hashContents();
    leveldb::Slice key(reinterpret_cast<const char*>(txHash.data()), txHash.size());
    std::string value;
    leveldb::Status status = db->Get(leveldb::ReadOptions(), key, &value);
    return status.ok();
}

uint32_t TransactionStore::blockForTransaction(Transaction &t) {
    SHA256Hash txHash = t.hashContents();
    leveldb::Slice key(reinterpret_cast<const char*>(txHash.data()), txHash.size());
    std::string value;
    leveldb::Status status = db->Get(leveldb::ReadOptions(), key, &value);
    if (!status.ok() || value.size() < sizeof(uint32_t)) return 0;
    uint32_t val;
    std::memcpy(&val, value.data(), sizeof(uint32_t));
    return val;
}

uint32_t TransactionStore::blockForTransactionId(SHA256Hash txHash) const {
    leveldb::Slice key(reinterpret_cast<const char*>(txHash.data()), txHash.size());
    std::string value;
    leveldb::Status status = db->Get(leveldb::ReadOptions(), key, &value);
    if (!status.ok() || value.size() < sizeof(uint32_t)) return 0;
    uint32_t val;
    std::memcpy(&val, value.data(), sizeof(uint32_t));
    return val;
}

void TransactionStore::insertTransaction(Transaction& t, uint32_t blockId) {
    SHA256Hash txHash = t.hashContents();
    leveldb::Slice key(reinterpret_cast<const char*>(txHash.data()), txHash.size());
    const uint32_t stored = blockId;
    leveldb::Slice slice(reinterpret_cast<const char*>(&stored), sizeof(uint32_t));
    leveldb::Status status = db->Put(leveldb::WriteOptions(), key, slice);
    if(!status.ok())
        throw std::runtime_error("Could not write transaction hash to tx db : " + status.ToString());
}

void TransactionStore::removeTransaction(Transaction& t) {
    SHA256Hash txHash = t.hashContents();
    leveldb::Slice key(reinterpret_cast<const char*>(txHash.data()), txHash.size());
    leveldb::Status status = db->Delete(leveldb::WriteOptions(), key);
    if(!status.ok())
        throw std::runtime_error("Could not remove transaction hash from tx db : " + status.ToString());
}
