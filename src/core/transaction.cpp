##include "transaction.hpp"
#include "helpers.hpp"
#include "block.hpp"
#include "openssl/sha.h"
#include <sstream>
#include <iostream>
#include <cstring>
#include <ctime>
using namespace std;

/* ---------- Safe, bounded (de)serialization ---------- */

TransactionInfo transactionInfoFromBuffer(const char* buffer, size_t len) {
    TransactionInfo t{};
    size_t remaining = len;

    // signature (64) + signingKey (32) + timestamp (8) + to (25) + amount (8) + fee (8) + flag (4)
    readNetworkNBytes(buffer, remaining, t.signature, 64);
    readNetworkNBytes(buffer, remaining, t.signingKey, 32);
    t.timestamp       = readNetworkUint64(buffer, remaining);
    t.to              = readNetworkPublicWalletAddress(buffer, remaining);
    t.amount          = readNetworkUint64(buffer, remaining);
    t.fee             = readNetworkUint64(buffer, remaining);
    t.isTransactionFee = (readNetworkUint32(buffer, remaining) > 0);

    if (!t.isTransactionFee) {
        PublicKey pub{};
        std::memcpy(pub.data(), t.signingKey, 32);
        t.from = walletAddressFromPublicKey(pub);
    } else {
        t.from = NULL_ADDRESS;
    }

    return t;
}

// Legacy wrapper (keeps old signature). Requires the fixed serialized size.
TransactionInfo transactionInfoFromBuffer(const char* buffer) {
    // If your project exposes TRANSACTIONINFO_BUFFER_SIZE, use it here.
#ifdef TRANSACTIONINFO_BUFFER_SIZE
    return transactionInfoFromBuffer(buffer, TRANSACTIONINFO_BUFFER_SIZE);
#else
    // Fallback: compute expected size explicitly (hardcoded layout)
    constexpr size_t kExpected =
        64 /*sig*/ + 32 /*pubkey*/ + 8 /*ts*/ + 25 /*to*/ + 8 /*amount*/ + 8 /*fee*/ + 4 /*flag*/;
    return transactionInfoFromBuffer(buffer, kExpected);
#endif
}

void transactionInfoToBuffer(TransactionInfo& t, char* buffer, size_t len) {
    size_t remaining = len;

    writeNetworkNBytes(buffer, remaining, t.signature, 64);
    writeNetworkNBytes(buffer, remaining, t.signingKey, 32);
    writeNetworkUint64(buffer, remaining, t.timestamp);
    writeNetworkPublicWalletAddress(buffer, remaining, t.to);
    writeNetworkUint64(buffer, remaining, t.amount);
    writeNetworkUint64(buffer, remaining, t.fee);

    uint32_t flag = t.isTransactionFee ? 1u : 0u;
    writeNetworkUint32(buffer, remaining, flag);
}

// Legacy wrapper (keeps old signature). Requires the fixed serialized size.
void transactionInfoToBuffer(TransactionInfo& t, char* buffer) {
#ifdef TRANSACTIONINFO_BUFFER_SIZE
    transactionInfoToBuffer(t, buffer, TRANSACTIONINFO_BUFFER_SIZE);
#else
    constexpr size_t kExpected =
        64 /*sig*/ + 32 /*pubkey*/ + 8 /*ts*/ + 25 /*to*/ + 8 /*amount*/ + 8 /*fee*/ + 4 /*flag*/;
    transactionInfoToBuffer(t, buffer, kExpected);
#endif
}

/* ---------- Transaction constructors / serialization ---------- */

Transaction::Transaction(PublicWalletAddress from, PublicWalletAddress to, TransactionAmount amount, PublicKey signingKey, TransactionAmount fee) {
    this->from = from;
    this->to = to;
    this->amount = amount;
    this->isTransactionFee = false;
    this->timestamp = std::time(nullptr);
    this->fee = fee;
    this->signingKey = signingKey;
}

Transaction::Transaction(PublicWalletAddress from, PublicWalletAddress to, TransactionAmount amount, PublicKey signingKey, TransactionAmount fee, uint64_t timestamp) {
    this->from = from;
    this->to = to;
    this->amount = amount;
    this->isTransactionFee = false;
    this->timestamp = timestamp;
    this->fee = fee;
    this->signingKey = signingKey;
}

Transaction::Transaction() = default;

Transaction::Transaction(const TransactionInfo& t) {
    this->to = t.to;
    if (!t.isTransactionFee) this->from = t.from;
    std::memcpy(this->signature.data(), t.signature, 64);
    std::memcpy(this->signingKey.data(), t.signingKey, 32);
    this->amount = t.amount;
    this->isTransactionFee = t.isTransactionFee;
    this->timestamp = t.timestamp;
    this->fee = t.fee;
}

TransactionInfo Transaction::serialize() const {
    TransactionInfo t{};
    std::memcpy(t.signature, this->signature.data(), 64);
    std::memcpy(t.signingKey, this->signingKey.data(), 32);
    t.timestamp = this->timestamp;
    t.to = this->to;
    t.from = this->from;
    t.amount = this->amount;
    t.fee = this->fee;
    t.isTransactionFee = this->isTransactionFee;
    return t;
}

Transaction::Transaction(const Transaction & t) = default;

Transaction::Transaction(PublicWalletAddress to, TransactionAmount fee) {
    this->to = to;
    this->amount = fee;
    this->isTransactionFee = true;
    this->timestamp = getCurrentTime();
    this->fee = 0;
}

Transaction::Transaction(json data) {
    this->timestamp = stringToUint64(data["timestamp"]);
    this->to = stringToWalletAddress(data["to"]);
    this->fee = data["fee"];
    if (data["from"] == "") {        
        this->amount = data["amount"];
        this->isTransactionFee = true;
    } else {
        this->from = stringToWalletAddress(data["from"]);
        this->signature = stringToSignature(data["signature"]);
        this->amount = data["amount"];
        this->isTransactionFee = false;
        this->signingKey = stringToPublicKey(data["signingKey"]);
    }
}

/* ---------- Getters / setters ---------- */

void Transaction::setTransactionFee(TransactionAmount amount) { this->fee = amount; }
TransactionAmount Transaction::getTransactionFee() const { return this->fee; }

json Transaction::toJson() {
    json result;
    result["to"] = walletAddressToString(this->toWallet());
    result["amount"] = this->amount;
    result["timestamp"] = uint64ToString(this->timestamp);
    result["fee"] = this->fee;
    result["txid"] = SHA256toString(this->hashContents());
    if (!this->isTransactionFee) {
        result["from"] = walletAddressToString(this->fromWallet());
        result["signingKey"] = publicKeyToString(this->signingKey);
        result["signature"] = signatureToString(this->signature);
    } else {
        result["from"] = "";
    }
    return result;
}

bool Transaction::isFee() const { return this->isTransactionFee; }
void Transaction::setTimestamp(uint64_t t) { this->timestamp = t; }
uint64_t Transaction::getTimestamp() const { return this->timestamp; }
TransactionSignature Transaction::getSignature() const { return this->signature; }
void Transaction::setAmount(TransactionAmount amt) { this->amount = amt; }
PublicKey Transaction::getSigningKey() { return this->signingKey; }

/* ---------- Hashing & signatures ---------- */

SHA256Hash Transaction::getHash() const {
    SHA256Hash ret{};
    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    SHA256Hash contentHash = this->hashContents();
    SHA256_Update(&sha256, (unsigned char*)contentHash.data(), contentHash.size());

    if (!this->isTransactionFee) {
        SHA256_Update(&sha256, (unsigned char*)this->signature.data(), this->signature.size());
    }

    SHA256_Final(ret.data(), &sha256);
    return ret;
}

SHA256Hash Transaction::hashContents() const {
    // Canonicalize numeric fields to little-endian before hashing to avoid platform variance.
    uint64_t feeLE  = toLE64(this->fee);
    uint64_t amtLE  = toLE64(this->amount);
    uint64_t tsLE   = toLE64(this->timestamp);

    SHA256Hash ret{};
    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    PublicWalletAddress wallet = this->toWallet();
    SHA256_Update(&sha256, (unsigned char*)wallet.data(), wallet.size());

    if (!this->isTransactionFee) {
        wallet = this->fromWallet();
        SHA256_Update(&sha256, (unsigned char*)wallet.data(), wallet.size());
    }

    SHA256_Update(&sha256, (unsigned char*)&feeLE, sizeof(uint64_t));
    SHA256_Update(&sha256, (unsigned char*)&amtLE, sizeof(uint64_t));
    SHA256_Update(&sha256, (unsigned char*)&tsLE,  sizeof(uint64_t));

    SHA256_Final(ret.data(), &sha256);
    return ret;
}

void Transaction::sign(PublicKey pubKey, PrivateKey signingKey) {
    SHA256Hash hash = this->hashContents();
    TransactionSignature signature = signWithPrivateKey((const char*)hash.data(), hash.size(), pubKey, signingKey);
    this->signature = signature;
}

/* ---------- Comparators ---------- */

bool operator<(const Transaction& a, const Transaction& b) {
    return a.signature < b.signature;
}

bool operator==(const Transaction& a, const Transaction& b) {
    if (a.timestamp != b.timestamp) return false;
    if (a.toWallet() != b.toWallet()) return false;
    if (a.getTransactionFee() != b.getTransactionFee()) return false;
    if (a.amount != b.amount) return false;
    if (a.isTransactionFee != b.isTransactionFee) return false;
    if (!a.isTransactionFee) {
        if (a.fromWallet() != b.fromWallet()) return false;
        if (signatureToString(a.signature) != signatureToString(b.signature)) return false;
        if (publicKeyToString(a.signingKey) != publicKeyToString(b.signingKey)) return false;
    }
    return true;
}
