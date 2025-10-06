#pragma once
#include <array>
#include <cstdint>
#include <cstddef>
#include <string>
#include <chrono>
#include "common.hpp"   // defines TransactionAmount, SHA256Hash, PublicWalletAddress, json, etc.

// ---------- Monetary units (6 decimals) ----------
static constexpr uint64_t FRD_DECIMALS = 6;
static constexpr uint64_t FRD_COIN     = 1'000'000ULL; // 1 FRD = 1e6 atoms

// ---------- Endianness helpers (wire = little-endian) ----------
#if defined(_MSC_VER)
  #include <intrin.h>
  #define bswap32 _byteswap_ulong
  #define bswap64 _byteswap_uint64
#else
  #define bswap32 __builtin_bswap32
  #define bswap64 __builtin_bswap64
#endif

inline uint32_t toLE32(uint32_t x) {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  return bswap32(x);
#else
  return x;
#endif
}
inline uint64_t toLE64(uint64_t x) {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  return bswap64(x);
#else
  return x;
#endif
}
inline uint32_t fromLE32(uint32_t x) { return toLE32(x); }
inline uint64_t fromLE64(uint64_t x) { return toLE64(x); }

// Keep these names if other code calls them:
inline uint64_t hostToNetworkUint64(uint64_t x) { return toLE64(x); }
inline uint32_t hostToNetworkUint32(uint32_t x) { return toLE32(x); }
inline uint64_t networkToHostUint64(uint64_t x) { return fromLE64(x); }
inline uint32_t networkToHostUint32(uint32_t x) { return fromLE32(x); }

// ---------- Safe amount helpers (no floating point) ----------
TransactionAmount PDN_parse(const std::string& s);   // "123.456789" -> atoms (6 dp)
inline TransactionAmount PDN_from_atoms(uint64_t atoms) { return atoms; }

// Legacy signature (will be removed). Keep to avoid breakage; make it explicit bad:
TransactionAmount PDN(double amount) = delete;

// ---------- Random / time / utils ----------
std::string randomString(int length);
void writeJsonToFile(json data, std::string filepath);
json readJsonFromFile(std::string filepath);

std::uint64_t getCurrentTime();
std::string   uint64ToString(const std::uint64_t& t);
std::uint64_t stringToUint64(const std::string& input);
std::string   exec(const char* cmd);

template <typename T>
static T getSystemTime() {
    return std::chrono::duration_cast<T>(std::chrono::system_clock::now().time_since_epoch());
}
int64_t getTimeMilliseconds();

// ---------- Bounded network (de)serialization ----------
// All readers take (const char*& buf, size_t& remaining), throw on short buffer.
uint32_t         readNetworkUint32(const char*& buffer, size_t& remaining);
uint64_t         readNetworkUint64(const char*& buffer, size_t& remaining);
SHA256Hash       readNetworkSHA256(const char*& buffer, size_t& remaining);
PublicWalletAddress readNetworkPublicWalletAddress(const char*& buffer, size_t& remaining);
void             readNetworkNBytes(const char*& buffer, size_t& remaining, char* outBuffer, size_t N);

// Writers take (char*& buf, size_t& remaining); throw on overflow.
void writeNetworkUint32(char*& buffer, size_t& remaining, uint32_t x);
void writeNetworkUint64(char*& buffer, size_t& remaining, uint64_t x);
void writeNetworkSHA256(char*& buffer, size_t& remaining, const SHA256Hash& x);
void writeNetworkPublicWalletAddress(char*& buffer, size_t& remaining, const PublicWalletAddress& x);
void writeNetworkNBytes(char*& buffer, size_t& remaining, const char* inputBuffer, size_t N);

// ---------- Back-compat UNBOUNDED shims (deprecate) ----------
// If you need time to migrate call sites, these keep the old signatures.
// They do NOT bounds-check; prefer the bounded versions above.
uint32_t         readNetworkUint32(const char*& buffer);
uint64_t         readNetworkUint64(const char*& buffer);
SHA256Hash       readNetworkSHA256(const char*& buffer);
PublicWalletAddress readNetworkPublicWalletAddress(const char*& buffer);
void             readNetworkNBytes(const char*& buffer, char* outBuffer, size_t N);
void writeNetworkUint32(char*& buffer, uint32_t x);
void writeNetworkUint64(char*& buffer, uint64_t x);
void writeNetworkSHA256(char*& buffer, SHA256Hash& x);
void writeNetworkPublicWalletAddress(char*& buffer, PublicWalletAddress& x);
void writeNetworkNBytes(char*& buffer, char const* inputBuffer, size_t N);
