#include "helpers.hpp"
#include "constants.hpp"
#include <fstream>
#include <sstream>
#include <random>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <cstring>

// ---------------- Amounts (6 decimals, no FP) ----------------
TransactionAmount PDN_parse(const std::string& s) {
    // Accepts optional leading '+', digits, optional '.', up to FRD_DECIMALS fractional digits.
    if (s.empty()) throw std::runtime_error("bad amount: empty");
    size_t pos = 0;
    bool neg = false;
    if (s[pos] == '+') pos++;
    else if (s[pos] == '-') { neg = true; pos++; }

    std::string whole, frac;
    for (; pos < s.size() && std::isdigit(static_cast<unsigned char>(s[pos])); ++pos) whole.push_back(s[pos]);
    if (pos < s.size() && s[pos] == '.') {
        ++pos;
        while (pos < s.size() && std::isdigit(static_cast<unsigned char>(s[pos])) && frac.size() < FRD_DECIMALS) {
            frac.push_back(s[pos++]);
        }
        // ignore any trailing non-digits silently? Better: reject
        if (pos < s.size() && std::isdigit(static_cast<unsigned char>(s[pos]))) {
            // too many fractional digits
            throw std::runtime_error("bad amount: too many fractional digits");
        }
    }
    while (frac.size() < FRD_DECIMALS) frac.push_back('0');
    if (whole.empty()) whole = "0";

    uint64_t w = 0, f = 0;
    for (char c : whole) {
        if (c < '0' || c > '9') throw std::runtime_error("bad amount");
        if (w > (UINT64_MAX / 10)) throw std::overflow_error("amount overflow");
        w = w * 10 + (c - '0');
    }
    for (char c : frac) {
        if (c < '0' || c > '9') throw std::runtime_error("bad amount");
        if (f > (UINT64_MAX / 10)) throw std::overflow_error("amount overflow");
        f = f * 10 + (c - '0');
    }

    __int128 atoms = (__int128)w * FRD_COIN + f;
    if (neg) atoms = -atoms;
    if (atoms < 0 || atoms > (__int128)std::numeric_limits<uint64_t>::max())
        throw std::overflow_error("amount overflow");
    return (uint64_t)atoms;
}

// ---------------- Random / time / utils ----------------
std::string randomString(int len) {
    static thread_local std::mt19937_64 rng(std::random_device{}());
    static constexpr char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    std::uniform_int_distribution<size_t> dist(0, sizeof(alphanum) - 2);
    std::string out;
    out.reserve(len);
    for (int i = 0; i < len; ++i) out.push_back(alphanum[dist(rng)]);
    return out;
}

void writeJsonToFile(json data, std::string filepath) {
    std::ofstream output(filepath, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("cannot open file for writing: " + filepath);
    const std::string dataStr = data.dump();
    output.write(dataStr.data(), static_cast<std::streamsize>(dataStr.size()));
    if (!output) throw std::runtime_error("write failed: " + filepath);
}

json readJsonFromFile(std::string filepath) {
    std::ifstream input(filepath, std::ios::binary);
    if (!input) throw std::runtime_error("cannot open file: " + filepath);
    std::stringstream buffer;
    buffer << input.rdbuf();
    return json::parse(buffer.str());
}

std::uint64_t getCurrentTime() { return static_cast<std::uint64_t>(std::time(nullptr)); }

std::string uint64ToString(const std::uint64_t& t) {
    std::ostringstream oss; oss << t; return oss.str();
}

std::uint64_t stringToUint64(const std::string& input) {
    std::istringstream stream(input);
    uint64_t t = 0; stream >> t; return t;
}

std::string exec(const char* cmd) {
    std::array<char, 128> buffer{};
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) throw std::runtime_error("popen() failed");
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

int64_t getTimeMilliseconds() {
    return int64_t{ getSystemTime<std::chrono::milliseconds>().count() };
}

// ---------------- Bounded network (de)serialization ----------------
static inline void require_space(size_t need, size_t remaining) {
    if (remaining < need) throw std::runtime_error("short buffer");
}

uint32_t readNetworkUint32(const char*& buffer, size_t& remaining) {
    require_space(4, remaining);
    uint32_t x;
    std::memcpy(&x, buffer, 4);
    buffer += 4; remaining -= 4;
    return networkToHostUint32(x);
}
uint64_t readNetworkUint64(const char*& buffer, size_t& remaining) {
    require_space(8, remaining);
    uint64_t x;
    std::memcpy(&x, buffer, 8);
    buffer += 8; remaining -= 8;
    return networkToHostUint64(x);
}
SHA256Hash readNetworkSHA256(const char*& buffer, size_t& remaining) {
    SHA256Hash h{};
    require_space(h.size(), remaining);
    std::memcpy(h.data(), buffer, h.size());
    buffer += h.size(); remaining -= h.size();
    return h;
}
PublicWalletAddress readNetworkPublicWalletAddress(const char*& buffer, size_t& remaining) {
    PublicWalletAddress w{};
    require_space(w.size(), remaining);
    std::memcpy(w.data(), buffer, w.size());
    buffer += w.size(); remaining -= w.size();
    return w;
}
void readNetworkNBytes(const char*& buffer, size_t& remaining, char* outBuffer, size_t N) {
    require_space(N, remaining);
    std::memcpy(outBuffer, buffer, N);
    buffer += N; remaining -= N;
}

void writeNetworkUint32(char*& buffer, size_t& remaining, uint32_t x) {
    require_space(4, remaining);
    x = hostToNetworkUint32(x);
    std::memcpy(buffer, &x, 4);
    buffer += 4; remaining -= 4;
}
void writeNetworkUint64(char*& buffer, size_t& remaining, uint64_t x) {
    require_space(8, remaining);
    x = hostToNetworkUint64(x);
    std::memcpy(buffer, &x, 8);
    buffer += 8; remaining -= 8;
}
void writeNetworkSHA256(char*& buffer, size_t& remaining, const SHA256Hash& x) {
    require_space(x.size(), remaining);
    std::memcpy(buffer, x.data(), x.size());
    buffer += x.size(); remaining -= x.size();
}
void writeNetworkPublicWalletAddress(char*& buffer, size_t& remaining, const PublicWalletAddress& x) {
    require_space(x.size(), remaining);
    std::memcpy(buffer, x.data(), x.size());
    buffer += x.size(); remaining -= x.size();
}
void writeNetworkNBytes(char*& buffer, size_t& remaining, const char* inputBuffer, size_t N) {
    require_space(N, remaining);
    std::memcpy(buffer, inputBuffer, N);
    buffer += N; remaining -= N;
}

// --------------- Back-compat unbounded shims (DEPRECATED) ---------------
uint32_t readNetworkUint32(const char*& buffer) {
    uint32_t x; std::_
