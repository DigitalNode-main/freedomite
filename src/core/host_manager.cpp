#include "host_manager.hpp"
#include "helpers.hpp"
#include "api.hpp"
#include "constants.hpp"
#include "logger.hpp"
#include "header_chain.hpp"
#include "../external/http.hpp"

#include <iostream>
#include <sstream>
#include <thread>
#include <mutex>
#include <future>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <set>

#if defined(_WIN32)
// Windows alternative to inet_pton can be used if needed (InetPtonA from Ws2_32)
#else
  #include <arpa/inet.h>
#endif

using namespace std;

#define ADD_PEER_BRANCH_FACTOR       10
#define HEADER_VALIDATION_HOST_COUNT 8
#define RANDOM_GOOD_HOST_COUNT       9
#define HOST_MIN_FRESHNESS           (180 * 60) // 3 hours

/*
    Fetches the public IP of the node
*/

static bool isJsHost(const std::string& addr) {
    return addr.find("peer://") != std::string::npos;
}

static bool isValidIPv4(std::string& ip) {
#if defined(_WIN32)
    // Minimal validation on Windows if InetPtonA is not wired here
    unsigned int a,b,c,d;
    if (std::sscanf(ip.c_str(), "%u.%u.%u.%u", &a,&b,&c,&d) != 4) return false;
    return a<=255 && b<=255 && c<=255 && d<=255;
#else
    struct in_addr addr{};
    return ::inet_pton(AF_INET, ip.c_str(), &addr) == 1;
#endif
}

string HostManager::computeAddress() {
    if (this->firewall) {
        return "http://undiscoverable";
    }
    if (this->ip == "") {
        bool found = false;
        vector<string> lookupServices = {
            "checkip.amazonaws.com",
            "icanhazip.com",
            "ifconfig.co",
            "wtfismyip.com/text",
            "ifconfig.io"
        };

        for (auto& lookupService : lookupServices) {
            string cmd = "curl -s4 " + lookupService;
            string rawUrl = exec(cmd.c_str());
            if (rawUrl.empty()) continue;
            string ip = rawUrl;
            if (!ip.empty() && (ip.back() == '\n' || ip.back() == '\r')) ip.pop_back();
            if (!ip.empty() && (ip.back() == '\n' || ip.back() == '\r')) ip.pop_back();

            if (isValidIPv4(ip)) {
                this->address = "http://" + ip  + ":" + to_string(this->port);
                found = true;
                break;
            }
        }

        if (!found) {
            Logger::logError("IP discovery", "Could not determine current IP address");
        }
    } else {
        this->address = this->ip + ":" + to_string(this->port);
    }
    return this->address;
}

/*
    This thread periodically updates all neighboring hosts with the node's current IP
*/  
static void peer_sync(HostManager& hm) {
    while (true) {
        for (auto host : hm.hosts) {
            try {
                pingPeer(host, hm.computeAddress(), std::time(0), hm.version, hm.networkName);
            } catch (...) { }
        }
        std::this_thread::sleep_for(std::chrono::minutes(5));
    }
}

/*
    This thread updates the current display of sync'd headers
*/
static void header_stats(HostManager& hm) {
    std::this_thread::sleep_for(std::chrono::seconds(30));
    while (true) {
        Logger::logStatus("================ Header Sync Status ===============");
        map<string, uint64_t> stats = hm.getHeaderChainStats();
        for (auto& item : stats) {
            std::stringstream ss;
            ss << "Host: " << item.first << ", blocks: " << item.second;
            Logger::logStatus(ss.str());
        }
        Logger::logStatus("===================================================");
        std::this_thread::sleep_for(std::chrono::seconds(30));
    }
}

HostManager::HostManager(json config) {
    this->name        = config["name"];
    this->port        = config["port"];
    this->ip          = config["ip"];
    this->firewall    = config["firewall"];
    this->version     = BUILD_VERSION;
    this->networkName = config["networkName"];
    this->computeAddress();

    // parse checkpoints
    for (auto checkpoint : config["checkpoints"]) {
        this->checkpoints.insert(std::pair<uint64_t, SHA256Hash>(checkpoint[0], stringToSHA256(checkpoint[1])));
    }

    // parse banned hashes
    for (auto bannedHash : config["bannedHashes"]) {
        this->bannedHashes.insert(std::pair<uint64_t, SHA256Hash>(bannedHash[0], stringToSHA256(bannedHash[1])));
    }

    // parse supported host versions
    this->minHostVersion = config["minHostVersion"];

    // blacklist
    {
        std::ifstream blacklist("blacklist.txt");
        if (blacklist.good()) {
            std::string line;
            while (std::getline(blacklist, line)) {
                if (line.empty() || line[0] == '#') continue;
                string blocked = line;
                if (!blocked.empty() && blocked.back() == '/') blocked.pop_back();
                this->blacklist.insert(blocked);
                Logger::logStatus("Ignoring host " + blocked);
            }
        }
    }

    // whitelist
    {
        std::ifstream whitelist("whitelist.txt");
        if (whitelist.good()) {
            std::string line;
            while (std::getline(whitelist, line)) {
                if (line.empty() || line[0] == '#') continue;
                string enabled = line;
                if (!enabled.empty() && enabled.back() == '/') enabled.pop_back();
                this->whitelist.insert(enabled);
                Logger::logStatus("Enabling host " + enabled);
            }
        }
    }

    this->disabled = false;
    for (auto h : config["hostSources"]) {
        this->hostSources.push_back(h);
    }
    if (this->hostSources.size() == 0) {
        string localhost = "http://localhost:3000";
        this->hosts.push_back(localhost);
        this->hostPingTimes[localhost] = std::time(0);
        this->peerClockDeltas[localhost] = 0;
        this->syncHeadersWithPeers();
    } else {
        this->refreshHostList();
    }

    // start thread to print header chain stats
    bool showHeaderStats = config["showHeaderStats"];
    if (showHeaderStats) this->headerStatsThread.push_back(std::thread(header_stats, std::ref(*this)));
}

HostManager::~HostManager() {
    // Note: these threads are infinite loops today. If you later add a stop flag,
    // signal it here and join. For now, detach to avoid terminating the process.
    for (auto &t : this->headerStatsThread) { if (t.joinable()) t.detach(); }
    for (auto &t : this->syncThread)        { if (t.joinable()) t.detach();  }
}

void HostManager::startPingingPeers() {
    if (this->syncThread.size() > 0) throw std::runtime_error("Peer ping thread exists.");
    this->syncThread.push_back(std::thread(peer_sync, std::ref(*this)));
}

string HostManager::getAddress() const { return this->address; }

// Only used for tests
HostManager::HostManager() { this->disabled = true; }

uint64_t HostManager::getNetworkTimestamp() const {
    // find deltas of all hosts that pinged recently
    vector<int32_t> deltas;
    for (auto pair : this->hostPingTimes) {
        uint64_t lastPingAge = std::time(0) - pair.second;
        if (lastPingAge < HOST_MIN_FRESHNESS) { 
            auto it = peerClockDeltas.find(pair.first);
            if (it != peerClockDeltas.end()) deltas.push_back(it->second);
        }
    }
    if (deltas.empty()) return std::time(0);

    std::sort(deltas.begin(), deltas.end());
    uint64_t medianTime;
    if (deltas.size() % 2 == 0) {
        int32_t avg = (deltas[deltas.size()/2] + deltas[deltas.size()/2 - 1]) / 2;
        medianTime = std::time(0) + avg;
    } else {
        int32_t delta = deltas[deltas.size()/2];
        medianTime = std::time(0) + delta;
    }
    return medianTime;
}

string HostManager::getGoodHost() const {
    if (this->currPeers.size() < 1) return "";
    Bigint bestWork = 0;
    string bestHost = this->currPeers[0]->getHost();
    std::unique_lock<std::mutex> ul(lock);
    for (auto h : this->currPeers) {
        if (h->getTotalWork() > bestWork) {
            bestWork = h->getTotalWork();
            bestHost = h->getHost();
        }
    }
    return bestHost;
}

map<string,uint64_t> HostManager::getHeaderChainStats() const {
    map<string, uint64_t> ret;
    for (auto h : this->currPeers) ret[h->getHost()] = h->getCurrentDownloaded();
    return ret;
}

uint64_t HostManager::getBlockCount() const {
    if (this->currPeers.size() < 1) return 0;
    uint64_t bestLength = 0;
    Bigint bestWork = 0;
    std::unique_lock<std::mutex> ul(lock);
    for (auto h : this->currPeers) {
        if (h->getTotalWork() > bestWork) {
            bestWork = h->getTotalWork();
            bestLength = h->getChainLength();
        }
    }
    return bestLength;
}

Bigint HostManager::getTotalWork() const {
    Bigint bestWork = 0;
    std::unique_lock<std::mutex> ul(lock);
    if (this->currPeers.size() < 1) return bestWork;
    for (auto h : this->currPeers) {
        if (h->getTotalWork() > bestWork) {
            bestWork = h->getTotalWork();
        }
    }
    return bestWork;
}

SHA256Hash HostManager::getBlockHash(string host, uint64_t blockId) const {
    SHA256Hash ret = NULL_SHA256_HASH;
    std::unique_lock<std::mutex> ul(lock);
    for (auto h : this->currPeers) {
        if (h->getHost() == host) {
            ret = h->getHash(blockId);
            break;
        }
    }
    return ret;
}

set<string> HostManager::sampleFreshHosts(int count) {
    vector<string> freshHosts;
    for (auto pair : this->hostPingTimes) {
        uint64_t lastPingAge = std::time(0) - pair.second;
        if (lastPingAge < HOST_MIN_FRESHNESS && !isJsHost(pair.first)) {
            freshHosts.push_back(pair.first);
        }
    }

    int numToPick = std::min(count, static_cast<int>(freshHosts.size()));
    set<string> sampledHosts;
    while (static_cast<int>(sampledHosts.size()) < numToPick) {
        string host = freshHosts[std::rand() % freshHosts.size()];
        sampledHosts.insert(host);
    }
    return sampledHosts;
}

void HostManager::addPeer(string addr, uint64_t time, string version, string network) {
    if (network != this->networkName) return;
    if (version < this->minHostVersion) return;

    if (this->blacklist.find(addr) != this->blacklist.end()) return;

    auto existing = std::find(this->hosts.begin(), this->hosts.end(), addr);
    if (existing != this->hosts.end()) {
        this->hostPingTimes[addr] = std::time(0);
        this->peerClockDeltas[addr] = std::time(0) - time;
        return;
    }

    if (!isJsHost(addr)) {
        try { (void)getName(addr); } catch(...) { return; }
    }

    if (this->whitelist.size() == 0 || this->whitelist.find(addr) != this->whitelist.end()){
        Logger::logStatus("Added new peer: " + addr);
        hosts.push_back(addr);
    } else {
        return;
    }

    if (this->currPeers.size() < RANDOM_GOOD_HOST_COUNT) {
        std::unique_lock<std::mutex> ul(lock);
        this->currPeers.push_back(std::make_shared<HeaderChain>(addr, this->checkpoints, this->bannedHashes));
    }

    set<string> neighbors = this->sampleFreshHosts(ADD_PEER_BRANCH_FACTOR);
    vector<future<void>> reqs;
    string _version = this->version;
    string networkName = this->networkName;
    for (auto neighbor : neighbors) {
        reqs.push_back(std::async([neighbor, addr, _version, networkName](){
            if (neighbor == addr) return;
            try {
                pingPeer(neighbor, addr, std::time(0), _version, networkName);
            } catch(...) {
                Logger::logStatus("Could not add peer " + addr + " to " + neighbor);
            }
        }));
    }

    for (auto &r : reqs) r.get();
}

void HostManager::setBlockstore(std::shared_ptr<BlockStore> blockStore) {
    this->blockStore = blockStore;
}

bool HostManager::isDisabled() { return this->disabled; }

void HostManager::refreshHostList() {
    if (this->hostSources.size() == 0) return;
    Logger::logStatus("Finding peers...");

    set<string> fullHostList;

    for (size_t i = 0; i < this->hostSources.size(); i++) {
        try {
            string hostUrl = this->hostSources[i];
            http::Request request{hostUrl};
            const auto response = request.send("GET","",{},std::chrono::milliseconds{TIMEOUT_MS});
            json hostList = json::parse(std::string{response.body.begin(), response.body.end()});
            for (auto host : hostList) fullHostList.insert(string(host));
        } catch (...) {
            continue;
        }
    }

    if (fullHostList.size() == 0) return;

    vector<std::thread> threads;
    std::mutex add_lock;
    for (auto hostJson : fullHostList) {
        string hostUrl = string(hostJson);
        auto existing = std::find(this->hosts.begin(), this->hosts.end(), hostUrl);
        if (existing != this->hosts.end()) continue;
        if (this->blacklist.find(hostUrl) != this->blacklist.end()) continue;

        HostManager & hm = *this;
        threads.emplace_back(
            std::thread([hostUrl, &hm, &add_lock](){
                try {
                    json hostInfo = getName(hostUrl);
                    if (hostInfo["version"] < hm.minHostVersion) {
                        Logger::logStatus(RED + std::string("[ DEPRECATED ] ") + RESET + hostUrl);
                        return;
                    }
                    std::unique_lock<std::mutex> ul(add_lock);
                    if (hm.whitelist.size() == 0 || hm.whitelist.find(hostUrl) != hm.whitelist.end()){
                        hm.hosts.push_back(hostUrl);
                        Logger::logStatus(GREEN + std::string("[ CONNECTED ] ") + RESET + hostUrl);
                        hm.hostPingTimes[hostUrl] = std::time(0);
                    }
                } catch (...) {
                    Logger::logStatus(RED + std::string("[ UNREACHABLE ] ") + RESET + hostUrl);
                }
            })
        );
    }
    for (auto& th : threads) th.join();
}

void HostManager::syncHeadersWithPeers() {
    std::unique_lock<std::mutex> ul(lock);
    this->currPeers.clear();

    set<string> hosts = this->sampleFreshHosts(RANDOM_GOOD_HOST_COUNT);
    for (auto h : hosts) {
        this->currPeers.push_back(std::make_shared<HeaderChain>(h, this->checkpoints, this->bannedHashes, this->blockStore));
    }
}

vector<string> HostManager::getHosts(bool includeSelf) const {
    vector<string> ret;
    for (auto pair : this->hostPingTimes) {
        uint64_t lastPingAge = std::time(0) - pair.second;
        if (lastPingAge < HOST_MIN_FRESHNESS) ret.push_back(pair.first);
    }
    if (includeSelf) ret.push_back(this->address);
    return ret;
}

size_t HostManager::size() { return this->hosts.size(); }
