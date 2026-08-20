#pragma once
#include <Arduino.h>
#include <LittleFS.h>
#include <vector>
#include <algorithm>

// Forward declaration of 40-bit FNV-1a hash function defined in main.cpp
uint64_t fnv1a_40(const char *str, size_t len);

// ─────────────────────────────────────────────────────────────────────────────
// lists.h  –  Whitelist / Blacklist management with pre-hashed sorted arrays
//
// /whitelist.txt  –  one domain per line; matching skips ALL block checks
// /blacklist.txt  –  one domain per line; blocks BEFORE blocklist.bin lookup
//
// Pre-hashes loaded domains into sorted vectors for instant O(log N) integer
// binary search across parent subdomains in IRAM.
// ─────────────────────────────────────────────────────────────────────────────

#define WHITELIST_FILE "/whitelist.txt"
#define BLACKLIST_FILE "/blacklist.txt"

std::vector<String>   g_whitelist;
std::vector<String>   g_blacklist;
std::vector<uint64_t> g_whitelistHashes;
std::vector<uint64_t> g_blacklistHashes;

// ── Internal helpers ────────────────────────────────────────────────────────

static void _rebuildHashes() {
    g_whitelistHashes.clear();
    for (const auto &s : g_whitelist) {
        g_whitelistHashes.push_back(fnv1a_40(s.c_str(), s.length()));
    }
    std::sort(g_whitelistHashes.begin(), g_whitelistHashes.end());

    g_blacklistHashes.clear();
    for (const auto &s : g_blacklist) {
        g_blacklistHashes.push_back(fnv1a_40(s.c_str(), s.length()));
    }
    std::sort(g_blacklistHashes.begin(), g_blacklistHashes.end());
}

static void _readListFile(const char *path, std::vector<String> &list) {
    list.clear();
    File f = LittleFS.open(path, "r");
    if (!f) return;
    while (f.available()) {
        String line = f.readStringUntil('\n');
        line.trim();
        line.toLowerCase();
        if (line.length() > 0 && line[0] != '#')
            list.push_back(line);
    }
    f.close();
}

static void _writeListFile(const char *path, const std::vector<String> &list) {
    File f = LittleFS.open(path, "w");
    if (!f) return;
    for (const auto &e : list) f.println(e);
    f.close();
}

// ── Public API ───────────────────────────────────────────────────────────────

void listsLoad() {
    _readListFile(WHITELIST_FILE, g_whitelist);
    _readListFile(BLACKLIST_FILE, g_blacklist);
    _rebuildHashes();
    Serial.printf("[LISTS] Whitelist: %d  Blacklist: %d entries\n",
                  (int)g_whitelist.size(), (int)g_blacklist.size());
}

IRAM_ATTR static inline bool _isHashInVec(const std::vector<uint64_t> &vec, uint64_t target) {
    if (vec.empty()) return false;
    int32_t low = 0, high = (int32_t)vec.size() - 1;
    while (low <= high) {
        int32_t mid = low + ((high - low) >> 1);
        uint64_t val = vec[mid];
        if (val == target) return true;
        if (val < target) low = mid + 1;
        else high = mid - 1;
    }
    return false;
}

IRAM_ATTR bool isWhitelisted(const char *domain, size_t domLen, uint64_t fullHash,
                             const uint8_t *labelOffsets, uint8_t labelCount) {
    if (g_whitelistHashes.empty()) return false;
    for (uint8_t i = 0; i < labelCount; i++) {
        const uint8_t off = labelOffsets[i];
        const uint64_t h = (i == 0) ? fullHash : fnv1a_40(domain + off, domLen - off);
        if (_isHashInVec(g_whitelistHashes, h)) return true;
    }
    return false;
}

IRAM_ATTR bool isCustomBlocked(const char *domain, size_t domLen, uint64_t fullHash,
                               const uint8_t *labelOffsets, uint8_t labelCount) {
    if (g_blacklistHashes.empty()) return false;
    for (uint8_t i = 0; i < labelCount; i++) {
        const uint8_t off = labelOffsets[i];
        const uint64_t h = (i == 0) ? fullHash : fnv1a_40(domain + off, domLen - off);
        if (_isHashInVec(g_blacklistHashes, h)) return true;
    }
    return false;
}

bool addToWhitelist(const char *domain) {
    String d(domain);
    d.trim();
    d.toLowerCase();
    for (const auto &e : g_whitelist)
        if (e == d) return false;
    g_whitelist.push_back(d);
    _writeListFile(WHITELIST_FILE, g_whitelist);
    _rebuildHashes();
    return true;
}

bool removeFromWhitelist(const char *domain) {
    String d(domain);
    d.trim();
    d.toLowerCase();
    for (auto it = g_whitelist.begin(); it != g_whitelist.end(); ++it) {
        if (*it == d) {
            g_whitelist.erase(it);
            _writeListFile(WHITELIST_FILE, g_whitelist);
            _rebuildHashes();
            return true;
        }
    }
    return false;
}

bool addToBlacklist(const char *domain) {
    String d(domain);
    d.trim();
    d.toLowerCase();
    for (const auto &e : g_blacklist)
        if (e == d) return false;
    g_blacklist.push_back(d);
    _writeListFile(BLACKLIST_FILE, g_blacklist);
    _rebuildHashes();
    return true;
}

bool removeFromBlacklist(const char *domain) {
    String d(domain);
    d.trim();
    d.toLowerCase();
    for (auto it = g_blacklist.begin(); it != g_blacklist.end(); ++it) {
        if (*it == d) {
            g_blacklist.erase(it);
            _writeListFile(BLACKLIST_FILE, g_blacklist);
            _rebuildHashes();
            return true;
        }
    }
    return false;
}
