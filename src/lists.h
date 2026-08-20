#pragma once
#include <Arduino.h>
#include <LittleFS.h>
#include <vector>

// ─────────────────────────────────────────────────────────────────────────────
// lists.h  –  Whitelist / Blacklist management backed by LittleFS text files
//
// /whitelist.txt  –  one domain per line; matching skips ALL block checks
// /blacklist.txt  –  one domain per line; blocks BEFORE blocklist.bin lookup
//
// Both lists are normalized to lowercase on load. Matching uses fast length
// pre-checks and memcmp rather than expensive locale-aware strcasecmp.
// ─────────────────────────────────────────────────────────────────────────────

#define WHITELIST_FILE "/whitelist.txt"
#define BLACKLIST_FILE "/blacklist.txt"

std::vector<String> g_whitelist;
std::vector<String> g_blacklist;

// ── Internal helpers ────────────────────────────────────────────────────────

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

// True if `domain` (lowercase) equals `entry` or is a subdomain of it.
IRAM_ATTR static inline bool _matches(const char *domain, size_t domLen, const String &entry) {
    const size_t entLen = entry.length();
    if (domLen == entLen)
        return memcmp(domain, entry.c_str(), domLen) == 0;
    if (domLen > entLen + 1 &&
        domain[domLen - entLen - 1] == '.' &&
        memcmp(domain + domLen - entLen, entry.c_str(), entLen) == 0)
        return true;
    return false;
}

// ── Public API ───────────────────────────────────────────────────────────────

void listsLoad() {
    _readListFile(WHITELIST_FILE, g_whitelist);
    _readListFile(BLACKLIST_FILE, g_blacklist);
    Serial.printf("[LISTS] Whitelist: %d  Blacklist: %d entries\n",
                  (int)g_whitelist.size(), (int)g_blacklist.size());
}

IRAM_ATTR bool isWhitelisted(const char *domain, size_t domLen) {
    if (g_whitelist.empty()) return false;
    for (const auto &e : g_whitelist)
        if (_matches(domain, domLen, e)) return true;
    return false;
}

IRAM_ATTR bool isCustomBlocked(const char *domain, size_t domLen) {
    if (g_blacklist.empty()) return false;
    for (const auto &e : g_blacklist)
        if (_matches(domain, domLen, e)) return true;
    return false;
}

bool addToWhitelist(const char *domain) {
    String d(domain);
    d.trim();
    d.toLowerCase();
    for (const auto &e : g_whitelist)
        if (e == d) return false; // duplicate
    g_whitelist.push_back(d);
    _writeListFile(WHITELIST_FILE, g_whitelist);
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
        if (e == d) return false; // duplicate
    g_blacklist.push_back(d);
    _writeListFile(BLACKLIST_FILE, g_blacklist);
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
            return true;
        }
    }
    return false;
}
