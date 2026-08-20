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
// Both lists are loaded into RAM vectors on boot. Max practical size: ~200
// entries each before heap pressure becomes a concern.
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

// True if `domain` equals `entry` or is a subdomain of it.
static bool _matches(const char *domain, const String &entry) {
    size_t domLen = strlen(domain);
    size_t entLen = entry.length();
    if (domLen == entLen)
        return strcasecmp(domain, entry.c_str()) == 0;
    if (domLen > entLen + 1 &&
        domain[domLen - entLen - 1] == '.' &&
        strcasecmp(domain + domLen - entLen, entry.c_str()) == 0)
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

bool isWhitelisted(const char *domain) {
    for (const auto &e : g_whitelist)
        if (_matches(domain, e)) return true;
    return false;
}

bool isCustomBlocked(const char *domain) {
    for (const auto &e : g_blacklist)
        if (_matches(domain, e)) return true;
    return false;
}

bool addToWhitelist(const char *domain) {
    String d(domain);
    for (const auto &e : g_whitelist)
        if (e.equalsIgnoreCase(d)) return false; // duplicate
    g_whitelist.push_back(d);
    _writeListFile(WHITELIST_FILE, g_whitelist);
    return true;
}

bool removeFromWhitelist(const char *domain) {
    String d(domain);
    for (auto it = g_whitelist.begin(); it != g_whitelist.end(); ++it) {
        if (it->equalsIgnoreCase(d)) {
            g_whitelist.erase(it);
            _writeListFile(WHITELIST_FILE, g_whitelist);
            return true;
        }
    }
    return false;
}

bool addToBlacklist(const char *domain) {
    String d(domain);
    for (const auto &e : g_blacklist)
        if (e.equalsIgnoreCase(d)) return false; // duplicate
    g_blacklist.push_back(d);
    _writeListFile(BLACKLIST_FILE, g_blacklist);
    return true;
}

bool removeFromBlacklist(const char *domain) {
    String d(domain);
    for (auto it = g_blacklist.begin(); it != g_blacklist.end(); ++it) {
        if (it->equalsIgnoreCase(d)) {
            g_blacklist.erase(it);
            _writeListFile(BLACKLIST_FILE, g_blacklist);
            return true;
        }
    }
    return false;
}
