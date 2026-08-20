#pragma once
#include <Arduino.h>

// ─────────────────────────────────────────────────────────────────────────────
// lru_cache.h  –  64-entry LRU cache keyed on 40-bit FNV-1a domain hash
//
// Each entry costs 14 bytes → total RAM: 64 × 14 = 896 bytes
// A cache hit avoids all binary-search flash seeks for that domain.
// ─────────────────────────────────────────────────────────────────────────────

const int LRU_CACHE_SIZE = 64;

struct CacheEntry {
    uint64_t hash;
    uint32_t lastUsed; // monotonic counter, not wall time
    bool     blocked;
    bool     valid;
};

CacheEntry lruCache[LRU_CACHE_SIZE];
uint32_t   lruCounter = 0;

void lruInit() {
    memset(lruCache, 0, sizeof(lruCache));
    lruCounter = 0;
}

// Returns true + sets result if hash is cached.
bool lruLookup(uint64_t hash, bool &result) {
    for (int i = 0; i < LRU_CACHE_SIZE; i++) {
        if (lruCache[i].valid && lruCache[i].hash == hash) {
            lruCache[i].lastUsed = ++lruCounter;
            result = lruCache[i].blocked;
            return true;
        }
    }
    return false;
}

// Insert or overwrite the LRU slot.
void lruInsert(uint64_t hash, bool blocked) {
    int      slot    = 0;
    uint32_t oldest  = UINT32_MAX;

    for (int i = 0; i < LRU_CACHE_SIZE; i++) {
        if (!lruCache[i].valid) { slot = i; goto insert; } // free slot
        if (lruCache[i].lastUsed < oldest) {
            oldest = lruCache[i].lastUsed;
            slot   = i;
        }
    }
    insert:
    lruCache[slot] = { hash, ++lruCounter, blocked, true };
}

// Wipe the cache (call after blocklist update or list change)
void lruInvalidate() {
    memset(lruCache, 0, sizeof(lruCache));
    lruCounter = 0;
}
