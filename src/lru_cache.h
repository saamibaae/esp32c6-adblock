#pragma once
#include <Arduino.h>

// ─────────────────────────────────────────────────────────────────────────────
// lru_cache.h  –  1024-entry direct-mapped cache keyed on 40-bit FNV-1a hash
//
// O(1) lookup and insert: slot = hash & (LRU_CACHE_SIZE - 1) (fast bitwise AND).
// Collisions overwrite the slot. Zero memory allocation, pinned to IRAM.
//
// Total RAM: 1024 × 16 = 16 384 bytes
// ─────────────────────────────────────────────────────────────────────────────

static const int LRU_CACHE_SIZE = 1024;

struct CacheEntry {
    uint64_t hash;    // 8 bytes — 40-bit FNV-1a domain hash
    bool     blocked; // 1 byte
    bool     valid;   // 1 byte
};

static CacheEntry lruCache[LRU_CACHE_SIZE];

// Reset all cache entries
void lruInit() {
    memset(lruCache, 0, sizeof(lruCache));
}

// O(1) IRAM lookup — returns true + sets 'result' if hash is cached
IRAM_ATTR static inline bool lruLookup(uint64_t hash, bool &result) {
    const int idx = (int)(hash & (LRU_CACHE_SIZE - 1));
    if (__builtin_expect(lruCache[idx].valid && lruCache[idx].hash == hash, 1)) {
        result = lruCache[idx].blocked;
        return true;
    }
    return false;
}

// O(1) IRAM insert — overwrites slot (direct-mapped eviction)
IRAM_ATTR static inline void lruInsert(uint64_t hash, bool blocked) {
    const int idx = (int)(hash & (LRU_CACHE_SIZE - 1));
    lruCache[idx] = { hash, blocked, true };
}

// Wipe the cache (call after blocklist update or list change)
void lruInvalidate() {
    memset(lruCache, 0, sizeof(lruCache));
}
