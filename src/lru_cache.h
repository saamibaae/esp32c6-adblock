#pragma once
#include <Arduino.h>

// ─────────────────────────────────────────────────────────────────────────────
// lru_cache.h  –  1,024-entry 2-Way Set-Associative Cache keyed on 40-bit hash
//
// 512 sets × 2 ways. Eliminates hash collision thrashing.
// O(1) lookup and insert: set = hash & (LRU_CACHE_SETS - 1).
// Zero heap allocation, pinned to IRAM.
//
// Total RAM: 512 × (2 × 16 + 1) = 16 896 bytes
// ─────────────────────────────────────────────────────────────────────────────

static const int LRU_CACHE_SETS = 512;

struct CacheEntry {
    uint64_t hash;    // 8 bytes — 40-bit FNV-1a domain hash
    bool     blocked; // 1 byte
    bool     valid;   // 1 byte
};

struct CacheSet {
    CacheEntry ways[2];
    uint8_t    lru;   // indicates which way to evict next
};

static CacheSet lruCache[LRU_CACHE_SETS];

// Reset all cache entries
void lruInit() {
    memset(lruCache, 0, sizeof(lruCache));
}

// O(1) IRAM lookup — checks both ways in parallel
IRAM_ATTR static inline bool lruLookup(uint64_t hash, bool &result) {
    const int set = (int)(hash & (LRU_CACHE_SETS - 1));
    CacheSet &s = lruCache[set];

    if (__builtin_expect(s.ways[0].valid && s.ways[0].hash == hash, 1)) {
        result = s.ways[0].blocked;
        s.lru = 1;
        return true;
    }
    if (__builtin_expect(s.ways[1].valid && s.ways[1].hash == hash, 1)) {
        result = s.ways[1].blocked;
        s.lru = 0;
        return true;
    }
    return false;
}

// O(1) IRAM insert — fills empty way or replaces least recently used way
IRAM_ATTR static inline void lruInsert(uint64_t hash, bool blocked) {
    const int set = (int)(hash & (LRU_CACHE_SETS - 1));
    CacheSet &s = lruCache[set];

    if (!s.ways[0].valid) {
        s.ways[0] = { hash, blocked, true };
        s.lru = 1;
    } else if (!s.ways[1].valid) {
        s.ways[1] = { hash, blocked, true };
        s.lru = 0;
    } else {
        const uint8_t victim = s.lru;
        s.ways[victim] = { hash, blocked, true };
        s.lru = 1 - victim;
    }
}

// Wipe the cache (call after blocklist update or list change)
void lruInvalidate() {
    memset(lruCache, 0, sizeof(lruCache));
}
