#pragma once
#include <Arduino.h>

// ─────────────────────────────────────────────────────────────────────────────
// lru_cache.h  –  256-entry direct-mapped cache keyed on 40-bit FNV-1a hash
//
// O(1) lookup and insert: slot = hash % CACHE_SIZE (direct-mapped).
// Collisions simply overwrite the existing slot (no chain, no probing).
// With 256 slots and typical DNS traffic, collision eviction is negligible.
//
// Each entry costs 10 bytes → total RAM: 256 × 10 = 2 560 bytes
// (was 64 × 14 = 896 bytes with O(64) scan — now 4× larger AND faster)
// ─────────────────────────────────────────────────────────────────────────────

static const int LRU_CACHE_SIZE = 256;

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

// O(1) lookup — returns true + sets 'result' if hash is cached
bool lruLookup(uint64_t hash, bool &result) {
    const int idx = (int)(hash % LRU_CACHE_SIZE);
    if (lruCache[idx].valid && lruCache[idx].hash == hash) {
        result = lruCache[idx].blocked;
        return true;
    }
    return false;
}

// O(1) insert — overwrites slot (direct-mapped eviction)
void lruInsert(uint64_t hash, bool blocked) {
    const int idx = (int)(hash % LRU_CACHE_SIZE);
    lruCache[idx] = { hash, blocked, true };
}

// Wipe the cache (call after blocklist update or list change)
void lruInvalidate() {
    memset(lruCache, 0, sizeof(lruCache));
}
