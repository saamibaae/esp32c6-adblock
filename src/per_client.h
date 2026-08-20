#pragma once
#include <Arduino.h>
#include <WiFi.h>

// ─────────────────────────────────────────────────────────────────────────────
// per_client.h  –  Per-device DNS query statistics (fixed 16-slot hash table)
//
// Keyed on IPv4 address packed as uint32_t. When the table is full, the
// least-recently-seen entry is evicted.
//
// Total RAM: 16 × 28 = 448 bytes — zero heap allocation.
// Call recordClient() from the DNS hot path; exposed via /api/clients.
// ─────────────────────────────────────────────────────────────────────────────

static const int CLIENT_TABLE_SIZE = 16;

struct ClientEntry {
    uint32_t ip;          // 0 = empty slot
    uint32_t total;       // total queries from this client
    uint32_t blocked;     // blocked queries from this client
    uint32_t lastSeen;    // millis() — used for LRU eviction
    char     ipStr[16];   // cached "a.b.c.d\0" string for the web API
};

static ClientEntry g_clients[CLIENT_TABLE_SIZE];

void clientsInit() {
    memset(g_clients, 0, sizeof(g_clients));
}

IRAM_ATTR void recordClient(const IPAddress &ip, bool blocked, const char *ipStr) {
    const uint32_t key = (uint32_t)ip;
    const uint32_t now = millis();

    int      freeSlot  = -1;
    int      evictSlot =  0;
    uint32_t oldest    = UINT32_MAX;

    for (int i = 0; i < CLIENT_TABLE_SIZE; i++) {
        // Fast path: existing entry found
        if (g_clients[i].ip == key) {
            g_clients[i].total++;
            if (blocked) g_clients[i].blocked++;
            g_clients[i].lastSeen = now;
            return;
        }
        // Track free and oldest slots for potential insert
        if (g_clients[i].ip == 0 && freeSlot < 0) freeSlot = i;
        if (g_clients[i].lastSeen < oldest) {
            oldest    = g_clients[i].lastSeen;
            evictSlot = i;
        }
    }

    // Insert into free slot or evict the oldest
    const int slot = (freeSlot >= 0) ? freeSlot : evictSlot;
    g_clients[slot].ip       = key;
    g_clients[slot].total    = 1;
    g_clients[slot].blocked  = blocked ? 1 : 0;
    g_clients[slot].lastSeen = now;
    strlcpy(g_clients[slot].ipStr, ipStr, sizeof(g_clients[slot].ipStr));
}
