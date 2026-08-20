#pragma once
#include <Arduino.h>

// ─────────────────────────────────────────────────────────────────────────────
// stats.h  –  Zero-allocation statistics counters + power-of-2 circular log
//
// New in this version:
//   • RTT_HIST_SIZE = 32 (power of 2) — bitwise AND indexing (no division)
//   • QUERY_LOG_SIZE = 64 (power of 2) — bitwise AND indexing (no division)
//   • Bounded memcpy for domain string copying
//   • Pure integer scaled percentage & average calculations
// ─────────────────────────────────────────────────────────────────────────────

static const int QUERY_LOG_SIZE = 64;
static const int RTT_HIST_SIZE  = 32;

struct QueryEntry {
    char     domain[64];
    char     clientIP[16]; // "255.255.255.255\0"
    uint16_t qtype;
    bool     blocked;
    uint32_t timestamp;    // millis() when query was received
    uint16_t rttMs;        // upstream RTT in ms (0 = blocked or cached)
};

struct Stats {
    uint32_t totalQueries   = 0;
    uint32_t blockedQueries = 0;
    uint32_t cacheHits      = 0;
    uint32_t startTime      = 0; // set to millis() in setup()

    // ── Upstream RTT tracking (forwarded queries only) ─────────────────────
    uint32_t minRtt    = UINT32_MAX; // UINT32_MAX = "not yet measured"
    uint32_t maxRtt    = 0;
    uint64_t totalRtt  = 0;          // 64-bit to avoid overflow after millions of queries
    uint32_t rttCount  = 0;

    // Circular RTT history — power of 2
    uint16_t rttHistory[RTT_HIST_SIZE];
    int      rttHistHead  = 0;
    int      rttHistCount = 0;

    // ── Circular query log — power of 2 ───────────────────────────────────
    QueryEntry log[QUERY_LOG_SIZE];
    int        logHead  = 0;
    int        logCount = 0;

    // Record a DNS decision (called in the hot path — bounded memcpy, no heap)
    void record(const char *domain, size_t domLen, uint16_t qtype, bool blocked,
                const char *clientIP, uint16_t rttMs = 0)
    {
        totalQueries++;
        if (blocked) blockedQueries++;

        QueryEntry &e = log[logHead];
        size_t cpy = domLen < 63 ? domLen : 63;
        memcpy(e.domain, domain, cpy);
        e.domain[cpy] = '\0';
        strlcpy(e.clientIP, clientIP, sizeof(e.clientIP));
        e.qtype     = qtype;
        e.blocked   = blocked;
        e.timestamp = millis();
        e.rttMs     = rttMs;

        logHead = (logHead + 1) & (QUERY_LOG_SIZE - 1);
        if (logCount < QUERY_LOG_SIZE) logCount++;
    }

    void record(const char *domain, uint16_t qtype, bool blocked,
                const char *clientIP, uint16_t rttMs = 0)
    {
        record(domain, strlen(domain), qtype, blocked, clientIP, rttMs);
    }

    // Record upstream RTT (call when upstream response arrives)
    void recordRTT(uint32_t ms) {
        uint16_t val = (uint16_t)min(ms, (uint32_t)65535);
        if (ms < minRtt) minRtt = ms;
        if (ms > maxRtt) maxRtt = ms;
        totalRtt += ms;
        rttCount++;

        rttHistory[rttHistHead] = val;
        rttHistHead = (rttHistHead + 1) & (RTT_HIST_SIZE - 1);
        if (rttHistCount < RTT_HIST_SIZE) rttHistCount++;
    }

    uint32_t avgRtt() const {
        return rttCount ? (uint32_t)(totalRtt / rttCount) : 0;
    }

    uint32_t uptimeSecs() const { return (millis() - startTime) / 1000; }
    uint32_t blockedPct() const {
        return totalQueries ? (blockedQueries * 100UL) / totalQueries : 0;
    }
};

// Single global instance — only include this header from main.cpp
Stats g_stats;
