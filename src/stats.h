#pragma once
#include <Arduino.h>

// ─────────────────────────────────────────────────────────────────────────────
// stats.h  –  Zero-allocation statistics counters + circular DNS query log
// ─────────────────────────────────────────────────────────────────────────────

const int QUERY_LOG_SIZE = 30;

struct QueryEntry {
    char     domain[64];
    char     clientIP[16]; // IPv4 address format: "255.255.255.255\0"
    uint16_t qtype;
    bool     blocked;
    uint32_t timestamp; // millis() value
};

struct Stats {
    uint32_t   totalQueries   = 0;
    uint32_t   blockedQueries = 0;
    uint32_t   cacheHits      = 0;
    uint32_t   startTime      = 0; // set to millis() in setup()

    // Circular buffer — logHead is the NEXT write slot
    QueryEntry log[QUERY_LOG_SIZE];
    int        logHead  = 0;
    int        logCount = 0;  // clamped at QUERY_LOG_SIZE

    // Record a DNS decision (called in the hot path — no heap allocation)
    void record(const char *domain, uint16_t qtype, bool blocked, const char *clientIP) {
        totalQueries++;
        if (blocked) blockedQueries++;

        QueryEntry &e = log[logHead];
        strlcpy(e.domain, domain, sizeof(e.domain));
        strlcpy(e.clientIP, clientIP, sizeof(e.clientIP));
        e.qtype     = qtype;
        e.blocked   = blocked;
        e.timestamp = millis();

        logHead = (logHead + 1) % QUERY_LOG_SIZE;
        if (logCount < QUERY_LOG_SIZE) logCount++;
    }

    uint32_t uptimeSecs()   const { return (millis() - startTime) / 1000; }
    uint32_t blockedPct()   const {
        return totalQueries ? (blockedQueries * 100UL) / totalQueries : 0;
    }
};

// Single global instance — only include this header from main.cpp
Stats g_stats;
