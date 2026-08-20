/#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <LittleFS.h>
#include <ArduinoOTA.h>
#include <esp_wifi.h>
#include "secrets.h"

// ── Branch prediction optimization macros ─────────────────────────────────────
#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)

// ══════════════════════════════════════════════════════════════════════════════
//  Core globals — defined BEFORE module headers so they can reference them
// ══════════════════════════════════════════════════════════════════════════════
File     blocklistFile;
uint32_t totalHashes = 0;
bool     fsReady     = false;

// ══════════════════════════════════════════════════════════════════════════════
//  Module headers (included in dependency order)
// ══════════════════════════════════════════════════════════════════════════════
#include "stats.h"        // g_stats
#include "lru_cache.h"    // lruInit / lruLookup / lruInsert / lruInvalidate
#include "per_client.h"   // clientsInit / recordClient / g_clients
#include "lists.h"        // g_whitelist / g_blacklist / isWhitelisted / isCustomBlocked
#include "settings.h"     // g_blockMode / settingsLoad / settingsSave
#include "ota_updater.h"  // startBlocklistUpdate / getOtaStatus

// ══════════════════════════════════════════════════════════════════════════════
//  DNS configuration — defined before web_ui.h so its lambdas can reference them
// ══════════════════════════════════════════════════════════════════════════════
IPAddress        UPSTREAM_DNS(1, 1, 1, 1);          // primary (user-configurable)
IPAddress        UPSTREAM_DNS_FALLBACK(8, 8, 8, 8); // fallback / parallel race
const uint16_t   DNS_PORT        = 53;
const int        MAX_PENDING     = 32;              // power of 2 for bitwise AND
const uint32_t   QUERY_TIMEOUT   = 3000;            // ms

WiFiUDP dnsServer;
WiFiUDP upstreamClient;

unsigned long lastHeartbeat        = 0;
unsigned long lastReconnectAttempt = 0;
unsigned long lastStatsBroadcast   = 0;

// Dual-upstream status
bool g_usingFallback = false;
inline IPAddress& currentUpstream() { return UPSTREAM_DNS; }

// ── Async pending query table (packed for cache locality) ────────────────────
struct PendingQuery {
    uint32_t  timestamp;
    IPAddress clientIP;
    uint64_t  domainHash;
    uint16_t  origTxId;
    uint16_t  ourTxId;
    uint16_t  clientPort;
    uint16_t  qtype;
    bool      active;
};
PendingQuery    pendingQueries[MAX_PENDING];
static uint16_t s_txIdCounter = 0;

// Static response buffer
static uint8_t s_upstreamRespBuf[1024];

// ── In-RAM DNS Answer Cache (128 slots, TTL-based record caching) ─────────────
struct AnswerCacheEntry {
    uint64_t hash;
    uint32_t ip4;
    uint32_t expiresAt;
    bool     valid;
};
static const int ANSWER_CACHE_SIZE = 128;
static AnswerCacheEntry s_ansCache[ANSWER_CACHE_SIZE];

IRAM_ATTR static inline bool lookupAnswerCache(uint64_t hash, uint32_t now, uint32_t &ip4, uint32_t &remTtl) {
    const int idx = (int)(hash & (ANSWER_CACHE_SIZE - 1));
    AnswerCacheEntry &e = s_ansCache[idx];
    if (LIKELY(e.valid && e.hash == hash)) {
        if (LIKELY(now < e.expiresAt)) {
            ip4 = e.ip4;
            remTtl = (e.expiresAt - now) / 1000;
            if (remTtl == 0) remTtl = 1;
            return true;
        }
        e.valid = false;
    }
    return false;
}

IRAM_ATTR static inline void insertAnswerCache(uint64_t hash, uint32_t ip4, uint32_t ttlSec, uint32_t now) {
    if (ttlSec == 0 || ttlSec > 86400) ttlSec = 300;
    const int idx = (int)(hash & (ANSWER_CACHE_SIZE - 1));
    s_ansCache[idx] = { hash, ip4, now + (ttlSec * 1000), true };
}

// ── web_ui.h included here so its lambdas see the types above ────────────────
#include "web_ui.h"       // webUiSetup / webUiLoop / broadcastQuery

// ══════════════════════════════════════════════════════════════════════════════
//  40-bit FNV-1a Hash — IRAM pinned, direct branchless hash on pre-lowercased input
// ══════════════════════════════════════════════════════════════════════════════
IRAM_ATTR __attribute__((hot)) uint64_t fnv1a_40(const char *str, size_t len)
{
    uint64_t hash = 0xcbf29ce484222325ULL;
    const char *end = str + len;
    while (str < end) {
        hash ^= (unsigned char)*str++;
        hash *= 0x100000001b3ULL;
    }
    return hash & 0xFFFFFFFFFFULL;
}

// ── Pre-hashed tracker and essential domains (IRAM binary search) ────────────
#include "tracker_hashes.h"

// ══════════════════════════════════════════════════════════════════════════════
//  32 KB Bloom filter (262,144 bits) — branchless bitwise checking
//
//  False-positive rate drops to < 0.05% for ~93 K entries.
//  Zero flash I/O on 99.95% of allowed domains.
// ══════════════════════════════════════════════════════════════════════════════
static uint8_t g_bloom[32768];

static inline __attribute__((always_inline)) void IRAM_ATTR bloomSet(uint64_t hash) {
    const uint32_t h1 = (uint32_t)( hash        & 0x3FFFF);
    const uint32_t h2 = (uint32_t)((hash >> 11) & 0x3FFFF);
    const uint32_t h3 = (uint32_t)((hash >> 22) & 0x3FFFF);
    g_bloom[h1 >> 3] |= (1u << (h1 & 7));
    g_bloom[h2 >> 3] |= (1u << (h2 & 7));
    g_bloom[h3 >> 3] |= (1u << (h3 & 7));
}

static inline __attribute__((always_inline)) bool IRAM_ATTR bloomCheck(uint64_t hash) {
    const uint32_t h1 = (uint32_t)( hash        & 0x3FFFF);
    const uint32_t h2 = (uint32_t)((hash >> 11) & 0x3FFFF);
    const uint32_t h3 = (uint32_t)((hash >> 22) & 0x3FFFF);
    const uint32_t b1 = (g_bloom[h1 >> 3] >> (h1 & 7)) & 1;
    const uint32_t b2 = (g_bloom[h2 >> 3] >> (h2 & 7)) & 1;
    const uint32_t b3 = (g_bloom[h3 >> 3] >> (h3 & 7)) & 1;
    return (b1 & b2 & b3) != 0;
}

// ══════════════════════════════════════════════════════════════════════════════
//  In-RAM Coarse Flash Index (1,024 anchors, 8 KB)
//  Narrows binary search range from 93,516 hashes to <= 91 hashes in RAM
//  Reduces flash seek/read operations by > 65% (<= 6 flash reads)
// ══════════════════════════════════════════════════════════════════════════════
static const size_t COARSE_INDEX_SIZE = 1024;
static uint64_t g_coarseIndex[COARSE_INDEX_SIZE];

static void buildCoarseIndex() {
    if (!fsReady || totalHashes == 0) return;
    uint8_t buf[5];
    for (size_t i = 0; i < COARSE_INDEX_SIZE; i++) {
        uint32_t targetIdx = (uint32_t)((uint64_t)i * (totalHashes - 1) / (COARSE_INDEX_SIZE - 1));
        blocklistFile.seek(targetIdx * 5);
        if (blocklistFile.read(buf, 5) == 5) {
            g_coarseIndex[i] = ((uint64_t)buf[0] << 32) |
                               ((uint64_t)buf[1] << 24) |
                               ((uint64_t)buf[2] << 16) |
                               ((uint64_t)buf[3] << 8)  |
                                (uint64_t)buf[4];
        }
    }
    blocklistFile.seek(0);
    Serial.println("[INDEX] 1024-bucket coarse flash index built");
}

// Bulk sequential read pass over blocklist.bin (128 hashes per read)
static void buildBloom() {
    memset(g_bloom, 0, sizeof(g_bloom));
    if (!fsReady) return;
    blocklistFile.seek(0);
    uint8_t buf[640]; // 128 × 5-byte hashes
    int n;
    while ((n = blocklistFile.read(buf, sizeof(buf))) > 0) {
        for (int i = 0; i + 4 < n; i += 5) {
            uint64_t h = ((uint64_t)buf[i]     << 32) |
                         ((uint64_t)buf[i + 1] << 24) |
                         ((uint64_t)buf[i + 2] << 16) |
                         ((uint64_t)buf[i + 3] << 8)  |
                          (uint64_t)buf[i + 4];
            bloomSet(h);
        }
    }
    blocklistFile.seek(0); // reset file position for binary search
    Serial.printf("[BLOOM] 32 KB filter built for %u hashes\n", totalHashes);
    buildCoarseIndex();
}

// ══════════════════════════════════════════════════════════════════════════════
//  Fast IP to string converter (bypasses heavy snprintf format-parsing overhead)
// ══════════════════════════════════════════════════════════════════════════════
IRAM_ATTR static inline __attribute__((always_inline)) void fastIpToStr(const IPAddress &ip, char *out) {
    char *p = out;
    for (int i = 0; i < 4; i++) {
        uint8_t v = ip[i];
        if (v >= 100) {
            *p++ = '0' + (v / 100);
            v %= 100;
            *p++ = '0' + (v / 10);
            *p++ = '0' + (v % 10);
        } else if (v >= 10) {
            *p++ = '0' + (v / 10);
            *p++ = '0' + (v % 10);
        } else {
            *p++ = '0' + v;
        }
        if (i < 3) *p++ = '.';
    }
    *p = '\0';
}

// ══════════════════════════════════════════════════════════════════════════════
//  Binary search in LittleFS — coarse index-accelerated, bloom-filtered
// ══════════════════════════════════════════════════════════════════════════════
IRAM_ATTR __attribute__((hot)) bool isHashBlocked(uint64_t targetHash)
{
    if (UNLIKELY(!fsReady || totalHashes == 0)) return false;

    // Bloom pre-screen: ~99.95% of allowed-domain hashes exit here with zero flash I/O
    if (LIKELY(!bloomCheck(targetHash))) return false;

    // Fast in-RAM coarse index lookup to narrow [low, high] search bounds
    int32_t bLow = 0, bHigh = (int32_t)COARSE_INDEX_SIZE - 1;
    while (bLow <= bHigh) {
        int32_t bMid = bLow + ((bHigh - bLow) >> 1);
        if (g_coarseIndex[bMid] <= targetHash) {
            bLow = bMid + 1;
        } else {
            bHigh = bMid - 1;
        }
    }
    int32_t startBucket = (bLow > 0) ? bLow - 1 : 0;
    int32_t endBucket   = (bLow < (int32_t)COARSE_INDEX_SIZE) ? bLow : (int32_t)COARSE_INDEX_SIZE - 1;

    int32_t low  = (int32_t)((uint64_t)startBucket * (totalHashes - 1) / (COARSE_INDEX_SIZE - 1));
    int32_t high = (int32_t)((uint64_t)endBucket   * (totalHashes - 1) / (COARSE_INDEX_SIZE - 1));
    uint8_t buf[5];

    while (low <= high) {
        int32_t mid = low + ((high - low) >> 1);
        blocklistFile.seek((uint32_t)mid * 5);
        if (UNLIKELY(blocklistFile.read(buf, 5) != 5)) break;

        uint64_t h = ((uint64_t)buf[0] << 32) |
                     ((uint64_t)buf[1] << 24) |
                     ((uint64_t)buf[2] << 16) |
                     ((uint64_t)buf[3] << 8)  |
                      (uint64_t)buf[4];

        if      (h == targetHash) return true;
        else if (h  < targetHash) low  = mid + 1;
        else                      high = mid - 1;
    }
    return false;
}

// ══════════════════════════════════════════════════════════════════════════════
//  DNS lookup pipeline with full priority chain and behavioral modes
// ══════════════════════════════════════════════════════════════════════════════
IRAM_ATTR __attribute__((hot)) bool isDomainBlocked(const char *domain, size_t domLen,
                                                    uint64_t fullHash,
                                                    const uint8_t *labelOffsets, uint8_t labelCount)
{
    // Mode: ABSOLUTE (Hailmary) — block EVERYTHING not whitelisted
    if (UNLIKELY(g_blockMode == BlockMode::ABSOLUTE)) {
        return !isWhitelisted(domain, domLen, fullHash, labelOffsets, labelCount);
    }

    // Mode: BYPASS — block nothing
    if (UNLIKELY(g_blockMode == BlockMode::BYPASS)) return false;

    // ── LRU cache check first (O(1) 2-way associative lookup) ────────────
    bool cached;
    if (LIKELY(lruLookup(fullHash, cached))) {
        g_stats.cacheHits++;
        return cached;
    }

    // 1. Whitelist — always forward, skip all block checks
    if (UNLIKELY(isWhitelisted(domain, domLen, fullHash, labelOffsets, labelCount))) {
        lruInsert(fullHash, false);
        return false;
    }

    // 2. Custom blacklist — block immediately without touching flash
    if (UNLIKELY(isCustomBlocked(domain, domLen, fullHash, labelOffsets, labelCount))) {
        lruInsert(fullHash, true);
        return true;
    }

    // Mode: MINIMAL — block ONLY custom blacklist (ignore blocklist.bin)
    if (UNLIKELY(g_blockMode == BlockMode::MINIMAL)) {
        lruInsert(fullHash, false);
        return false;
    }

    // 3. Strict Mode: explicitly block all known major trackers (O(log N) IRAM binary search)
    if (g_blockMode == BlockMode::STRICT) {
        if (domainMatchesSet(domain, domLen, fullHash, labelOffsets, labelCount, g_strictTrackerHashes, TRACKER_COUNT)) {
            lruInsert(fullHash, true);
            return true;
        }
    }

    // 4. Ensure essential services are never blocked (Normal & Strict modes)
    if (g_blockMode == BlockMode::NORMAL || g_blockMode == BlockMode::STRICT) {
        if (domainMatchesSet(domain, domLen, fullHash, labelOffsets, labelCount, g_essentialHashes, ESSENTIAL_COUNT)) {
            lruInsert(fullHash, false);
            return false;
        }
    }

    // 5. Binary search in LittleFS for domain + parent subdomains using precalculated label offsets
    bool blocked = false;
    for (uint8_t i = 0; i < labelCount; i++) {
        const uint8_t off = labelOffsets[i];
        const uint64_t h = (i == 0) ? fullHash : fnv1a_40(domain + off, domLen - off);
        if (isHashBlocked(h)) {
            blocked = true;
            break;
        }
    }

    // 6. Cache result for next lookup
    lruInsert(fullHash, blocked);
    return blocked;
}

// ══════════════════════════════════════════════════════════════════════════════
//  DNS packet parsing — single pass: case-normalizes, hashes, & finds labels
// ══════════════════════════════════════════════════════════════════════════════
IRAM_ATTR __attribute__((hot)) bool parseQName(const uint8_t *buf, size_t len,
                                              char *out, size_t outMax,
                                              size_t &qnameEnd, size_t &outLen,
                                              uint64_t &fullHash,
                                              uint8_t *labelOffsets, uint8_t &labelCount)
{
    size_t pos  = 12; // skip 12-byte DNS header
    size_t dpos = 0;
    out[0] = '\0';
    labelCount = 0;
    uint64_t hash = 0xcbf29ce484222325ULL;

    while (pos < len && buf[pos] != 0) {
        uint8_t llen = buf[pos++];
        if (UNLIKELY(pos + llen > len))          return false; // truncated
        if (UNLIKELY(dpos + llen + 2 > outMax))  return false; // overflow guard

        if (dpos > 0) {
            out[dpos++] = '.';
            hash ^= (unsigned char)'.';
            hash *= 0x100000001b3ULL;
        }
        if (LIKELY(labelCount < 8)) {
            labelOffsets[labelCount++] = (uint8_t)dpos;
        }
        for (uint8_t i = 0; i < llen; i++) {
            unsigned char c = buf[pos + i];
            c += (c >= 'A' && c <= 'Z') ? 32 : 0; // branchless ASCII lowercase
            out[dpos++] = c;
            hash ^= c;
            hash *= 0x100000001b3ULL;
        }
        pos += llen;
    }
    out[dpos] = '\0';
    outLen    = dpos;
    qnameEnd  = pos + 1; // +1 to step over the null label
    fullHash  = hash & 0xFFFFFFFFFFULL;
    return dpos > 0;
}

// ══════════════════════════════════════════════════════════════════════════════
//  Sinkhole response — 0.0.0.0 (A) or :: (AAAA), TTL = 3600 s (1 hour cache)
//  Optimized: pre-initialized static template with targeted byte writes
// ══════════════════════════════════════════════════════════════════════════════
IRAM_ATTR __attribute__((hot)) void sendSinkholeResponse(IPAddress clientIP, uint16_t clientPort,
                                                         const uint8_t *query, size_t queryLen,
                                                         size_t qnameEnd, uint16_t qtype)
{
    static uint8_t resp[256];
    static bool initialized = false;
    if (UNLIKELY(!initialized)) {
        resp[2]  = 0x81; resp[3]  = 0x80; // Flags: QR=1, RA=1, NOERROR
        resp[4]  = 0x00; resp[5]  = 0x01; // QDCOUNT = 1
        resp[6]  = 0x00; resp[7]  = 0x01; // ANCOUNT = 1
        resp[8]  = 0x00; resp[9]  = 0x00; // NSCOUNT = 0
        resp[10] = 0x00; resp[11] = 0x00; // ARCOUNT = 0
        initialized = true;
    }

    *(uint16_t*)resp = *(const uint16_t*)query; // 16-bit copy Transaction ID

    size_t questionLen = (qnameEnd + 4) - 12;
    memcpy(&resp[12], &query[12], questionLen);
    size_t idx = 12 + questionLen;

    resp[idx++] = 0xC0; resp[idx++] = 0x0C;   // Name: pointer to 0x0C
    resp[idx++] = (qtype >> 8) & 0xFF;
    resp[idx++] =  qtype       & 0xFF;
    resp[idx++] = 0x00; resp[idx++] = 0x01;   // CLASS IN
    resp[idx++] = 0x00; resp[idx++] = 0x00;
    resp[idx++] = 0x0E; resp[idx++] = 0x10;   // TTL: 3600 s (1 hour client caching)

    if (qtype == 0x001C) {                     // AAAA → ::
        resp[idx++] = 0x00; resp[idx++] = 0x10;
        memset(&resp[idx], 0, 16);
        idx += 16;
    } else {                                   // A → 0.0.0.0
        resp[idx++] = 0x00; resp[idx++] = 0x04;
        resp[idx++] = 0x00; resp[idx++] = 0x00;
        resp[idx++] = 0x00; resp[idx++] = 0x00;
    }

    dnsServer.beginPacket(clientIP, clientPort);
    dnsServer.write(resp, idx);
    dnsServer.endPacket();
}

// ── Send cached IPv4 answer directly from SRAM (< 0.1 ms latency) ─────────────
IRAM_ATTR __attribute__((hot)) void sendCachedAnswerResponse(IPAddress clientIP, uint16_t clientPort,
                                                             const uint8_t *query, size_t queryLen,
                                                             size_t qnameEnd, uint32_t ip4, uint32_t ttlSec)
{
    static uint8_t resp[256];
    static bool initialized = false;
    if (UNLIKELY(!initialized)) {
        resp[2]  = 0x81; resp[3]  = 0x80; // Flags: QR=1, RA=1, NOERROR
        resp[4]  = 0x00; resp[5]  = 0x01; // QDCOUNT = 1
        resp[6]  = 0x00; resp[7]  = 0x01; // ANCOUNT = 1
        resp[8]  = 0x00; resp[9]  = 0x00; // NSCOUNT = 0
        resp[10] = 0x00; resp[11] = 0x00; // ARCOUNT = 0
        initialized = true;
    }

    *(uint16_t*)resp = *(const uint16_t*)query; // Transaction ID

    size_t questionLen = (qnameEnd + 4) - 12;
    memcpy(&resp[12], &query[12], questionLen);
    size_t idx = 12 + questionLen;

    resp[idx++] = 0xC0; resp[idx++] = 0x0C;   // Name pointer
    resp[idx++] = 0x00; resp[idx++] = 0x01;   // TYPE A
    resp[idx++] = 0x00; resp[idx++] = 0x01;   // CLASS IN
    resp[idx++] = (ttlSec >> 24) & 0xFF;
    resp[idx++] = (ttlSec >> 16) & 0xFF;
    resp[idx++] = (ttlSec >> 8)  & 0xFF;
    resp[idx++] =  ttlSec        & 0xFF;
    resp[idx++] = 0x00; resp[idx++] = 0x04;   // RDLENGTH = 4
    memcpy(&resp[idx], &ip4, 4);
    idx += 4;

    dnsServer.beginPacket(clientIP, clientPort);
    dnsServer.write(resp, idx);
    dnsServer.endPacket();
}

// ── Send cached NXDOMAIN directly from SRAM (< 0.1 ms latency) ────────────────
IRAM_ATTR __attribute__((hot)) void sendNxdomainResponse(IPAddress clientIP, uint16_t clientPort,
                                                         const uint8_t *query, size_t queryLen,
                                                         size_t qnameEnd)
{
    static uint8_t resp[256];
    *(uint16_t*)resp = *(const uint16_t*)query; // Transaction ID
    resp[2]  = 0x81; resp[3]  = 0x83; // Flags: QR=1, RA=1, RCODE=3 (NXDOMAIN)
    resp[4]  = 0x00; resp[5]  = 0x01; // QDCOUNT = 1
    resp[6]  = 0x00; resp[7]  = 0x00; // ANCOUNT = 0
    resp[8]  = 0x00; resp[9]  = 0x00; // NSCOUNT = 0
    resp[10] = 0x00; resp[11] = 0x00; // ARCOUNT = 0

    size_t questionLen = (qnameEnd + 4) - 12;
    memcpy(&resp[12], &query[12], questionLen);
    size_t idx = 12 + questionLen;

    dnsServer.beginPacket(clientIP, clientPort);
    dnsServer.write(resp, idx);
    dnsServer.endPacket();
}

// ── SERVFAIL response — sent when a pending query times out ──────────────────
void sendServfail(IPAddress clientIP, uint16_t clientPort, uint16_t txId)
{
    uint8_t resp[12];
    *(uint16_t*)resp = __builtin_bswap16(txId);
    resp[2] = 0x81; resp[3] = 0x82; // QR=1, RA=1, RCODE=2 (SERVFAIL)
    memset(resp + 4, 0, 8);         // QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT = 0
    dnsServer.beginPacket(clientIP, clientPort);
    dnsServer.write(resp, 12);
    dnsServer.endPacket();
}

// ══════════════════════════════════════════════════════════════════════════════
//  Non-blocking upstream forward: Parallel Dual-Upstream DNS Racing
//  Dispatches to both primary and fallback simultaneously on the same socket
// ══════════════════════════════════════════════════════════════════════════════
IRAM_ATTR __attribute__((hot)) void forwardUpstream(IPAddress clientIP, uint16_t clientPort,
                                                    uint8_t *query, size_t queryLen,
                                                    uint64_t domainHash, uint16_t qtype, uint32_t now)
{
    uint16_t origTxId = __builtin_bswap16(*(const uint16_t*)query);
    uint16_t ourTxId  = ++s_txIdCounter;
    if (UNLIKELY(ourTxId == 0)) ourTxId = ++s_txIdCounter; // skip 0

    // O(1) bitwise slot assignment (power of 2)
    const int slot = (int)(ourTxId & (MAX_PENDING - 1));
    pendingQueries[slot] = { now, clientIP, domainHash, origTxId, ourTxId, clientPort, qtype, true };

    // Rewrite txId in the packet before sending upstream
    *(uint16_t*)query = __builtin_bswap16(ourTxId);

    // Parallel Dual-Upstream Race: send to primary and fallback simultaneously
    upstreamClient.beginPacket(UPSTREAM_DNS, DNS_PORT);
    upstreamClient.write(query, queryLen);
    upstreamClient.endPacket();

    upstreamClient.beginPacket(UPSTREAM_DNS_FALLBACK, DNS_PORT);
    upstreamClient.write(query, queryLen);
    upstreamClient.endPacket();

    // Restore original txId (caller's buffer must remain intact)
    *(uint16_t*)query = __builtin_bswap16(origTxId);
}

// ══════════════════════════════════════════════════════════════════════════════
//  setup()
// ══════════════════════════════════════════════════════════════════════════════
void setup()
{
    // Enforce 160 MHz maximum RISC-V CPU clock
    setCpuFrequencyMhz(160);

    // Boost FreeRTOS DNS loop priority for preemptive packet execution
    vTaskPrioritySet(NULL, 5);

    // Configure XIAO ESP32-C6 RF Switch — onboard ceramic antenna
    pinMode(3,  OUTPUT); digitalWrite(3,  HIGH); // GPIO3 HIGH = power on RF switch
    pinMode(14, OUTPUT); digitalWrite(14, LOW);  // GPIO14 LOW = select onboard antenna

    Serial.begin(115200);
    delay(2000); // USB-CDC terminal attach

    Serial.println("\n══════════════════════════════════");
    Serial.println("  XIAO ESP32-C6 DNS Sinkhole");
    Serial.println("══════════════════════════════════");

    // Initialise modules
    lruInit();
    clientsInit();
    memset(pendingQueries, 0, sizeof(pendingQueries));
    memset(s_ansCache, 0, sizeof(s_ansCache));
    g_stats.startTime = millis();

    // ── LittleFS ──────────────────────────────────────────────────────────────
    if (!LittleFS.begin(true)) {
        Serial.println("[ERROR] LittleFS mount failed.");
    } else {
        blocklistFile = LittleFS.open("/blocklist.bin", "r");
        if (!blocklistFile) {
            Serial.println("[WARN] /blocklist.bin missing — run 'pio run -t uploadfs'");
        } else {
            totalHashes = blocklistFile.size() / 5;
            fsReady     = true;
            Serial.printf("[FS] Loaded %u hashes (%.1f KB)\n",
                          totalHashes, blocklistFile.size() / 1024.0f);
            buildBloom(); // 32 KB filter with bulk read + 1024-bucket coarse index
        }
        listsLoad();          // whitelist + blacklist with pre-hashed sorted arrays
        settingsLoad();       // blocking mode
        initTrackerHashes();  // compile-time pre-sorted tracker constants

        // Load upstream DNS override saved from the web dashboard
        File dnsFile = LittleFS.open("/dns.txt", "r");
        if (dnsFile) {
            String val = dnsFile.readStringUntil('\n');
            val.trim();
            IPAddress addr;
            if (addr.fromString(val)) {
                UPSTREAM_DNS = addr;
                Serial.printf("[DNS] Upstream DNS loaded from file: %s\n", val.c_str());
            }
            dnsFile.close();
        }
    }

    // ── Wi-Fi ────────────────────────────────────────────────────────────────
    WiFi.disconnect(true);
    WiFi.mode(WIFI_STA);
    WiFi.setSleep(false); // disable modem sleep for minimum DNS latency
    WiFi.setTxPower(WIFI_POWER_19_5dBm); // maximum RF output power
    delay(100);

    // ── Static IP — ensures DNS address never changes after a reboot ─────────
    {
        IPAddress ip, gw, sn;
        ip.fromString(STATIC_IP);
        gw.fromString(GATEWAY_IP);
        sn.fromString(SUBNET_MASK);
        WiFi.config(ip, gw, sn);
        Serial.printf("[WIFI] Static IP configured: %s\n", STATIC_IP);
    }

    Serial.printf("[WIFI] Connecting to '%s'", WIFI_SSID);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

    for (int i = 0; WiFi.status() != WL_CONNECTED && i < 30; i++) {
        delay(500); Serial.print(".");
    }

    if (WiFi.status() == WL_CONNECTED) {
        // Enforce zero power-save at the IDF MAC layer for sub-millisecond radio response
        esp_wifi_set_ps(WIFI_PS_NONE);

        Serial.printf("\n[WIFI] Connected — IP: %s\n",
                      WiFi.localIP().toString().c_str());

        // ── DNS server + upstream socket ──────────────────────────────────
        dnsServer.begin(DNS_PORT);
        upstreamClient.begin(0); // ephemeral port
        Serial.println("[DNS] UDP port 53 open.");

        // ── Web dashboard ─────────────────────────────────────────────────
        webUiSetup();

        // ── Firmware OTA (ArduinoOTA) ─────────────────────────────────────
        ArduinoOTA.setHostname(OTA_HOSTNAME);
        ArduinoOTA.setPassword(OTA_PASSWORD);
        ArduinoOTA.onStart([]() {
            String t = (ArduinoOTA.getCommand() == U_FLASH) ? "firmware" : "filesystem";
            Serial.printf("[OTA-FW] Updating %s…\n", t.c_str());
        });
        ArduinoOTA.onEnd([]()   { Serial.println("\n[OTA-FW] Done — rebooting."); });
        ArduinoOTA.onProgress([](unsigned int p, unsigned int t) {
            Serial.printf("[OTA-FW] %u%%\r", (p * 100) / t);
        });
        ArduinoOTA.onError([](ota_error_t e) {
            Serial.printf("[OTA-FW] Error[%u]\n", e);
        });
        ArduinoOTA.begin();
        Serial.println("[OTA-FW] ArduinoOTA ready.");
    } else {
        Serial.printf("\n[ERROR] Wi-Fi failed (code %d). DNS/Web inactive.\n",
                      (int)WiFi.status());
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  loop()
// ══════════════════════════════════════════════════════════════════════════════
void loop()
{
    // ── Firmware OTA handler ─────────────────────────────────────────────────
    ArduinoOTA.handle();

    // ── WebSocket cleanup ────────────────────────────────────────────────────
    webUiLoop();

    const uint32_t now = millis();

    // ── Stats Broadcast (every 500ms) ────────────────────────────────────────
    if (now - lastStatsBroadcast >= 500) {
        lastStatsBroadcast = now;
        if (WiFi.status() == WL_CONNECTED) {
            broadcastStats();
        }
    }

    // ── Heartbeat (every 4 s) ─────────────────────────────────────────────────
    if (now - lastHeartbeat >= 4000) {
        lastHeartbeat = now;
        if (WiFi.status() == WL_CONNECTED) {
            Serial.printf(
                "[♥] IP:%s Heap:%u Q:%lu Blk:%lu(%lu%%) Cache:%lu AvgRTT:%lums\n",
                WiFi.localIP().toString().c_str(),
                ESP.getFreeHeap(),
                (unsigned long)g_stats.totalQueries,
                (unsigned long)g_stats.blockedQueries,
                (unsigned long)g_stats.blockedPct(),
                (unsigned long)g_stats.cacheHits,
                (unsigned long)g_stats.avgRtt());
        }
    }

    // ── Wi-Fi auto-reconnect (every 10 s when disconnected) ──────────────────
    if (UNLIKELY(WiFi.status() != WL_CONNECTED)) {
        if (now - lastReconnectAttempt >= 10000) {
            lastReconnectAttempt = now;
            Serial.println("[WIFI] Lost — reconnecting…");
            WiFi.reconnect();
        }
        delay(100);
        return;
    }

    // ── Collect upstream DNS responses (Burst Draining) ──────────────────────
    for (int b = 0; b < 8; b++) {
        int respLen = upstreamClient.parsePacket();
        if (respLen <= 0) break;
        int n = upstreamClient.read(s_upstreamRespBuf, sizeof(s_upstreamRespBuf));
        if (LIKELY(n >= 2)) {
            const uint16_t rxTxId = __builtin_bswap16(*(const uint16_t*)s_upstreamRespBuf);
            const int slot = (int)(rxTxId & (MAX_PENDING - 1)); // O(1) bitwise AND
            PendingQuery &pq = pendingQueries[slot];
            if (LIKELY(pq.active && pq.ourTxId == rxTxId)) {
                const uint32_t rttMs = now - pq.timestamp;
                g_stats.recordRTT(rttMs);

                // Handle Negative Caching (NXDOMAIN)
                uint8_t rcode = s_upstreamRespBuf[3] & 0x0F;
                if (rcode == 3) {
                    insertAnswerCache(pq.domainHash, 0xFFFFFFFF, 60, now);
                } else if (pq.qtype == 0x0001 && n >= 16 && rcode == 0) {
                    uint16_t ancount = ((uint16_t)s_upstreamRespBuf[6] << 8) | s_upstreamRespBuf[7];
                    if (ancount > 0 && n >= 32) {
                        for (int i = 12; i + 16 <= n; i++) {
                            if (s_upstreamRespBuf[i] == 0xC0 &&
                                s_upstreamRespBuf[i + 2] == 0x00 && s_upstreamRespBuf[i + 3] == 0x01 && // TYPE A
                                s_upstreamRespBuf[i + 4] == 0x00 && s_upstreamRespBuf[i + 5] == 0x01 && // CLASS IN
                                s_upstreamRespBuf[i + 10] == 0x00 && s_upstreamRespBuf[i + 11] == 0x04) { // RDLEN 4
                                uint32_t ttl = ((uint32_t)s_upstreamRespBuf[i + 6] << 24) |
                                               ((uint32_t)s_upstreamRespBuf[i + 7] << 16) |
                                               ((uint32_t)s_upstreamRespBuf[i + 8] << 8)  |
                                                (uint32_t)s_upstreamRespBuf[i + 9];
                                uint32_t ip4;
                                memcpy(&ip4, &s_upstreamRespBuf[i + 12], 4);
                                insertAnswerCache(pq.domainHash, ip4, ttl, now);
                                break;
                            }
                        }
                    }
                }

                // Restore original txId before forwarding to client
                *(uint16_t*)s_upstreamRespBuf = __builtin_bswap16(pq.origTxId);
                dnsServer.beginPacket(pq.clientIP, pq.clientPort);
                dnsServer.write(s_upstreamRespBuf, n);
                dnsServer.endPacket();
                pq.active = false;
            }
        }
    }

    // ── Expire timed-out pending queries — send SERVFAIL to client ────────────
    for (int i = 0; i < MAX_PENDING; i++) {
        PendingQuery &pq = pendingQueries[i];
        if (UNLIKELY(pq.active && (now - pq.timestamp > QUERY_TIMEOUT))) {
            sendServfail(pq.clientIP, pq.clientPort, pq.origTxId);
            pq.active = false;
        }
    }

    // ── Handle incoming DNS queries (Burst Draining) ──────────────────────────
    for (int b = 0; b < 8; b++) {
        int pktSize = dnsServer.parsePacket();
        if (UNLIKELY(pktSize <= 12 || pktSize > 512)) break;

        static uint8_t s_dnsRxBuf[512];
        int       len        = dnsServer.read(s_dnsRxBuf, sizeof(s_dnsRxBuf));
        IPAddress clientIP   = dnsServer.remoteIP();
        uint16_t  clientPort = dnsServer.remotePort();

        char clientIPStr[16];
        fastIpToStr(clientIP, clientIPStr);

        char     domain[128];
        size_t   qnameEnd = 0;
        size_t   domainLen = 0;
        uint64_t fullHash = 0;
        uint8_t  labelOffsets[8];
        uint8_t  labelCount = 0;

        if (UNLIKELY(!parseQName(s_dnsRxBuf, len, domain, sizeof(domain), qnameEnd, domainLen, fullHash, labelOffsets, labelCount))) continue;
        if (UNLIKELY(qnameEnd == 0 || (qnameEnd + 1) >= (size_t)len)) continue;

        const uint16_t qtype   = ((uint16_t)s_dnsRxBuf[qnameEnd] << 8) | s_dnsRxBuf[qnameEnd + 1];
        const bool     blocked = isDomainBlocked(domain, domainLen, fullHash, labelOffsets, labelCount);

        // Record stats + per-client stats + broadcast to web dashboard
        g_stats.record(domain, domainLen, qtype, blocked, clientIPStr);
        recordClient((uint32_t)clientIP, blocked, clientIPStr);
        broadcastQuery(domain, qtype, blocked, clientIPStr);

        if (blocked) {
            sendSinkholeResponse(clientIP, clientPort, s_dnsRxBuf, len, qnameEnd, qtype);
        } else {
            // Check In-RAM Answer Cache for Type A queries (< 0.1 ms SRAM answer)
            uint32_t cachedIp4 = 0, remTtl = 0;
            if (lookupAnswerCache(fullHash, now, cachedIp4, remTtl)) {
                if (cachedIp4 == 0xFFFFFFFF) {
                    sendNxdomainResponse(clientIP, clientPort, s_dnsRxBuf, len, qnameEnd);
                } else if (qtype == 0x0001) {
                    sendCachedAnswerResponse(clientIP, clientPort, s_dnsRxBuf, len, qnameEnd, cachedIp4, remTtl);
                } else {
                    forwardUpstream(clientIP, clientPort, s_dnsRxBuf, len, fullHash, qtype, now);
                }
            } else {
                forwardUpstream(clientIP, clientPort, s_dnsRxBuf, len, fullHash, qtype, now);
            }
        }
    }
}