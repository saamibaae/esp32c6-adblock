#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <LittleFS.h>
#include <ArduinoOTA.h>
#include "secrets.h"

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
#include "lists.h"        // g_whitelist / g_blacklist / isWhitelisted / isCustomBlocked
#include "ota_updater.h"  // startBlocklistUpdate / getOtaStatus
#include "web_ui.h"       // webUiSetup / webUiLoop / broadcastQuery

// ══════════════════════════════════════════════════════════════════════════════
//  DNS configuration
// ══════════════════════════════════════════════════════════════════════════════
IPAddress        UPSTREAM_DNS(1, 1, 1, 1);
const uint16_t   DNS_PORT        = 53;
const int        MAX_PENDING     = 16;   // Bug #1 fix: was 8
const uint32_t   QUERY_TIMEOUT   = 3000; // ms

WiFiUDP dnsServer;
WiFiUDP upstreamClient;

unsigned long lastHeartbeat       = 0;
unsigned long lastReconnectAttempt = 0;

// ── Async pending query table (Bug #2 fix: match by ourTxId not origTxId) ────
struct PendingQuery {
    bool      active;
    uint16_t  origTxId;  // original txId from client — restored in response
    uint16_t  ourTxId;   // unique rewritten txId sent upstream — used for matching
    IPAddress clientIP;
    uint16_t  clientPort;
    uint32_t  timestamp;
};
PendingQuery pendingQueries[MAX_PENDING];
static uint16_t s_txIdCounter = 0; // wrapping counter for unique ourTxId

// Bug #3 fix: static buffer — never on the stack
static uint8_t s_upstreamRespBuf[1024];

// ══════════════════════════════════════════════════════════════════════════════
//  40-bit FNV-1a Hash (no change — correct implementation)
// ══════════════════════════════════════════════════════════════════════════════
uint64_t fnv1a_40(const char *str, size_t len)
{
    uint64_t hash = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < len; ++i) {
        hash ^= (uint8_t)tolower((unsigned char)str[i]);
        hash *= 0x100000001b3ULL;
    }
    return hash & 0xFFFFFFFFFFULL;
}

// ══════════════════════════════════════════════════════════════════════════════
//  Binary search in LittleFS (unchanged — correct)
// ══════════════════════════════════════════════════════════════════════════════
bool isHashBlocked(uint64_t targetHash)
{
    if (!fsReady || totalHashes == 0) return false;

    int32_t low = 0, high = (int32_t)totalHashes - 1;
    uint8_t buf[5];

    while (low <= high) {
        int32_t mid = low + ((high - low) / 2);
        blocklistFile.seek((uint32_t)mid * 5);
        if (blocklistFile.read(buf, 5) != 5) break;

        uint64_t h = 0;
        for (int i = 0; i < 5; i++) h = (h << 8) | buf[i];

        if      (h == targetHash) return true;
        else if (h  < targetHash) low  = mid + 1;
        else                      high = mid - 1;
    }
    return false;
}

// ══════════════════════════════════════════════════════════════════════════════
//  DNS lookup pipeline with full priority chain
//  Bug #4 fix: LRU cache wraps every LittleFS search
//  Bug #7 fix: pure char* — zero heap allocation in hot path
// ══════════════════════════════════════════════════════════════════════════════
bool isDomainBlocked(const char *domain)
{
    // 1. Whitelist — always forward, skip all block checks
    if (isWhitelisted(domain)) return false;

    // 2. Custom blacklist — block immediately without touching flash
    if (isCustomBlocked(domain)) return true;

    // 3. LRU cache — avoids flash seeks for repeated domains
    uint64_t fullHash = fnv1a_40(domain, strlen(domain));
    bool cached;
    if (lruLookup(fullHash, cached)) {
        g_stats.cacheHits++;
        return cached;
    }

    // 4. Binary search in LittleFS for domain + parent subdomains
    const char *cur = domain;
    bool blocked = false;
    while (*cur) {
        if (isHashBlocked(fnv1a_40(cur, strlen(cur)))) { blocked = true; break; }
        cur = strchr(cur, '.');
        if (!cur) break;
        cur++; // advance past dot
    }

    // 5. Cache result for next time
    lruInsert(fullHash, blocked);
    return blocked;
}

// ══════════════════════════════════════════════════════════════════════════════
//  DNS packet parsing — char[] output, no heap allocation (Bug #7 fix)
// ══════════════════════════════════════════════════════════════════════════════
bool parseQName(const uint8_t *buf, size_t len,
                char *out, size_t outMax,
                size_t &qnameEnd)
{
    size_t pos = 12; // skip 12-byte DNS header
    size_t dpos = 0;
    out[0] = '\0';

    while (pos < len && buf[pos] != 0) {
        uint8_t llen = buf[pos++];
        if (pos + llen > len) return false;              // truncated
        if (dpos + llen + 2 > outMax) return false;     // overflow guard
        if (dpos > 0) out[dpos++] = '.';
        memcpy(out + dpos, buf + pos, llen);
        dpos += llen;
        pos  += llen;
    }
    out[dpos] = '\0';
    qnameEnd = pos + 1; // +1 to step over the null label
    return dpos > 0;
}

// ══════════════════════════════════════════════════════════════════════════════
//  Sinkhole response — 0.0.0.0 (A) or :: (AAAA)
// ══════════════════════════════════════════════════════════════════════════════
void sendSinkholeResponse(IPAddress clientIP, uint16_t clientPort,
                          const uint8_t *query, size_t queryLen,
                          size_t qnameEnd, uint16_t qtype)
{
    uint8_t resp[512];
    memset(resp, 0, sizeof(resp));

    resp[0] = query[0]; resp[1] = query[1];   // Transaction ID
    resp[2] = 0x81;     resp[3] = 0x80;       // Flags: QR=1, RA=1, NOERROR
    resp[4] = 0x00;     resp[5] = 0x01;       // QDCOUNT = 1
    resp[6] = 0x00;     resp[7] = 0x01;       // ANCOUNT = 1

    size_t questionLen = (qnameEnd + 4) - 12;
    memcpy(&resp[12], &query[12], questionLen);
    size_t idx = 12 + questionLen;

    resp[idx++] = 0xC0; resp[idx++] = 0x0C;  // Name: pointer to 0x0C
    resp[idx++] = (qtype >> 8) & 0xFF;
    resp[idx++] =  qtype       & 0xFF;
    resp[idx++] = 0x00; resp[idx++] = 0x01;  // CLASS IN
    resp[idx++] = 0x00; resp[idx++] = 0x00;
    resp[idx++] = 0x01; resp[idx++] = 0x2C;  // TTL: 300 s

    if (qtype == 0x001C) {                    // AAAA → ::
        resp[idx++] = 0x00; resp[idx++] = 0x10;
        for (int i = 0; i < 16; i++) resp[idx++] = 0x00;
    } else {                                  // A → 0.0.0.0
        resp[idx++] = 0x00; resp[idx++] = 0x04;
        resp[idx++] = 0x00; resp[idx++] = 0x00;
        resp[idx++] = 0x00; resp[idx++] = 0x00;
    }

    dnsServer.beginPacket(clientIP, clientPort);
    dnsServer.write(resp, idx);
    dnsServer.endPacket();
}

// ══════════════════════════════════════════════════════════════════════════════
//  Non-blocking upstream forward
//  Bug #2 fix: rewrite txId so matching is unambiguous (slot-based ourTxId)
// ══════════════════════════════════════════════════════════════════════════════
void forwardUpstream(IPAddress clientIP, uint16_t clientPort,
                     uint8_t *query, size_t queryLen)
{
    // Find a free slot; evict oldest if all taken
    int      slot      = -1;
    uint32_t oldestTs  = UINT32_MAX;
    int      oldestIdx = 0;

    for (int i = 0; i < MAX_PENDING; i++) {
        if (!pendingQueries[i].active) { slot = i; break; }
        if (pendingQueries[i].timestamp < oldestTs) {
            oldestTs  = pendingQueries[i].timestamp;
            oldestIdx = i;
        }
    }
    if (slot == -1) slot = oldestIdx;

    uint16_t origTxId = ((uint16_t)query[0] << 8) | query[1];
    uint16_t ourTxId  = ++s_txIdCounter;
    if (ourTxId == 0) ourTxId = ++s_txIdCounter; // skip 0

    pendingQueries[slot] = { true, origTxId, ourTxId, clientIP, clientPort, millis() };

    // Rewrite txId in the packet before sending upstream
    query[0] = (ourTxId >> 8) & 0xFF;
    query[1] =  ourTxId       & 0xFF;

    upstreamClient.beginPacket(UPSTREAM_DNS, DNS_PORT);
    upstreamClient.write(query, queryLen);
    upstreamClient.endPacket();

    // Restore original txId (caller's buffer must remain intact)
    query[0] = (origTxId >> 8) & 0xFF;
    query[1] =  origTxId       & 0xFF;
}

// ══════════════════════════════════════════════════════════════════════════════
//  setup()
// ══════════════════════════════════════════════════════════════════════════════
void setup()
{
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
    memset(pendingQueries, 0, sizeof(pendingQueries));
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
        }
        listsLoad(); // whitelist + blacklist
    }

    // ── Wi-Fi ────────────────────────────────────────────────────────────────
    WiFi.disconnect(true);
    WiFi.mode(WIFI_STA);
    WiFi.setSleep(false); // disable modem sleep for minimum DNS latency
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

    // ── Heartbeat (every 4 s) ─────────────────────────────────────────────────
    if (millis() - lastHeartbeat >= 4000) {
        lastHeartbeat = millis();
        if (WiFi.status() == WL_CONNECTED) {
            Serial.printf("[♥] IP:%s Heap:%u Q:%lu Blk:%lu(%lu%%) Cache:%lu\n",
                WiFi.localIP().toString().c_str(),
                ESP.getFreeHeap(),
                (unsigned long)g_stats.totalQueries,
                (unsigned long)g_stats.blockedQueries,
                (unsigned long)g_stats.blockedPct(),
                (unsigned long)g_stats.cacheHits);
        }
    }

    // ── Wi-Fi auto-reconnect (every 10 s when disconnected) ──────────────────
    if (WiFi.status() != WL_CONNECTED) {
        if (millis() - lastReconnectAttempt >= 10000) {
            lastReconnectAttempt = millis();
            Serial.println("[WIFI] Lost — reconnecting…");
            WiFi.reconnect();
        }
        delay(100);
        return;
    }

    // ── Collect upstream DNS responses (non-blocking) ─────────────────────────
    int respLen = upstreamClient.parsePacket();
    if (respLen > 0) {
        int n = upstreamClient.read(s_upstreamRespBuf, sizeof(s_upstreamRespBuf));
        if (n >= 2) {
            // Match by ourTxId (unambiguous even if two clients share the same origTxId)
            uint16_t ourTxId = ((uint16_t)s_upstreamRespBuf[0] << 8) | s_upstreamRespBuf[1];
            for (int i = 0; i < MAX_PENDING; i++) {
                PendingQuery &pq = pendingQueries[i];
                if (pq.active && pq.ourTxId == ourTxId) {
                    // Restore original txId before sending to client
                    s_upstreamRespBuf[0] = (pq.origTxId >> 8) & 0xFF;
                    s_upstreamRespBuf[1] =  pq.origTxId       & 0xFF;
                    dnsServer.beginPacket(pq.clientIP, pq.clientPort);
                    dnsServer.write(s_upstreamRespBuf, n);
                    dnsServer.endPacket();
                    pq.active = false;
                    break;
                }
            }
        }
    }

    // ── Expire timed-out pending queries ─────────────────────────────────────
    uint32_t now = millis();
    for (int i = 0; i < MAX_PENDING; i++) {
        if (pendingQueries[i].active && now - pendingQueries[i].timestamp > QUERY_TIMEOUT)
            pendingQueries[i].active = false;
    }

    // ── Handle incoming DNS query ────────────────────────────────────────────
    int pktSize = dnsServer.parsePacket();
    if (pktSize > 12 && pktSize <= 512) {
        uint8_t   buf[512];
        int       len        = dnsServer.read(buf, sizeof(buf));
        IPAddress clientIP   = dnsServer.remoteIP();
        uint16_t  clientPort = dnsServer.remotePort();

        char   domain[128];
        size_t qnameEnd = 0;

        // Bug #7 fix: parseQName writes into char[] — no String allocation
        if (!parseQName(buf, len, domain, sizeof(domain), qnameEnd)) return;

        // Bug #3 (bounds) fix: validate qnameEnd before reading qtype
        if (qnameEnd == 0 || (qnameEnd + 1) >= (size_t)len) return;

        uint16_t qtype   = ((uint16_t)buf[qnameEnd] << 8) | buf[qnameEnd + 1];
        bool     blocked = isDomainBlocked(domain);

        // Record stats + broadcast to web dashboard
        g_stats.record(domain, qtype, blocked);
        broadcastQuery(domain, qtype, blocked);

        if (blocked) {
            Serial.printf("[BLOCK] %s (%s)\n", domain,
                          qtype == 28 ? "AAAA" : qtype == 1 ? "A" : "?");
            sendSinkholeResponse(clientIP, clientPort, buf, len, qnameEnd, qtype);
        } else {
            Serial.printf("[FWD]   %s\n", domain);
            forwardUpstream(clientIP, clientPort, buf, len);
        }
    }
}