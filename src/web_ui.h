#pragma once
#include <Arduino.h>
#include <WiFi.h>
#include <LittleFS.h>
#include <ESPAsyncWebServer.h>
#include <ArduinoJson.h>

#include "stats.h"
#include "lru_cache.h"
#include "per_client.h"
#include "lists.h"
#include "ota_updater.h"

// ─────────────────────────────────────────────────────────────────────────────
// web_ui.h  –  ESPAsyncWebServer (port 80) + WebSocket (/ws)
//
// REST API:
//   GET  /api/stats          → JSON counters + RTT + upstream info
//   GET  /api/queries        → JSON last-50 query log
//   GET  /api/mode           → {"mode":2}
//   POST /api/mode           → {"mode":3}
//   GET  /api/whitelist      → JSON list
//   POST /api/whitelist      → {"domain":"x"}
//   DELETE /api/whitelist?domain=x
//   GET  /api/blacklist      → same pattern
//   POST /api/blacklist      → same pattern
//   DELETE /api/blacklist?domain=x
//   GET  /api/clients        → [{"ip":"...","total":N,"blocked":N,"pct":N}]
//   GET  /api/dns            → {"dns":"1.1.1.1","fallback":"8.8.8.8","usingFallback":false}
//   POST /api/dns            → {"dns":"9.9.9.9"} — changes upstream DNS + persists to /dns.txt
//   POST /api/update         → {"url":"http://..."} — trigger blocklist OTA
//   POST /api/upload         → multipart file — direct blocklist.bin upload
//   GET  /api/ota/status     → {"status":"...","progress":N,"msg":"..."}
//   POST /api/reboot         → reboots the device
//
// WebSocket /ws pushes per-query JSON events to all connected clients:
//   {"d":"domain","t":1,"b":true,"ip":"...","ts":12345}
// ─────────────────────────────────────────────────────────────────────────────

// Resolved from main.cpp's translation unit
// All types below are defined in main.cpp before this header is included.
extern File       blocklistFile;
extern uint32_t   totalHashes;
extern bool       fsReady;
extern IPAddress  UPSTREAM_DNS;
extern IPAddress  UPSTREAM_DNS_FALLBACK;
extern bool       g_usingFallback;
// PendingQuery, pendingQueries[], MAX_PENDING, currentUpstream() are already in scope.

// Forward declarations of core classification functions
uint64_t fnv1a_40(const char *str, size_t len);
bool isDomainBlocked(const char *domain, size_t domLen, uint64_t fullHash, const uint8_t *labelOffsets, uint8_t labelCount);


static AsyncWebServer webServer(80);
static AsyncWebSocket webSocket("/ws");

// ── Helper: CORS headers ──────────────────────────────────────────────────────
static void _cors(AsyncWebServerResponse *resp) {
    resp->addHeader("Access-Control-Allow-Origin",  "*");
    resp->addHeader("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
    resp->addHeader("Access-Control-Allow-Headers", "Content-Type");
}

static void _sendJson(AsyncWebServerRequest *req, int code, const String &json) {
    AsyncWebServerResponse *r = req->beginResponse(code, "application/json", json);
    _cors(r);
    req->send(r);
}

// ── Body-parse helper for small JSON bodies (< 512 B) ────────────────────────
struct BodyAccum {
    uint8_t data[512];
    size_t  len = 0;
};

static ArBodyHandlerFunction _bodyHandler(
    std::function<void(AsyncWebServerRequest *, const uint8_t *, size_t)> cb)
{
    return [cb](AsyncWebServerRequest *req,
                uint8_t *data, size_t len,
                size_t index, size_t total) {
        if (index == 0) {
            req->_tempObject = new BodyAccum();
        }
        auto *acc = static_cast<BodyAccum *>(req->_tempObject);
        if (acc && acc->len + len < sizeof(acc->data)) {
            memcpy(acc->data + acc->len, data, len);
            acc->len += len;
        }
        if (index + len == total && acc) {
            acc->data[acc->len] = 0;
            cb(req, acc->data, acc->len);
            delete acc;
            req->_tempObject = nullptr;
        }
    };
}

// ── Broadcast a query event to all WebSocket clients ─────────────────────────
void broadcastQuery(const char *domain, uint16_t qtype, bool blocked, const char *clientIP) {
    if (webSocket.count() == 0) return;
    char buf[256];
    snprintf(buf, sizeof(buf),
             R"({"d":"%s","t":%u,"b":%s,"ip":"%s","ts":%lu})",
             domain, qtype, blocked ? "true" : "false", clientIP,
             (unsigned long)millis());
    webSocket.textAll(buf);
}

// ── Broadcast stats to all WebSocket clients ─────────────────────────────────
void broadcastStats() {
    if (webSocket.count() == 0) return;

    char rttHistBuf[256] = "[";
    int  rttHistLen = 1;
    const int cnt  = g_stats.rttHistCount;
    const int head = g_stats.rttHistHead;
    for (int i = 0; i < cnt; i++) {
        int idx = (head - cnt + i + 30) % 30;
        char tmp[8];
        int w = snprintf(tmp, sizeof(tmp), "%s%u",
                         i > 0 ? "," : "", g_stats.rttHistory[idx]);
        if (rttHistLen + w < (int)sizeof(rttHistBuf) - 2) {
            memcpy(rttHistBuf + rttHistLen, tmp, w);
            rttHistLen += w;
        }
    }
    rttHistBuf[rttHistLen++] = ']';
    rttHistBuf[rttHistLen]   = '\0';

    int activePending = 0;
    for (int i = 0; i < MAX_PENDING; i++)
        if (pendingQueries[i].active) activePending++;

    const int8_t      rssi    = WiFi.RSSI();
    const char* const rssiTag = rssi >= -50 ? "Best"
                              : rssi >= -65 ? "Good"
                              : rssi >= -80 ? "Medium" : "Bad";

    const uint32_t safeMin = (g_stats.minRtt == UINT32_MAX) ? 0 : g_stats.minRtt;

    char buf[896];
    snprintf(buf, sizeof(buf),
        R"({"type":"stats","total":%lu,"blocked":%lu,"pct":%lu,"uptime":%lu,"heap":%lu,)"
        R"("ip":"%s","hashes":%lu,"cacheHits":%lu,"ssid":"%s","rssi":%d,)"
        R"("rssiTag":"%s","minRtt":%lu,"avgRtt":%lu,"maxRtt":%lu,)"
        R"("rttHist":%s,"upstream":"%s","usingFallback":%s,"pending":%d,"avgProc":%lu})",
        (unsigned long)g_stats.totalQueries,
        (unsigned long)g_stats.blockedQueries,
        (unsigned long)g_stats.blockedPct(),
        (unsigned long)g_stats.uptimeSecs(),
        (unsigned long)ESP.getFreeHeap(),
        WiFi.localIP().toString().c_str(),
        (unsigned long)totalHashes,
        (unsigned long)g_stats.cacheHits,
        WiFi.SSID().c_str(),
        rssi,
        rssiTag,
        (unsigned long)safeMin,
        (unsigned long)g_stats.avgRtt(),
        (unsigned long)g_stats.maxRtt,
        rttHistBuf,
        currentUpstream().toString().c_str(),
        g_usingFallback ? "true" : "false",
        activePending,
        (unsigned long)g_stats.avgProc());
    webSocket.textAll(buf);
}

// ── Web server setup ──────────────────────────────────────────────────────────
void webUiSetup() {
    // ── WebSocket ────────────────────────────────────────────────────────────
    webSocket.onEvent([](AsyncWebSocket *, AsyncWebSocketClient *client,
                         AwsEventType type, void *, uint8_t *, size_t) {
        if (type == WS_EVT_CONNECT)
            Serial.printf("[WS] Client #%u connected\n", client->id());
        else if (type == WS_EVT_DISCONNECT)
            Serial.printf("[WS] Client #%u disconnected\n", client->id());
    });
    webServer.addHandler(&webSocket);

    // ── CORS pre-flight ───────────────────────────────────────────────────────
    webServer.on("/*", HTTP_OPTIONS, [](AsyncWebServerRequest *req) {
        AsyncWebServerResponse *r = req->beginResponse(204);
        _cors(r);
        req->send(r);
    });

    // ── Dashboard & Static Assets ─────────────────────────────────────────────
    webServer.on("/manifest.json", HTTP_GET, [](AsyncWebServerRequest *req) {
        AsyncWebServerResponse *r = req->beginResponse(200, "application/manifest+json",
            R"({"name":"DNS Sinkhole","short_name":"DNS Hole","start_url":"/","display":"standalone","background_color":"#070c18","theme_color":"#070c18","icons":[{"src":"data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡️</text></svg>","sizes":"192x192 512x512","type":"image/svg+xml"}]})");
        r->addHeader("Cache-Control", "public, max-age=86400");
        _cors(r);
        req->send(r);
    });

    webServer.on("/", HTTP_GET, [](AsyncWebServerRequest *req) {
        if (LittleFS.exists("/index.html.gz")) {
            AsyncWebServerResponse *r = req->beginResponse(LittleFS, "/index.html.gz", "text/html");
            r->addHeader("Content-Encoding", "gzip");
            r->addHeader("Cache-Control", "public, max-age=3600, must-revalidate");
            r->addHeader("ETag", "\"c6-v2.2\"");
            _cors(r);
            req->send(r);
        } else if (LittleFS.exists("/index.html")) {
            AsyncWebServerResponse *r = req->beginResponse(LittleFS, "/index.html", "text/html");
            r->addHeader("Cache-Control", "public, max-age=3600, must-revalidate");
            r->addHeader("ETag", "\"c6-v2.2\"");
            _cors(r);
            req->send(r);
        } else {
            req->send(503, "text/plain", "index.html missing — run uploadfs");
        }
    });

    webServer.on("/index.html", HTTP_GET, [](AsyncWebServerRequest *req) {
        req->redirect("/");
    });

    // ── GET /api/stats ────────────────────────────────────────────────────────
    webServer.on("/api/stats", HTTP_GET, [](AsyncWebServerRequest *req) {
        // Build compact rttHist JSON array from the circular buffer
        char rttHistBuf[256] = "[";
        int  rttHistLen = 1;
        const int cnt  = g_stats.rttHistCount;
        const int head = g_stats.rttHistHead;
        for (int i = 0; i < cnt; i++) {
            int idx = (head - cnt + i + 30) % 30;
            char tmp[8];
            int w = snprintf(tmp, sizeof(tmp), "%s%u",
                             i > 0 ? "," : "", g_stats.rttHistory[idx]);
            if (rttHistLen + w < (int)sizeof(rttHistBuf) - 2) {
                memcpy(rttHistBuf + rttHistLen, tmp, w);
                rttHistLen += w;
            }
        }
        rttHistBuf[rttHistLen++] = ']';
        rttHistBuf[rttHistLen]   = '\0';

        // Count active pending slots
        int activePending = 0;
        for (int i = 0; i < MAX_PENDING; i++)
            if (pendingQueries[i].active) activePending++;

        const int8_t      rssi    = WiFi.RSSI();
        const char* const rssiTag = rssi >= -50 ? "Best"
                                  : rssi >= -65 ? "Good"
                                  : rssi >= -80 ? "Medium" : "Bad";

        const uint32_t safeMin = (g_stats.minRtt == UINT32_MAX) ? 0 : g_stats.minRtt;

        char buf[896];
        snprintf(buf, sizeof(buf),
            R"({"total":%lu,"blocked":%lu,"pct":%lu,"uptime":%lu,"heap":%lu,)"
            R"("ip":"%s","hashes":%lu,"cacheHits":%lu,"ssid":"%s","rssi":%d,)"
            R"("rssiTag":"%s","minRtt":%lu,"avgRtt":%lu,"maxRtt":%lu,)"
            R"("rttHist":%s,"upstream":"%s","usingFallback":%s,"pending":%d,"avgProc":%lu})",
            (unsigned long)g_stats.totalQueries,
            (unsigned long)g_stats.blockedQueries,
            (unsigned long)g_stats.blockedPct(),
            (unsigned long)g_stats.uptimeSecs(),
            (unsigned long)ESP.getFreeHeap(),
            WiFi.localIP().toString().c_str(),
            (unsigned long)totalHashes,
            (unsigned long)g_stats.cacheHits,
            WiFi.SSID().c_str(),
            rssi,
            rssiTag,
            (unsigned long)safeMin,
            (unsigned long)g_stats.avgRtt(),
            (unsigned long)g_stats.maxRtt,
            rttHistBuf,
            currentUpstream().toString().c_str(),
            g_usingFallback ? "true" : "false",
            activePending,
            (unsigned long)g_stats.avgProc());
        _sendJson(req, 200, buf);
    });

    // ── GET /api/queries ──────────────────────────────────────────────────────
    webServer.on("/api/queries", HTTP_GET, [](AsyncWebServerRequest *req) {
        static char json[3072];
        size_t offset = 0;
        json[offset++] = '[';

        int idx = (g_stats.logHead - 1) & (QUERY_LOG_SIZE - 1);

        for (int i = 0; i < g_stats.logCount; i++) {
            const QueryEntry &e = g_stats.log[idx];
            if (i > 0 && offset < sizeof(json) - 1) json[offset++] = ',';
            int written = snprintf(json + offset, sizeof(json) - offset,
                     R"({"d":"%s","t":%u,"b":%s,"ip":"%s","ts":%lu})",
                     e.domain, e.qtype, e.blocked ? "true" : "false",
                     e.clientIP, e.timestamp);
            if (written > 0 && offset + written < sizeof(json) - 2) {
                offset += written;
            } else {
                break;
            }
            idx = (idx - 1) & (QUERY_LOG_SIZE - 1);
        }
        if (offset < sizeof(json) - 1) {
            json[offset++] = ']';
            json[offset] = '\0';
        }
        _sendJson(req, 200, json);
    });

    // ── GET /api/mode ─────────────────────────────────────────────────────────
    webServer.on("/api/mode", HTTP_GET, [](AsyncWebServerRequest *req) {
        char buf[32];
        snprintf(buf, sizeof(buf), R"({"mode":%d})", (int)g_blockMode);
        _sendJson(req, 200, buf);
    });

    // ── POST /api/mode  {"mode":x} ────────────────────────────────────────────
    webServer.on("/api/mode", HTTP_POST,
        [](AsyncWebServerRequest *) {},
        nullptr,
        _bodyHandler([](AsyncWebServerRequest *req, const uint8_t *data, size_t len) {
            JsonDocument doc;
            if (deserializeJson(doc, data, len) || !doc["mode"].is<int>()) {
                _sendJson(req, 400, R"({"ok":false,"msg":"Bad JSON"})");
                return;
            }
            int newMode = doc["mode"].as<int>();
            if (newMode >= 0 && newMode <= 4) {
                settingsSave(static_cast<BlockMode>(newMode));
                lruInvalidate();
                _sendJson(req, 200, R"({"ok":true})");
            } else {
                _sendJson(req, 400, R"({"ok":false,"msg":"Invalid mode"})");
            }
        })
    );

    // ── GET /api/whitelist ────────────────────────────────────────────────────
    webServer.on("/api/whitelist", HTTP_GET, [](AsyncWebServerRequest *req) {
        JsonDocument doc;
        JsonArray arr = doc.to<JsonArray>();
        for (const auto &e : g_whitelist) arr.add(e);
        String json; serializeJson(doc, json);
        _sendJson(req, 200, json);
    });

    // ── POST /api/whitelist {"domain":"x"} ────────────────────────────────────
    webServer.on("/api/whitelist", HTTP_POST,
        [](AsyncWebServerRequest *) {},
        nullptr,
        _bodyHandler([](AsyncWebServerRequest *req, const uint8_t *data, size_t len) {
            JsonDocument doc;
            if (deserializeJson(doc, data, len) || !doc["domain"].is<const char *>()) {
                _sendJson(req, 400, R"({"ok":false,"msg":"Bad JSON"})");
                return;
            }
            bool ok = addToWhitelist(doc["domain"].as<const char *>());
            lruInvalidate();
            _sendJson(req, ok ? 200 : 409,
                      ok ? R"({"ok":true})" : R"({"ok":false,"msg":"Duplicate"})");
        })
    );

    // ── DELETE /api/whitelist?domain=x ────────────────────────────────────────
    webServer.on("/api/whitelist", HTTP_DELETE, [](AsyncWebServerRequest *req) {
        if (!req->hasParam("domain")) {
            _sendJson(req, 400, R"({"ok":false,"msg":"Missing ?domain"})"); return;
        }
        bool ok = removeFromWhitelist(req->getParam("domain")->value().c_str());
        if (ok) lruInvalidate();
        _sendJson(req, ok ? 200 : 404,
                  ok ? R"({"ok":true})" : R"({"ok":false,"msg":"Not found"})");
    });

    // ── GET /api/blacklist ────────────────────────────────────────────────────
    webServer.on("/api/blacklist", HTTP_GET, [](AsyncWebServerRequest *req) {
        JsonDocument doc;
        JsonArray arr = doc.to<JsonArray>();
        for (const auto &e : g_blacklist) arr.add(e);
        String json; serializeJson(doc, json);
        _sendJson(req, 200, json);
    });

    // ── POST /api/blacklist ───────────────────────────────────────────────────
    webServer.on("/api/blacklist", HTTP_POST,
        [](AsyncWebServerRequest *) {},
        nullptr,
        _bodyHandler([](AsyncWebServerRequest *req, const uint8_t *data, size_t len) {
            JsonDocument doc;
            if (deserializeJson(doc, data, len) || !doc["domain"].is<const char *>()) {
                _sendJson(req, 400, R"({"ok":false,"msg":"Bad JSON"})"); return;
            }
            bool ok = addToBlacklist(doc["domain"].as<const char *>());
            lruInvalidate();
            _sendJson(req, ok ? 200 : 409,
                      ok ? R"({"ok":true})" : R"({"ok":false,"msg":"Duplicate"})");
        })
    );

    // ── DELETE /api/blacklist?domain=x ────────────────────────────────────────
    webServer.on("/api/blacklist", HTTP_DELETE, [](AsyncWebServerRequest *req) {
        if (!req->hasParam("domain")) {
            _sendJson(req, 400, R"({"ok":false,"msg":"Missing ?domain"})"); return;
        }
        bool ok = removeFromBlacklist(req->getParam("domain")->value().c_str());
        if (ok) lruInvalidate();
        _sendJson(req, ok ? 200 : 404,
                  ok ? R"({"ok":true})" : R"({"ok":false,"msg":"Not found"})");
    });

    // ── GET /api/clients ──────────────────────────────────────────────────────
    webServer.on("/api/clients", HTTP_GET, [](AsyncWebServerRequest *req) {
        static char json[1024];
        size_t offset = 0;
        json[offset++] = '[';
        bool first = true;
        for (int i = 0; i < CLIENT_TABLE_SIZE; i++) {
            if (g_clients[i].ip == 0) continue;
            if (!first && offset < sizeof(json) - 1) json[offset++] = ',';
            const uint32_t pct = g_clients[i].total
                ? (g_clients[i].blocked * 100UL / g_clients[i].total) : 0;
            int written = snprintf(json + offset, sizeof(json) - offset,
                R"({"ip":"%s","total":%lu,"blocked":%lu,"pct":%lu})",
                g_clients[i].ipStr,
                (unsigned long)g_clients[i].total,
                (unsigned long)g_clients[i].blocked,
                (unsigned long)pct);
            if (written > 0 && offset + written < sizeof(json) - 2) {
                offset += written;
            }
            first = false;
        }
        if (offset < sizeof(json) - 1) {
            json[offset++] = ']';
            json[offset] = '\0';
        }
        _sendJson(req, 200, json);
    });

    // ── GET /api/dns ──────────────────────────────────────────────────────────
    webServer.on("/api/dns", HTTP_GET, [](AsyncWebServerRequest *req) {
        char buf[128];
        snprintf(buf, sizeof(buf),
            R"({"dns":"%s","fallback":"%s","usingFallback":%s})",
            UPSTREAM_DNS.toString().c_str(),
            UPSTREAM_DNS_FALLBACK.toString().c_str(),
            g_usingFallback ? "true" : "false");
        _sendJson(req, 200, buf);
    });

    // ── POST /api/dns {"dns":"9.9.9.9"} ──────────────────────────────────────
    webServer.on("/api/dns", HTTP_POST,
        [](AsyncWebServerRequest *) {},
        nullptr,
        _bodyHandler([](AsyncWebServerRequest *req, const uint8_t *data, size_t len) {
            JsonDocument doc;
            if (deserializeJson(doc, data, len) || !doc["dns"].is<const char *>()) {
                _sendJson(req, 400, R"({"ok":false,"msg":"Bad JSON"})"); return;
            }
            IPAddress addr;
            if (!addr.fromString(doc["dns"].as<const char *>())) {
                _sendJson(req, 400, R"({"ok":false,"msg":"Invalid IP address"})"); return;
            }
            UPSTREAM_DNS = addr;
            // Persist to LittleFS so it survives reboots
            File f = LittleFS.open("/dns.txt", "w");
            if (f) { f.println(addr.toString()); f.close(); }
            Serial.printf("[DNS] Upstream DNS changed to %s\n", addr.toString().c_str());
            _sendJson(req, 200, R"({"ok":true})");
        })
    );

    // ── POST /api/update {"url":"http://..."} ─────────────────────────────────
    webServer.on("/api/update", HTTP_POST,
        [](AsyncWebServerRequest *) {},
        nullptr,
        _bodyHandler([](AsyncWebServerRequest *req, const uint8_t *data, size_t len) {
            if (getOtaStatus() == OtaStatus::RUNNING) {
                _sendJson(req, 409, R"({"ok":false,"msg":"OTA already running"})"); return;
            }
            JsonDocument doc;
            if (deserializeJson(doc, data, len) || !doc["url"].is<const char *>()) {
                _sendJson(req, 400, R"({"ok":false,"msg":"Need {\"url\":\"...\"}"})"  ); return;
            }
            startBlocklistUpdate(doc["url"].as<String>());
            _sendJson(req, 202, R"({"ok":true,"msg":"Download started"})");
        })
    );

    // ── POST /api/upload  (multipart blocklist.bin) ───────────────────────────
    webServer.on("/api/upload", HTTP_POST,
        [](AsyncWebServerRequest *req) {
            bool ok = fsReady;
            _sendJson(req, ok ? 200 : 500,
                      ok ? R"({"ok":true,"msg":"Blocklist replaced"})"
                         : R"({"ok":false,"msg":"Validation failed"})");
        },
        [](AsyncWebServerRequest *req, String /*filename*/,
           size_t index, uint8_t *data, size_t len, bool final) {
            static File uploadTmp;
            if (getOtaStatus() == OtaStatus::RUNNING) return;
            if (index == 0) {
                fsReady = false;
                blocklistFile.close();
                LittleFS.remove("/blocklist.tmp");
                uploadTmp = LittleFS.open("/blocklist.tmp", "w");
            }
            if (uploadTmp) uploadTmp.write(data, len);
            if (final && uploadTmp) {
                uploadTmp.close();
                size_t total = index + len;
                if (total % 5 == 0) {
                    LittleFS.remove("/blocklist.bin");
                    LittleFS.rename("/blocklist.tmp", "/blocklist.bin");
                    blocklistFile = LittleFS.open("/blocklist.bin", "r");
                    if (blocklistFile) {
                        totalHashes = blocklistFile.size() / 5;
                        fsReady     = true;
                        lruInvalidate();
                        Serial.printf("[UPLOAD] Blocklist updated: %u hashes\n", totalHashes);
                        return;
                    }
                }
                LittleFS.remove("/blocklist.tmp");
                blocklistFile = LittleFS.open("/blocklist.bin", "r");
                if (blocklistFile) { totalHashes = blocklistFile.size() / 5; fsReady = true; }
            }
        }
    );

    // ── GET /api/ota/status ───────────────────────────────────────────────────
    webServer.on("/api/ota/status", HTTP_GET, [](AsyncWebServerRequest *req) {
        const char *s = "idle";
        switch (getOtaStatus()) {
            case OtaStatus::RUNNING: s = "running"; break;
            case OtaStatus::SUCCESS: s = "success"; break;
            case OtaStatus::FAILED:  s = "failed";  break;
            default: break;
        }
        char buf[128];
        snprintf(buf, sizeof(buf),
                 R"({"status":"%s","progress":%d,"msg":"%s"})",
                 s, getOtaProgress(), getOtaMsg().c_str());
        _sendJson(req, 200, buf);
    });

    // ── GET /api/fs ──────────────────────────────────────────────────────────
    webServer.on("/api/fs", HTTP_GET, [](AsyncWebServerRequest *req) {
        size_t total = LittleFS.totalBytes();
        size_t used  = LittleFS.usedBytes();
        size_t blSize = blocklistFile ? blocklistFile.size() : 0;
        char buf[192];
        snprintf(buf, sizeof(buf),
                 R"({"totalBytes":%u,"usedBytes":%u,"blocklistBytes":%u,"hashes":%u})",
                 (unsigned int)total, (unsigned int)used, (unsigned int)blSize, (unsigned int)totalHashes);
        _sendJson(req, 200, buf);
    });

    // ── GET /api/test?domain=x (DNS Classifier Playground) ────────────────────
    webServer.on("/api/test", HTTP_GET, [](AsyncWebServerRequest *req) {
        if (!req->hasParam("domain")) {
            _sendJson(req, 400, R"({"error":"Missing ?domain"})"); return;
        }
        String d = req->getParam("domain")->value();
        d.trim(); d.toLowerCase();
        if (d.length() == 0 || d.length() > 120) {
            _sendJson(req, 400, R"({"error":"Invalid domain"})"); return;
        }

        uint8_t labelOffsets[8];
        uint8_t labelCount = 0;
        size_t len = d.length();
        const char *str = d.c_str();

        for (size_t i = 0; i < len; i++) {
            if (i == 0 || str[i-1] == '.') {
                if (labelCount < 8) labelOffsets[labelCount++] = (uint8_t)i;
            }
        }
        uint64_t fullHash = fnv1a_40(str, len);

        uint32_t t0 = micros();
        bool blocked = isDomainBlocked(str, len, fullHash, labelOffsets, labelCount);
        uint32_t elapsedUs = micros() - t0;

        char buf[256];
        snprintf(buf, sizeof(buf),
                 R"({"domain":"%s","blocked":%s,"elapsedUs":%lu,"hash":"0x%llX"})",
                 str, blocked ? "true" : "false", (unsigned long)elapsedUs, (unsigned long long)fullHash);
        _sendJson(req, 200, buf);
    });

    // ── GET /api/benchmark (Upstream DNS Latency Speed Battle) ────────────────
    webServer.on("/api/benchmark", HTTP_GET, [](AsyncWebServerRequest *req) {
        struct Provider {
            const char *name;
            const char *ipStr;
        };
        const Provider providers[] = {
            {"Cloudflare", "1.1.1.1"},
            {"Cloudflare Secondary", "1.0.0.1"},
            {"Google", "8.8.8.8"},
            {"Quad9", "9.9.9.9"},
            {"AdGuard", "94.140.14.14"},
            {"OpenDNS", "208.67.222.222"}
        };
        const size_t pCount = sizeof(providers) / sizeof(providers[0]);

        static const uint8_t probePkt[] = {
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x06, 'g', 'o', 'o', 'g', 'l', 'e',
            0x03, 'c', 'o', 'm',
            0x00,
            0x00, 0x01, 0x00, 0x01
        };

        WiFiUDP benchUdp;
        benchUdp.begin(0);

        char json[512] = "[";
        size_t offset = 1;

        for (size_t i = 0; i < pCount; i++) {
            IPAddress target;
            target.fromString(providers[i].ipStr);

            benchUdp.beginPacket(target, 53);
            benchUdp.write(probePkt, sizeof(probePkt));
            benchUdp.endPacket();

            uint32_t t0 = millis();
            int rtt = -1;
            while (millis() - t0 < 600) {
                int sz = benchUdp.parsePacket();
                if (sz > 0) {
                    rtt = (int)(millis() - t0);
                    benchUdp.clear();
                    break;
                }
                delay(2);
            }

            char item[96];
            snprintf(item, sizeof(item),
                     R"(%s{"name":"%s","ip":"%s","rtt":%d})",
                     (i == 0 ? "" : ","),
                     providers[i].name,
                     providers[i].ipStr,
                     rtt);
            size_t itemLen = strlen(item);
            if (offset + itemLen < sizeof(json) - 2) {
                memcpy(json + offset, item, itemLen);
                offset += itemLen;
            }
        }
        benchUdp.stop();

        json[offset++] = ']';
        json[offset] = '\0';
        _sendJson(req, 200, json);
    });

    // ── POST /api/reboot ──────────────────────────────────────────────────────
    webServer.on("/api/reboot", HTTP_POST, [](AsyncWebServerRequest *req) {
        _sendJson(req, 200, R"({"ok":true,"msg":"Rebooting\u2026"})");
        delay(300);
        ESP.restart();
    });

    // ── 404 fallback ──────────────────────────────────────────────────────────
    webServer.onNotFound([](AsyncWebServerRequest *req) {
        _sendJson(req, 404, R"({"error":"Not found"})");
    });

    webServer.begin();
    Serial.println("[WEB] Dashboard ready on port 80.");
}

// ── Call from loop() to clean up stale WebSocket clients ─────────────────────
void webUiLoop() {
    webSocket.cleanupClients();
}
