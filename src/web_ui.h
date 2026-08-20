#pragma once
#include <Arduino.h>
#include <WiFi.h>
#include <LittleFS.h>
#include <ESPAsyncWebServer.h>
#include <ArduinoJson.h>

#include "stats.h"
#include "lru_cache.h"
#include "lists.h"
#include "ota_updater.h"

// ─────────────────────────────────────────────────────────────────────────────
// web_ui.h  –  ESPAsyncWebServer (port 80) + WebSocket (/ws)
//
// REST API:
//   GET  /api/stats        → JSON counters
//   GET  /api/queries      → JSON last-30 query log
//   GET  /api/mode         → {"mode":2}
//   POST /api/mode         → {"mode":3} — update mode and invalidate cache
//   GET  /api/whitelist    → JSON list
//   POST /api/whitelist    → {"domain":"x"} — add
//   DELETE /api/whitelist?domain=x — remove
//   GET  /api/blacklist    → same
//   POST /api/blacklist    → same
//   DELETE /api/blacklist?domain=x — remove
//   POST /api/update       → {"url":"http://..."} — trigger blocklist OTA
//   POST /api/upload       → multipart file — direct blocklist.bin upload
//   GET  /api/ota/status   → {"status":"...","progress":N,"msg":"..."}
//
// WebSocket /ws pushes per-query JSON events to all connected clients:
//   {"d":"domain","t":1,"b":true,"ts":12345}
// ─────────────────────────────────────────────────────────────────────────────

// Resolved from main.cpp's translation unit
extern File     blocklistFile;
extern uint32_t totalHashes;
extern bool     fsReady;

static AsyncWebServer webServer(80);
static AsyncWebSocket webSocket("/ws");

// ── Helper: add CORS headers ─────────────────────────────────────────────────
static void _cors(AsyncWebServerResponse *resp) {
    resp->addHeader("Access-Control-Allow-Origin", "*");
    resp->addHeader("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
    resp->addHeader("Access-Control-Allow-Headers", "Content-Type");
}

static void _sendJson(AsyncWebServerRequest *req, int code, const String &json) {
    AsyncWebServerResponse *r = req->beginResponse(code, "application/json", json);
    _cors(r);
    req->send(r);
}

// ── Body-parse helper for small JSON bodies (< 512 B) ───────────────────────
// Used with ESPAsyncWebServer's onBody callback. Assembles multi-chunk bodies
// into a single null-terminated buffer using request's _tempObject slot.

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

// ── Broadcast a query event to all WebSocket clients ────────────────────────
void broadcastQuery(const char *domain, uint16_t qtype, bool blocked) {
    if (webSocket.count() == 0) return;
    char buf[128];
    snprintf(buf, sizeof(buf),
             R"({"d":"%s","t":%u,"b":%s,"ts":%lu})",
             domain, qtype, blocked ? "true" : "false",
             (unsigned long)millis());
    webSocket.textAll(buf);
}

// ── Web server setup ─────────────────────────────────────────────────────────
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

    // ── Dashboard ─────────────────────────────────────────────────────────────
    webServer.on("/", HTTP_GET, [](AsyncWebServerRequest *req) {
        if (LittleFS.exists("/index.html"))
            req->send(LittleFS, "/index.html", "text/html");
        else
            req->send(503, "text/plain", "index.html missing — run uploadfs");
    });

    // ── GET /api/stats ────────────────────────────────────────────────────────
    webServer.on("/api/stats", HTTP_GET, [](AsyncWebServerRequest *req) {
        char buf[256];
        snprintf(buf, sizeof(buf),
            R"({"total":%lu,"blocked":%lu,"pct":%lu,"uptime":%lu,"heap":%lu,"ip":"%s","hashes":%lu,"cacheHits":%lu})",
            (unsigned long)g_stats.totalQueries,
            (unsigned long)g_stats.blockedQueries,
            (unsigned long)g_stats.blockedPct(),
            (unsigned long)g_stats.uptimeSecs(),
            (unsigned long)ESP.getFreeHeap(),
            WiFi.localIP().toString().c_str(),
            (unsigned long)totalHashes,
            (unsigned long)g_stats.cacheHits);
        _sendJson(req, 200, buf);
    });

    // ── GET /api/queries ──────────────────────────────────────────────────────
    webServer.on("/api/queries", HTTP_GET, [](AsyncWebServerRequest *req) {
        JsonDocument doc;
        JsonArray arr = doc.to<JsonArray>();
        int count = g_stats.logCount;
        int start = (g_stats.logHead - count + QUERY_LOG_SIZE) % QUERY_LOG_SIZE;
        for (int i = 0; i < count; i++) {
            int idx = (start + i) % QUERY_LOG_SIZE;
            JsonObject o = arr.add<JsonObject>();
            o["d"]  = g_stats.log[idx].domain;
            o["t"]  = g_stats.log[idx].qtype;
            o["b"]  = g_stats.log[idx].blocked;
            o["ts"] = g_stats.log[idx].timestamp;
        }
        String json;
        serializeJson(doc, json);
        _sendJson(req, 200, json);
    });

    // ── GET /api/mode ─────────────────────────────────────────────────────────
    webServer.on("/api/mode", HTTP_GET, [](AsyncWebServerRequest *req) {
        char buf[64];
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
            if (newMode >= 0 && newMode <= 3) {
                settingsSave(static_cast<BlockMode>(newMode));
                lruInvalidate(); // wipe cache since rules changed
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

    // ── POST /api/whitelist  {"domain":"x"} ───────────────────────────────────
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
            _sendJson(req, ok ? 200 : 409, ok ? R"({"ok":true})" : R"({"ok":false,"msg":"Duplicate"})");
        })
    );

    // ── DELETE /api/whitelist?domain=x ────────────────────────────────────────
    webServer.on("/api/whitelist", HTTP_DELETE, [](AsyncWebServerRequest *req) {
        if (!req->hasParam("domain")) {
            _sendJson(req, 400, R"({"ok":false,"msg":"Missing ?domain"})");
            return;
        }
        bool ok = removeFromWhitelist(req->getParam("domain")->value().c_str());
        if (ok) lruInvalidate();
        _sendJson(req, ok ? 200 : 404, ok ? R"({"ok":true})" : R"({"ok":false,"msg":"Not found"})");
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
                _sendJson(req, 400, R"({"ok":false,"msg":"Bad JSON"})");
                return;
            }
            bool ok = addToBlacklist(doc["domain"].as<const char *>());
            lruInvalidate();
            _sendJson(req, ok ? 200 : 409, ok ? R"({"ok":true})" : R"({"ok":false,"msg":"Duplicate"})");
        })
    );

    // ── DELETE /api/blacklist?domain=x ────────────────────────────────────────
    webServer.on("/api/blacklist", HTTP_DELETE, [](AsyncWebServerRequest *req) {
        if (!req->hasParam("domain")) {
            _sendJson(req, 400, R"({"ok":false,"msg":"Missing ?domain"})");
            return;
        }
        bool ok = removeFromBlacklist(req->getParam("domain")->value().c_str());
        if (ok) lruInvalidate();
        _sendJson(req, ok ? 200 : 404, ok ? R"({"ok":true})" : R"({"ok":false,"msg":"Not found"})");
    });

    // ── POST /api/update  {"url":"http://..."} ────────────────────────────────
    webServer.on("/api/update", HTTP_POST,
        [](AsyncWebServerRequest *) {},
        nullptr,
        _bodyHandler([](AsyncWebServerRequest *req, const uint8_t *data, size_t len) {
            if (getOtaStatus() == OtaStatus::RUNNING) {
                _sendJson(req, 409, R"({"ok":false,"msg":"OTA already running"})");
                return;
            }
            JsonDocument doc;
            if (deserializeJson(doc, data, len) || !doc["url"].is<const char *>()) {
                _sendJson(req, 400, R"({"ok":false,"msg":"Need {\"url\":\"...\"}"})");
                return;
            }
            startBlocklistUpdate(doc["url"].as<String>());
            _sendJson(req, 202, R"({"ok":true,"msg":"Download started"})");
        })
    );

    // ── POST /api/upload  (multipart blocklist.bin) ────────────────────────────
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
                        fsReady = true;
                        lruInvalidate();
                        Serial.printf("[UPLOAD] Blocklist updated: %u hashes\n", totalHashes);
                        return;
                    }
                }
                // Validation failed — restore
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

    // ── 404 fallback ──────────────────────────────────────────────────────────
    webServer.onNotFound([](AsyncWebServerRequest *req) {
        _sendJson(req, 404, R"({"error":"Not found"})");
    });

    webServer.begin();
    Serial.println("[WEB] Dashboard ready on port 80.");
}

// ── Call from loop() to clean up stale WebSocket clients ────────────────────
void webUiLoop() {
    webSocket.cleanupClients();
}
