#pragma once
#include <Arduino.h>
#include <LittleFS.h>
#include <HTTPClient.h>

// ─────────────────────────────────────────────────────────────────────────────
// ota_updater.h  –  Non-blocking blocklist OTA via FreeRTOS task
//
// Runs as a background FreeRTOS task so the DNS loop keeps processing
// queries during the download (ads are temporarily not blocked, but
// DNS resolution remains fully operational).
//
// Usage:
//   startBlocklistUpdate("http://yourserver.com/blocklist.bin");
//   OtaStatus s = getOtaStatus();
//
// NOTE: This header must be included AFTER blocklistFile, totalHashes,
// and fsReady are declared in main.cpp (same translation unit).
// ─────────────────────────────────────────────────────────────────────────────

// Forward declarations — resolved by main.cpp's translation unit
extern File     blocklistFile;
extern uint32_t totalHashes;
extern bool     fsReady;
void lruInvalidate(); // defined in lru_cache.h (included before this)

enum class OtaStatus { IDLE, RUNNING, SUCCESS, FAILED };

static volatile OtaStatus g_otaStatus = OtaStatus::IDLE;
static String             g_otaMsg    = "";
static int                g_otaProgress = 0; // 0-100 %

// ── Internal FreeRTOS download task ─────────────────────────────────────────

static void _otaDownloadTask(void *param) {
    String *urlPtr = static_cast<String *>(param);
    String  url    = *urlPtr;
    delete urlPtr;

    Serial.printf("[OTA-BL] Starting download: %s\n", url.c_str());

    // Suspend blocklist lookups — DNS still works (forward-only mode)
    fsReady = false;
    blocklistFile.close();

    HTTPClient http;
    http.begin(url);
    http.setTimeout(60000);
    http.addHeader("Accept", "application/octet-stream");

    int code = http.GET();
    if (code != HTTP_CODE_OK) {
        g_otaMsg    = "HTTP error " + String(code);
        g_otaStatus = OtaStatus::FAILED;
        http.end();
        goto restore;
    }

    {
        int contentLen = http.getSize();
        Serial.printf("[OTA-BL] Content-Length: %d bytes\n", contentLen);

        LittleFS.remove("/blocklist.tmp");
        File tmpFile = LittleFS.open("/blocklist.tmp", "w");
        if (!tmpFile) {
            g_otaMsg    = "LittleFS write error";
            g_otaStatus = OtaStatus::FAILED;
            http.end();
            goto restore;
        }

        WiFiClient *stream     = http.getStreamPtr();
        uint8_t     buf[512];
        int         downloaded = 0;

        while (http.connected() && (contentLen < 0 || downloaded < contentLen)) {
            int avail = stream->available();
            if (avail > 0) {
                int toRead = min(avail, (int)sizeof(buf));
                int nRead  = stream->readBytes(buf, toRead);
                tmpFile.write(buf, nRead);
                downloaded += nRead;
                if (contentLen > 0)
                    g_otaProgress = (downloaded * 100) / contentLen;
            }
            vTaskDelay(pdMS_TO_TICKS(1)); // yield to WiFi/DNS
        }
        tmpFile.close();
        http.end();

        bool valid = (contentLen < 0)
            ? (downloaded > 0 && downloaded % 5 == 0)
            : (downloaded == contentLen && downloaded % 5 == 0);

        if (valid) {
            LittleFS.remove("/blocklist.bin");
            if (LittleFS.rename("/blocklist.tmp", "/blocklist.bin")) {
                blocklistFile = LittleFS.open("/blocklist.bin", "r");
                if (blocklistFile) {
                    totalHashes = blocklistFile.size() / 5;
                    fsReady     = true;
                    lruInvalidate();
                    g_otaMsg      = "Updated: " + String(totalHashes) + " hashes";
                    g_otaStatus   = OtaStatus::SUCCESS;
                    g_otaProgress = 100;
                    Serial.printf("[OTA-BL] Success! %u hashes loaded.\n", totalHashes);
                    vTaskDelete(NULL);
                    return;
                }
            }
            g_otaMsg    = "Rename/reopen failed";
            g_otaStatus = OtaStatus::FAILED;
        } else {
            LittleFS.remove("/blocklist.tmp");
            g_otaMsg    = "Bad size: " + String(downloaded) + " B";
            g_otaStatus = OtaStatus::FAILED;
        }
    }

restore:
    // Attempt to restore previous blocklist on failure
    blocklistFile = LittleFS.open("/blocklist.bin", "r");
    if (blocklistFile) {
        totalHashes = blocklistFile.size() / 5;
        fsReady     = true;
        Serial.printf("[OTA-BL] Restored previous blocklist (%u hashes).\n", totalHashes);
    }
    Serial.printf("[OTA-BL] Failed: %s\n", g_otaMsg.c_str());
    vTaskDelete(NULL);
}

// ── Public API ───────────────────────────────────────────────────────────────

void startBlocklistUpdate(const String &url) {
    if (g_otaStatus == OtaStatus::RUNNING) return;
    g_otaStatus   = OtaStatus::RUNNING;
    g_otaProgress = 0;
    g_otaMsg      = "Connecting...";
    xTaskCreate(_otaDownloadTask, "ota_bl", 8192, new String(url), 1, nullptr);
}

OtaStatus   getOtaStatus()   { return g_otaStatus;   }
int         getOtaProgress()  { return g_otaProgress;  }
const String &getOtaMsg()    { return g_otaMsg;        }
void        clearOtaStatus() {
    if (g_otaStatus != OtaStatus::RUNNING)
        g_otaStatus = OtaStatus::IDLE;
}
