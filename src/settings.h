#pragma once
#include <Arduino.h>
#include <LittleFS.h>

// ─────────────────────────────────────────────────────────────────────────────
// settings.h  –  Persistent device settings (Block Mode)
// ─────────────────────────────────────────────────────────────────────────────

enum class BlockMode {
    BYPASS   = 0, // Block nothing
    MINIMAL  = 1, // Block ONLY custom blacklist
    NORMAL   = 2, // Block custom blacklist + blocklist.bin
    ABSOLUTE = 3  // Block EVERYTHING except custom whitelist
};

BlockMode g_blockMode = BlockMode::NORMAL;

void settingsLoad() {
    File f = LittleFS.open("/mode.txt", "r");
    if (f) {
        String val = f.readStringUntil('\n');
        int modeInt = val.toInt();
        if (modeInt >= 0 && modeInt <= 3) {
            g_blockMode = static_cast<BlockMode>(modeInt);
        }
        f.close();
    }
    Serial.printf("[SETTINGS] Block Mode: %d\n", (int)g_blockMode);
}

void settingsSave(BlockMode mode) {
    g_blockMode = mode;
    File f = LittleFS.open("/mode.txt", "w");
    if (f) {
        f.println((int)mode);
        f.close();
    }
    Serial.printf("[SETTINGS] Block Mode saved: %d\n", (int)g_blockMode);
}
