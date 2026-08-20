# 🛡️ ESP32-C6 DNS Sinkhole

> **Pi-hole on a $6 microcontroller.** Hardware-based DNS ad-blocker and network sinkhole running on the Seeed Studio XIAO ESP32-C6.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PlatformIO](https://img.shields.io/badge/Built%20with-PlatformIO-orange)](https://platformio.org)
[![ESP32-C6](https://img.shields.io/badge/Board-ESP32--C6-blue)](https://www.seeedstudio.com/Seeed-Studio-XIAO-ESP32C6-p-5884.html)
[![Arduino](https://img.shields.io/badge/Framework-Arduino-teal)](https://docs.espressif.com/projects/arduino-esp32)
[![Blocklist](https://img.shields.io/badge/Blocklist-95k%2B%20domains-red)](tools/generate_blocklist.py)

Block ads, trackers, and malware domains **for every device on your network** — with no cloud dependency, no subscription, and hardware that costs less than a cup of coffee.

---

## ✨ Features

- 🔒 **95,000+ blocked domains** — StevenBlack + AdAway lists compiled into a 467 KB binary
- ⚡ **Sub-millisecond lookups** — 40-bit FNV-1a binary search directly in flash
- 🧠 **64-entry LRU cache** — eliminates repeated flash seeks for hot domains
- 🌐 **Live web dashboard** — real-time query feed, stats, and list management at `http://192.168.x.x`
- 📡 **WebSocket push** — every DNS query appears on the dashboard instantly
- ✅ **Custom whitelist / blacklist** — add/remove domains via the web UI, persisted to flash
- 🔄 **Over-the-air updates** — update firmware wirelessly with PlatformIO; update blocklist via URL or file upload
- 📶 **Wi-Fi auto-reconnect** — recovers from network drops without rebooting
- 🔌 **Fully standalone** — just plug into any USB charger, no laptop needed
- 💡 **<1W power draw** — runs 24/7 for pennies a month

---

## 🔧 Hardware

| Component | Details |
|---|---|
| **Board** | [Seeed Studio XIAO ESP32-C6](https://www.seeedstudio.com/Seeed-Studio-XIAO-ESP32C6-p-5884.html) |
| **Chip** | ESP32-C6FH4, RISC-V 160 MHz, 4 MB Flash, 320 KB RAM |
| **Power** | USB-C, 5V, ~150–200 mA (~1W) |
| **Price** | ~$6 USD |
| **Antenna** | Onboard ceramic (GPIO3/14 RF switch configured automatically) |

Any ESP32-C6 board with 4 MB flash should work with minor pin adjustments.

---

## 🚀 Quick Start

### 1. Install PlatformIO

```bash
pip install platformio
# or install the VS Code extension: https://platformio.org/install/ide?install=vscode
```

### 2. Clone the repo

```bash
git clone https://github.com/yourusername/esp32c6-adblock.git
cd esp32c6-adblock
```

### 3. Create your credentials file

```bash
cp include/secrets.h.example include/secrets.h
```

Edit `include/secrets.h` with your Wi-Fi SSID, password, and desired static IP:

```cpp
#define WIFI_SSID   "YourNetwork"
#define WIFI_PASSWORD "YourPassword"
#define STATIC_IP   "192.168.0.247"   // change to match your subnet
#define GATEWAY_IP  "192.168.0.1"
```

### 4. Generate the blocklist

```bash
pip install requests
python tools/generate_blocklist.py
# Generates data/blocklist.bin (~467 KB, 95k+ hashes)

# Optional: larger lists (~200k+ domains)
python tools/generate_blocklist.py --extra
```

### 5. Flash everything

```bash
pio run -e esp32-c6 -t uploadfs   # uploads blocklist + dashboard
pio run -e esp32-c6 -t upload     # flashes firmware
```

### 6. Set your router DNS

In your router's DHCP/DNS settings:

| Field | Value |
|---|---|
| Primary DNS | `192.168.0.247` (your static IP) |
| Secondary DNS | `1.1.1.1` (fallback if ESP32 is offline) |

Reconnect your devices — done. Every DNS query on your network now goes through the sinkhole.

---

## 🌐 Web Dashboard

Open **`http://192.168.0.247`** in any browser on your network.

**Dashboard features:**
- 📊 Live stats — total queries, blocked count, block %, uptime, free heap, cache hits
- ⚡ Real-time query feed — domain, query type, blocked/allowed status (pushed via WebSocket)
- ✅ Whitelist management — add/remove domains that should never be blocked
- 🚫 Blacklist management — add/remove domains that should always be blocked
- 📦 Blocklist OTA — paste a URL to download a new `blocklist.bin` in the background
- 📤 Direct upload — drag a `blocklist.bin` file to replace the blocklist instantly

---

## 📐 Architecture

```
Client device
    │  DNS query (UDP port 53)
    ▼
ESP32-C6
    ├─ isWhitelisted()     → FORWARD always (skip all checks)
    ├─ isCustomBlocked()   → SINKHOLE immediately (custom blacklist)
    ├─ LRU cache hit?      → cached result (no flash seek)
    └─ Binary search       → 40-bit FNV-1a hash in blocklist.bin
            │
            ├─ BLOCKED → 0.0.0.0 (A) or :: (AAAA) response
            └─ ALLOWED → forwarded to 1.1.1.1 asynchronously
                              │
                        Real IP returned to client
```

### Flash Layout (4 MB)

| Partition | Offset | Size | Contents |
|---|---|---|---|
| nvs | 0x9000 | 20 KB | Wi-Fi credentials, OTA state |
| otadata | 0xE000 | 8 KB | Active OTA slot indicator |
| app0 | 0x10000 | 1.375 MB | Firmware (active) |
| app1 | 0x170000 | 1.375 MB | OTA firmware staging |
| spiffs | 0x2D0000 | 1.1875 MB | blocklist.bin, index.html, whitelist.txt, blacklist.txt |

---

## 🔄 Updating the Blocklist

### Via the web dashboard (no laptop needed)

1. Host a new `blocklist.bin` anywhere accessible on your network (or the internet)
2. Open `http://192.168.0.247` → Maintenance tab → paste URL → click Download
3. The ESP32 downloads it in the background while still serving DNS

### Via file upload

1. Run `python tools/generate_blocklist.py` on any machine
2. Open dashboard → Maintenance → upload the `data/blocklist.bin` file directly

### Via PlatformIO (USB)

```bash
python tools/generate_blocklist.py
pio run -e esp32-c6 -t uploadfs
```

---

## 📡 Firmware OTA

Update the firmware wirelessly — no USB cable needed after initial flash:

```bash
# Replace with your device's IP
pio run -e esp32-c6 -t upload --upload-port 192.168.0.247
# OTA password: dnshole  (set in secrets.h)
```

---

## ⚙️ Configuration Reference

All user-facing configuration lives in `include/secrets.h` (never committed):

| Define | Default | Description |
|---|---|---|
| `WIFI_SSID` | — | Your Wi-Fi network name |
| `WIFI_PASSWORD` | — | Your Wi-Fi password |
| `OTA_HOSTNAME` | `dns-sinkhole` | mDNS hostname for OTA |
| `OTA_PASSWORD` | `dnshole` | ArduinoOTA password |
| `STATIC_IP` | `192.168.0.247` | Fixed IP the ESP32 claims |
| `GATEWAY_IP` | `192.168.0.1` | Your router's IP |
| `SUBNET_MASK` | `255.255.255.0` | Usually this for home networks |

Advanced settings in `src/main.cpp`:

| Constant | Default | Description |
|---|---|---|
| `UPSTREAM_DNS` | `1.1.1.1` | Where to forward clean queries |
| `MAX_PENDING` | `16` | Max in-flight async DNS queries |
| `QUERY_TIMEOUT` | `3000 ms` | Upstream timeout before eviction |

---

## 🐛 Troubleshooting

| Symptom | Fix |
|---|---|
| Dashboard shows 0 queries | Devices haven't renewed DHCP yet — run `ipconfig /renew` or reconnect Wi-Fi |
| `nslookup` returns real IP for blocked domain | Run `pio device monitor` and check for `[FS] Loaded ... hashes` — filesystem may not be uploaded |
| All DNS fails | Ensure secondary DNS `1.1.1.1` is set in router as fallback |
| Can't reach `192.168.0.247` | Ping it first. If no ping, check serial monitor for Wi-Fi connection errors |
| OSError(22) during flash | Harmless — ESP32-C6 USB-CDC re-enumerates on reset. The upload completed successfully |
| LittleFS mount fail | Re-run `pio run -t uploadfs` |

**Enable verbose serial logging:**
```ini
# platformio.ini
build_flags = -DCORE_DEBUG_LEVEL=4
```

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). PRs welcome — especially:
- Additional blocklist sources in `generate_blocklist.py`
- Dashboard UI improvements
- DNS-over-TLS upstream support
- Per-device query tracking

---

## 📊 Compared to Pi-hole

| | ESP32-C6 Sinkhole | Pi-hole |
|---|---|---|
| **Hardware cost** | ~$6 | ~$35 (Raspberry Pi Zero 2W) |
| **Power draw** | ~1W | ~2.5W |
| **Setup time** | ~10 min | ~30 min |
| **Blocklist size** | 95k–200k domains | 100k–1M+ domains |
| **Per-device rules** | ❌ | ✅ |
| **DHCP server** | ❌ | ✅ |
| **Query logging to disk** | ❌ (resets on reboot) | ✅ |
| **DNS-over-HTTPS** | ❌ | ❌ (same limitation) |

---

## 📄 License

MIT — see [LICENSE](LICENSE). Use it, fork it, ship it.

---

<p align="center">
  Built with ❤️ on a $6 microcontroller · Blocks ads so you don't have to
</p>
