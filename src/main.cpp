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
#include "per_client.h"   // clientsInit / recordClient / g_clients
#include "lists.h"        // g_whitelist / g_blacklist / isWhitelisted / isCustomBlocked
#include "settings.h"     // g_blockMode / settingsLoad / settingsSave
#include "ota_updater.h"  // startBlocklistUpdate / getOtaStatus

// ══════════════════════════════════════════════════════════════════════════════
//  DNS configuration — defined before web_ui.h so its lambdas can reference them
// ══════════════════════════════════════════════════════════════════════════════
IPAddress        UPSTREAM_DNS(1, 1, 1, 1);          // primary (user-configurable)
IPAddress        UPSTREAM_DNS_FALLBACK(8, 8, 8, 8); // automatic fallback
const uint16_t   DNS_PORT        = 53;
const int        MAX_PENDING     = 32;
const uint32_t   QUERY_TIMEOUT   = 3000; // ms

WiFiUDP dnsServer;
WiFiUDP upstreamClient;

unsigned long lastHeartbeat        = 0;
unsigned long lastReconnectAttempt = 0;

// ── Dual-upstream failover state ──────────────────────────────────────────────
bool g_usingFallback     = false;
int  g_upstreamFailCount = 0;
int  g_upstreamOkCount   = 0;

IPAddress& currentUpstream() {
    return g_usingFallback ? UPSTREAM_DNS_FALLBACK : UPSTREAM_DNS;
}

void notifyUpstreamSuccess() {
    g_upstreamFailCount = 0;
    if (g_usingFallback) {
        if (++g_upstreamOkCount >= 3) {
            g_usingFallback   = false;
            g_upstreamOkCount = 0;
            Serial.printf("[DNS] Primary upstream restored: %s\n",
                          UPSTREAM_DNS.toString().c_str());
        }
    }
}

void notifyUpstreamFailure() {
    g_upstreamOkCount = 0;
    if (++g_upstreamFailCount >= 5 && !g_usingFallback) {
        g_usingFallback     = true;
        g_upstreamFailCount = 0;
        Serial.printf("[DNS] Switched to fallback upstream: %s\n",
                      UPSTREAM_DNS_FALLBACK.toString().c_str());
    }
}

// ── Async pending query table ─────────────────────────────────────────────────
struct PendingQuery {
    bool      active;
    uint16_t  origTxId;
    uint16_t  ourTxId;
    IPAddress clientIP;
    uint16_t  clientPort;
    uint32_t  timestamp;
};
PendingQuery    pendingQueries[MAX_PENDING];
static uint16_t s_txIdCounter = 0;

// Static response buffer
static uint8_t s_upstreamRespBuf[1024];

// ── web_ui.h included here so its lambdas see the types above ────────────────
#include "web_ui.h"       // webUiSetup / webUiLoop / broadcastQuery

// ══════════════════════════════════════════════════════════════════════════════
//  4 KB Bloom filter — pre-screens isHashBlocked() calls
//
//  ~99% of non-blocked domains bypass the binary flash search entirely.
//  Built once at boot from blocklist.bin (one sequential read pass).
//  False-positive rate ≈ 1% for ~93 K entries with 3 hash functions.
// ══════════════════════════════════════════════════════════════════════════════
static uint8_t g_bloom[4096]; // 32 768 bits

static inline void bloomSet(uint64_t hash) {
    const uint16_t h1 = (uint16_t)( hash        & 0x7FFF); // bits  0-14
    const uint16_t h2 = (uint16_t)((hash >> 15) & 0x7FFF); // bits 15-29
    const uint16_t h3 = (uint16_t)((hash >> 25) & 0x7FFF); // bits 25-39
    g_bloom[h1 >> 3] |= (1u << (h1 & 7));
    g_bloom[h2 >> 3] |= (1u << (h2 & 7));
    g_bloom[h3 >> 3] |= (1u << (h3 & 7));
}

static inline bool bloomCheck(uint64_t hash) {
    const uint16_t h1 = (uint16_t)( hash        & 0x7FFF);
    const uint16_t h2 = (uint16_t)((hash >> 15) & 0x7FFF);
    const uint16_t h3 = (uint16_t)((hash >> 25) & 0x7FFF);
    return (g_bloom[h1 >> 3] >> (h1 & 7) & 1) &&
           (g_bloom[h2 >> 3] >> (h2 & 7) & 1) &&
           (g_bloom[h3 >> 3] >> (h3 & 7) & 1);
}

// One sequential read pass over blocklist.bin — called once at boot
static void buildBloom() {
    memset(g_bloom, 0, sizeof(g_bloom));
    if (!fsReady) return;
    blocklistFile.seek(0);
    uint8_t buf[5];
    while (blocklistFile.read(buf, 5) == 5) {
        uint64_t h = 0;
        for (int i = 0; i < 5; i++) h = (h << 8) | buf[i];
        bloomSet(h);
    }
    blocklistFile.seek(0); // reset file position for binary search
    Serial.printf("[BLOOM] 4 KB filter built for %u hashes\n", totalHashes);
}

// ══════════════════════════════════════════════════════════════════════════════
//  40-bit FNV-1a Hash (unchanged — correct implementation)
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
//  Binary search in LittleFS — bloom-filtered (flash I/O only when bloom says yes)
// ══════════════════════════════════════════════════════════════════════════════
bool isHashBlocked(uint64_t targetHash)
{
    if (!fsReady || totalHashes == 0) return false;

    // Bloom pre-screen: ~99% of allowed-domain hashes exit here with zero flash I/O
    if (!bloomCheck(targetHash)) return false;

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
//  DNS lookup pipeline with full priority chain and behavioral modes
// ══════════════════════════════════════════════════════════════════════════════

bool endsWith(const char* str, const char* suffix) {
    size_t strLen    = strlen(str);
    size_t suffixLen = strlen(suffix);
    if (strLen < suffixLen) return false;
    return (strcasecmp(str + strLen - suffixLen, suffix) == 0) &&
           (strLen == suffixLen || str[strLen - suffixLen - 1] == '.');
}

bool isEssentialGoogle(const char* domain) {
    const char* targets[] = {
        "google.com", "googleapis.com", "gstatic.com", "youtube.com", "googlevideo.com",
        "gmail.com", "googleusercontent.com", "g.co", "ggpht.com"
    };
    for (const char* t : targets) if (endsWith(domain, t)) return true;
    return false;
}

bool isApple(const char* domain) {
    const char* targets[] = {
        "apple.com", "icloud.com", "mzstatic.com", "me.com", "mac.com", "apple-cloudkit.com"
    };
    for (const char* t : targets) if (endsWith(domain, t)) return true;
    return false;
}

bool isAppleTracking(const char* domain) {
    const char* targets[] = {
        "metrics.apple.com", "securemetrics.apple.com", "iad.apple.com",
        "iadsdk.apple.com", "api-adservices.apple.com", "metrics.icloud.com",
        "metrics.mzstatic.com", "triadsdk.apple.com", "xp.apple.com"
    };
    for (const char* t : targets) if (endsWith(domain, t)) return true;
    return false;
}

bool isGoogleTracking(const char* domain) {
    const char* targets[] = {
        "doubleclick.net", "google-analytics.com", "googleadservices.com",
        "googlesyndication.com", "admob.com", "2mdn.net", "googletagservices.com",
        "googletagmanager.com", "analytics.google.com", "click.googleanalytics.com",
        "tagmanager.google.com", "dai.google.com", "adservice.google.com"
    };
    for (const char* t : targets) if (endsWith(domain, t)) return true;
    return false;
}

bool isStrictTracker(const char* domain) {
    const char* targets[] = {
        "amazon-adsystem.com", "a-mo.net", "fls-na.amazon.com", "device-metrics-us.amazon.com",
        "device-metrics-us-2.amazon.com", "mads-eu.amazon.com", "connect.facebook.net",
        "pixel.facebook.com", "graph.facebook.com", "an.facebook.com", "tr.facebook.com",
        "graph.instagram.com", "i.instagram.com", "ads1.msn.com", "rad.msn.com", "bat.bing.com",
        "bingads.microsoft.com", "ads.microsoft.com", "vortex.data.microsoft.com",
        "telemetry.microsoft.com", "watson.telemetry.microsoft.com",
        "browser.events.data.microsoft.com", "c.bing.com", "media.net", "adcolony.com",
        "criteo.com", "criteo.net", "taboola.com", "outbrain.com", "mgid.com",
        "propellerads.com", "onclickads.net", "applovin.com", "vungle.com", "liftoff.io",
        "adnxs.com", "pubmatic.com", "openx.net", "rubiconproject.com", "spotxchange.com",
        "indexexchange.com", "casalemedia.com", "htlbid.com", "unityads.unity3d.com",
        "yandex.ru", "yandex.net", "supersonicads.com", "chartboost.com", "fyber.com",
        "inmobi.com", "ironsource.mobi", "kargo.com", "adsrvr.org", "adroll.com",
        "smartyads.com", "ad.gt", "contextweb.com", "sharethrough.com", "pangleglobal.com",
        "stackadapt.com", "stickyadstv.com", "doubleverify.com", "3lift.com",
        "adsafeprotected.com", "sonobi.com", "gumgum.com", "teads.tv",
        "insightexpressai.com", "ads.yahoo.com", "analytics.yahoo.com", "geo.yahoo.com",
        "udc.yahoo.com", "advertising.yahoo.com", "gemini.yahoo.com", "adtech.yahooinc.com",
        "adobe.io", "omtrdc.net", "metrics.adobe.com", "clarity.ms", "hotjar.com",
        "hotjar.io", "luckyorange.com", "luckyorange.net", "mouseflow.com",
        "heapanalytics.com", "mixpanel.com", "amplitude.com", "segment.com", "segment.io",
        "fullstory.com", "quantserve.com", "quantcast.com", "scorecardresearch.com",
        "cloudflareinsights.com", "posthog.com", "rudderstack.com", "rudderlabs.com",
        "snowplowanalytics.com", "fingerprintjs.com", "fpjs.io", "bluekai.com",
        "onetag-sys.com", "pippio.com", "siftscience.com", "id5-sync.com", "mathtag.com",
        "permutive.com", "crwdentrl.net", "bidswitch.net", "everesttech.net", "uidapi.com",
        "rledn.com", "ricdn.com", "appsflyer.com", "adjust.com", "branch.io", "bnc.lt",
        "kochava.com", "singular.net", "bugsnag.com", "sentry-cdn.com", "getsentry.com",
        "sentry.io", "nr-data.net", "newrelic.com", "browser-intake-datadoghq.com",
        "lr-ingest.com", "coinimp.com", "webminepool.com", "minero.cc", "mineralt.io",
        "monerominer.rocks", "popads.net", "popcash.net", "popmyads.com", "clickadu.com",
        "trafficjunky.net", "exoclick.com", "juicyads.com", "sc-static.net",
        "tr.snapchat.com", "ads.snapchat.com", "sc-analytics.appspot.com",
        "ads.linkedin.com", "pointdrive.linkedin.com", "snap.licdn.com", "ads-twitter.com",
        "ads-api.twitter.com", "ads-api.x.com", "analytics.twitter.com", "analytics.x.com",
        "ads.x.com", "events.reddit.com", "events.redditmedia.com",
        "pixel.redditmedia.com", "d.reddit.com", "ads.pinterest.com", "ct.pinterest.com",
        "log.pinterest.com", "analytics.pinterest.com", "trk.pinterest.com",
        "widgets.pinterest.com", "ads-api.tiktok.com", "analytics.tiktok.com",
        "ads-sg.tiktok.com", "business-api.tiktok.com", "ads.tiktok.com",
        "byteoversea.com", "tiktokv.com", "pixel.quora.com", "gevents.quora.com",
        "iot-logser.realme.com", "realmemobile.com", "oppomobile.com", "oneplus.cn",
        "oneplus.net", "ad.xiaomi.com", "mistat.xiaomi.com", "hicloud.com", "miui.com",
        "ads.huawei.com", "samsungads.com", "smetrics.samsung.com", "nmetrics.samsung.com",
        "samsunghealth.com", "adlog.vivo.com", "ads-api.vivo.com", "a.lenovo.com",
        "lgsmartad.com", "lgappstv.com", "lge.com", "yumenetworks.com", "smartclip.net",
        "smartclip.com", "logs.roku.com", "ads.roku.com", "amoeba.web.roku.com",
        "ads.vizio.com", "tvinteractive.tv", "tvpixel.com", "cookielaw.org", "onetrust.com",
        "cookiebot.com", "trustarc.com", "privacy-center.org", "privacy-mgmt.com",
        "usercentrics.eu", "cmp.inmobi.com", "cmp.osano.com", "anrdoezrs.net",
        "partnerstack.com", "dpbolvw.net", "tkglhce.com", "refersion.com", "shareasale.com",
        "pepperjamnetwork.com", "linksynergy.com", "skimresources.com",
        "impactradius-event.com", "redirectingat.com", "awin1.com", "zenaps.com",
        "prf.hn", "viglink.com", "optimizely.com", "dynamicyield.com", "launchdarkly.com",
        "list-manage.com", "hubspot.com", "marketo.net", "mailchimp.com", "intercom.io",
        "driftt.com", "braze.com", "onesignal.com", "klaviyo.com", "customer.io",
        "jwpsrv.com", "jwpedn.com", "jwpltx.com", "fwmrm.net", "brightcove.com",
        "innovid.com", "connatix.com", "tremorhub.com"
    };
    for (const char* t : targets) if (endsWith(domain, t)) return true;
    return false;
}

bool isDomainBlocked(const char *domain)
{
    // Mode: ABSOLUTE (Hailmary) — block EVERYTHING not whitelisted
    if (g_blockMode == BlockMode::ABSOLUTE) {
        if (isWhitelisted(domain)) return false;
        return true;
    }

    // Mode: BYPASS — block nothing
    if (g_blockMode == BlockMode::BYPASS) return false;

    // ── LRU cache check first (O(1) direct-mapped lookup) ─────────────────
    const uint64_t fullHash = fnv1a_40(domain, strlen(domain));
    bool cached;
    if (lruLookup(fullHash, cached)) {
        g_stats.cacheHits++;
        return cached;
    }

    // 1. Whitelist — always forward, skip all block checks
    if (isWhitelisted(domain)) {
        lruInsert(fullHash, false);
        return false;
    }

    // 2. Custom blacklist — block immediately without touching flash
    if (isCustomBlocked(domain)) {
        lruInsert(fullHash, true);
        return true;
    }

    // Mode: MINIMAL — block ONLY custom blacklist (ignore blocklist.bin)
    if (g_blockMode == BlockMode::MINIMAL) {
        lruInsert(fullHash, false);
        return false;
    }

    // 3. Strict Mode: explicitly block all known major trackers
    if (g_blockMode == BlockMode::STRICT) {
        if (isAppleTracking(domain) || isGoogleTracking(domain) || isStrictTracker(domain)) {
            lruInsert(fullHash, true);
            return true;
        }
    }

    // 4. Ensure essential services are never blocked (Normal & Strict modes)
    if (g_blockMode == BlockMode::NORMAL || g_blockMode == BlockMode::STRICT) {
        if (isApple(domain) || isEssentialGoogle(domain)) {
            lruInsert(fullHash, false);
            return false;
        }
    }

    // 5. Binary search in LittleFS for domain + parent subdomains
    //    Optimised: strlen computed once; pointer arithmetic + memchr replaces strchr
    const char  *base    = domain;
    const size_t baseLen = strlen(domain);
    const char  *cur     = base;
    bool blocked = false;

    while (*cur) {
        const size_t curLen = baseLen - (size_t)(cur - base);
        if (isHashBlocked(fnv1a_40(cur, curLen))) { blocked = true; break; }
        const char *dot = (const char*)memchr(cur, '.', curLen);
        if (!dot) break;
        cur = dot + 1;
    }

    // 6. Cache result for next lookup
    lruInsert(fullHash, blocked);
    return blocked;
}

// ══════════════════════════════════════════════════════════════════════════════
//  DNS packet parsing — char[] output, no heap allocation
// ══════════════════════════════════════════════════════════════════════════════
bool parseQName(const uint8_t *buf, size_t len,
                char *out, size_t outMax,
                size_t &qnameEnd)
{
    size_t pos  = 12; // skip 12-byte DNS header
    size_t dpos = 0;
    out[0] = '\0';

    while (pos < len && buf[pos] != 0) {
        uint8_t llen = buf[pos++];
        if (pos + llen > len)          return false; // truncated
        if (dpos + llen + 2 > outMax)  return false; // overflow guard
        if (dpos > 0) out[dpos++] = '.';
        memcpy(out + dpos, buf + pos, llen);
        dpos += llen;
        pos  += llen;
    }
    out[dpos] = '\0';
    qnameEnd  = pos + 1; // +1 to step over the null label
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

    resp[idx++] = 0xC0; resp[idx++] = 0x0C;   // Name: pointer to 0x0C
    resp[idx++] = (qtype >> 8) & 0xFF;
    resp[idx++] =  qtype       & 0xFF;
    resp[idx++] = 0x00; resp[idx++] = 0x01;   // CLASS IN
    resp[idx++] = 0x00; resp[idx++] = 0x00;
    resp[idx++] = 0x01; resp[idx++] = 0x2C;   // TTL: 300 s

    if (qtype == 0x001C) {                     // AAAA → ::
        resp[idx++] = 0x00; resp[idx++] = 0x10;
        for (int i = 0; i < 16; i++) resp[idx++] = 0x00;
    } else {                                   // A → 0.0.0.0
        resp[idx++] = 0x00; resp[idx++] = 0x04;
        for (int i = 0; i < 4;  i++) resp[idx++] = 0x00;
    }

    dnsServer.beginPacket(clientIP, clientPort);
    dnsServer.write(resp, idx);
    dnsServer.endPacket();
}

// ── SERVFAIL response — sent when a pending query times out ──────────────────
// Clients get an immediate error instead of hanging until their own timeout.
void sendServfail(IPAddress clientIP, uint16_t clientPort, uint16_t txId)
{
    uint8_t resp[12];
    resp[0] = (txId >> 8) & 0xFF;
    resp[1] =  txId       & 0xFF;
    resp[2] = 0x81; resp[3] = 0x82; // QR=1, RA=1, RCODE=2 (SERVFAIL)
    memset(resp + 4, 0, 8);         // QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT = 0
    dnsServer.beginPacket(clientIP, clientPort);
    dnsServer.write(resp, 12);
    dnsServer.endPacket();
}

// ══════════════════════════════════════════════════════════════════════════════
//  Non-blocking upstream forward
//  O(1) slot: ourTxId % MAX_PENDING — no search, no eviction loop needed
// ══════════════════════════════════════════════════════════════════════════════
void forwardUpstream(IPAddress clientIP, uint16_t clientPort,
                     uint8_t *query, size_t queryLen)
{
    uint16_t origTxId = ((uint16_t)query[0] << 8) | query[1];
    uint16_t ourTxId  = ++s_txIdCounter;
    if (ourTxId == 0) ourTxId = ++s_txIdCounter; // skip 0

    // O(1) slot assignment (overwrite if slot is still active — harmless)
    const int slot = ourTxId % MAX_PENDING;
    pendingQueries[slot] = { true, origTxId, ourTxId, clientIP, clientPort, millis() };

    // Rewrite txId in the packet before sending upstream
    query[0] = (ourTxId >> 8) & 0xFF;
    query[1] =  ourTxId       & 0xFF;

    upstreamClient.beginPacket(currentUpstream(), DNS_PORT);
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
    clientsInit();
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
            buildBloom(); // one sequential read pass to build the 4 KB filter
        }
        listsLoad();    // whitelist + blacklist
        settingsLoad(); // blocking mode

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
    if (WiFi.status() != WL_CONNECTED) {
        if (millis() - lastReconnectAttempt >= 10000) {
            lastReconnectAttempt = millis();
            Serial.println("[WIFI] Lost — reconnecting…");
            WiFi.reconnect();
        }
        delay(100);
        return;
    }

    // ── Collect upstream DNS responses (O(1) slot lookup) ────────────────────
    int respLen = upstreamClient.parsePacket();
    if (respLen > 0) {
        int n = upstreamClient.read(s_upstreamRespBuf, sizeof(s_upstreamRespBuf));
        if (n >= 2) {
            const uint16_t rxTxId = ((uint16_t)s_upstreamRespBuf[0] << 8)
                                  |  s_upstreamRespBuf[1];
            const int slot = rxTxId % MAX_PENDING; // O(1) — no loop
            PendingQuery &pq = pendingQueries[slot];
            if (pq.active && pq.ourTxId == rxTxId) {
                const uint32_t rttMs = millis() - pq.timestamp;
                g_stats.recordRTT(rttMs);

                // Restore original txId before forwarding to client
                s_upstreamRespBuf[0] = (pq.origTxId >> 8) & 0xFF;
                s_upstreamRespBuf[1] =  pq.origTxId       & 0xFF;
                dnsServer.beginPacket(pq.clientIP, pq.clientPort);
                dnsServer.write(s_upstreamRespBuf, n);
                dnsServer.endPacket();
                pq.active = false;
                notifyUpstreamSuccess();
            }
        }
    }

    // ── Expire timed-out pending queries — send SERVFAIL to client ────────────
    const uint32_t now = millis();
    for (int i = 0; i < MAX_PENDING; i++) {
        PendingQuery &pq = pendingQueries[i];
        if (pq.active && now - pq.timestamp > QUERY_TIMEOUT) {
            sendServfail(pq.clientIP, pq.clientPort, pq.origTxId);
            pq.active = false;
            notifyUpstreamFailure();
        }
    }

    // ── Handle incoming DNS query ─────────────────────────────────────────────
    int pktSize = dnsServer.parsePacket();
    if (pktSize > 12 && pktSize <= 512) {
        uint8_t   buf[512];
        int       len        = dnsServer.read(buf, sizeof(buf));
        IPAddress clientIP   = dnsServer.remoteIP();
        uint16_t  clientPort = dnsServer.remotePort();

        // Stack-allocated IP string — no heap allocation on the hot path
        char clientIPStr[16];
        snprintf(clientIPStr, sizeof(clientIPStr), "%u.%u.%u.%u",
                 clientIP[0], clientIP[1], clientIP[2], clientIP[3]);

        char   domain[128];
        size_t qnameEnd = 0;

        if (!parseQName(buf, len, domain, sizeof(domain), qnameEnd)) return;
        if (qnameEnd == 0 || (qnameEnd + 1) >= (size_t)len) return;

        const uint16_t qtype   = ((uint16_t)buf[qnameEnd] << 8) | buf[qnameEnd + 1];
        const bool     blocked = isDomainBlocked(domain);

        // Record stats + per-client stats + broadcast to web dashboard
        g_stats.record(domain, qtype, blocked, clientIPStr);
        recordClient(clientIP, blocked);
        broadcastQuery(domain, qtype, blocked, clientIPStr);

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