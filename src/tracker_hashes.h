#pragma once
#include <Arduino.h>
#include <algorithm>

// Forward declaration of 40-bit FNV-1a hash function defined in main.cpp
uint64_t fnv1a_40(const char *str, size_t len);

// ─────────────────────────────────────────────────────────────────────────────
// tracker_hashes.h – Pre-hashed sorted arrays for instant binary search in IRAM
// ─────────────────────────────────────────────────────────────────────────────

static const char* const RAW_ESSENTIAL_DOMAINS[] = {
    "google.com", "googleapis.com", "gstatic.com", "youtube.com", "googlevideo.com",
    "gmail.com", "googleusercontent.com", "g.co", "ggpht.com",
    "apple.com", "icloud.com", "mzstatic.com", "me.com", "mac.com", "apple-cloudkit.com"
};
static const size_t ESSENTIAL_COUNT = sizeof(RAW_ESSENTIAL_DOMAINS) / sizeof(RAW_ESSENTIAL_DOMAINS[0]);

static const char* const RAW_TRACKER_DOMAINS[] = {
    // Apple Tracking
    "metrics.apple.com", "securemetrics.apple.com", "iad.apple.com",
    "iadsdk.apple.com", "api-adservices.apple.com", "metrics.icloud.com",
    "metrics.mzstatic.com", "triadsdk.apple.com", "xp.apple.com",
    // Google Tracking
    "doubleclick.net", "google-analytics.com", "googleadservices.com",
    "googlesyndication.com", "admob.com", "2mdn.net", "googletagservices.com",
    "googletagmanager.com", "analytics.google.com", "click.googleanalytics.com",
    "tagmanager.google.com", "dai.google.com", "adservice.google.com",
    // Strict Tracker list
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
static const size_t TRACKER_COUNT = sizeof(RAW_TRACKER_DOMAINS) / sizeof(RAW_TRACKER_DOMAINS[0]);

static uint64_t g_essentialHashes[ESSENTIAL_COUNT];
static uint64_t g_strictTrackerHashes[TRACKER_COUNT];

static inline void initTrackerHashes() {
    for (size_t i = 0; i < ESSENTIAL_COUNT; i++) {
        g_essentialHashes[i] = fnv1a_40(RAW_ESSENTIAL_DOMAINS[i], strlen(RAW_ESSENTIAL_DOMAINS[i]));
    }
    std::sort(g_essentialHashes, g_essentialHashes + ESSENTIAL_COUNT);

    for (size_t i = 0; i < TRACKER_COUNT; i++) {
        g_strictTrackerHashes[i] = fnv1a_40(RAW_TRACKER_DOMAINS[i], strlen(RAW_TRACKER_DOMAINS[i]));
    }
    std::sort(g_strictTrackerHashes, g_strictTrackerHashes + TRACKER_COUNT);

    Serial.printf("[TRACKER] Pre-hashed %u essential & %u strict tracker domains\n",
                  (unsigned int)ESSENTIAL_COUNT, (unsigned int)TRACKER_COUNT);
}

// O(log N) binary search in sorted uint64_t array (IRAM pinned)
// O(log N) binary search in sorted uint64_t array (IRAM pinned)
IRAM_ATTR static inline __attribute__((always_inline)) bool isHashInSet(const uint64_t *arr, size_t size, uint64_t target) {
    int32_t low = 0, high = (int32_t)size - 1;
    while (low <= high) {
        int32_t mid = low + ((high - low) >> 1);
        uint64_t val = arr[mid];
        if (val == target) return true;
        if (val < target) low = mid + 1;
        else high = mid - 1;
    }
    return false;
}

// Walks domain + parent subdomain hashes using precomputed label offsets and checks against sorted set
IRAM_ATTR static inline bool domainMatchesSet(const char *domain, size_t domLen, uint64_t fullHash,
                                              const uint8_t *labelOffsets, uint8_t labelCount,
                                              const uint64_t *arr, size_t size) {
    for (uint8_t i = 0; i < labelCount; i++) {
        const uint8_t off = labelOffsets[i];
        const uint64_t h = (i == 0) ? fullHash : fnv1a_40(domain + off, domLen - off);
        if (isHashInSet(arr, size, h)) return true;
    }
    return false;
}
