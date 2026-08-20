#!/usr/bin/env python3
"""
generate_blocklist.py
─────────────────────
Downloads ad-blocking host lists, extracts domains, hashes each one with
40-bit FNV-1a, sorts the hashes, and writes a compact binary file
(5 bytes per hash) suitable for in-place binary search on ESP32 flash.

Output: data/blocklist.bin

Usage:
    python tools/generate_blocklist.py           # default sources
    python tools/generate_blocklist.py --extra   # include OISD + Hagezi lists

Requirements:
    pip install requests
"""

import argparse
import struct
import sys
from pathlib import Path

try:
    import requests
except ImportError:
    sys.exit("Install requests first:  pip install requests")

# ── Blocklist sources ────────────────────────────────────────────────────────
SOURCES = [
    # StevenBlack (Ads + Malware + Fakenews + Gambling + Porn + Social)
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts"
]

EXTRA_SOURCES = [
    # OISD basic (large, high-quality)
    "https://abp.oisd.nl/basic/",
    # Hagezi Pro (comprehensive)
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt",
]

# ── FNV-1a 40-bit hash ───────────────────────────────────────────────────────
FNV_OFFSET = 0xcbf29ce484222325
FNV_PRIME  = 0x100000001b3
MASK_64    = 0xFFFFFFFFFFFFFFFF
MASK_40    = 0xFFFFFFFFFF

def fnv1a_40(domain: str) -> int:
    h = FNV_OFFSET
    for ch in domain.lower():
        h ^= ord(ch)
        h  = (h * FNV_PRIME) & MASK_64
    return h & MASK_40

# ── Hosts-file parser ────────────────────────────────────────────────────────
def parse_hosts(text: str) -> set:
    domains = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        # Standard hosts-file format: "0.0.0.0 domain.com" or "127.0.0.1 ..."
        if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
            domain = parts[1].lower().rstrip(".")
            # Skip localhost and empty entries
            if domain and domain not in ("localhost", "localhost.localdomain",
                                         "local", "broadcasthost"):
                domains.add(domain)
        # Some lists just have bare domains
        elif len(parts) == 1 and "." in parts[0] and not parts[0].startswith("#"):
            domains.add(parts[0].lower().rstrip("."))
    return domains

# ── Main ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Generate blocklist.bin for ESP32 DNS sinkhole")
    parser.add_argument("--extra", action="store_true",
                        help="Include OISD + Hagezi lists (~200k+ domains)")
    parser.add_argument("--output", default="data/blocklist.bin",
                        help="Output file path (default: data/blocklist.bin)")
    args = parser.parse_args()

    sources = SOURCES + (EXTRA_SOURCES if args.extra else [])
    all_domains = set()

    print("Downloading {} blocklist(s)...".format(len(sources)))
    for url in sources:
        try:
            print("  down {}".format(url))
            r = requests.get(url, timeout=30,
                             headers={"User-Agent": "esp32-dns-sinkhole/1.0"})
            r.raise_for_status()
            found = parse_hosts(r.text)
            print("    -> {:,} domains".format(len(found)))
            all_domains |= found
        except Exception as e:
            print("    FAILED: {}".format(e))

    print("\nTotal unique domains: {:,}".format(len(all_domains)))

    # Hash and sort
    print("Hashing...")
    hashes = sorted(fnv1a_40(d) for d in all_domains)

    # Write binary (big-endian 5-byte per hash)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "wb") as f:
        for h in hashes:
            # Pack as 8-byte big-endian, take the last 5 bytes
            f.write(struct.pack(">Q", h)[3:])

    size_kb = out.stat().st_size / 1024
    print("Written: {}  ({:,} hashes, {:.1f} KB)".format(out, len(hashes), size_kb))
    print("\nNext steps:")
    print("  pio run -t uploadfs   # upload blocklist + dashboard to ESP32")
    print("  pio run -t upload     # flash firmware")

if __name__ == "__main__":
    main()