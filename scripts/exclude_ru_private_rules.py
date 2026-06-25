#!/usr/bin/env python3
import argparse
import fnmatch
import ipaddress
import re
import sys
import urllib.request
from bisect import bisect_right
from pathlib import Path


DOMAIN_EXCLUDE_SOURCES = [
    "https://raw.githubusercontent.com/Davoyan/mihomo-rule-sets/main/rules/category-ru.lst",
    "https://raw.githubusercontent.com/LaKardo/MIHOMO_YAMLS/GeoData/MetaCubeX/geosite/geosite.dat_text/geosite_private.txt",
]

CIDR_EXCLUDE_SOURCES = [
    "https://raw.githubusercontent.com/Davoyan/mihomo-rule-sets/main/ip-for-ru/lists/ips-for-ru.txt",
    "https://raw.githubusercontent.com/LaKardo/MIHOMO_YAMLS/GeoData/MetaCubeX/geoip/geoip.dat_text/geoip_private.txt",
    "https://raw.githubusercontent.com/LaKardo/MIHOMO_YAMLS/GeoData/MetaCubeX/geoip/geoip.dat_text/geoip_ru.txt",
    "https://raw.githubusercontent.com/LaKardo/MIHOMO_YAMLS/GeoData/xream/geoip/ip2location.geoip.dat_text/ip2location.geoip_ru.txt",
    "https://raw.githubusercontent.com/LaKardo/MIHOMO_YAMLS/GeoData/xream/geoip/ipinfo.geoip.dat_text/ipinfo.geoip_ru.txt",
]


DOMAIN_RULE_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-REGEX",
}

CIDR_RULE_TYPES = {
    "IP-CIDR",
    "IP-CIDR6",
}


def fetch_text(url: str) -> str:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "MIHOMO_YAMLS RU/private exclusion filter"},
    )
    with urllib.request.urlopen(req, timeout=120) as response:
        return response.read().decode("utf-8", "ignore")


def split_source_tokens(text: str):
    for raw_line in text.splitlines():
        line = raw_line.strip()

        if not line:
            continue

        if line.startswith("#") or line.startswith(";"):
            continue

        # YAML payload style:
        # - DOMAIN-SUFFIX,example.com
        line = re.sub(r"^\s*-\s*", "", line).strip()
        line = line.strip("\"'")

        # Many upstream lists are space-separated or line-separated.
        for token in re.split(r"\s+", line):
            token = token.strip().strip("\"'")
            if token:
                yield token


def clean_domain(value: str) -> str:
    value = value.strip().strip("\"'").lower()
    value = value.rstrip(".")
    return value


def add_domain_token(token: str, suffixes: set[str], wildcards: set[str], regexes: set[str]):
    token = token.strip().strip("\"'")

    if not token:
        return

    if token.startswith("#") or token.startswith(";"):
        return

    # Clash/Mihomo classical format:
    # DOMAIN,example.com
    # DOMAIN-SUFFIX,example.com
    # DOMAIN-REGEX,^example
    parts = [p.strip() for p in token.split(",", 2)]

    if len(parts) >= 2 and parts[0].upper() in DOMAIN_RULE_TYPES:
        rule_type = parts[0].upper()
        value = clean_domain(parts[1])

        if not value:
            return

        if rule_type in {"DOMAIN", "DOMAIN-SUFFIX"}:
            # Для исключений безопаснее считать DOMAIN как suffix:
            # vk.com должен исключать и vk.com, и sub.vk.com.
            suffixes.add(value)
        elif rule_type == "DOMAIN-REGEX":
            regexes.add(value)
        elif rule_type == "DOMAIN-KEYWORD":
            # KEYWORD автоматом не применяем: слишком велик риск ложных срабатываний.
            pass

        return

    value = clean_domain(token)

    if not value:
        return

    # Geosite-style tokens.
    if value.startswith("full:"):
        suffixes.add(clean_domain(value[5:]))
        return

    if value.startswith("domain:"):
        suffixes.add(clean_domain(value[7:]))
        return

    if value.startswith("regexp:"):
        regexes.add(value[7:])
        return

    if value.startswith("keyword:"):
        return

    # +.example.com means example.com and subdomains.
    if value.startswith("+."):
        value = value[2:]

    # Examples from category-ru: +.tinkoff.*, +.sovcombank.*
    if "*" in value:
        wildcards.add(value)
        wildcards.add("*." + value)
        return

    # Bare TLDs like ru, su, xn--p1ai should act as suffixes.
    # Bare domains like vk.com also act as suffixes for subdomains.
    suffixes.add(value)


def add_cidr_token(token: str, networks: list[ipaddress._BaseNetwork]):
    token = token.strip().strip("\"'")

    if not token:
        return

    if token.startswith("#") or token.startswith(";"):
        return

    parts = [p.strip() for p in token.split(",")]

    if len(parts) >= 2 and parts[0].upper() in CIDR_RULE_TYPES:
        value = parts[1]
    else:
        value = parts[0]

    value = value.strip().strip("\"'")

    if not value or "/" not in value:
        return

    try:
        networks.append(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return


def build_exclusion_sets():
    suffixes: set[str] = set()
    wildcards: set[str] = set()
    regexes: set[str] = set()
    networks: list[ipaddress._BaseNetwork] = []

    for url in DOMAIN_EXCLUDE_SOURCES:
        print(f"[exclude] downloading domain source: {url}", file=sys.stderr)
        text = fetch_text(url)

        for token in split_source_tokens(text):
            add_domain_token(token, suffixes, wildcards, regexes)

    for url in CIDR_EXCLUDE_SOURCES:
        print(f"[exclude] downloading cidr source: {url}", file=sys.stderr)
        text = fetch_text(url)

        for token in split_source_tokens(text):
            add_cidr_token(token, networks)

    v4 = [n for n in networks if n.version == 4]
    v6 = [n for n in networks if n.version == 6]

    v4_intervals = merge_network_intervals(v4)
    v6_intervals = merge_network_intervals(v6)

    print(
        f"[exclude] domain suffixes={len(suffixes)}, wildcards={len(wildcards)}, "
        f"regexes={len(regexes)}, cidr_v4={len(v4_intervals)}, cidr_v6={len(v6_intervals)}",
        file=sys.stderr,
    )

    return suffixes, wildcards, regexes, v4_intervals, v6_intervals


def merge_network_intervals(networks):
    intervals = []

    for net in networks:
        start = int(net.network_address)
        end = int(net.broadcast_address)
        intervals.append((start, end))

    intervals.sort()

    merged = []
    for start, end in intervals:
        if not merged or start > merged[-1][1] + 1:
            merged.append([start, end])
        else:
            merged[-1][1] = max(merged[-1][1], end)

    return [(start, end) for start, end in merged]


def domain_matches_suffix(domain: str, suffix: str) -> bool:
    return domain == suffix or domain.endswith("." + suffix)


def domain_is_excluded(domain: str, suffixes: set[str], wildcards: set[str], regexes: set[str]) -> bool:
    domain = clean_domain(domain)

    if not domain:
        return False

    for suffix in suffixes:
        if domain_matches_suffix(domain, suffix):
            return True

    for pattern in wildcards:
        if fnmatch.fnmatchcase(domain, pattern):
            return True

    for pattern in regexes:
        try:
            if re.search(pattern, domain):
                return True
        except re.error:
            continue

    return False


def network_is_fully_excluded(net: ipaddress._BaseNetwork, v4_intervals, v6_intervals) -> bool:
    intervals = v4_intervals if net.version == 4 else v6_intervals

    if not intervals:
        return False

    start = int(net.network_address)
    end = int(net.broadcast_address)

    starts = [i[0] for i in intervals]
    idx = bisect_right(starts, start) - 1

    if idx < 0:
        return False

    interval_start, interval_end = intervals[idx]

    return interval_start <= start and end <= interval_end


def should_drop_rule(line: str, suffixes, wildcards, regexes, v4_intervals, v6_intervals) -> tuple[bool, str]:
    stripped = line.strip()

    if not stripped or stripped.startswith("#") or stripped.startswith(";"):
        return False, ""

    parts = [p.strip() for p in stripped.split(",")]
    rule_type = parts[0].upper()

    if rule_type in {"DOMAIN", "DOMAIN-SUFFIX"} and len(parts) >= 2:
        domain = parts[1]
        if domain_is_excluded(domain, suffixes, wildcards, regexes):
            return True, "domain"

    # DOMAIN-KEYWORD intentionally skipped:
    # keyword matching against RU/private lists creates too many false positives.

    if rule_type in CIDR_RULE_TYPES and len(parts) >= 2:
        try:
            net = ipaddress.ip_network(parts[1], strict=False)
        except ValueError:
            return False, ""

        if network_is_fully_excluded(net, v4_intervals, v6_intervals):
            return True, "cidr"

    return False, ""


def filter_file(path: Path, suffixes, wildcards, regexes, v4_intervals, v6_intervals, dry_run: bool):
    if not path.exists():
        print(f"[skip] {path} does not exist", file=sys.stderr)
        return 0, 0, 0

    original_lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()

    kept = []
    dropped_domain = 0
    dropped_cidr = 0

    for line in original_lines:
        drop, reason = should_drop_rule(
            line,
            suffixes,
            wildcards,
            regexes,
            v4_intervals,
            v6_intervals,
        )

        if drop:
            if reason == "domain":
                dropped_domain += 1
            elif reason == "cidr":
                dropped_cidr += 1
            continue

        kept.append(line)

    if not dry_run:
        path.write_text("\n".join(kept).rstrip() + "\n", encoding="utf-8")

    return len(original_lines), dropped_domain, dropped_cidr


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("files", nargs="+", help="meta/*.list files to filter")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    suffixes, wildcards, regexes, v4_intervals, v6_intervals = build_exclusion_sets()

    total_domain = 0
    total_cidr = 0

    for file_name in args.files:
        path = Path(file_name)
        total, dropped_domain, dropped_cidr = filter_file(
            path,
            suffixes,
            wildcards,
            regexes,
            v4_intervals,
            v6_intervals,
            args.dry_run,
        )

        total_domain += dropped_domain
        total_cidr += dropped_cidr

        print(
            f"[filter] {path}: total={total}, "
            f"dropped_domain={dropped_domain}, dropped_cidr={dropped_cidr}",
            file=sys.stderr,
        )

    print(
        f"[filter] done: dropped_domain={total_domain}, dropped_cidr={total_cidr}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
