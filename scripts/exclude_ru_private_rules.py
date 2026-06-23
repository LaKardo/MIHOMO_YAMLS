#!/usr/bin/env python3
"""Filter generated Mihomo/Clash rulesets with Anti-RU/Anti-Private exclusions.

The script subtracts domain and CIDR exclusion sources from existing classical
ruleset files. It is intentionally conservative for keyword/regex rules because
blind text matching there causes many false positives.
"""
from __future__ import annotations

import argparse
import ipaddress
import re
from pathlib import Path
from typing import Iterable

CIDR_RULES = {"IP-CIDR", "IP-CIDR6"}


def read_tokens(paths: Iterable[str]) -> list[str]:
    tokens: list[str] = []
    for path_str in paths:
        path = Path(path_str)
        if not path.is_file():
            raise FileNotFoundError(path)
        text = path.read_text(encoding="utf-8", errors="ignore")
        for raw in re.split(r"\s+", text):
            token = raw.strip().strip('"').strip("'")
            if not token or token.startswith(("#", ";")):
                continue
            token = token.split("#", 1)[0].split(";", 1)[0].strip()
            if token:
                tokens.append(token)
    return tokens


def normalize_domain_token(token: str) -> tuple[str, str | re.Pattern[str]] | None:
    """Return ('suffix', domain) or ('wildcard', compiled_regex)."""
    token = token.strip().lower().strip('"').strip("'")
    if not token:
        return None

    if "," in token:
        rule_type, value = token.split(",", 1)
        rule_type = rule_type.strip().upper()
        value = value.strip().lower().strip('"').strip("'")
        if rule_type in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-WILDCARD"}:
            token = value
        else:
            return None

    for prefix in ("domain:", "full:"):
        if token.startswith(prefix):
            token = token[len(prefix):]
            break

    if token.startswith("regexp:") or token.startswith("regex:"):
        return None

    if token.startswith("+."):
        token = token[2:]
    elif token.startswith("*."):
        token = token[2:]
    elif token.startswith("."):
        token = token[1:]

    token = token.strip(".")
    if not token:
        return None

    if "*" in token:
        escaped = re.escape(token).replace(r"\*", r"[^.]+")
        return ("wildcard", re.compile(r"(^|\.)" + escaped + r"$", re.IGNORECASE))

    return ("suffix", token)


def load_domain_excludes(paths: Iterable[str]) -> tuple[set[str], list[re.Pattern[str]]]:
    suffixes: set[str] = set()
    wildcards: list[re.Pattern[str]] = []

    for token in read_tokens(paths):
        item = normalize_domain_token(token)
        if not item:
            continue
        kind, value = item
        if kind == "suffix":
            suffixes.add(str(value))
        else:
            wildcards.append(value)  # type: ignore[arg-type]

    return suffixes, wildcards


def domain_blocked(domain: str, suffixes: set[str], wildcards: list[re.Pattern[str]]) -> bool:
    domain = domain.lower().strip().strip('"').strip("'").lstrip(".")
    if not domain:
        return False

    for suffix in suffixes:
        if domain == suffix or domain.endswith("." + suffix):
            return True

    return any(rx.search(domain) for rx in wildcards)


def load_cidr_excludes(paths: Iterable[str]) -> dict[int, list[ipaddress._BaseNetwork]]:
    networks: dict[int, list[ipaddress._BaseNetwork]] = {4: [], 6: []}

    for token in read_tokens(paths):
        token = token.split(",", 1)[0].strip()
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError:
            continue
        networks[net.version].append(net)

    for version in (4, 6):
        networks[version] = sorted(
            ipaddress.collapse_addresses(networks[version]),
            key=lambda n: (int(n.network_address), n.prefixlen),
        )

    return networks


def subtract_network(
    net: ipaddress._BaseNetwork,
    excludes: dict[int, list[ipaddress._BaseNetwork]],
) -> list[ipaddress._BaseNetwork]:
    remaining: list[ipaddress._BaseNetwork] = [net]

    for ex in excludes.get(net.version, []):
        next_remaining: list[ipaddress._BaseNetwork] = []

        for part in remaining:
            if not part.overlaps(ex):
                next_remaining.append(part)
                continue

            if part.subnet_of(ex) or part == ex:
                continue

            if ex.subnet_of(part):
                next_remaining.extend(part.address_exclude(ex))
                continue

            next_remaining.append(part)

        remaining = next_remaining
        if not remaining:
            break

    return sorted(remaining, key=lambda n: (int(n.network_address), n.prefixlen))


def filter_file(
    path_str: str,
    suffixes: set[str],
    wildcards: list[re.Pattern[str]],
    cidr_excludes: dict[int, list[ipaddress._BaseNetwork]],
) -> tuple[int, int]:
    path = Path(path_str)
    output: list[str] = []
    removed = 0
    expanded_cidr = 0

    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            output.append(raw_line)
            continue

        rule_type, sep, payload = line.partition(",")
        rule_type = rule_type.strip().upper()
        payload = payload.strip()

        if rule_type in {"DOMAIN", "DOMAIN-SUFFIX"}:
            if sep and domain_blocked(payload.split(",", 1)[0], suffixes, wildcards):
                removed += 1
                continue
            output.append(line)
            continue

        if rule_type == "DOMAIN-WILDCARD":
            probe = payload.replace("*.", "").replace("*", "").strip(".")
            if probe and domain_blocked(probe, suffixes, wildcards):
                removed += 1
                continue
            output.append(line)
            continue

        if rule_type in {"DOMAIN-KEYWORD", "DOMAIN-REGEX"}:
            output.append(line)
            continue

        if rule_type in CIDR_RULES:
            cidr_text = payload.split(",", 1)[0].strip()
            suffix = ",no-resolve" if line.endswith(",no-resolve") else ""
            try:
                net = ipaddress.ip_network(cidr_text, strict=False)
            except ValueError:
                output.append(line)
                continue

            pieces = subtract_network(net, cidr_excludes)
            if not pieces:
                removed += 1
                continue

            if len(pieces) != 1 or pieces[0] != net:
                removed += 1
                expanded_cidr += len(pieces)

            for piece in pieces:
                new_type = "IP-CIDR6" if piece.version == 6 else "IP-CIDR"
                output.append(f"{new_type},{piece}{suffix}")
            continue

        output.append(line)

    seen: set[str] = set()
    deduped: list[str] = []
    for item in output:
        key = item.strip()
        if key and key in seen:
            continue
        if key:
            seen.add(key)
        deduped.append(item)

    path.write_text("\n".join(deduped).rstrip() + "\n", encoding="utf-8")
    return removed, expanded_cidr


def main() -> int:
    parser = argparse.ArgumentParser(description="Subtract RU/private exclusions from generated rulesets.")
    parser.add_argument("--domain-exclude", action="append", default=[], help="Domain exclusion source")
    parser.add_argument("--cidr-exclude", action="append", default=[], help="CIDR exclusion source")
    parser.add_argument("--targets", nargs="+", required=True, help="Ruleset files to filter")
    args = parser.parse_args()

    suffixes, wildcards = load_domain_excludes(args.domain_exclude)
    cidr_excludes = load_cidr_excludes(args.cidr_exclude)

    print(f"Domain suffix exclusions: {len(suffixes)}")
    print(f"Domain wildcard exclusions: {len(wildcards)}")
    print(f"CIDR IPv4 exclusions: {len(cidr_excludes[4])}")
    print(f"CIDR IPv6 exclusions: {len(cidr_excludes[6])}")

    total_removed = 0
    total_expanded = 0
    for target in args.targets:
        path = Path(target)
        if not path.is_file():
            print(f"skip missing target: {target}")
            continue
        removed, expanded = filter_file(target, suffixes, wildcards, cidr_excludes)
        total_removed += removed
        total_expanded += expanded
        print(f"{target}: removed={removed}, cidr_expanded={expanded}")

    print(f"Total removed rules: {total_removed}")
    print(f"Total emitted replacement CIDRs: {total_expanded}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
