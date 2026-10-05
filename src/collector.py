#!/usr/bin/env python3
"""Collect publicly advertised MTProto links from a small, explicit source set.

This deliberately does not scan arbitrary IP ranges or probe undisclosed hosts.
Only endpoints explicitly published as MTProto proxy links are checked.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import requests

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "proxies"
OUT.mkdir(exist_ok=True)
TIMEOUT = float(os.getenv("CHECK_TIMEOUT", "3"))
MAX_CANDIDATES = int(os.getenv("MAX_CANDIDATES", "300"))
HEADERS = {"User-Agent": "Mtproxy-list-collector/1.0 (public-link-validation)"}

# Explicit public repositories known to publish proxy lists. Add sources via PR.
RAW_SOURCES = [
    "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
    "https://raw.githubusercontent.com/Argh94/Proxy-List/main/MTProto.txt",
]
GITHUB_QUERY = "MTProto proxies in:readme"

def extract_links(text: str) -> set[str]:
    pattern = re.compile(r"(?i)(?:tg://proxy|https?://t\.me/proxy)\?[^\s<>\"']+")
    return {m.group(0).rstrip(".,);]") for m in pattern.finditer(text)}

def parse_link(link: str):
    try:
        p = urlparse(link)
        q = parse_qs(p.query)
        host = q.get("server", [""])[0].strip()
        port = int(q.get("port", ["0"])[0])
        secret = q.get("secret", [""])[0].strip()
        if not host or not (1 <= port <= 65535) or not re.fullmatch(r"[A-Fa-f0-9]+", secret):
            return None
        # Avoid local/private/link-local and special-use destinations.
        try:
            addr = ipaddress.ip_address(host)
            if not addr.is_global:
                return None
        except ValueError:
            if len(host) > 253 or not re.fullmatch(r"(?i)(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*", host):
                return None
        return host, port
    except (ValueError, IndexError):
        return None

def discover() -> set[str]:
    found = set()
    session = requests.Session()
    session.headers.update(HEADERS)
    for url in RAW_SOURCES:
        try:
            r = session.get(url, timeout=8)
            if r.ok:
                found.update(extract_links(r.text))
        except requests.RequestException as e:
            print(f"Source unavailable: {url}: {e}")
    # GitHub code search requires authentication; search repository metadata/readmes instead.
    token = os.getenv("GITHUB_TOKEN")
    if token:
        try:
            r = session.get(
                "https://api.github.com/search/repositories",
                params={"q": GITHUB_QUERY, "sort": "updated", "per_page": 10},
                headers={"Authorization": f"Bearer {token}"},
                timeout=8,
            )
            if r.ok:
                for repo in r.json().get("items", []):
                    branch = repo.get("default_branch", "main")
                    raw = f"https://raw.githubusercontent.com/{repo['full_name']}/{branch}/README.md"
                    try:
                        rr = session.get(raw, timeout=6)
                        if rr.ok:
                            found.update(extract_links(rr.text))
                    except requests.RequestException:
                        pass
        except (requests.RequestException, ValueError) as e:
            print(f"GitHub discovery unavailable: {e}")
    return found

def reachable(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT):
            return True
    except (OSError, TimeoutError):
        return False

def main():
    candidates = discover()
    print(f"Discovered {len(candidates)} distinct public links")
    # Stable cap prevents a source from triggering unbounded connection attempts.
    candidates = sorted(candidates)[:MAX_CANDIDATES]
    working = []
    for link in candidates:
        parsed = parse_link(link)
        if not parsed:
            continue
        host, port = parsed
        if reachable(host, port):
            working.append(link)
        time.sleep(0.05)
    (OUT / "working.txt").write_text("\n".join(sorted(set(working))) + ("\n" if working else ""), encoding="utf-8")
    (OUT / "all.txt").write_text("\n".join(sorted(candidates)) + ("\n" if candidates else ""), encoding="utf-8")
    stats = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "discovered": len(candidates),
        "tcp_reachable": len(working),
        "note": "TCP reachability only; not proof of a successful Telegram MTProto session."
    }
    (OUT / "stats.json").write_text(json.dumps(stats, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(stats))

if __name__ == "__main__":
    main()
