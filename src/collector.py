#!/usr/bin/env python3

import json
import os
import re
import socket
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse


# ============================================================
# Configuration
# ============================================================

ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = ROOT / "proxies"

ALL_FILE = OUTPUT_DIR / "all.txt"
WORKING_FILE = OUTPUT_DIR / "working.txt"
STATS_FILE = OUTPUT_DIR / "stats.json"

REQUEST_TIMEOUT = 15
TCP_TIMEOUT = 3

# Number of parallel TCP checks.
MAX_WORKERS = 40

# Public sources with proxy links.
SOURCES = [
    "https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/all_proxies.txt",
    "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
]


# ============================================================
# Regex / parsing
# ============================================================

TG_PROXY_RE = re.compile(
    r"(?:tg://proxy|https://t\.me/proxy)\?[^\s\"'<>]+",
    re.IGNORECASE,
)


def normalize_proxy_url(url: str) -> str | None:
    """
    Normalize tg://proxy and https://t.me/proxy URLs.

    Expected format:
      tg://proxy?server=1.2.3.4&port=443&secret=...
    """

    url = url.strip()

    if not url:
        return None

    # Remove common surrounding punctuation.
    url = url.strip("()[]{}<>,;\"'")

    if url.startswith("https://t.me/proxy?"):
        parsed = urlparse(url)
        query = parse_qs(parsed.query)

    elif url.startswith("tg://proxy?"):
        parsed = urlparse(url)
        query = parse_qs(parsed.query)

    else:
        return None

    server = query.get("server", [None])[0]
    port = query.get("port", [None])[0]
    secret = query.get("secret", [None])[0]

    if not server or not port or not secret:
        return None

    server = unquote(server).strip()
    port = unquote(port).strip()
    secret = unquote(secret).strip()

    try:
        port_int = int(port)
    except ValueError:
        return None

    if not (1 <= port_int <= 65535):
        return None

    # We intentionally keep only public IPv4 addresses.
    try:
        ip = socket.inet_aton(server)
    except OSError:
        return None

    # inet_aton accepts some non-standard forms, so require
    # normal dotted IPv4 representation.
    parts = server.split(".")

    if len(parts) != 4:
        return None

    try:
        if any(not 0 <= int(part) <= 255 for part in parts):
            return None
    except ValueError:
        return None

    first, second = int(parts[0]), int(parts[1])

    # Private / reserved / local IPv4 ranges.
    private_or_reserved = (
        first == 10
        or first == 127
        or (first == 172 and 16 <= second <= 31)
        or (first == 192 and second == 168)
        or first == 0
        or first >= 224
    )

    if private_or_reserved:
        return None

    return f"tg://proxy?server={server}&port={port_int}&secret={secret}"


# ============================================================
# Download
# ============================================================

def download_source(url: str) -> str:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "MTProtoProxyCollector/1.0",
        },
    )

    with urllib.request.urlopen(
        request,
        timeout=REQUEST_TIMEOUT,
    ) as response:
        data = response.read()

    return data.decode("utf-8", errors="ignore")


# ============================================================
# Collection
# ============================================================

def collect_from_sources() -> set[str]:
    proxies: set[str] = set()

    for source in SOURCES:
        try:
            print(f"Downloading: {source}")

            text = download_source(source)

            matches = TG_PROXY_RE.findall(text)

            print(f"  Found links: {len(matches)}")

            for match in matches:
                normalized = normalize_proxy_url(match)

                if normalized:
                    proxies.add(normalized)

        except Exception as exc:
            print(f"  ERROR: {exc}")

    return proxies


# ============================================================
# Proxy parsing
# ============================================================

def parse_proxy(proxy: str):
    parsed = urlparse(proxy)

    query = parse_qs(parsed.query)

    server = query.get("server", [None])[0]
    port = query.get("port", [None])[0]

    if not server or not port:
        return None

    try:
        port = int(port)
    except ValueError:
        return None

    return server, port


# ============================================================
# TCP test
# ============================================================

def tcp_reachable(proxy: str) -> bool:
    parsed = parse_proxy(proxy)

    if not parsed:
        return False

    host, port = parsed

    try:
        with socket.create_connection(
            (host, port),
            timeout=TCP_TIMEOUT,
        ):
            return True

    except (OSError, TimeoutError):
        return False


def check_proxies(proxies: list[str]) -> list[str]:
    working = []

    total = len(proxies)

    print(
        f"Checking TCP connectivity for {total} proxies "
        f"using {MAX_WORKERS} workers..."
    )

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:

        futures = {
            executor.submit(tcp_reachable, proxy): proxy
            for proxy in proxies
        }

        completed = 0

        for future in as_completed(futures):
            proxy = futures[future]

            completed += 1

            try:
                if future.result():
                    working.append(proxy)
            except Exception:
                pass

            if completed % 50 == 0 or completed == total:
                print(
                    f"  Checked {completed}/{total}, "
                    f"reachable: {len(working)}"
                )

    return sorted(set(working))


# ============================================================
# Output
# ============================================================

def write_outputs(all_proxies: list[str], working: list[str]) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    ALL_FILE.write_text(
        "\n".join(all_proxies) + ("\n" if all_proxies else ""),
        encoding="utf-8",
    )

    WORKING_FILE.write_text(
        "\n".join(working) + ("\n" if working else ""),
        encoding="utf-8",
    )

    stats = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "discovered": len(all_proxies),
        "tcp_reachable": len(working),
        "note": (
            "TCP reachability only; not proof of a successful "
            "Telegram MTProto session."
        ),
    }

    STATS_FILE.write_text(
        json.dumps(stats, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    print()
    print("===== Statistics =====")
    print(json.dumps(stats, ensure_ascii=False))
    print("======================")
    print()


# ============================================================
# Main
# ============================================================

def main() -> None:
    print("Starting MTProto proxy collector...")
    print()

    proxies = collect_from_sources()

    print()
    print(f"Discovered {len(proxies)} distinct public links")

    if not proxies:
        print("No valid proxies discovered.")
        write_outputs([], [])
        return

    all_proxies = sorted(proxies)

    working = check_proxies(all_proxies)

    write_outputs(all_proxies, working)

    print(
        f"Finished: {len(all_proxies)} discovered, "
        f"{len(working)} TCP reachable."
    )


if __name__ == "__main__":
    main()
