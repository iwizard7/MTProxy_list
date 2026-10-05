import concurrent.futures
import json
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import requests


BASE_DIR = Path(__file__).resolve().parent.parent
PROXIES_DIR = BASE_DIR / "proxies"

ALL_FILE = PROXIES_DIR / "all.txt"
WORKING_FILE = PROXIES_DIR / "working.txt"
STATS_FILE = PROXIES_DIR / "stats.json"


SOURCES = [
    "https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/all_proxies.txt",
    "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
]

MAX_WORKERS = 20
SOURCE_TIMEOUT = 15
CHECK_TIMEOUT = 3


PROXY_PATTERN = re.compile(
    r"(?:tg://proxy|https://t\.me/proxy)\?[^\s\"'<>]+",
    re.IGNORECASE,
)


def fetch_source(url: str) -> str:
    response = requests.get(url, timeout=SOURCE_TIMEOUT)
    response.raise_for_status()
    return response.text


def normalize_proxy(url: str) -> str | None:
    url = url.strip().rstrip(".,);]}")

    if not (
        url.lower().startswith("tg://proxy?")
        or url.lower().startswith("https://t.me/proxy?")
    ):
        return None

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    server = params.get("server", [None])[0]
    port = params.get("port", [None])[0]
    secret = params.get("secret", [None])[0]

    if not server or not port or not secret:
        return None

    # Проверяем, что server — IPv4.
    ipv4_pattern = re.compile(
        r"^(?:\d{1,3}\.){3}\d{1,3}$"
    )

    if not ipv4_pattern.match(server):
        return None

    try:
        octets = [int(x) for x in server.split(".")]
        if any(x < 0 or x > 255 for x in octets):
            return None
    except ValueError:
        return None

    try:
        port_int = int(port)
        if not 1 <= port_int <= 65535:
            return None
    except ValueError:
        return None

    # Нормализуем в tg://proxy.
    return (
        f"tg://proxy?"
        f"server={server}"
        f"&port={port_int}"
        f"&secret={secret}"
    )


def collect_proxies() -> list[str]:
    found = set()

    for source in SOURCES:
        try:
            print(f"Fetching: {source}")

            text = fetch_source(source)

            for match in PROXY_PATTERN.findall(text):
                proxy = normalize_proxy(match)

                if proxy:
                    found.add(proxy)

            print(f"  Found so far: {len(found)}")

        except Exception as exc:
            print(f"  Source failed: {exc}")

    return sorted(found)


def check_proxy(proxy: str) -> tuple[str, float | None]:
    """
    Реальная проверка MTProto proxy.

    mtproxy-check выполняет:
      - TCP connection
      - MTProxy obfuscated2 handshake
      - MTProto req_pq_multi
      - проверку корректного Telegram resPQ

    Exit code 0 означает успешную проверку.
    """

    start = time.perf_counter()

    try:
        result = subprocess.run(
            [
                "mtproxy-check",
                "--url",
                proxy,
                "--connect-timeout",
                str(CHECK_TIMEOUT),
                "--response-timeout",
                str(CHECK_TIMEOUT),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=CHECK_TIMEOUT * 2 + 2,
            check=False,
        )

        latency_ms = round(
            (time.perf_counter() - start) * 1000,
            2,
        )

        if result.returncode == 0:
            return proxy, latency_ms

    except (
        subprocess.TimeoutExpired,
        FileNotFoundError,
        OSError,
    ):
        pass

    return proxy, None


def verify_proxies(proxies: list[str]) -> list[tuple[str, float]]:
    working = []

    print(f"Checking {len(proxies)} proxies with real MTProto handshake...")

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        futures = {
            executor.submit(check_proxy, proxy): proxy
            for proxy in proxies
        }

        completed = 0

        for future in concurrent.futures.as_completed(futures):
            proxy, latency = future.result()

            completed += 1

            if latency is not None:
                working.append((proxy, latency))

            if completed % 50 == 0 or completed == len(proxies):
                print(
                    f"Checked {completed}/{len(proxies)} "
                    f"— working: {len(working)}"
                )

    working.sort(key=lambda item: item[1])

    return working


def write_results(
    all_proxies: list[str],
    working: list[tuple[str, float]],
) -> None:

    PROXIES_DIR.mkdir(parents=True, exist_ok=True)

    ALL_FILE.write_text(
        "\n".join(all_proxies) + ("\n" if all_proxies else ""),
        encoding="utf-8",
    )

    WORKING_FILE.write_text(
        "\n".join(proxy for proxy, _ in working)
        + ("\n" if working else ""),
        encoding="utf-8",
    )

    latencies = [latency for _, latency in working]

    average_latency = (
        round(sum(latencies) / len(latencies), 2)
        if latencies
        else None
    )

    stats = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "discovered": len(all_proxies),
        "mtproto_verified": len(working),
        "average_latency_ms": average_latency,
        "check": "real MTProto relay health check",
        "verification": [
            "TCP connect",
            "MTProxy obfuscated2 handshake",
            "MTProto req_pq_multi",
            "valid Telegram resPQ response",
        ],
        "note": (
            "working.txt contains only proxies that passed "
            "the real MTProto health check."
        ),
    }

    STATS_FILE.write_text(
        json.dumps(stats, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    print("Collecting MTProto proxies...")

    all_proxies = collect_proxies()

    print(f"\nDiscovered {len(all_proxies)} distinct public proxies.")

    if not all_proxies:
        print("No proxies discovered.")

        write_results([], [])
        return

    working = verify_proxies(all_proxies)

    print(
        f"\nMTProto verification complete: "
        f"{len(working)}/{len(all_proxies)} working."
    )

    write_results(all_proxies, working)

    print(f"Saved: {ALL_FILE}")
    print(f"Saved: {WORKING_FILE}")
    print(f"Saved: {STATS_FILE}")


if __name__ == "__main__":
    main()
