#!/usr/bin/env python3
"""Collect and verify publicly advertised Telegram MTProto proxy links.

Design notes (see FIXES.md for the full rationale):

* Only explicitly published proxy links are read. Nothing is port-scanned:
  every checked endpoint comes from a source we were told to read.
* Only *publicly reachable* endpoints are checked. Host names are resolved
  first and rejected when any address is private, loopback, link-local or
  otherwise non-global (SSRF guard, protects the CI runner's metadata IP).
* Candidates are verified with a real MTProto health check (obfuscated2
  handshake + ``req_pq_multi`` + ``resPQ`` validation), in-process when the
  ``mtproxy_checker`` package is importable, otherwise through the
  ``mtproxy-check`` CLI.
* Published files are never overwritten with degraded data: if discovery or
  verification collapses, the run fails loudly and keeps the previous lists.

Exit codes: 0 = published, 2 = publish guard tripped (nothing published),
3 = configuration/usage error.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import os
import re
import socket
import statistics
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:  # requests is optional: the collector falls back to urllib.
    import requests
except ImportError:  # pragma: no cover - exercised only without requests
    requests = None  # type: ignore[assignment]

BASE_DIR = Path(__file__).resolve().parent.parent
PROXIES_DIR = BASE_DIR / "proxies"

ALL_FILE = PROXIES_DIR / "all.txt"
WORKING_FILE = PROXIES_DIR / "working.txt"
STABLE_FILE = PROXIES_DIR / "stable.txt"
BEST_FILE = PROXIES_DIR / "best.txt"
BADGE_FILE = PROXIES_DIR / "badge.json"
STATS_FILE = PROXIES_DIR / "stats.json"
STATE_FILE = PROXIES_DIR / "state.json"
ENDPOINTS_FILE = PROXIES_DIR / "endpoints.json"
ADS_FILE = PROXIES_DIR / "ads.json"

STATE_VERSION = 1

# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------
# Only lists that explicitly publish MTProto proxy links belong here. Add new
# sources via pull request and record their licence in FIXES.md / README.md.
#
# Measured on 2026-10-09 (see FIXES.md for the full inventory):
#   * ALIILAPRO/MTProtoProxy (MIT) and SoliSpirit/mtproto publish byte-identical
#     files, so only one of them is kept — the other would add nothing.
#   * Argh94/Proxy-List contributes 124 endpoints that the first source does not
#     have (295 distinct endpoints in total).
DEFAULT_SOURCES = [
    "https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/mtproto.txt",
    "https://raw.githubusercontent.com/Argh94/Proxy-List/main/MTProto.txt",
]

# Every source can also be overridden without editing code:
#   PROXY_SOURCES="https://a/list.txt,https://b/list.txt" python src/collector.py
SOURCES_ENV = "PROXY_SOURCES"

# Optional JSON sources that enrich endpoints with upstream metadata (latency,
# operator scores). They are never used to discover new proxies.
#
# Disabled by default on purpose: measured on 2026-10-09, the candidate source
# (ALIILAPRO/proxies.json, 16 endpoints) has *zero* overlap with our list
# sources, so it would cost a fetch per run and annotate nothing. The capability
# is kept and tested; enable it via PROXY_METADATA_SOURCES once a source that
# covers our endpoints exists.
DEFAULT_METADATA_SOURCES: list[str] = []
METADATA_SOURCES_ENV = "PROXY_METADATA_SOURCES"

PROXY_PATTERN = re.compile(
    r"(?i)(?:tg://proxy|https?://t\.me/proxy)\?[^\s\"'<>]+",
)

HEX_SECRET_RE = re.compile(r"[0-9a-fA-F]+")
B64_SECRET_RE = re.compile(r"[A-Za-z0-9_\-]+")
HOST_RE = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*"
)
PORT_RE = re.compile(r"[0-9]{1,5}")

TRAILING_JUNK = ".,);]}\"'"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ[name])
    except (KeyError, ValueError):
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ[name])
    except (KeyError, ValueError):
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Config:
    """Runtime configuration (environment-overridable)."""

    sources: list[str] = field(default_factory=lambda: list(DEFAULT_SOURCES))
    metadata_sources: list[str] = field(
        default_factory=lambda: list(DEFAULT_METADATA_SOURCES)
    )
    source_timeout: float = 15.0
    max_source_bytes: int = 5_000_000
    check_timeout: float = 3.0
    max_workers: int = 20
    # 0 disables the candidate cap (the cap protects against runaway sources).
    max_candidates: int = 400
    # Publish guard thresholds.
    min_discovered: int = 10
    min_keep_ratio: float = 0.25
    # An endpoint that passed within this window is preferred when capping.
    known_good_hours: float = 6.0
    # Endpoints verified within this window land in stable.txt.
    stable_ttl_hours: float = 24.0
    # How many of the most stable endpoints land in best.txt.
    best_count: int = 20
    # How many RTT samples / recent results are kept per endpoint.
    rtt_history: int = 10
    # Positive and negative DNS answers are reused for this long.
    dns_cache_hours: float = 6.0
    # Optional explicit Telegram DC list for the health check (empty = fast mode).
    dcs: tuple[int, ...] = ()
    # State retention.
    state_keep_days: float = 14.0
    state_max_entries: int = 20_000
    guard_dns: bool = True
    engine: str = "auto"  # auto | library | cli
    allow_degraded: bool = False
    user_agent: str = (
        "mtproxy-list-collector/2.0 "
        "(+https://github.com/iwizard7/MTProxy_list; public link validation)"
    )

    @classmethod
    def from_env(cls) -> "Config":
        raw_sources = os.environ.get(SOURCES_ENV, "")
        sources = [s.strip() for s in raw_sources.split(",") if s.strip()]
        raw_metadata = os.environ.get(METADATA_SOURCES_ENV, "")
        metadata_sources = [s.strip() for s in raw_metadata.split(",") if s.strip()]
        return cls(
            sources=sources or list(DEFAULT_SOURCES),
            metadata_sources=metadata_sources or list(DEFAULT_METADATA_SOURCES),
            source_timeout=_env_float("SOURCE_TIMEOUT", 15.0),
            max_source_bytes=_env_int("MAX_SOURCE_BYTES", 5_000_000),
            check_timeout=_env_float("CHECK_TIMEOUT", 3.0),
            max_workers=max(1, _env_int("MAX_WORKERS", 20)),
            max_candidates=_env_int("MAX_CANDIDATES", 400),
            min_discovered=_env_int("MIN_DISCOVERED", 10),
            min_keep_ratio=_env_float("MIN_KEEP_RATIO", 0.25),
            known_good_hours=_env_float("KNOWN_GOOD_HOURS", 6.0),
            stable_ttl_hours=_env_float("STABLE_TTL_HOURS", 24.0),
            best_count=max(0, _env_int("BEST_COUNT", 20)),
            rtt_history=max(2, _env_int("RTT_HISTORY", 10)),
            dns_cache_hours=_env_float("DNS_CACHE_HOURS", 6.0),
            dcs=parse_dcs(os.environ.get("CHECK_DCS", "")),
            state_keep_days=_env_float("STATE_KEEP_DAYS", 14.0),
            state_max_entries=_env_int("STATE_MAX_ENTRIES", 20_000),
            guard_dns=_env_bool("GUARD_DNS", True),
            engine=os.environ.get("CHECK_ENGINE", "auto").strip().lower(),
            allow_degraded=_env_bool("ALLOW_DEGRADED", False),
        )


def parse_dcs(raw: str) -> tuple[int, ...]:
    """Parse ``CHECK_DCS="2,4"`` into a tuple of valid Telegram DC ids."""
    values = []
    for part in (raw or "").replace(";", ",").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            value = int(part)
        except ValueError:
            continue
        if 1 <= value <= 5:
            values.append(value)
    return tuple(sorted(set(values)))


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Proxy:
    """A single normalized MTProto proxy link."""

    url: str
    server: str
    port: int
    secret: str

    @property
    def endpoint(self) -> str:
        return endpoint_key(self.server, self.port)

    def as_dict(self) -> dict:
        return {
            "url": self.url,
            "server": self.server,
            "port": self.port,
            "secret": self.secret,
            "endpoint": self.endpoint,
        }


def endpoint_key(server: str, port: int) -> str:
    """Return a canonical ``host:port`` key (IPv6 hosts in brackets)."""
    host = f"[{server}]" if ":" in server else server
    return f"{host}:{port}"


def parse_ip_literal(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def canonical_host(server: str) -> str | None:
    """Normalize a host.

    Accepts IPv4/IPv6 literals and host names (trailing root dot removed).
    Rejects anything that is not a plausible host, and never consults DNS.
    """
    host = (server or "").strip()
    if not host or len(host) > 253:
        return None

    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]

    literal = parse_ip_literal(host)
    if literal is not None:
        return literal.compressed

    host = host.rstrip(".").lower()
    if not host or len(host) > 253:
        return None
    if not HOST_RE.fullmatch(host):
        return None
    return host


def canonical_port(raw: str) -> int | None:
    text = (raw or "").strip()
    if not PORT_RE.fullmatch(text):
        return None
    port = int(text)
    return port if 1 <= port <= 65535 else None


def canonical_secret(secret: str) -> str | None:
    """Validate an MTProxy secret.

    Accepts hex (>= 32 chars, i.e. a 16-byte secret, optionally with the
    ``dd``/``ee`` prefix) and base64url (>= 22 chars, the encoding of the same
    16 bytes) as published by real lists. Everything else is rejected instead
    of being published as a broken link.
    """
    text = (secret or "").strip().rstrip("=")
    if len(text) > 256:
        return None
    if HEX_SECRET_RE.fullmatch(text):
        if len(text) % 2 or len(text) < 32:
            return None
        return text.lower()
    if B64_SECRET_RE.fullmatch(text):
        if len(text) < 22:
            return None
        return text
    return None


def build_url(server: str, port: int, secret: str) -> str:
    host = f"[{server}]" if ":" in server else server
    return f"tg://proxy?server={host}&port={port}&secret={secret}"


def parse_proxy(raw: str) -> tuple[Proxy | None, str]:
    """Parse one raw link. Returns ``(proxy, reason)``.

    ``reason`` is a short machine-readable rejection code when no proxy is
    returned, which lets ``--dry-run`` and stats.json explain data loss.
    """
    url = raw.strip().rstrip(TRAILING_JUNK)
    lowered = url.lower()
    if not (
        lowered.startswith("tg://proxy?")
        or lowered.startswith("https://t.me/proxy?")
        or lowered.startswith("http://t.me/proxy?")
    ):
        return None, "not_a_proxy_link"

    params = parse_qs(urlparse(url).query, keep_blank_values=False)
    server = (params.get("server") or [""])[0]
    port_raw = (params.get("port") or [""])[0]
    secret_raw = (params.get("secret") or [""])[0]

    if not server or not port_raw or not secret_raw:
        return None, "missing_parameter"

    host = canonical_host(server)
    if host is None:
        return None, "bad_host"

    port = canonical_port(port_raw)
    if port is None:
        return None, "bad_port"

    secret = canonical_secret(secret_raw)
    if secret is None:
        return None, "bad_secret"

    return Proxy(build_url(host, port, secret), host, port, secret), "ok"


def normalize_proxy(raw: str) -> Proxy | None:
    """Backwards-compatible wrapper returning only the parsed proxy."""
    proxy, _ = parse_proxy(raw)
    return proxy


def extract_links(text: str) -> list[str]:
    """Extract proxy links in document order (deterministic dedup later)."""
    return [m.group(0) for m in PROXY_PATTERN.finditer(text)]


# ---------------------------------------------------------------------------
# Source fetching
# ---------------------------------------------------------------------------
def fetch_source(url: str, cfg: Config) -> tuple[str, str, int]:
    """Fetch a source. Returns ``(text, error, size)`` (``text == ""`` on error).

    Bodies are capped at ``cfg.max_source_bytes`` so that a hostile or broken
    source cannot exhaust the runner's memory.
    """
    if requests is not None:
        try:
            response = requests.get(
                url,
                timeout=cfg.source_timeout,
                headers={"User-Agent": cfg.user_agent},
                stream=True,
            )
            response.raise_for_status()
            chunks: list[bytes] = []
            size = 0
            for chunk in response.iter_content(65536):
                if not chunk:
                    continue
                size += len(chunk)
                chunks.append(chunk)
                if size >= cfg.max_source_bytes:
                    break
            return b"".join(chunks).decode("utf-8", "replace"), "", size
        except Exception as exc:  # requests raises a wide family of errors
            return "", f"{type(exc).__name__}: {exc}", 0

    try:
        request = Request(url, headers={"User-Agent": cfg.user_agent})
        with urlopen(request, timeout=cfg.source_timeout) as response:  # noqa: S310
            data = response.read(cfg.max_source_bytes)
        return data.decode("utf-8", "replace"), "", len(data)
    except (HTTPError, URLError, OSError, ValueError) as exc:
        return "", f"{type(exc).__name__}: {exc}", 0


def collect(
    cfg: Config,
) -> tuple[list[Proxy], list[dict], dict[str, list[str]], dict[str, int], dict[str, list[str]]]:
    """Fetch every source and return candidates plus per-source health.

    Returns ``(candidates, source_stats, sources_by_endpoint, rejections,
    duplicate_urls)`` where ``duplicate_urls`` maps an endpoint to the extra
    links that advertise it (same host:port, different secret).
    """
    seen: dict[str, Proxy] = {}
    source_stats: list[dict] = []
    sources_by_endpoint: dict[str, list[str]] = {}
    rejections: dict[str, int] = {}
    duplicate_urls: dict[str, list[str]] = {}

    for url in cfg.sources:
        text, error, size = fetch_source(url, cfg)
        links = extract_links(text) if text else []
        accepted = 0
        duplicates = 0
        new_endpoints = 0

        for raw in links:
            proxy, reason = parse_proxy(raw)
            if proxy is None:
                rejections[reason] = rejections.get(reason, 0) + 1
                continue
            accepted += 1
            if proxy.endpoint in seen:
                duplicates += 1
                existing = seen[proxy.endpoint]
                bucket = duplicate_urls.setdefault(proxy.endpoint, [])
                if proxy.url != existing.url and proxy.url not in bucket:
                    bucket.append(proxy.url)
                sources_by_endpoint.setdefault(proxy.endpoint, []).append(url)
                continue
            seen[proxy.endpoint] = proxy
            sources_by_endpoint[proxy.endpoint] = [url]
            new_endpoints += 1

        source_stats.append(
            {
                "url": url,
                "ok": not error,
                "bytes": size,
                "links_found": len(links),
                "links_accepted": accepted,
                "endpoints_new": new_endpoints,
                "duplicate_endpoints": duplicates,
                "error": error or None,
            }
        )
        status = "ok" if not error else f"FAILED ({error})"
        print(f"  {url}: {status}, {len(links)} links, {accepted} valid")

    candidates = sorted(seen.values(), key=lambda p: p.endpoint)
    return candidates, source_stats, sources_by_endpoint, rejections, duplicate_urls


def fetch_metadata(cfg: Config) -> tuple[dict[str, dict], list[dict]]:
    """Fetch optional JSON metadata sources.

    These sources never add proxies — they only annotate endpoints that are
    already published by a list source. The recognised shape is a JSON array of
    ``{"host", "port", "latency", "operator": {...}}`` (as published by
    ALIILAPRO/proxies.json). The unit of ``latency`` is upstream-defined, so it
    is stored as-is under ``upstream`` and never mixed with our own ``rtt_ms``.
    """
    metadata: dict[str, dict] = {}
    source_stats: list[dict] = []

    for url in cfg.metadata_sources:
        text, error, size = fetch_source(url, cfg)
        entries = 0

        if text and not error:
            try:
                payload = json.loads(text)
            except ValueError as exc:
                payload = None
                error = f"invalid_json: {exc}"
            if payload is not None and not isinstance(payload, list):
                error = "unexpected_shape: expected a JSON array"

            if isinstance(payload, list):
                for item in payload:
                    if not isinstance(item, dict):
                        continue
                    host = canonical_host(str(item.get("host", "")))
                    port = canonical_port(str(item.get("port", "")))
                    if host is None or port is None:
                        continue
                    key = endpoint_key(host, port)
                    record = metadata.setdefault(key, {"sources": []})
                    latency = item.get("latency")
                    if isinstance(latency, (int, float)) and not isinstance(latency, bool):
                        record["latency"] = latency
                    operators = item.get("operator")
                    if isinstance(operators, dict):
                        record["operators"] = {
                            str(name): value
                            for name, value in operators.items()
                            if isinstance(value, (int, float)) and not isinstance(value, bool)
                        }
                    if url not in record["sources"]:
                        record["sources"].append(url)
                    entries += 1

        source_stats.append(
            {
                "url": url,
                "ok": not error,
                "bytes": size,
                "entries": entries,
                "error": error or None,
            }
        )
        status = "ok" if not error else f"FAILED ({error})"
        print(f"  {url}: {status}, {entries} metadata entries")

    return metadata, source_stats


# ---------------------------------------------------------------------------
# Public-address guard (SSRF protection)
# ---------------------------------------------------------------------------
def is_public_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(address.is_global)


def resolve_addresses(
    host: str, resolver=None
) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve a host to addresses (IP literals are returned as-is)."""
    literal = parse_ip_literal(host)
    if literal is not None:
        return [literal]

    resolver = resolver or socket.getaddrinfo
    try:
        infos = resolver(host, None, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return []
    addresses = []
    for info in infos:
        try:
            addresses.append(ipaddress.ip_address(info[4][0]))
        except (ValueError, IndexError):
            continue
    return addresses


def is_public_target(
    host: str, resolver=None, cache: "DnsCache | None" = None, now: datetime | None = None
) -> tuple[bool, str]:
    """Return ``(allowed, reason)`` for a candidate host.

    A host name is only allowed when *all* of its addresses are global, which
    blocks DNS-based pivots to loopback, RFC1918 space and the cloud metadata
    endpoint 169.254.169.254. When a ``cache`` is supplied, answers (including
    negative ones) are reused for ``cache.ttl`` so that a run with hundreds of
    dead host names does not pay for the same lookups twice.
    """
    if cache is not None:
        addresses = cache.get(host, resolver=resolver, now=now or datetime.now(timezone.utc))
    else:
        addresses = resolve_addresses(host, resolver=resolver)
    if not addresses:
        return False, "dns_no_addresses"
    if any(not is_public_ip(address) for address in addresses):
        return False, "non_public_address"
    return True, "ok"


class DnsCache:
    """Small, thread-safe, persistent DNS answer cache.

    Stored inside ``proxies/state.json`` under ``dns`` and reused between runs.
    A short TTL bounds the (accepted) risk of trusting a stale "this host is
    public" verdict.
    """

    def __init__(
        self,
        data: dict | None = None,
        ttl_hours: float = 6.0,
        keep_days: float = 14.0,
    ) -> None:
        self._data: dict = data if isinstance(data, dict) else {}
        self.ttl = timedelta(hours=max(0.0, ttl_hours))
        self.keep = timedelta(days=max(0.0, keep_days))
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def get(self, host: str, resolver=None, now: datetime | None = None) -> list:
        """Return addresses for ``host``, resolving and caching when needed."""
        literal = parse_ip_literal(host)
        if literal is not None:
            return [literal]

        now = now or datetime.now(timezone.utc)
        with self._lock:
            entry = self._data.get(host)
            if isinstance(entry, dict):
                resolved_at = _parse_timestamp(entry.get("resolved_at"))
                if resolved_at is not None and now - resolved_at <= self.ttl:
                    self.hits += 1
                    return [
                        ipaddress.ip_address(value)
                        for value in entry.get("addresses", [])
                        if _is_ip(value)
                    ]

        addresses = resolve_addresses(host, resolver=resolver)

        with self._lock:
            self.misses += 1
            self._data[host] = {
                "addresses": [address.compressed for address in addresses],
                "resolved_at": now.isoformat(),
            }
        return addresses

    def as_dict(self, now: datetime | None = None) -> dict:
        """Serializable snapshot, pruned of entries older than ``keep``."""
        now = now or datetime.now(timezone.utc)
        with self._lock:
            pruned = {}
            for host, entry in self._data.items():
                resolved_at = _parse_timestamp(
                    entry.get("resolved_at") if isinstance(entry, dict) else None
                )
                if resolved_at is None or now - resolved_at > self.keep:
                    continue
                pruned[host] = entry
            self._data = pruned
            return dict(pruned)

    def stats(self) -> dict:
        return {
            "hosts": len(self._data),
            "hits": self.hits,
            "misses": self.misses,
            "ttl_hours": round(self.ttl.total_seconds() / 3600, 2),
        }


def _is_ip(value) -> bool:
    try:
        ipaddress.ip_address(value)
    except (ValueError, TypeError):
        return False
    return True


# ---------------------------------------------------------------------------
# Candidate selection
# ---------------------------------------------------------------------------
def spread_sample(items: list, limit: int, rotation: int = 0) -> list:
    """Deterministically sample ``limit`` items spread across the whole list.

    Truncation (``items[:limit]``) permanently starves everything past the
    cut; spreading plus a rotating offset gives every candidate a turn.
    """
    if limit <= 0 or len(items) <= limit:
        return list(items)
    if rotation:
        offset = rotation % len(items)
        items = items[offset:] + items[:offset]

    step = len(items) / limit
    picked = []
    seen_indexes: set[int] = set()
    for i in range(limit):
        index = int(i * step)
        if index not in seen_indexes:
            seen_indexes.add(index)
            picked.append(items[index])
    return picked


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def recently_ok(state: dict, endpoint: str, hours: float, now: datetime) -> bool:
    entry = (state.get("endpoints") or {}).get(endpoint)
    if not entry:
        return False
    last_ok = _parse_timestamp(entry.get("last_ok"))
    if last_ok is None:
        return False
    return last_ok >= now - timedelta(hours=hours)


def select_candidates(
    candidates: list[Proxy], state: dict, cfg: Config, now: datetime
) -> list[Proxy]:
    """Pick which candidates to check, preferring recently working endpoints.

    Half of the budget goes to endpoints that worked recently (so the
    published list stays useful), the rest is spread over the remaining pool
    with a per-run rotation, so unattempted proxies eventually get checked.
    """
    limit = cfg.max_candidates
    if limit <= 0 or len(candidates) <= limit:
        return list(candidates)

    known = [
        p for p in candidates if recently_ok(state, p.endpoint, cfg.known_good_hours, now)
    ]
    known_keys = {p.endpoint for p in known}
    unknown = [p for p in candidates if p.endpoint not in known_keys]

    known_budget = min(len(known), max(1, limit // 2))
    picked = spread_sample(known, known_budget) if known else []
    remaining = limit - len(picked)
    if remaining > 0:
        picked.extend(spread_sample(unknown, remaining, rotation=state.get("runs", 0)))

    return picked


def dedupe_by_endpoint(
    candidates: list[Proxy], preferred_urls: dict[str, str] | None = None
) -> tuple[list[Proxy], dict[str, list[str]]]:
    """Keep one link per endpoint; record the alternates.

    Several secrets can be advertised for the same host:port. Checking all of
    them multiplies work for the same endpoint and makes the published list
    flap between equivalent links.
    """
    preferred_urls = preferred_urls or {}
    chosen: dict[str, Proxy] = {}
    alternates: dict[str, list[str]] = {}

    for proxy in candidates:
        current = chosen.get(proxy.endpoint)
        if current is None:
            chosen[proxy.endpoint] = proxy
            continue
        alternates.setdefault(proxy.endpoint, []).append(proxy.url)
        preferred = preferred_urls.get(proxy.endpoint)
        if preferred and current.url != preferred and proxy.url == preferred:
            alternates[proxy.endpoint].append(current.url)
            chosen[proxy.endpoint] = proxy

    ordered = [chosen[key] for key in sorted(chosen)]
    return ordered, alternates


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
@dataclass
class Outcome:
    endpoint: str
    ok: bool
    rtt_ms: float | None = None
    duration_ms: float | None = None
    engine: str = ""
    error: str | None = None


_LIBRARY: tuple | None = None
_LIBRARY_ERROR: str | None = None


def _load_library():
    """Import ``mtproxy_checker`` once, if available."""
    global _LIBRARY, _LIBRARY_ERROR
    if _LIBRARY is not None or _LIBRARY_ERROR is not None:
        return _LIBRARY
    try:
        from mtproxy_checker import CheckOptions, check_proxy as lib_check

        _LIBRARY = (lib_check, CheckOptions)
    except Exception as exc:  # pragma: no cover - depends on the environment
        _LIBRARY_ERROR = f"{type(exc).__name__}: {exc}"
        _LIBRARY = None
    return _LIBRARY


def check_with_library(proxy: Proxy, cfg: Config) -> Outcome | None:
    """In-process check via the ``mtproxy_checker`` Python API.

    Returns ``None`` when the package is unavailable so the caller can fall
    back to the CLI. This path avoids one Python interpreter per proxy and
    yields a real protocol round-trip time (``rtt_ms``).
    """
    library = _load_library()
    if library is None:
        return None
    lib_check, check_options = library

    started = time.perf_counter()
    try:
        options = check_options(
            connect_timeout=cfg.check_timeout,
            response_timeout=cfg.check_timeout,
        )
        if cfg.dcs:
            # Explicit DC list (CHECK_DCS="2,4"): a proxy may relay to some
            # Telegram DCs only, which is what callers in other regions see.
            options = check_options(
                connect_timeout=cfg.check_timeout,
                response_timeout=cfg.check_timeout,
                dcs=tuple(cfg.dcs),
            )
        result = lib_check(proxy.url, options)
    except Exception as exc:  # pragma: no cover - defensive
        return Outcome(
            endpoint=proxy.endpoint,
            ok=False,
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
            engine="library",
            error=f"{type(exc).__name__}: {exc}",
        )

    duration_ms = round((time.perf_counter() - started) * 1000, 2)
    if result.ok:
        return Outcome(
            endpoint=proxy.endpoint,
            ok=True,
            rtt_ms=round(result.rtt_ms, 2) if result.rtt_ms is not None else None,
            duration_ms=duration_ms,
            engine="library",
        )

    error_code = getattr(result.error_code, "value", result.error_code)
    return Outcome(
        endpoint=proxy.endpoint,
        ok=False,
        duration_ms=duration_ms,
        engine="library",
        error=str(error_code or result.error_message or "check_failed"),
    )


def check_with_cli(proxy: Proxy, cfg: Config) -> Outcome:
    """Fallback check through the ``mtproxy-check`` console script."""
    started = time.perf_counter()
    try:
        result = subprocess.run(
            [
                "mtproxy-check",
                "--url",
                proxy.url,
                "--connect-timeout",
                str(cfg.check_timeout),
                "--response-timeout",
                str(cfg.check_timeout),
            ]
            + (["--dcs", ",".join(str(dc) for dc in cfg.dcs)] if cfg.dcs else []),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=cfg.check_timeout * 2 + 2,
            check=False,
        )
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        if result.returncode == 0:
            # NOTE: this is wall time of a whole subprocess, not a network RTT.
            return Outcome(
                endpoint=proxy.endpoint,
                ok=True,
                duration_ms=duration_ms,
                engine="cli",
            )
        return Outcome(
            endpoint=proxy.endpoint,
            ok=False,
            duration_ms=duration_ms,
            engine="cli",
            error=f"exit_code_{result.returncode}",
        )
    except subprocess.TimeoutExpired:
        return Outcome(proxy.endpoint, False, engine="cli", error="timeout")
    except (FileNotFoundError, OSError) as exc:
        return Outcome(
            proxy.endpoint, False, engine="cli", error=f"{type(exc).__name__}: {exc}"
        )


def check_proxy(proxy: Proxy, cfg: Config) -> Outcome:
    """Run the strongest available check for one proxy."""
    if cfg.engine in ("auto", "library"):
        outcome = check_with_library(proxy, cfg)
        if outcome is not None:
            return outcome
        if cfg.engine == "library":
            return Outcome(
                proxy.endpoint,
                False,
                engine="library",
                error=f"library_unavailable: {_LIBRARY_ERROR}",
            )
    return check_with_cli(proxy, cfg)


def verify(
    candidates: list[Proxy],
    cfg: Config,
    resolver=None,
    dns_cache: "DnsCache | None" = None,
) -> tuple[list[tuple[Proxy, Outcome]], list[tuple[Proxy, str]]]:
    """Check every candidate. Returns ``(outcomes, blocked)``.

    The public-address guard runs *inside* the worker pool: DNS resolution has
    no timeout in the standard library, so resolving sequentially could stall a
    run with many dead host names. With the guard in the pool the wall clock is
    bounded by ``max_workers`` instead of by the sum of all lookups, and a
    blocked address is never connected to. Successful and failed lookups are
    cached on disk between runs (``DnsCache``).
    """
    outcomes: list[tuple[Proxy, Outcome]] = []
    blocked: list[tuple[Proxy, str]] = []

    if not candidates:
        return outcomes, blocked

    def guarded_check(proxy: Proxy):
        if cfg.guard_dns:
            allowed, reason = is_public_target(proxy.server, resolver=resolver, cache=dns_cache)
            if not allowed:
                return proxy, None, reason
        return proxy, check_proxy(proxy, cfg), None

    print(f"Checking {len(candidates)} proxies with a real MTProto handshake...")
    completed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=cfg.max_workers) as executor:
        futures = {
            executor.submit(guarded_check, proxy): proxy for proxy in candidates
        }
        for future in concurrent.futures.as_completed(futures):
            proxy = futures[future]
            try:
                proxy, outcome, block_reason = future.result()
            except Exception as exc:  # pragma: no cover - defensive
                outcome = Outcome(
                    proxy.endpoint, False, error=f"{type(exc).__name__}: {exc}"
                )
                block_reason = None
            if outcome is None:
                blocked.append((proxy, block_reason or "non_public_address"))
            else:
                outcomes.append((proxy, outcome))
            completed += 1
            if completed % 25 == 0 or completed == len(candidates):
                working = sum(1 for _, item in outcomes if item.ok)
                print(
                    f"  processed {completed}/{len(candidates)} — "
                    f"working: {working}, skipped: {len(blocked)}"
                )

    outcomes.sort(key=lambda item: (not item[1].ok, item[0].endpoint))
    blocked.sort(key=lambda item: item[0].endpoint)
    return outcomes, blocked


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
def load_state(path: Path) -> dict:
    """Load state.json, tolerating a missing or corrupted file."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"version": STATE_VERSION, "runs": 0, "endpoints": {}}
    if not isinstance(data, dict) or "endpoints" not in data:
        return {"version": STATE_VERSION, "runs": 0, "endpoints": {}}
    data.setdefault("version", STATE_VERSION)
    data.setdefault("runs", 0)
    if not isinstance(data["endpoints"], dict):
        data["endpoints"] = {}
    return data


def update_state(
    state: dict,
    candidates: list[Proxy],
    outcomes: list[tuple[Proxy, Outcome]],
    sources_by_endpoint: dict[str, list[str]],
    now: datetime,
    keep_days: float = 14.0,
    max_entries: int = 20_000,
    history: int = 10,
) -> None:
    entries = state.setdefault("endpoints", {})
    stamp = now.isoformat()
    outcome_by_endpoint = {proxy.endpoint: outcome for proxy, outcome in outcomes}

    for proxy in candidates:
        entry = entries.get(proxy.endpoint)
        if entry is None:
            entry = {
                "url": proxy.url,
                "server": proxy.server,
                "port": proxy.port,
                "secret": proxy.secret,
                "first_seen": stamp,
                "last_seen": stamp,
                "last_ok": None,
                "ok_count": 0,
                "fail_count": 0,
                "last_rtt_ms": None,
                "rtt_samples": [],
                "recent": [],
                "sources": [],
            }
            entries[proxy.endpoint] = entry

        entry["url"] = proxy.url
        entry["server"] = proxy.server
        entry["port"] = proxy.port
        entry["secret"] = proxy.secret
        entry["last_seen"] = stamp

        known_sources = entry.setdefault("sources", [])
        for source in sources_by_endpoint.get(proxy.endpoint, []):
            if source not in known_sources:
                known_sources.append(source)

        outcome = outcome_by_endpoint.get(proxy.endpoint)
        if outcome is None:
            continue
        if outcome.ok:
            entry["last_ok"] = stamp
            entry["ok_count"] = int(entry.get("ok_count", 0)) + 1
            entry["last_rtt_ms"] = outcome.rtt_ms
            entry["last_engine"] = outcome.engine
            entry["last_error"] = None
        else:
            entry["fail_count"] = int(entry.get("fail_count", 0)) + 1
            entry["last_error"] = outcome.error

        # Rolling history: used for median RTT, success rate and trend.
        entry["recent"] = (list(entry.get("recent") or []) + [outcome.ok])[-history:]
        samples = list(entry.get("rtt_samples") or [])
        if outcome.ok and outcome.rtt_ms is not None:
            samples.append(outcome.rtt_ms)
        entry["rtt_samples"] = samples[-history:]

    state["runs"] = int(state.get("runs", 0)) + 1
    state["updated_at"] = stamp
    prune_state(state, now=now, keep_days=keep_days, max_entries=max_entries)


def prune_state(state: dict, now: datetime, keep_days: float, max_entries: int = 20_000) -> None:
    entries = state.get("endpoints") or {}
    cutoff = now - timedelta(days=keep_days)
    for endpoint in list(entries):
        entry = entries.get(endpoint) or {}
        last_seen = _parse_timestamp(entry.get("last_seen")) or _parse_timestamp(
            entry.get("last_ok")
        )
        if last_seen is None or last_seen < cutoff:
            entries.pop(endpoint, None)

    if len(entries) > max_entries:
        ordered = sorted(
            entries.items(),
            key=lambda item: item[1].get("last_seen") or "",
            reverse=True,
        )
        state["endpoints"] = dict(ordered[:max_entries])


def median(values: list[float]) -> float | None:
    """Median of a numeric list (``None`` when empty)."""
    clean = [float(v) for v in values if isinstance(v, (int, float))]
    if not clean:
        return None
    return round(statistics.median(clean), 2)


def entry_metrics(entry: dict) -> dict:
    """Derive stability metrics from a state entry.

    ``median_rtt_ms`` is far more useful than the last sample (which can be a
    fluke), ``success_rate`` counts the rolling window of the last checks, and
    ``rtt_trend`` compares the newer half of the samples with the older half.
    """
    recent = [bool(value) for value in (entry.get("recent") or [])]
    samples = [float(v) for v in (entry.get("rtt_samples") or []) if isinstance(v, (int, float))]

    success_rate = round(sum(1 for value in recent if value) / len(recent), 3) if recent else None
    median_rtt = median(samples)

    trend = "unknown"
    if len(samples) >= 4:
        half = len(samples) // 2
        older = median(samples[:half])
        newer = median(samples[half:])
        if older and newer:
            delta = (newer - older) / older
            if delta < -0.15:
                trend = "improving"
            elif delta > 0.15:
                trend = "degrading"
            else:
                trend = "stable"

    return {
        "median_rtt_ms": median_rtt,
        "success_rate": success_rate,
        "rtt_trend": trend,
        "samples": len(samples),
        "last_rtt_ms": entry.get("last_rtt_ms"),
    }


def stability_sort_key(item: dict) -> tuple:
    """Best first: high success rate, low median RTT, fresher wins ties."""
    success = item.get("success_rate")
    median_rtt = item.get("median_rtt_ms")
    return (
        -(success if success is not None else 0.0),
        1 if median_rtt is None else 0,
        median_rtt if median_rtt is not None else 0.0,
        item.get("last_ok") or "",
    )


def stable_entries(
    state: dict, ttl_hours: float, now: datetime
) -> list[dict]:
    """Endpoints that passed a check within the TTL window, best first."""
    cutoff = now - timedelta(hours=ttl_hours)
    result = []
    for endpoint, entry in (state.get("endpoints") or {}).items():
        last_ok = _parse_timestamp(entry.get("last_ok"))
        if last_ok is None or last_ok < cutoff:
            continue
        if not entry.get("url"):
            continue
        result.append(
            {
                "endpoint": endpoint,
                "url": entry.get("url"),
                "last_ok": entry.get("last_ok"),
                **entry_metrics(entry),
            }
        )
    result.sort(key=stability_sort_key)
    return result


def best_entries(stable: list[dict], limit: int) -> list[dict]:
    """Top-N most stable endpoints (already sorted by :func:`stable_entries`)."""
    if limit <= 0:
        return []
    return stable[:limit]


def update_source_history(
    state: dict,
    source_stats: list[dict],
    metadata_stats: list[dict],
    now: datetime,
) -> dict:
    """Track how much each source contributes over time (last run + totals)."""
    history = state.setdefault("sources", {})
    stamp = now.isoformat()

    for item in source_stats:
        record = history.setdefault(item["url"], {"kind": "list"})
        record["kind"] = "list"
        record["runs"] = int(record.get("runs", 0)) + 1
        record["last_run"] = stamp
        record["last_ok"] = stamp if item["ok"] else record.get("last_ok")
        record["last_error"] = item["error"]
        record["last_links_found"] = item.get("links_found", 0)
        record["last_links_accepted"] = item.get("links_accepted", 0)
        record["last_new_endpoints"] = item.get("endpoints_new", 0)
        record["total_new_endpoints"] = int(record.get("total_new_endpoints", 0)) + int(
            item.get("endpoints_new", 0)
        )
        record["total_links_accepted"] = int(record.get("total_links_accepted", 0)) + int(
            item.get("links_accepted", 0)
        )
        if item["ok"]:
            record["ok_runs"] = int(record.get("ok_runs", 0)) + 1

    for item in metadata_stats:
        record = history.setdefault(item["url"], {"kind": "metadata"})
        record["kind"] = "metadata"
        record["runs"] = int(record.get("runs", 0)) + 1
        record["last_run"] = stamp
        record["last_ok"] = stamp if item["ok"] else record.get("last_ok")
        record["last_error"] = item["error"]
        record["last_entries"] = item.get("entries", 0)
        record["total_entries"] = int(record.get("total_entries", 0)) + int(
            item.get("entries", 0)
        )

    return history


# ---------------------------------------------------------------------------
# Ads metadata (produced by src/adcheck.py, optional)
# ---------------------------------------------------------------------------
def load_ads(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    results = data.get("results")
    return results if isinstance(results, dict) else {}


def ads_for(ads: dict, endpoint: str) -> dict:
    entry = ads.get(endpoint)
    if not isinstance(entry, dict):
        return {"status": "unknown", "channel": None, "checked_at": None}
    if entry.get("has_ads") is True:
        status = "present"
    elif entry.get("has_ads") is False:
        status = "none"
    else:
        status = "unknown"
    return {
        "status": status,
        "channel": entry.get("channel"),
        "checked_at": entry.get("checked_at"),
    }


# ---------------------------------------------------------------------------
# Publish guard
# ---------------------------------------------------------------------------
def evaluate_guard(
    discovered: int,
    verified: int,
    previous_working: int,
    sources_ok: int,
    cfg: Config,
) -> tuple[bool, list[str]]:
    """Decide whether this run may overwrite the published lists.

    The previous version of this script happily published (and committed)
    empty files when every source failed. This guard keeps the last known
    good lists instead.
    """
    reasons: list[str] = []
    if sources_ok <= 0:
        reasons.append("all_sources_failed")
    if discovered <= 0:
        reasons.append("nothing_discovered")
    elif discovered < cfg.min_discovered:
        reasons.append(
            f"too_few_discovered:{discovered}<{cfg.min_discovered}"
        )
    if discovered > 0 and verified <= 0:
        reasons.append("nothing_verified")
    if previous_working >= 5 and verified < previous_working * cfg.min_keep_ratio:
        reasons.append(
            f"verified_drop:{verified}<{cfg.min_keep_ratio:.2f}*{previous_working}"
        )

    if cfg.allow_degraded:
        return True, reasons
    return (not reasons), reasons


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def _write_lines(path: Path, lines: list[str]) -> None:
    path.write_text(
        "\n".join(lines) + ("\n" if lines else ""),
        encoding="utf-8",
    )


def _average(values: list[float]) -> float | None:
    values = [v for v in values if v is not None]
    return round(sum(values) / len(values), 2) if values else None


def badge_payload(verified: int, stable_in_window: int, now: datetime) -> dict:
    """shields.io endpoint badge (see README).

    ``proxies/badge.json`` is committed with the rest, so the badge in the
    README reflects the last successful run without any extra service.
    """
    if verified >= 20:
        color = "brightgreen"
    elif verified >= 5:
        color = "yellow"
    elif verified > 0:
        color = "orange"
    else:
        color = "red"
    return {
        "schemaVersion": 1,
        "label": "verified proxies",
        "message": f"{verified} now · {stable_in_window} in 24h",
        "color": color,
        "cacheSeconds": 1800,
    }


def write_published(
    candidates: list[Proxy],
    outcomes: list[tuple[Proxy, Outcome]],
    stable: list[dict],
    best: list[dict],
    ads: dict,
    metadata: dict[str, dict],
    state: dict,
    now: datetime,
) -> None:
    PROXIES_DIR.mkdir(parents=True, exist_ok=True)

    working = [(proxy, outcome) for proxy, outcome in outcomes if outcome.ok]
    working.sort(key=lambda item: (item[1].rtt_ms is None, item[1].rtt_ms or 0, item[0].endpoint))

    _write_lines(ALL_FILE, [proxy.url for proxy in candidates])
    _write_lines(WORKING_FILE, [proxy.url for proxy, _ in working])
    _write_lines(STABLE_FILE, [item["url"] for item in stable])
    _write_lines(BEST_FILE, [item["url"] for item in best])

    endpoints = []
    for proxy, outcome in outcomes:
        entry = (state.get("endpoints") or {}).get(proxy.endpoint) or {}
        record = {
            **proxy.as_dict(),
            "verified": outcome.ok,
            "check_ms": outcome.duration_ms,
            "rtt_ms": outcome.rtt_ms,
            "engine": outcome.engine,
            "error": outcome.error,
            **{
                key: value
                for key, value in entry_metrics(entry).items()
                if key != "last_rtt_ms"
            },
            "ads": ads_for(ads, proxy.endpoint),
        }
        upstream = metadata.get(proxy.endpoint)
        if upstream:
            record["upstream"] = upstream
        endpoints.append(record)

    ENDPOINTS_FILE.write_text(
        json.dumps(
            {
                "updated_at": now.isoformat(),
                "count": len(endpoints),
                "verified": sum(1 for _, outcome in outcomes if outcome.ok),
                "endpoints": endpoints,
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )


def write_badge(payload: dict) -> None:
    PROXIES_DIR.mkdir(parents=True, exist_ok=True)
    BADGE_FILE.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def build_stats(
    cfg: Config,
    source_stats: list[dict],
    metadata_stats: list[dict],
    source_history: dict,
    dns_stats: dict,
    rejections: dict[str, int],
    candidates: list[Proxy],
    selected: list[Proxy],
    outcomes: list[tuple[Proxy, Outcome]],
    blocked: list[tuple[Proxy, str]],
    stable: list[dict],
    alternates: dict[str, list[str]],
    published: bool,
    reasons: list[str],
    now: datetime,
) -> dict:
    working = [outcome for _, outcome in outcomes if outcome.ok]
    engines = sorted({outcome.engine for _, outcome in outcomes if outcome.engine})
    return {
        "updated_at": now.isoformat(),
        "published": published,
        "publish_blocked_reasons": reasons,
        "sources": source_stats,
        "metadata_sources": metadata_stats,
        "source_history": source_history,
        "sources_ok": sum(1 for item in source_stats if item["ok"]),
        "sources_total": len(source_stats),
        "discovered": len(candidates),
        "duplicate_endpoints_removed": sum(len(set(urls)) for urls in alternates.values()),
        "checked_candidates": len(selected),
        "skipped_by_cap": max(0, len(candidates) - len(selected)),
        "mtproto_verified": len(working),
        "stable_in_window": len(stable),
        "best_published": min(cfg.best_count, len(stable)) if published else 0,
        "blocked_non_public": len(blocked),
        "block_reasons": {
            reason: sum(1 for _, item in blocked if item == reason)
            for reason in sorted({item for _, item in blocked})
        },
        "rejected_links": dict(sorted(rejections.items())),
        "average_rtt_ms": _average([outcome.rtt_ms for _, outcome in outcomes]),
        "average_check_ms": _average([outcome.duration_ms for _, outcome in outcomes]),
        "median_rtt_ms": median([outcome.rtt_ms for _, outcome in outcomes if outcome.rtt_ms]),
        "dns_cache": dns_stats,
        "engines": engines,
        "check": "real MTProto relay health check",
        "verification": [
            "TCP connect",
            "MTProxy obfuscated2 handshake",
            "MTProto req_pq_multi",
            "valid Telegram resPQ response",
        ],
        "policy": {
            "min_discovered": cfg.min_discovered,
            "min_keep_ratio": cfg.min_keep_ratio,
            "max_candidates": cfg.max_candidates,
            "known_good_hours": cfg.known_good_hours,
            "stable_ttl_hours": cfg.stable_ttl_hours,
            "best_count": cfg.best_count,
            "rtt_history": cfg.rtt_history,
            "dns_cache_hours": cfg.dns_cache_hours,
            "dcs": list(cfg.dcs),
            "guard_dns": cfg.guard_dns,
            "engine": cfg.engine,
        },
        "note": (
            "working.txt = verified in this run; stable.txt = verified within "
            f"{cfg.stable_ttl_hours:g}h, best first; best.txt = top "
            f"{cfg.best_count} by stability; a green check only means the MTProto "
            "handshake to Telegram succeeded."
        ),
    }


def write_stats(stats: dict) -> None:
    PROXIES_DIR.mkdir(parents=True, exist_ok=True)
    STATS_FILE.write_text(
        json.dumps(stats, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------
def run_dry(cfg: Config) -> int:
    """Fetch and parse sources, print a report, touch nothing."""
    print("Dry run: fetching sources only (no proxy connections, no writes).")
    candidates, source_stats, _, rejections, duplicates = collect(cfg)
    print(f"\nDistinct endpoints after dedup: {len(candidates)}")
    print(f"Rejected links: {json.dumps(dict(sorted(rejections.items())))}")
    print(f"Extra duplicate links dropped: {sum(len(v) for v in duplicates.values())}")
    kinds: dict[str, int] = {}
    for proxy in candidates:
        literal = parse_ip_literal(proxy.server)
        if literal is None:
            kind = "hostname"
        else:
            kind = "ipv4" if literal.version == 4 else "ipv6"
        kinds[kind] = kinds.get(kind, 0) + 1
    print(f"Endpoint kinds: {json.dumps(kinds)}")
    for item in source_stats:
        print(
            f"  {item['url']}: ok={item['ok']} bytes={item['bytes']} "
            f"links={item['links_found']} accepted={item['links_accepted']} "
            f"new_endpoints={item['endpoints_new']}"
        )
    for proxy in candidates[:5]:
        print(f"  sample: {proxy.url}")

    if cfg.metadata_sources:
        print("\nMetadata sources:")
        metadata, metadata_stats = fetch_metadata(cfg)
        matched = sum(1 for proxy in candidates if proxy.endpoint in metadata)
        print(f"  metadata covers {matched}/{len(candidates)} discovered endpoints")
        for item in metadata_stats:
            print(
                f"  {item['url']}: ok={item['ok']} bytes={item['bytes']} "
                f"entries={item['entries']} error={item['error']}"
            )
    return 0


def run(cfg: Config) -> int:
    now = datetime.now(timezone.utc)
    PROXIES_DIR.mkdir(parents=True, exist_ok=True)

    print("Collecting MTProto proxies...")
    candidates, source_stats, sources_by_endpoint, rejections, alternates = collect(cfg)
    print(f"\nDiscovered {len(candidates)} distinct endpoints.")

    if cfg.metadata_sources:
        print("Fetching metadata sources...")
        metadata, metadata_stats = fetch_metadata(cfg)
    else:
        metadata, metadata_stats = {}, []

    state = load_state(STATE_FILE)
    previous_working = int((state.get("meta") or {}).get("last_working_count", 0))

    preferred = {
        endpoint: entry.get("url")
        for endpoint, entry in (state.get("endpoints") or {}).items()
        if entry.get("url")
    }
    candidates, swapped = dedupe_by_endpoint(candidates, preferred)
    for endpoint, urls in swapped.items():
        alternates.setdefault(endpoint, []).extend(urls)

    selected = select_candidates(candidates, state, cfg, now)
    if len(selected) < len(candidates):
        print(f"Candidate cap: checking {len(selected)} of {len(candidates)}.")

    dns_cache = DnsCache(
        data=state.get("dns"),
        ttl_hours=cfg.dns_cache_hours,
        keep_days=cfg.state_keep_days,
    )
    outcomes, blocked = verify(selected, cfg, dns_cache=dns_cache)
    for proxy, reason in blocked:
        print(f"  skipped {proxy.endpoint}: {reason}")
    print(f"  DNS cache: {dns_cache.stats()}")

    verified = [(proxy, outcome) for proxy, outcome in outcomes if outcome.ok]
    print(f"\nMTProto verification complete: {len(verified)}/{len(outcomes)} working.")

    update_state(
        state,
        candidates,
        outcomes,
        sources_by_endpoint,
        now,
        keep_days=cfg.state_keep_days,
        max_entries=cfg.state_max_entries,
        history=cfg.rtt_history,
    )
    stable = stable_entries(state, cfg.stable_ttl_hours, now)
    best = best_entries(stable, cfg.best_count)
    ads = load_ads(ADS_FILE)
    source_history = update_source_history(state, source_stats, metadata_stats, now)
    state["dns"] = dns_cache.as_dict(now)

    published, reasons = evaluate_guard(
        discovered=len(candidates),
        verified=len(verified),
        previous_working=previous_working,
        sources_ok=sum(1 for item in source_stats if item["ok"]),
        cfg=cfg,
    )

    stats = build_stats(
        cfg=cfg,
        source_stats=source_stats,
        metadata_stats=metadata_stats,
        source_history=source_history,
        dns_stats=dns_cache.stats(),
        rejections=rejections,
        candidates=candidates,
        selected=selected,
        outcomes=outcomes,
        blocked=blocked,
        stable=stable,
        alternates=alternates,
        published=published,
        reasons=reasons,
        now=now,
    )

    if not published:
        # Keep the previous published files and the previous state intact.
        write_stats(stats)
        print("\nPUBLISH GUARD TRIPPED — published lists were left untouched.")
        for reason in reasons:
            print(f"  - {reason}")
        print(f"  stats written to {STATS_FILE} (published: false)")
        return 2

    write_published(candidates, outcomes, stable, best, ads, metadata, state, now)
    badge = badge_payload(len(verified), len(stable), now)
    write_badge(badge)
    state.setdefault("meta", {})["last_working_count"] = len(verified)
    state["meta"]["last_published_at"] = now.isoformat()
    STATE_FILE.write_text(
        json.dumps(state, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    write_stats(stats)

    print(f"Saved: {ALL_FILE} ({len(candidates)} links)")
    print(f"Saved: {WORKING_FILE} ({len(verified)} verified)")
    print(f"Saved: {STABLE_FILE} ({len(stable)} verified within TTL)")
    print(f"Saved: {BEST_FILE} ({len(best)} most stable)")
    print(f"Saved: {ENDPOINTS_FILE}, {STATE_FILE}, {BADGE_FILE}, {STATS_FILE}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="fetch and parse sources, print a report, write nothing",
    )
    parser.add_argument(
        "--sources",
        help="comma-separated source URLs (overrides PROXY_SOURCES and defaults)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="maximum number of candidates to check (overrides MAX_CANDIDATES)",
    )
    parser.add_argument(
        "--engine",
        choices=["auto", "library", "cli"],
        help="health-check engine (default: auto)",
    )
    parser.add_argument(
        "--allow-degraded",
        action="store_true",
        help="publish even when the guard trips (manual bootstrap only)",
    )
    parser.add_argument(
        "--no-dns-guard",
        action="store_true",
        help="skip the public-address guard (not recommended)",
    )
    parser.add_argument(
        "--dcs",
        help='Telegram DC ids to test, e.g. "2" or "2,4" (overrides CHECK_DCS)',
    )
    parser.add_argument(
        "--no-metadata",
        action="store_true",
        help="skip optional JSON metadata sources",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = Config.from_env()

    if args.sources:
        cfg.sources = [s.strip() for s in args.sources.split(",") if s.strip()]
    if args.limit is not None:
        cfg.max_candidates = args.limit
    if args.engine:
        cfg.engine = args.engine
    if args.allow_degraded:
        cfg.allow_degraded = True
    if args.no_dns_guard:
        cfg.guard_dns = False
    if args.dcs:
        cfg.dcs = parse_dcs(args.dcs)
    if args.no_metadata:
        cfg.metadata_sources = []

    if not cfg.sources:
        print("No sources configured.", file=sys.stderr)
        return 3

    if args.dry_run:
        return run_dry(cfg)
    return run(cfg)


if __name__ == "__main__":
    raise SystemExit(main())
