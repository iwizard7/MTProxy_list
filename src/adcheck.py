#!/usr/bin/env python3
"""Detect MTProto proxies that inject a Telegram sponsored ("promoted") channel.

Why this exists
---------------
Some MTProto proxies are configured by their operator with a Telegram *ad tag*.
Telegram then inserts a sponsored channel into the chat list of every client
that connects through that proxy (that is what users see as "ads in Telegram
when a proxy is enabled"). The tag lives **server-side only**: it is not part of
the ``tg://proxy?server=..&port=..&secret=..`` link, so it cannot be read from a
proxy list, and it is invisible to a passive client.

The only reliable detection is to be a Telegram client: connect an *authorized
user session* through the proxy and ask Telegram for its promo data
(``help.getPromoData``). When the request arrives through an ad-enabled proxy,
the response carries ``proxy=True`` and a promoted ``peer``.

This module is deliberately **opt-in** and completely separate from the main
collector: it needs your own Telegram API credentials, a user session, and it
uses a real account.

Requirements
------------
    pip install -r requirements-ads.txt          # telethon
    export TELEGRAM_API_ID=123456                # https://my.telegram.org
    export TELEGRAM_API_HASH=0123456789abcdef
    export TELEGRAM_SESSION="1BVtsOK..."         # Telethon StringSession

Recommended: use a **dedicated account**, not your main one. See the warnings
section of FIXES.md before running this against many proxies.

Usage
-----
    python src/adcheck.py --limit 20             # check 20 endpoints from working.txt
    python src/adcheck.py --endpoint 1.2.3.4:443 # check a single endpoint
    python src/adcheck.py --force                # ignore the cache
    python src/adcheck.py --dry-run              # show what would be checked

Results are written to ``proxies/ads.json``; the main collector merges them into
``proxies/endpoints.json`` as ``ads.status`` = ``present`` / ``none`` /
``unknown``. Entries not checked in this run are preserved.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
PROXIES_DIR = BASE_DIR / "proxies"
ADS_FILE = PROXIES_DIR / "ads.json"
WORKING_FILE = PROXIES_DIR / "working.txt"
ENDPOINTS_FILE = PROXIES_DIR / "endpoints.json"

sys.path.insert(0, str(Path(__file__).resolve().parent))

from collector import (  # noqa: E402  (same directory import)
    Proxy,
    canonical_host,
    canonical_port,
    canonical_secret,
    endpoint_key,
    build_url,
    parse_proxy,
)

DEFAULT_CACHE_DAYS = 7.0
DEFAULT_DELAY = 2.0

PROMO_METHOD = "help.getPromoData"
METHOD_NOTE = (
    "connect an authorized user session through the proxy and call "
    "help.getPromoData; proxy=true + peer means an injected sponsored channel"
)


# ---------------------------------------------------------------------------
# Target discovery
# ---------------------------------------------------------------------------
def _dedupe(proxies: list[Proxy]) -> list[Proxy]:
    """Keep the first entry per endpoint (probing the same host twice is waste)."""
    seen: set[str] = set()
    unique = []
    for proxy in proxies:
        if proxy.endpoint in seen:
            continue
        seen.add(proxy.endpoint)
        unique.append(proxy)
    return unique


def targets_from_working(path: Path = WORKING_FILE) -> list[Proxy]:
    """Read endpoints from working.txt (the verified list)."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    proxies = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        proxy, _ = parse_proxy(line)
        if proxy is not None:
            proxies.append(proxy)
    return _dedupe(proxies)


def targets_from_endpoints(path: Path = ENDPOINTS_FILE) -> list[Proxy]:
    """Read endpoints from the collector's metadata (keeps order by RTT)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    proxies = []
    for item in data.get("endpoints", []):
        if not isinstance(item, dict) or not item.get("url"):
            continue
        proxy, _ = parse_proxy(item["url"])
        if proxy is not None:
            proxies.append(proxy)
    return _dedupe(proxies)


def make_target(host: str, port: str, secret: str) -> Proxy | None:
    """Build a proxy from explicit host/port/secret parts."""
    canonical = canonical_host(host)
    canonical_port_value = canonical_port(str(port))
    canonical_secret_value = canonical_secret(secret)
    if canonical is None or canonical_port_value is None or canonical_secret_value is None:
        return None
    return Proxy(
        build_url(canonical, canonical_port_value, canonical_secret_value),
        canonical,
        canonical_port_value,
        canonical_secret_value,
    )


def select_targets(proxy: Proxy | None, args) -> list[Proxy]:
    """Choose which endpoints to check (used by main and by tests)."""
    if proxy is not None:
        return [proxy]
    if getattr(args, "from_endpoints", False):
        return targets_from_endpoints(ENDPOINTS_FILE)
    return targets_from_working(WORKING_FILE)


# ---------------------------------------------------------------------------
# Promo-data interpretation (pure, unit-testable)
# ---------------------------------------------------------------------------
def describe_peer(peer) -> str | None:
    """Best-effort human readable name for a TL peer object."""
    if peer is None:
        return None
    for attribute in ("username", "title", "first_name"):
        value = getattr(peer, attribute, None)
        if value:
            return str(value)
    channel_id = getattr(peer, "channel_id", None)
    if channel_id is not None:
        return f"channel:{channel_id}"
    user_id = getattr(peer, "user_id", None)
    if user_id is not None:
        return f"user:{user_id}"
    chat_id = getattr(peer, "chat_id", None)
    if chat_id is not None:
        return f"chat:{chat_id}"
    return type(peer).__name__


def resolve_channel_from_promo(data, peer) -> str | None:
    """Find the promoted channel inside the promo response itself.

    ``help.promoData`` ships the referenced entities in its own ``chats`` /
    ``users`` lists, so the name can be resolved without an extra request.
    """
    if peer is None:
        return None
    channel_id = getattr(peer, "channel_id", None)
    user_id = getattr(peer, "user_id", None)
    chat_id = getattr(peer, "chat_id", None)

    candidates = []
    if channel_id is not None:
        candidates.append((getattr(data, "chats", None) or [], channel_id))
    if user_id is not None:
        candidates.append((getattr(data, "users", None) or [], user_id))
    if chat_id is not None:
        candidates.append((getattr(data, "chats", None) or [], chat_id))

    for entities, wanted in candidates:
        for entity in entities:
            if getattr(entity, "id", None) != wanted:
                continue
            for attribute in ("username", "title", "first_name"):
                value = getattr(entity, attribute, None)
                if value:
                    return str(value)
    return None


def verdict_from_promo_data(data, resolved_name: str | None = None) -> dict:
    """Interpret a ``help.getPromoData`` response.

    ``help.promoData`` carries a ``proxy`` flag that is set when the promo data
    was served for a session that arrived through a proxy, and a ``peer`` field
    naming the promoted channel. ``help.promoDataEmpty`` (or any object without
    those fields) means "no proxy-sponsored channel".

    This function intentionally uses ``getattr`` so it works with both Telethon
    objects and plain stubs in tests.
    """
    proxy_flag = bool(getattr(data, "proxy", False))
    peer = getattr(data, "peer", None)
    psa_type = getattr(data, "psa_type", None)
    channel = resolved_name or resolve_channel_from_promo(data, peer) or describe_peer(peer)

    return {
        "has_ads": proxy_flag and peer is not None,
        "proxy_flag": proxy_flag,
        "channel": channel if (proxy_flag and peer is not None) else None,
        "peer": describe_peer(peer),
        "expires": _iso_or_int(getattr(data, "expires", None)),
        "psa_type": psa_type,
    }


def _iso_or_int(value) -> str | int | None:
    """Telethon returns ``expires`` as a datetime, other clients as an int."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, int):
        return value
    return None


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------
def load_ads(path: Path = ADS_FILE) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"updated_at": None, "method": METHOD_NOTE, "results": {}}
    if not isinstance(data, dict):
        return {"updated_at": None, "method": METHOD_NOTE, "results": {}}
    data.setdefault("results", {})
    data.setdefault("method", METHOD_NOTE)
    return data


def is_fresh(entry: dict, now: datetime, cache_days: float) -> bool:
    if cache_days <= 0 or not isinstance(entry, dict):
        return False
    checked_at = entry.get("checked_at")
    if not checked_at:
        return False
    try:
        parsed = datetime.fromisoformat(checked_at)
    except ValueError:
        return False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed >= now - timedelta(days=cache_days)


def save_ads(data: dict, path: Path = ADS_FILE) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# Telethon probe
# ---------------------------------------------------------------------------
def secret_kind(secret: str) -> str:
    """Classify an MTProxy secret by the transport it requires.

    The distinction matters because Telethon (1.x) does **not** implement
    FakeTLS: it strips an ``ee`` prefix and speaks plain obfuscated2, so a
    FakeTLS-only proxy will simply close the connection. Such endpoints are
    reported as ``unsupported`` instead of being silently mis-labelled as
    "no ads".

    Returns one of ``plain``, ``dd``, ``faketls`` or ``unknown``.
    """
    text = (secret or "").strip().rstrip("=")
    lowered = text.lower()
    if lowered.startswith("ee"):
        return "faketls"
    if lowered.startswith("dd"):
        return "dd"

    payload = None
    try:
        payload = bytes.fromhex(lowered)
    except ValueError:
        try:
            padded = text + "=" * (-len(text) % 4)
            payload = base64.urlsafe_b64decode(padded.encode("ascii"))
        except Exception:
            return "unknown"

    if not payload:
        return "unknown"
    if payload[0] == 0xEE:
        return "faketls"
    if payload[0] == 0xDD:
        return "dd"
    if len(payload) >= 16:
        return "plain"
    return "unknown"


def connection_classes_for(kind: str, connection) -> list:
    """Ordered list of Telethon connection classes to try for a secret kind."""
    if kind == "dd":
        return [connection.ConnectionTcpMTProxyRandomizedIntermediate]
    if kind == "plain":
        return [
            connection.ConnectionTcpMTProxyIntermediate,
            connection.ConnectionTcpMTProxyAbridged,
        ]
    return []


def _require_telethon():
    try:
        from telethon import TelegramClient, connection, functions  # noqa: F401
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise SystemExit(
            "Telethon is required: pip install -r requirements-ads.txt"
        ) from exc
    return TelegramClient, connection, functions


def _credentials() -> tuple[int, str, str]:
    api_id = (os.environ.get("TELEGRAM_API_ID") or "").strip()
    api_hash = (os.environ.get("TELEGRAM_API_HASH") or "").strip()
    session = (os.environ.get("TELEGRAM_SESSION") or "").strip()
    if not api_id or not api_hash or not session:
        raise SystemExit(
            "TELEGRAM_API_ID, TELEGRAM_API_HASH and TELEGRAM_SESSION must be set "
            "(create an app at https://my.telegram.org; create a StringSession "
            "once with Telethon)."
        )
    return int(api_id), api_hash, session


async def _probe_with_connection(
    proxy: Proxy,
    connection_class,
    api_id: int,
    api_hash: str,
    session: str,
    timeout: float,
) -> dict:
    """One attempt with a specific MTProxy transport."""
    TelegramClient, _, functions = _require_telethon()

    client = TelegramClient(
        session,  # a StringSession keeps this stateless inside CI
        api_id,
        api_hash,
        connection=connection_class,
        proxy=(proxy.server, proxy.port, proxy.secret),
        timeout=timeout,
        connection_retries=1,
        retry_delay=0,
        auto_reconnect=False,
        request_retries=1,
    )

    await client.connect()
    try:
        if not await client.is_user_authorized():
            return {"error": "session_not_authorized"}
        data = await client(functions.help.GetPromoDataRequest())

        resolved = None
        peer = getattr(data, "peer", None)
        if getattr(data, "proxy", False) and peer is not None:
            resolved = resolve_channel_from_promo(data, peer)
            if resolved is None:
                try:
                    entity = await client.get_entity(peer)
                    resolved = getattr(entity, "username", None) or getattr(
                        entity, "title", None
                    )
                except Exception:
                    resolved = None

        verdict = verdict_from_promo_data(data, resolved_name=resolved)
        verdict["transport"] = getattr(connection_class, "__name__", str(connection_class))
        return verdict
    finally:
        await client.disconnect()


async def probe_endpoint(
    proxy: Proxy, api_id: int, api_hash: str, session: str, timeout: float
) -> dict:
    """Connect an authorized user session through one proxy and ask Telegram.

    Returns the ``verdict_from_promo_data`` dict, or a dict with an ``error``.
    """
    _, connection, _ = _require_telethon()
    kind = secret_kind(proxy.secret)
    classes = connection_classes_for(kind, connection)
    if not classes:
        return {
            "has_ads": None,
            "error": f"unsupported_transport:{kind}",
            "secret_kind": kind,
            "note": (
                "Telethon 1.x cannot speak FakeTLS; use a TDLib-based client for "
                "ee-secrets."
            )
            if kind == "faketls"
            else "unrecognised secret format",
        }

    last_error: str | None = None
    for connection_class in classes:
        try:
            verdict = await _probe_with_connection(
                proxy, connection_class, api_id, api_hash, session, timeout
            )
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            continue
        verdict["secret_kind"] = kind
        if verdict.get("error"):
            last_error = verdict["error"]
            continue
        return verdict

    return {"has_ads": None, "error": last_error or "probe_failed", "secret_kind": kind}


def check_all(proxies: list[Proxy], args, now: datetime) -> dict[str, dict]:
    """Sequentially probe endpoints, honouring the cache and the delay.

    Endpoints whose transport Telethon cannot speak (FakeTLS ``ee`` secrets) are
    recorded as ``unsupported_transport`` instead of being reported as clean,
    and credentials are only required when there is something left to probe.
    """
    cache = load_ads(ADS_FILE)
    results: dict[str, dict] = dict(cache.get("results") or {})
    pending: list[Proxy] = []

    for proxy in proxies:
        existing = results.get(proxy.endpoint)
        if not args.force and is_fresh(existing, now, args.cache_days):
            print(f"  {proxy.endpoint}: cached")
            continue

        kind = secret_kind(proxy.secret)
        if kind in ("faketls", "unknown"):
            results[proxy.endpoint] = {
                "has_ads": None,
                "error": f"unsupported_transport:{kind}",
                "secret_kind": kind,
                "checked_at": now.isoformat(),
                "url": proxy.url,
                "note": (
                    "Telethon 1.x cannot speak FakeTLS; this proxy can only be "
                    "checked with a TDLib-based client."
                    if kind == "faketls"
                    else "unrecognised secret format"
                ),
            }
            print(f"  {proxy.endpoint}: skipped ({kind})")
            continue

        pending.append(proxy)

    if not pending:
        print("Nothing left to probe with a user session.")
        return results

    api_id, api_hash, session = _credentials()
    checked = 0

    for proxy in pending:
        if checked and args.delay:
            time.sleep(args.delay)

        print(f"  {proxy.endpoint}: probing…")
        try:
            verdict = asyncio.run(
                probe_endpoint(proxy, api_id, api_hash, session, args.timeout)
            )
        except SystemExit:
            raise
        except Exception as exc:
            verdict = {"error": f"{type(exc).__name__}: {exc}"}

        verdict["checked_at"] = now.isoformat()
        verdict.setdefault("has_ads", None)
        verdict["url"] = proxy.url
        results[proxy.endpoint] = verdict
        checked += 1

        if verdict.get("has_ads") is True:
            print(f"    ADS: {verdict.get('channel')}")
        elif verdict.get("has_ads") is False:
            print("    clean")
        else:
            print(f"    unknown/error: {verdict.get('error')}")

    print(f"Probed {checked} endpoint(s), {len(results)} entries kept in ads.json.")
    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--endpoint", help="check a single host:port from working.txt")
    parser.add_argument(
        "--host", help="explicit host (requires --port and --secret)"
    )
    parser.add_argument("--port", help="explicit port")
    parser.add_argument("--secret", help="explicit secret")
    parser.add_argument(
        "--limit", type=int, help="check at most N endpoints"
    )
    parser.add_argument(
        "--from-endpoints",
        action="store_true",
        help="read proxies/endpoints.json instead of working.txt",
    )
    parser.add_argument(
        "--cache-days",
        type=float,
        default=DEFAULT_CACHE_DAYS,
        help=f"reuse results younger than N days (default {DEFAULT_CACHE_DAYS:g})",
    )
    parser.add_argument(
        "--force", action="store_true", help="ignore cached results"
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=DEFAULT_DELAY,
        help=f"seconds between probes (default {DEFAULT_DELAY:g})",
    )
    parser.add_argument(
        "--timeout", type=float, default=10.0, help="client timeout (default 10)"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="list targets, do not connect"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    now = datetime.now(timezone.utc)

    proxy = None
    if args.endpoint:
        match = next(
            (p for p in targets_from_working() if p.endpoint == args.endpoint), None
        )
        if match is None:
            match = next(
                (p for p in targets_from_endpoints() if p.endpoint == args.endpoint),
                None,
            )
        if match is None:
            print(f"Endpoint {args.endpoint} not found in published lists.")
            return 3
        proxy = match
    elif args.host:
        if not args.port or not args.secret:
            print("--host requires --port and --secret")
            return 3
        proxy = make_target(args.host, args.port, args.secret)
        if proxy is None:
            print("Invalid host/port/secret.")
            return 3

    targets = select_targets(proxy, args)
    if args.limit is not None:
        targets = targets[: max(0, args.limit)]

    if not targets:
        print("No targets to check.")
        return 0

    print(f"Targets: {len(targets)}")
    for target in targets[:10]:
        print(f"  {target.endpoint}")
    if len(targets) > 10:
        print(f"  … and {len(targets) - 10} more")

    if args.dry_run:
        print("Dry run: nothing was connected and nothing was written.")
        return 0

    results = check_all(targets, args, now)
    data = {
        "updated_at": now.isoformat(),
        "method": METHOD_NOTE,
        "promo_method": PROMO_METHOD,
        "cache_days": args.cache_days,
        "results": results,
    }
    save_ads(data)
    print(f"Saved: {ADS_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
