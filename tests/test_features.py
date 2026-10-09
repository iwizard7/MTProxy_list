#!/usr/bin/env python3
"""Tests for the added collector features (stdlib only, no network).

Covers: DC selection, RTT history/stability ranking, the persistent DNS cache,
upstream metadata sources, per-source history, the shields.io badge and the
engine passthrough.

Run with:  python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import collector  # noqa: E402

NOW = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)
LINK_A = "tg://proxy?server=1.2.3.4&port=443&secret=" + "ab" * 16
LINK_B = "tg://proxy?server=5.6.7.8&port=443&secret=" + "cd" * 16
# Host names (not IP literals) exercise the DNS guard and its cache.
LINK_HOST_A = "tg://proxy?server=host-a.example.com&port=443&secret=" + "ab" * 16
LINK_HOST_B = "tg://proxy?server=host-b.example.com&port=443&secret=" + "cd" * 16


def proxy_for(link: str) -> collector.Proxy:
    proxy = collector.normalize_proxy(link)
    assert proxy is not None
    return proxy


class DcsTests(unittest.TestCase):
    def test_parse_variants(self):
        self.assertEqual(collector.parse_dcs("2"), (2,))
        self.assertEqual(collector.parse_dcs("2,4"), (2, 4))
        self.assertEqual(collector.parse_dcs(" 4 ; 2 "), (2, 4))
        self.assertEqual(collector.parse_dcs("2,2"), (2,))

    def test_invalid_values_are_dropped(self):
        self.assertEqual(collector.parse_dcs(""), ())
        self.assertEqual(collector.parse_dcs("0,9,-1,abc"), ())

    def test_env_is_parsed(self):
        with mock.patch.dict("os.environ", {"CHECK_DCS": "2,4"}):
            self.assertEqual(collector.Config.from_env().dcs, (2, 4))


class DcPassthroughTests(unittest.TestCase):
    def _fake_library(self, recorder: dict):
        class FakeOptions:
            def __init__(self, **kwargs):
                recorder["options"] = kwargs

        def fake_check(url, options):
            recorder["url"] = url
            return SimpleNamespace(ok=True, rtt_ms=12.5, error_code=None)

        return (fake_check, FakeOptions)

    def test_library_engine_receives_dcs(self):
        recorder: dict = {}
        cfg = collector.Config(dcs=(2, 4), engine="library")
        proxy = proxy_for(LINK_A)
        with mock.patch.object(collector, "_LIBRARY", self._fake_library(recorder)):
            outcome = collector.check_with_library(proxy, cfg)
        self.assertTrue(outcome.ok)
        self.assertEqual(recorder["options"]["dcs"], (2, 4))
        self.assertEqual(outcome.rtt_ms, 12.5)

    def test_library_engine_without_dcs_omits_the_argument(self):
        recorder: dict = {}
        cfg = collector.Config(engine="library")
        with mock.patch.object(collector, "_LIBRARY", self._fake_library(recorder)):
            collector.check_with_library(proxy_for(LINK_A), cfg)
        self.assertNotIn("dcs", recorder["options"])

    def test_cli_engine_receives_dcs(self):
        cfg = collector.Config(dcs=(2,), engine="cli")
        with mock.patch.object(
            collector.subprocess, "run", return_value=SimpleNamespace(returncode=0)
        ) as run:
            outcome = collector.check_with_cli(proxy_for(LINK_A), cfg)
        self.assertTrue(outcome.ok)
        args = run.call_args[0][0]
        self.assertIn("--dcs", args)
        self.assertEqual(args[args.index("--dcs") + 1], "2")

    def test_cli_engine_without_dcs(self):
        cfg = collector.Config(engine="cli")
        with mock.patch.object(
            collector.subprocess, "run", return_value=SimpleNamespace(returncode=0)
        ) as run:
            collector.check_with_cli(proxy_for(LINK_A), cfg)
        self.assertNotIn("--dcs", run.call_args[0][0])


class MetricsTests(unittest.TestCase):
    def test_median(self):
        self.assertIsNone(collector.median([]))
        self.assertEqual(collector.median([5]), 5.0)
        self.assertEqual(collector.median([1, 3]), 2.0)
        self.assertEqual(collector.median([3, 1, 2]), 2.0)

    def test_entry_metrics(self):
        entry = {
            "recent": [True, True, False, True],
            "rtt_samples": [100, 110, 120, 130],
            "last_rtt_ms": 130,
        }
        metrics = collector.entry_metrics(entry)
        self.assertEqual(metrics["success_rate"], 0.75)
        self.assertEqual(metrics["median_rtt_ms"], 115.0)
        self.assertEqual(metrics["samples"], 4)
        self.assertEqual(metrics["rtt_trend"], "degrading")

    def test_trend_detection(self):
        fast_then_slow = {"rtt_samples": [50, 50, 200, 200]}
        slow_then_fast = {"rtt_samples": [200, 200, 50, 50]}
        stable = {"rtt_samples": [100, 100, 100, 100]}
        self.assertEqual(collector.entry_metrics(fast_then_slow)["rtt_trend"], "degrading")
        self.assertEqual(collector.entry_metrics(slow_then_fast)["rtt_trend"], "improving")
        self.assertEqual(collector.entry_metrics(stable)["rtt_trend"], "stable")
        self.assertEqual(collector.entry_metrics({"rtt_samples": [10]})["rtt_trend"], "unknown")

    def test_empty_entry_has_no_metrics(self):
        metrics = collector.entry_metrics({})
        self.assertIsNone(metrics["median_rtt_ms"])
        self.assertIsNone(metrics["success_rate"])

    def test_stable_entries_rank_by_success_then_speed(self):
        state = {
            "endpoints": {
                "a:1": {
                    "url": "tg://proxy?a",
                    "last_ok": NOW.isoformat(),
                    "recent": [True, True, True, True],
                    "rtt_samples": [300, 300],
                },
                "b:1": {
                    "url": "tg://proxy?b",
                    "last_ok": NOW.isoformat(),
                    "recent": [True, False, True, False],
                    "rtt_samples": [50, 50],
                },
                "c:1": {
                    "url": "tg://proxy?c",
                    "last_ok": NOW.isoformat(),
                    "recent": [True, True, True, True],
                    "rtt_samples": [100, 100],
                },
                "stale:1": {
                    "url": "tg://proxy?stale",
                    "last_ok": (NOW - timedelta(hours=48)).isoformat(),
                    "recent": [True],
                    "rtt_samples": [10],
                },
            }
        }
        stable = collector.stable_entries(state, ttl_hours=24, now=NOW)
        self.assertEqual([item["endpoint"] for item in stable], ["c:1", "a:1", "b:1"])
        self.assertEqual([item["url"] for item in collector.best_entries(stable, 2)],
                         ["tg://proxy?c", "tg://proxy?a"])
        self.assertEqual(collector.best_entries(stable, 0), [])


class DnsCacheTests(unittest.TestCase):
    def test_miss_then_hit(self):
        calls = []

        def resolver(host, port, **kwargs):
            calls.append(host)
            return [(2, 1, 6, "", ("1.2.3.4", port or 0))]

        cache = collector.DnsCache(ttl_hours=6)
        first = cache.get("example.com", resolver=resolver, now=NOW)
        second = cache.get("example.com", resolver=resolver, now=NOW + timedelta(hours=1))
        self.assertEqual(len(calls), 1)
        self.assertEqual([str(ip) for ip in first], ["1.2.3.4"])
        self.assertEqual([str(ip) for ip in second], ["1.2.3.4"])
        self.assertEqual(cache.stats()["hits"], 1)
        self.assertEqual(cache.stats()["misses"], 1)

    def test_entry_expires(self):
        calls = []

        def resolver(host, port, **kwargs):
            calls.append(host)
            return [(2, 1, 6, "", ("1.2.3.4", port or 0))]

        cache = collector.DnsCache(ttl_hours=1)
        cache.get("example.com", resolver=resolver, now=NOW)
        cache.get("example.com", resolver=resolver, now=NOW + timedelta(hours=2))
        self.assertEqual(len(calls), 2)

    def test_negative_answers_are_cached_too(self):
        calls = []

        def failing(host, port, **kwargs):
            calls.append(host)
            raise OSError("nxdomain")

        cache = collector.DnsCache(ttl_hours=6)
        allowed, reason = collector.is_public_target(
            "nx.example.com", resolver=failing, cache=cache, now=NOW
        )
        allowed2, reason2 = collector.is_public_target(
            "nx.example.com", resolver=failing, cache=cache, now=NOW + timedelta(minutes=5)
        )
        self.assertFalse(allowed)
        self.assertFalse(allowed2)
        self.assertEqual(reason, reason2)
        self.assertEqual(reason, "dns_no_addresses")
        self.assertEqual(len(calls), 1, "a dead host must not be resolved on every run")

    def test_private_answer_is_blocked_and_not_rechecked(self):
        calls = []

        def resolver(host, port, **kwargs):
            calls.append(host)
            return [(2, 1, 6, "", ("10.0.0.5", port or 0))]

        cache = collector.DnsCache(ttl_hours=6)
        allowed, reason = collector.is_public_target(
            "evil.example.com", resolver=resolver, cache=cache, now=NOW
        )
        self.assertFalse(allowed)
        self.assertEqual(reason, "non_public_address")
        collector.is_public_target("evil.example.com", resolver=resolver, cache=cache, now=NOW)
        self.assertEqual(len(calls), 1)

    def test_ip_literals_never_hit_the_cache(self):
        cache = collector.DnsCache(ttl_hours=6)
        addresses = cache.get("127.0.0.1", resolver=None, now=NOW)
        self.assertEqual([str(ip) for ip in addresses], ["127.0.0.1"])
        self.assertEqual(cache.stats()["misses"], 0)

    def test_snapshot_prunes_old_entries(self):
        cache = collector.DnsCache(ttl_hours=6, keep_days=1)
        cache.get("old.example.com", resolver=lambda *a, **k: [(2, 1, 6, "", ("1.2.3.4", 0))], now=NOW)
        snapshot = cache.as_dict(now=NOW + timedelta(days=5))
        self.assertEqual(snapshot, {})
        self.assertEqual(cache.stats()["hosts"], 0)

    def test_round_trip_through_state(self):
        cache = collector.DnsCache(ttl_hours=6)
        cache.get("keep.example.com", resolver=lambda *a, **k: [(2, 1, 6, "", ("1.2.3.4", 0))], now=NOW)
        data = json.loads(json.dumps(cache.as_dict(now=NOW)))

        calls = []
        restored = collector.DnsCache(data=data, ttl_hours=6)
        restored.get(
            "keep.example.com",
            resolver=lambda *a, **k: calls.append(1) or [],
            now=NOW + timedelta(minutes=30),
        )
        self.assertEqual(calls, [], "the restored cache must serve the stored answer")
        self.assertEqual(restored.stats()["hits"], 1)


class SlowResolverTests(unittest.TestCase):
    """A resolver that blocks must not hang the run and must never be dialled."""

    def test_blocked_host_is_skipped_without_connecting(self):
        def slow_resolver(host, port, **kwargs):
            time.sleep(0.05)
            return [(2, 1, 6, "", ("10.1.1.1", port or 0))]

        cfg = collector.Config(max_workers=2)
        candidates = [proxy_for(LINK_HOST_A), proxy_for(LINK_HOST_B)]
        with mock.patch.object(collector, "check_proxy") as check:
            started = time.perf_counter()
            outcomes, blocked = collector.verify(candidates, cfg, resolver=slow_resolver)
            elapsed = time.perf_counter() - started

        check.assert_not_called()
        self.assertEqual(outcomes, [])
        self.assertEqual(len(blocked), 2)
        self.assertTrue(all(reason == "non_public_address" for _, reason in blocked))
        self.assertLess(elapsed, 5.0)

    def test_failing_resolver_is_reported(self):
        def broken(host, port, **kwargs):
            raise OSError("dns down")

        cfg = collector.Config()
        outcomes, blocked = collector.verify([proxy_for(LINK_HOST_A)], cfg, resolver=broken)
        self.assertEqual(outcomes, [])
        self.assertEqual(blocked[0][1], "dns_no_addresses")


class MetadataTests(unittest.TestCase):
    def _cfg(self, url: str = "https://meta.example/proxies.json") -> collector.Config:
        return collector.Config(metadata_sources=[url], sources=["https://list.example/l.txt"])

    def test_valid_metadata_is_indexed_by_endpoint(self):
        payload = json.dumps(
            [
                {"host": "1.2.3.4", "port": 443, "latency": 2, "operator": {"mci": 85, "x": "n/a"}},
                {"host": "5.6.7.8", "port": "8443", "latency": "slow"},
                {"host": "bad..host", "port": 443},
                "not-a-dict",
            ]
        )
        with mock.patch.object(collector, "fetch_source", return_value=(payload, "", len(payload))):
            metadata, stats = collector.fetch_metadata(self._cfg())
        self.assertEqual(set(metadata), {"1.2.3.4:443", "5.6.7.8:8443"})
        self.assertEqual(metadata["1.2.3.4:443"]["latency"], 2)
        self.assertEqual(metadata["1.2.3.4:443"]["operators"], {"mci": 85})
        self.assertNotIn("latency", metadata["5.6.7.8:8443"])
        self.assertEqual(stats[0]["entries"], 2)
        self.assertTrue(stats[0]["ok"])

    def test_invalid_json_and_wrong_shape_are_reported(self):
        for payload, needle in (("{not json", "invalid_json"), ('{"a": 1}', "unexpected_shape")):
            with mock.patch.object(
                collector, "fetch_source", return_value=(payload, "", len(payload))
            ):
                metadata, stats = collector.fetch_metadata(self._cfg())
            self.assertEqual(metadata, {})
            self.assertFalse(stats[0]["ok"])
            self.assertIn(needle, stats[0]["error"])

    def test_source_failure_is_reported(self):
        with mock.patch.object(collector, "fetch_source", return_value=("", "HTTPError: 404", 0)):
            metadata, stats = collector.fetch_metadata(self._cfg())
        self.assertEqual(metadata, {})
        self.assertFalse(stats[0]["ok"])
        self.assertEqual(stats[0]["error"], "HTTPError: 404")


class SourceHistoryTests(unittest.TestCase):
    def test_history_accumulates(self):
        state: dict = {}
        list_stats = [
            {
                "url": "https://a/l.txt",
                "ok": True,
                "links_found": 10,
                "links_accepted": 9,
                "endpoints_new": 4,
                "error": None,
            }
        ]
        metadata_stats = [
            {"url": "https://m/p.json", "ok": False, "entries": 0, "error": "HTTPError: 404"}
        ]
        collector.update_source_history(state, list_stats, metadata_stats, NOW)
        collector.update_source_history(state, list_stats, metadata_stats, NOW + timedelta(hours=2))

        record = state["sources"]["https://a/l.txt"]
        self.assertEqual(record["kind"], "list")
        self.assertEqual(record["runs"], 2)
        self.assertEqual(record["ok_runs"], 2)
        self.assertEqual(record["total_new_endpoints"], 8)
        self.assertEqual(record["last_new_endpoints"], 4)
        self.assertEqual(record["last_links_accepted"], 9)

        meta = state["sources"]["https://m/p.json"]
        self.assertEqual(meta["kind"], "metadata")
        self.assertEqual(meta["runs"], 2)
        self.assertNotIn("ok_runs", meta)
        self.assertEqual(meta["last_error"], "HTTPError: 404")


class BadgeTests(unittest.TestCase):
    def test_colors(self):
        self.assertEqual(collector.badge_payload(25, 25, NOW)["color"], "brightgreen")
        self.assertEqual(collector.badge_payload(7, 7, NOW)["color"], "yellow")
        self.assertEqual(collector.badge_payload(1, 1, NOW)["color"], "orange")
        self.assertEqual(collector.badge_payload(0, 0, NOW)["color"], "red")

    def test_payload_shape(self):
        payload = collector.badge_payload(12, 30, NOW)
        self.assertEqual(payload["schemaVersion"], 1)
        self.assertEqual(payload["label"], "verified proxies")
        self.assertEqual(payload["message"], "12 now · 30 in 24h")


class RunIntegrationTests(unittest.TestCase):
    """run() with everything patched, checking the newly added outputs."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.paths = {
            "PROXIES_DIR": self.dir,
            "ALL_FILE": self.dir / "all.txt",
            "WORKING_FILE": self.dir / "working.txt",
            "STABLE_FILE": self.dir / "stable.txt",
            "BEST_FILE": self.dir / "best.txt",
            "BADGE_FILE": self.dir / "badge.json",
            "STATS_FILE": self.dir / "stats.json",
            "STATE_FILE": self.dir / "state.json",
            "ENDPOINTS_FILE": self.dir / "endpoints.json",
            "ADS_FILE": self.dir / "ads.json",
        }
        for name, value in self.paths.items():
            patcher = mock.patch.object(collector, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_outputs_include_best_badge_metadata_and_history(self):
        text = "\n".join([LINK_A, LINK_B])
        metadata = json.dumps([{"host": "1.2.3.4", "port": 443, "latency": 3, "operator": {"mci": 85}}])
        cfg = collector.Config(
            min_discovered=1,
            metadata_sources=["https://meta.example/p.json"],
        )

        def fake_fetch(url, config):
            if url in config.metadata_sources:
                return metadata, "", len(metadata)
            return text, "", len(text)

        with mock.patch.object(collector, "fetch_source", side_effect=fake_fetch):
            with mock.patch.object(
                collector,
                "check_proxy",
                side_effect=lambda proxy, config: collector.Outcome(
                    proxy.endpoint, True, rtt_ms=25.0, duration_ms=30.0, engine="stub"
                ),
            ):
                code = collector.run(cfg)
        self.assertEqual(code, 0)

        self.assertEqual(self.paths["BEST_FILE"].read_text().count("\n"), 2)
        badge = json.loads(self.paths["BADGE_FILE"].read_text())
        self.assertEqual(badge["schemaVersion"], 1)

        endpoints = json.loads(self.paths["ENDPOINTS_FILE"].read_text())
        self.assertEqual(endpoints["verified"], 2)
        first = endpoints["endpoints"][0]
        self.assertIn("median_rtt_ms", first)
        self.assertIn("success_rate", first)
        self.assertIn("rtt_trend", first)
        with_meta = [item for item in endpoints["endpoints"] if item["endpoint"] == "1.2.3.4:443"]
        self.assertEqual(with_meta[0]["upstream"]["latency"], 3)

        stats = json.loads(self.paths["STATS_FILE"].read_text())
        self.assertEqual(stats["metadata_sources"][0]["entries"], 1)
        self.assertIn("https://meta.example/p.json", stats["source_history"])
        self.assertIn("dns_cache", stats)
        self.assertEqual(stats["policy"]["best_count"], 20)
        self.assertEqual(stats["best_published"], 2)

        state = json.loads(self.paths["STATE_FILE"].read_text())
        self.assertIn("dns", state)
        entry = state["endpoints"]["1.2.3.4:443"]
        self.assertEqual(entry["rtt_samples"], [25.0])
        self.assertEqual(entry["recent"], [True])

    def test_rtt_history_is_capped(self):
        text = LINK_A
        cfg = collector.Config(min_discovered=1, rtt_history=3, metadata_sources=[])
        with mock.patch.object(collector, "fetch_source", return_value=(text, "", len(text))):
            with mock.patch.object(
                collector,
                "check_proxy",
                side_effect=lambda proxy, config: collector.Outcome(
                    proxy.endpoint, True, rtt_ms=10.0, duration_ms=12.0, engine="stub"
                ),
            ):
                for _ in range(5):
                    collector.run(cfg)
        state = json.loads(self.paths["STATE_FILE"].read_text())
        entry = state["endpoints"]["1.2.3.4:443"]
        self.assertEqual(len(entry["rtt_samples"]), 3)
        self.assertEqual(len(entry["recent"]), 3)
        self.assertEqual(entry["ok_count"], 5)

    def test_dns_guard_uses_the_persisted_cache(self):
        text = LINK_HOST_A
        cfg = collector.Config(min_discovered=1, metadata_sources=[])
        dns_calls = []

        def counting_resolver(host, port, **kwargs):
            dns_calls.append(host)
            return [(2, 1, 6, "", ("1.2.3.4", port or 0))]

        with mock.patch.object(collector, "fetch_source", return_value=(text, "", len(text))):
            with mock.patch.object(collector.socket, "getaddrinfo", counting_resolver):
                with mock.patch.object(
                    collector,
                    "check_proxy",
                    side_effect=lambda proxy, config: collector.Outcome(
                        proxy.endpoint, True, rtt_ms=10.0, engine="stub"
                    ),
                ):
                    collector.run(cfg)
                    collector.run(cfg)

        self.assertEqual(len(dns_calls), 1, "the second run must reuse the cached DNS answer")
        stats = json.loads(self.paths["STATS_FILE"].read_text())
        self.assertEqual(stats["dns_cache"]["hits"], 1)


if __name__ == "__main__":
    unittest.main()
