#!/usr/bin/env python3
"""Unit tests for src/collector.py (stdlib only, no network access).

Run with:  python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import collector  # noqa: E402  (import after sys.path tweak)

NOW = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)

IPV4_LINK = "tg://proxy?server=135.181.74.178&port=443&secret=" + "ab" * 16
DOMAIN_LINK = "https://t.me/proxy?server=Proxy.Example.COM.&port=8443&secret=eeNEgYdJvXrFGRMCIMJdCQ"
IPV6_LINK = "tg://proxy?server=2001:db8::1&port=443&secret=" + "cd" * 16
PRIVATE_LINK = "tg://proxy?server=127.0.0.1&port=443&secret=" + "ab" * 16


def fake_resolver(*addresses: str):
    def resolver(host, port, **kwargs):
        return [
            (2, 1, 6, "", (address, port or 0)) for address in addresses
        ]

    return resolver


class HostParsingTests(unittest.TestCase):
    def test_ipv4_literal(self):
        self.assertEqual(collector.canonical_host("135.181.74.178"), "135.181.74.178")

    def test_ipv6_brackets_are_stripped(self):
        self.assertEqual(collector.canonical_host("[2001:DB8::1]"), "2001:db8::1")

    def test_domain_is_lowercased_and_root_dot_removed(self):
        self.assertEqual(collector.canonical_host("Proxy.Example.COM."), "proxy.example.com")

    def test_rejects_garbage(self):
        for value in ("", " ", "foo..bar", "-foo.com", "foo_bar.com", "a" * 254, "foo.com/path"):
            self.assertIsNone(collector.canonical_host(value), value)

    def test_digits_only_host_is_treated_as_hostname(self):
        # Not a valid IPv4 literal, but a syntactically possible host name.
        self.assertEqual(collector.canonical_host("12345"), "12345")


class PortAndSecretTests(unittest.TestCase):
    def test_port_bounds(self):
        self.assertEqual(collector.canonical_port("443"), 443)
        # Surrounding whitespace is tolerated, everything else is not.
        self.assertEqual(collector.canonical_port(" 8443 "), 8443)
        for value in ("0", "65536", "-1", "abc", "1e3", "443.0"):
            self.assertIsNone(collector.canonical_port(value), value)

    def test_hex_secrets_are_normalized(self):
        self.assertEqual(collector.canonical_secret("AB" * 16), "ab" * 16)
        self.assertEqual(collector.canonical_secret("dd" + "ab" * 16), "dd" + "ab" * 16)

    def test_base64url_secret_is_accepted(self):
        # Regression: the old regex only allowed hex and dropped ~52% of the
        # links published by real sources.
        self.assertEqual(
            collector.canonical_secret("eeNEgYdJvXrFGRMCIMJdCQ"),
            "eeNEgYdJvXrFGRMCIMJdCQ",
        )

    def test_bogus_secrets_are_rejected(self):
        for value in ("", "abc", "zz!!", "ab" * 15, "x" * 300, "ab cd"):
            self.assertIsNone(collector.canonical_secret(value), value)


class LinkParsingTests(unittest.TestCase):
    def test_parses_ipv4_link(self):
        proxy = collector.normalize_proxy(IPV4_LINK)
        self.assertIsNotNone(proxy)
        self.assertEqual(proxy.server, "135.181.74.178")
        self.assertEqual(proxy.port, 443)
        self.assertEqual(proxy.endpoint, "135.181.74.178:443")

    def test_parses_domain_link_with_trailing_dot(self):
        proxy = collector.normalize_proxy(DOMAIN_LINK)
        self.assertIsNotNone(proxy)
        self.assertEqual(proxy.server, "proxy.example.com")
        self.assertEqual(proxy.endpoint, "proxy.example.com:8443")
        self.assertTrue(proxy.url.startswith("tg://proxy?"))

    def test_parses_ipv6_and_brackets_the_url(self):
        proxy = collector.normalize_proxy(IPV6_LINK)
        self.assertIsNotNone(proxy)
        self.assertEqual(proxy.server, "2001:db8::1")
        self.assertEqual(proxy.endpoint, "[2001:db8::1]:443")
        self.assertIn("server=[2001:db8::1]", proxy.url)
        # Round trip through the parser.
        self.assertEqual(collector.normalize_proxy(proxy.url).server, "2001:db8::1")

    def test_http_scheme_is_supported(self):
        link = "http://t.me/proxy?server=1.2.3.4&port=443&secret=" + "ab" * 16
        self.assertIsNotNone(collector.normalize_proxy(link))

    def test_rejection_reasons(self):
        cases = {
            "missing_parameter": "tg://proxy?server=1.2.3.4&port=443",
            "bad_port": "tg://proxy?server=1.2.3.4&port=0&secret=" + "ab" * 16,
            "bad_secret": "tg://proxy?server=1.2.3.4&port=443&secret=nope",
            "bad_host": "tg://proxy?server=foo..bar&port=443&secret=" + "ab" * 16,
            "not_a_proxy_link": "https://example.com/",
        }
        for reason, raw in cases.items():
            proxy, got = collector.parse_proxy(raw)
            self.assertIsNone(proxy, raw)
            self.assertEqual(got, reason, raw)

    def test_extract_links_handles_both_schemes(self):
        text = f"intro {IPV4_LINK}.\n{DOMAIN_LINK}\nhttps://example.com/x"
        links = collector.extract_links(text)
        self.assertEqual(len(links), 2)
        # Trailing sentence punctuation is stripped during parsing.
        self.assertIsNotNone(collector.normalize_proxy(links[0]))


class PublicTargetTests(unittest.TestCase):
    def test_public_literal_allowed(self):
        allowed, reason = collector.is_public_target("135.181.74.178")
        self.assertTrue(allowed)
        self.assertEqual(reason, "ok")

    def test_private_and_metadata_literals_blocked(self):
        for host in ("127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "::1", "fd00::1"):
            allowed, reason = collector.is_public_target(host)
            self.assertFalse(allowed, host)
            self.assertEqual(reason, "non_public_address", host)

    def test_hostname_resolving_to_private_is_blocked(self):
        allowed, reason = collector.is_public_target(
            "evil.example.com", resolver=fake_resolver("127.0.0.1")
        )
        self.assertFalse(allowed)
        self.assertEqual(reason, "non_public_address")

    def test_hostname_with_mixed_answers_is_blocked(self):
        allowed, _ = collector.is_public_target(
            "mixed.example.com", resolver=fake_resolver("1.2.3.4", "10.0.0.5")
        )
        self.assertFalse(allowed)

    def test_public_hostname_allowed(self):
        allowed, reason = collector.is_public_target(
            "good.example.com", resolver=fake_resolver("1.2.3.4", "5.6.7.8")
        )
        self.assertTrue(allowed)
        self.assertEqual(reason, "ok")

    def test_unresolvable_host_is_blocked(self):
        def failing(host, port, **kwargs):
            raise OSError("name resolution failed")

        allowed, reason = collector.is_public_target("nx.example.com", resolver=failing)
        self.assertFalse(allowed)
        self.assertEqual(reason, "dns_no_addresses")


class DedupeTests(unittest.TestCase):
    def test_one_link_per_endpoint(self):
        first = collector.normalize_proxy(IPV4_LINK)
        second = collector.normalize_proxy(
            "tg://proxy?server=135.181.74.178&port=443&secret=" + "ef" * 16
        )
        third = collector.normalize_proxy(
            "tg://proxy?server=135.181.74.178&port=8443&secret=" + "ef" * 16
        )
        kept, alternates = collector.dedupe_by_endpoint([first, second, third])
        self.assertEqual([p.endpoint for p in kept], ["135.181.74.178:443", "135.181.74.178:8443"])
        self.assertEqual(alternates["135.181.74.178:443"], [second.url])

    def test_preferred_url_wins(self):
        first = collector.normalize_proxy(IPV4_LINK)
        second = collector.normalize_proxy(
            "tg://proxy?server=135.181.74.178&port=443&secret=" + "ef" * 16
        )
        kept, alternates = collector.dedupe_by_endpoint(
            [first, second], preferred_urls={first.endpoint: second.url}
        )
        self.assertEqual(kept[0].url, second.url)
        self.assertIn(first.url, alternates[first.endpoint])


class SelectionTests(unittest.TestCase):
    def _proxies(self, count: int):
        return [
            collector.Proxy(
                url=f"tg://proxy?server=10.0.0.{i}&port=443&secret={'ab' * 16}",
                server=f"10.0.0.{i}",
                port=443,
                secret="ab" * 16,
            )
            for i in range(count)
        ]

    def test_spread_sample_covers_head_and_tail(self):
        items = list(range(100))
        picked = collector.spread_sample(items, 10)
        self.assertEqual(len(picked), 10)
        self.assertEqual(len(set(picked)), 10)
        self.assertLess(picked[0], 10)
        self.assertGreater(picked[-1], 80)

    def test_spread_sample_returns_everything_when_limit_is_large(self):
        items = list(range(5))
        self.assertEqual(collector.spread_sample(items, 10), items)
        self.assertEqual(collector.spread_sample(items, 0), items)

    def test_rotation_changes_selection(self):
        items = list(range(20))
        first = collector.spread_sample(items, 4, rotation=0)
        second = collector.spread_sample(items, 4, rotation=5)
        self.assertNotEqual(first, second)

    def test_select_candidates_prefers_known_good_and_respects_limit(self):
        candidates = self._proxies(40)
        state = {
            "runs": 0,
            "endpoints": {
                candidates[30].endpoint: {"last_ok": NOW.isoformat(), "url": candidates[30].url},
                candidates[39].endpoint: {"last_ok": NOW.isoformat(), "url": candidates[39].url},
            },
        }
        cfg = collector.Config(max_candidates=10, known_good_hours=6)
        selected = collector.select_candidates(candidates, state, cfg, NOW)
        endpoints = {p.endpoint for p in selected}
        self.assertEqual(len(selected), 10)
        self.assertIn(candidates[30].endpoint, endpoints)
        self.assertIn(candidates[39].endpoint, endpoints)

    def test_stale_known_good_is_not_prioritized(self):
        candidates = self._proxies(40)
        state = {
            "runs": 0,
            "endpoints": {
                candidates[0].endpoint: {
                    "last_ok": (NOW - timedelta(hours=48)).isoformat(),
                    "url": candidates[0].url,
                }
            },
        }
        self.assertFalse(
            collector.recently_ok(state, candidates[0].endpoint, 6, NOW)
        )


class GuardTests(unittest.TestCase):
    def test_healthy_run_publishes(self):
        published, reasons = collector.evaluate_guard(25, 18, 20, 1, collector.Config())
        self.assertTrue(published)
        self.assertEqual(reasons, [])

    def test_all_sources_failed_blocks_publish(self):
        published, reasons = collector.evaluate_guard(0, 0, 20, 0, collector.Config())
        self.assertFalse(published)
        self.assertIn("all_sources_failed", reasons)
        self.assertIn("nothing_discovered", reasons)

    def test_too_few_discovered_blocks_publish(self):
        published, reasons = collector.evaluate_guard(3, 2, 0, 1, collector.Config(min_discovered=10))
        self.assertFalse(published)
        self.assertTrue(any(r.startswith("too_few_discovered") for r in reasons))

    def test_sudden_verification_drop_blocks_publish(self):
        published, reasons = collector.evaluate_guard(100, 3, 40, 1, collector.Config())
        self.assertFalse(published)
        self.assertTrue(any(r.startswith("verified_drop") for r in reasons))

    def test_allow_degraded_overrides(self):
        published, reasons = collector.evaluate_guard(
            0, 0, 0, 0, collector.Config(allow_degraded=True)
        )
        self.assertTrue(published)
        self.assertIn("all_sources_failed", reasons)


class StateTests(unittest.TestCase):
    def test_update_state_records_results_and_sources(self):
        proxy = collector.normalize_proxy(IPV4_LINK)
        state = collector.load_state(Path("/nonexistent/state.json"))
        outcomes = [
            (proxy, collector.Outcome(proxy.endpoint, True, rtt_ms=120.0, engine="library"))
        ]
        collector.update_state(
            state,
            [proxy],
            outcomes,
            {proxy.endpoint: ["https://source.example/list.txt"]},
            NOW,
        )
        entry = state["endpoints"][proxy.endpoint]
        self.assertEqual(entry["ok_count"], 1)
        self.assertEqual(entry["last_ok"], NOW.isoformat())
        self.assertEqual(entry["last_rtt_ms"], 120.0)
        self.assertEqual(entry["sources"], ["https://source.example/list.txt"])
        self.assertEqual(state["runs"], 1)

    def test_failed_check_is_recorded(self):
        proxy = collector.normalize_proxy(IPV4_LINK)
        state = collector.load_state(Path("/nonexistent/state.json"))
        collector.update_state(
            state,
            [proxy],
            [(proxy, collector.Outcome(proxy.endpoint, False, error="PROTOCOL_ERROR"))],
            {},
            NOW,
        )
        entry = state["endpoints"][proxy.endpoint]
        self.assertEqual(entry["fail_count"], 1)
        self.assertIsNone(entry["last_ok"])
        self.assertEqual(entry["last_error"], "PROTOCOL_ERROR")

    def test_stable_entries_respect_ttl(self):
        fresh = collector.normalize_proxy(IPV4_LINK)
        stale = collector.normalize_proxy(
            "tg://proxy?server=1.2.3.4&port=443&secret=" + "ab" * 16
        )
        state = {"runs": 2, "endpoints": {}}
        collector.update_state(
            state,
            [fresh, stale],
            [
                (fresh, collector.Outcome(fresh.endpoint, True, rtt_ms=50.0)),
                (stale, collector.Outcome(stale.endpoint, True, rtt_ms=80.0)),
            ],
            {},
            NOW,
        )
        state["endpoints"][stale.endpoint]["last_ok"] = (NOW - timedelta(hours=30)).isoformat()
        stable = collector.stable_entries(state, ttl_hours=24, now=NOW)
        self.assertEqual([item["endpoint"] for item in stable], [fresh.endpoint])

    def test_prune_state_drops_old_entries(self):
        old = collector.normalize_proxy(IPV4_LINK)
        state = {
            "endpoints": {
                old.endpoint: {
                    "last_seen": (NOW - timedelta(days=30)).isoformat(),
                    "url": old.url,
                },
                "keep:1": {"last_seen": NOW.isoformat(), "url": "tg://proxy?x"},
            }
        }
        collector.prune_state(state, now=NOW, keep_days=14.0)
        self.assertNotIn(old.endpoint, state["endpoints"])
        self.assertIn("keep:1", state["endpoints"])

    def test_corrupted_state_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            path.write_text("{not json", encoding="utf-8")
            state = collector.load_state(path)
            self.assertEqual(state["endpoints"], {})
            self.assertEqual(state["runs"], 0)


class AdsMetadataTests(unittest.TestCase):
    def test_statuses(self):
        ads = {
            "a:1": {"has_ads": True, "channel": "@spam", "checked_at": "2026-10-09T00:00:00+00:00"},
            "b:1": {"has_ads": False},
            "c:1": {"has_ads": None},
        }
        self.assertEqual(collector.ads_for(ads, "a:1")["status"], "present")
        self.assertEqual(collector.ads_for(ads, "a:1")["channel"], "@spam")
        self.assertEqual(collector.ads_for(ads, "b:1")["status"], "none")
        self.assertEqual(collector.ads_for(ads, "c:1")["status"], "unknown")
        self.assertEqual(collector.ads_for(ads, "missing:1")["status"], "unknown")


class EndToEndTests(unittest.TestCase):
    """Exercise run() with patched paths, sources and health checks."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.patches = {
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
        for name, value in self.patches.items():
            patcher = mock.patch.object(collector, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _run(
        self,
        text: str,
        ok: bool,
        cfg: collector.Config | None = None,
        metadata: str = "",
        metadata_ok: bool = True,
    ) -> int:
        cfg = cfg or collector.Config(min_discovered=2)

        def fake_fetch(url: str, config) -> tuple[str, str, int]:
            if config.metadata_sources and url in config.metadata_sources:
                return (metadata, "" if metadata_ok else "", len(metadata))
            return (text, "", len(text))

        with mock.patch.object(collector, "fetch_source", side_effect=fake_fetch):
            with mock.patch.object(
                collector,
                "check_proxy",
                side_effect=lambda proxy, config: collector.Outcome(
                    proxy.endpoint, ok, rtt_ms=10.0, duration_ms=12.0, engine="stub"
                ),
            ):
                return collector.run(cfg)

    def test_successful_run_writes_all_outputs(self):
        text = "\n".join(
            [
                "tg://proxy?server=1.2.3.4&port=443&secret=" + "ab" * 16,
                "tg://proxy?server=5.6.7.8&port=443&secret=" + "cd" * 16,
            ]
        )
        code = self._run(text, ok=True)
        self.assertEqual(code, 0)
        self.assertEqual(self.patches["ALL_FILE"].read_text().count("\n"), 2)
        self.assertEqual(self.patches["WORKING_FILE"].read_text().count("\n"), 2)
        self.assertEqual(self.patches["STABLE_FILE"].read_text().count("\n"), 2)
        stats = json.loads(self.patches["STATS_FILE"].read_text())
        self.assertTrue(stats["published"])
        self.assertEqual(stats["discovered"], 2)
        self.assertEqual(stats["mtproto_verified"], 2)
        state = json.loads(self.patches["STATE_FILE"].read_text())
        self.assertEqual(state["runs"], 1)
        self.assertEqual(state["meta"]["last_working_count"], 2)
        endpoints = json.loads(self.patches["ENDPOINTS_FILE"].read_text())
        self.assertEqual(endpoints["count"], 2)
        self.assertEqual(endpoints["endpoints"][0]["ads"]["status"], "unknown")

    def test_empty_discovery_keeps_previous_lists(self):
        good = "tg://proxy?server=1.2.3.4&port=443&secret=" + "ab" * 16
        self.assertEqual(self._run(good, ok=True, cfg=collector.Config(min_discovered=1)), 0)
        before_all = self.patches["ALL_FILE"].read_text()
        before_working = self.patches["WORKING_FILE"].read_text()

        code = self._run("", ok=False)
        self.assertEqual(code, 2, "guard must trip and keep the published lists")
        self.assertEqual(self.patches["ALL_FILE"].read_text(), before_all)
        self.assertEqual(self.patches["WORKING_FILE"].read_text(), before_working)
        stats = json.loads(self.patches["STATS_FILE"].read_text())
        self.assertFalse(stats["published"])
        self.assertIn("nothing_discovered", stats["publish_blocked_reasons"])

    def test_private_endpoints_are_never_checked(self):
        text = "tg://proxy?server=127.0.0.1&port=443&secret=" + "ab" * 16
        code = self._run(text, ok=True)
        self.assertEqual(code, 2)  # nothing publishable discovered
        stats = json.loads(self.patches["STATS_FILE"].read_text())
        # The endpoint was discovered but blocked by the public-address guard,
        # so no connection to it was ever attempted.
        self.assertEqual(stats["blocked_non_public"], 1)
        self.assertEqual(stats["block_reasons"], {"non_public_address": 1})
        self.assertEqual(stats["mtproto_verified"], 0)

    def test_dns_guard_blocks_private_hostname(self):
        text = "tg://proxy?server=internal.example.com&port=443&secret=" + "ab" * 16
        cfg = collector.Config(min_discovered=1)
        with mock.patch.object(
            collector, "is_public_target", return_value=(False, "non_public_address")
        ):
            with mock.patch.object(
                collector, "fetch_source", return_value=(text, "", len(text))
            ):
                code = collector.run(cfg)
        self.assertEqual(code, 2)
        stats = json.loads(self.patches["STATS_FILE"].read_text())
        self.assertEqual(stats["blocked_non_public"], 1)
        self.assertEqual(stats["block_reasons"], {"non_public_address": 1})

    def test_duplicate_endpoints_are_checked_once(self):
        text = "\n".join(
            [
                "tg://proxy?server=1.2.3.4&port=443&secret=" + "ab" * 16,
                "tg://proxy?server=1.2.3.4&port=443&secret=" + "cd" * 16,
            ]
        )
        code = self._run(text, ok=True, cfg=collector.Config(min_discovered=1))
        self.assertEqual(code, 0)
        stats = json.loads(self.patches["STATS_FILE"].read_text())
        self.assertEqual(stats["discovered"], 1)
        # The second advertisement of the same endpoint is recorded, not checked.
        self.assertEqual(stats["duplicate_endpoints_removed"], 1)
        self.assertEqual(stats["checked_candidates"], 1)
        self.assertEqual(self.patches["ALL_FILE"].read_text().count("\n"), 1)


if __name__ == "__main__":
    unittest.main()
