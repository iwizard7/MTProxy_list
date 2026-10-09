#!/usr/bin/env python3
"""Unit tests for src/adcheck.py (stdlib only; Telethon is never imported).

Run with:  python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import adcheck  # noqa: E402

NOW = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)
LINK = "tg://proxy?server=135.181.74.178&port=443&secret=" + "ab" * 16


class VerdictTests(unittest.TestCase):
    def test_proxy_promo_with_peer_means_ads(self):
        data = SimpleNamespace(proxy=True, peer=SimpleNamespace(channel_id=123), expires=60, psa_type=None)
        verdict = adcheck.verdict_from_promo_data(data)
        self.assertTrue(verdict["has_ads"])
        self.assertEqual(verdict["channel"], "channel:123")
        self.assertEqual(verdict["expires"], 60)

    def test_resolved_name_wins(self):
        data = SimpleNamespace(proxy=True, peer=SimpleNamespace(channel_id=123), expires=None)
        verdict = adcheck.verdict_from_promo_data(data, resolved_name="@spam_channel")
        self.assertEqual(verdict["channel"], "@spam_channel")

    def test_proxy_flag_without_peer_is_not_ads(self):
        data = SimpleNamespace(proxy=True, peer=None, expires=None)
        verdict = adcheck.verdict_from_promo_data(data)
        self.assertFalse(verdict["has_ads"])
        self.assertIsNone(verdict["channel"])

    def test_plain_promo_data_is_not_ads(self):
        data = SimpleNamespace(proxy=False, peer=SimpleNamespace(channel_id=9), expires=None)
        verdict = adcheck.verdict_from_promo_data(data)
        self.assertFalse(verdict["has_ads"])
        self.assertIsNone(verdict["channel"])
        self.assertEqual(verdict["peer"], "channel:9")

    def test_empty_response_is_not_ads(self):
        verdict = adcheck.verdict_from_promo_data(SimpleNamespace())
        self.assertFalse(verdict["has_ads"])
        self.assertIsNone(verdict["channel"])

    def test_describe_peer_variants(self):
        self.assertIsNone(adcheck.describe_peer(None))
        self.assertEqual(adcheck.describe_peer(SimpleNamespace(username="chan")), "chan")
        self.assertEqual(adcheck.describe_peer(SimpleNamespace(title="Title")), "Title")
        self.assertEqual(adcheck.describe_peer(SimpleNamespace(user_id=5)), "user:5")
        self.assertEqual(adcheck.describe_peer(SimpleNamespace(chat_id=6)), "chat:6")
        self.assertEqual(adcheck.describe_peer(SimpleNamespace()), "SimpleNamespace")

    def test_channel_is_resolved_from_the_response_entities(self):
        # help.promoData ships the promoted channel in its own chats list, so no
        # extra request is needed to name it.
        data = SimpleNamespace(
            proxy=True,
            peer=SimpleNamespace(channel_id=777),
            chats=[SimpleNamespace(id=1, title="other"), SimpleNamespace(id=777, username="promo_chan")],
            users=[],
            expires=None,
        )
        self.assertEqual(adcheck.resolve_channel_from_promo(data, data.peer), "promo_chan")
        self.assertEqual(adcheck.verdict_from_promo_data(data)["channel"], "promo_chan")

    def test_channel_resolution_falls_back_to_ids(self):
        data = SimpleNamespace(proxy=True, peer=SimpleNamespace(channel_id=5), chats=[], users=[], expires=None)
        verdict = adcheck.verdict_from_promo_data(data)
        self.assertTrue(verdict["has_ads"])
        self.assertEqual(verdict["channel"], "channel:5")

    def test_expires_accepts_datetime_and_int(self):
        dt = datetime(2026, 10, 10, tzinfo=timezone.utc)
        self.assertEqual(
            adcheck.verdict_from_promo_data(SimpleNamespace(expires=dt))["expires"],
            dt.isoformat(),
        )
        self.assertEqual(
            adcheck.verdict_from_promo_data(SimpleNamespace(expires=60))["expires"], 60
        )
        self.assertIsNone(
            adcheck.verdict_from_promo_data(SimpleNamespace(expires="later"))["expires"]
        )


class SecretKindTests(unittest.TestCase):
    def test_hex_secrets(self):
        self.assertEqual(adcheck.secret_kind("ab" * 16), "plain")
        self.assertEqual(adcheck.secret_kind("dd" + "ab" * 16), "dd")
        self.assertEqual(adcheck.secret_kind("ee" + "ab" * 16 + "6578616d706c65"), "faketls")

    def test_base64_secrets(self):
        import base64 as b64

        def encode(first_byte: int) -> str:
            payload = bytes([first_byte]) + bytes(range(16))
            return b64.urlsafe_b64encode(payload).decode().rstrip("=")

        self.assertEqual(adcheck.secret_kind(encode(0xDD)), "dd")
        self.assertEqual(adcheck.secret_kind(encode(0xEE)), "faketls")
        self.assertEqual(adcheck.secret_kind(encode(0x01)), "plain")
        # A real sample from the published list: base64url of a dd-secure secret.
        self.assertEqual(adcheck.secret_kind("3XnnAQIAAQAH8AMDhuJMOt0"), "dd")

    def test_unknown_secrets(self):
        self.assertEqual(adcheck.secret_kind(""), "unknown")
        self.assertEqual(adcheck.secret_kind("zzzz"), "unknown")

    def test_connection_classes_by_kind(self):
        class FakeConnection:
            ConnectionTcpMTProxyRandomizedIntermediate = "randomized"
            ConnectionTcpMTProxyIntermediate = "intermediate"
            ConnectionTcpMTProxyAbridged = "abridged"

        self.assertEqual(
            adcheck.connection_classes_for("dd", FakeConnection), ["randomized"]
        )
        self.assertEqual(
            adcheck.connection_classes_for("plain", FakeConnection),
            ["intermediate", "abridged"],
        )
        self.assertEqual(adcheck.connection_classes_for("faketls", FakeConnection), [])
        self.assertEqual(adcheck.connection_classes_for("unknown", FakeConnection), [])


class TargetTests(unittest.TestCase):
    def test_make_target_accepts_domain_and_rejects_junk(self):
        proxy = adcheck.make_target("Example.COM.", "8443", "ab" * 16)
        self.assertIsNotNone(proxy)
        self.assertEqual(proxy.endpoint, "example.com:8443")
        self.assertIsNone(adcheck.make_target("bad..host", "8443", "ab" * 16))
        self.assertIsNone(adcheck.make_target("1.2.3.4", "0", "ab" * 16))
        self.assertIsNone(adcheck.make_target("1.2.3.4", "443", "junk"))

    def test_targets_from_working_skips_junk_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "working.txt"
            path.write_text(f"{LINK}\nnot-a-link\n\n{LINK}\n", encoding="utf-8")
            targets = adcheck.targets_from_working(path)
            self.assertEqual([t.endpoint for t in targets], ["135.181.74.178:443"])

    def test_targets_from_endpoints_reads_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "endpoints.json"
            path.write_text(
                json.dumps({"endpoints": [{"url": LINK}, {"url": "nonsense"}, {}]}),
                encoding="utf-8",
            )
            targets = adcheck.targets_from_endpoints(path)
            self.assertEqual(len(targets), 1)
            self.assertEqual(targets[0].endpoint, "135.181.74.178:443")

    def test_targets_from_missing_files_is_empty(self):
        self.assertEqual(adcheck.targets_from_working(Path("/nope/working.txt")), [])
        self.assertEqual(adcheck.targets_from_endpoints(Path("/nope/endpoints.json")), [])

    def test_select_targets_prefers_explicit_proxy(self):
        proxy = adcheck.make_target("1.2.3.4", "443", "ab" * 16)
        args = SimpleNamespace(from_endpoints=True)
        self.assertEqual(adcheck.select_targets(proxy, args), [proxy])


class CacheTests(unittest.TestCase):
    def test_fresh_and_stale_entries(self):
        self.assertTrue(
            adcheck.is_fresh({"checked_at": NOW.isoformat()}, NOW, cache_days=7)
        )
        self.assertFalse(
            adcheck.is_fresh(
                {"checked_at": (NOW - timedelta(days=8)).isoformat()}, NOW, cache_days=7
            )
        )

    def test_invalid_or_missing_timestamps_are_not_fresh(self):
        self.assertFalse(adcheck.is_fresh({}, NOW, cache_days=7))
        self.assertFalse(adcheck.is_fresh({"checked_at": "garbage"}, NOW, cache_days=7))
        self.assertFalse(
            adcheck.is_fresh({"checked_at": NOW.isoformat()}, NOW, cache_days=0)
        )

    def test_load_ads_tolerates_missing_and_corrupt_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "none.json"
            self.assertEqual(adcheck.load_ads(missing)["results"], {})
            corrupt = Path(tmp) / "bad.json"
            corrupt.write_text("{not json", encoding="utf-8")
            self.assertEqual(adcheck.load_ads(corrupt)["results"], {})

    def test_save_ads_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ads.json"
            adcheck.save_ads({"results": {"a:1": {"has_ads": True}}}, path)
            self.assertTrue(json.loads(path.read_text())["results"]["a:1"]["has_ads"])


class CheckAllTests(unittest.TestCase):
    """check_all() with the Telethon probe stubbed out."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ads_path = Path(self.tmp.name) / "ads.json"
        self.patch = mock.patch.object(adcheck, "ADS_FILE", self.ads_path)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        for name, value in (
            ("TELEGRAM_API_ID", "123"),
            ("TELEGRAM_API_HASH", "abc"),
            ("TELEGRAM_SESSION", "session"),
        ):
            patcher = mock.patch.dict("os.environ", {name: value})
            patcher.start()
            self.addCleanup(patcher.stop)

    def _args(self, **overrides):
        base = {"force": False, "cache_days": 7.0, "delay": 0.0, "timeout": 5.0}
        base.update(overrides)
        return SimpleNamespace(**base)

    def test_probe_result_is_recorded(self):
        proxy = adcheck.make_target("1.2.3.4", "443", "ab" * 16)

        async def fake_probe(target, api_id, api_hash, session, timeout):
            return adcheck.verdict_from_promo_data(
                SimpleNamespace(proxy=True, peer=SimpleNamespace(channel_id=7), expires=None)
            )

        with mock.patch.object(adcheck, "probe_endpoint", side_effect=fake_probe):
            results = adcheck.check_all([proxy], self._args(), NOW)

        entry = results[proxy.endpoint]
        self.assertTrue(entry["has_ads"])
        self.assertEqual(entry["checked_at"], NOW.isoformat())
        self.assertEqual(entry["url"], proxy.url)

    def test_error_is_recorded_not_raised(self):
        proxy = adcheck.make_target("1.2.3.4", "443", "ab" * 16)

        async def failing_probe(*args, **kwargs):
            raise OSError("connection refused")

        with mock.patch.object(adcheck, "probe_endpoint", side_effect=failing_probe):
            results = adcheck.check_all([proxy], self._args(), NOW)
        self.assertIn("connection refused", results[proxy.endpoint]["error"])
        self.assertIsNone(results[proxy.endpoint]["has_ads"])

    def test_cached_entry_is_not_reprobed(self):
        proxy = adcheck.make_target("1.2.3.4", "443", "ab" * 16)
        adcheck.save_ads(
            {
                "results": {
                    proxy.endpoint: {"has_ads": False, "checked_at": NOW.isoformat()}
                }
            },
            self.ads_path,
        )
        with mock.patch.object(adcheck, "probe_endpoint") as probe:
            results = adcheck.check_all([proxy], self._args(), NOW)
        probe.assert_not_called()
        self.assertFalse(results[proxy.endpoint]["has_ads"])

    def test_force_ignores_cache(self):
        proxy = adcheck.make_target("1.2.3.4", "443", "ab" * 16)
        adcheck.save_ads(
            {
                "results": {
                    proxy.endpoint: {"has_ads": False, "checked_at": NOW.isoformat()}
                }
            },
            self.ads_path,
        )

        async def fake_probe(*args, **kwargs):
            return {"has_ads": True, "channel": "@spam"}

        with mock.patch.object(adcheck, "probe_endpoint", side_effect=fake_probe):
            results = adcheck.check_all([proxy], self._args(force=True), NOW)
        self.assertTrue(results[proxy.endpoint]["has_ads"])

    def test_missing_credentials_exit_with_message(self):
        proxy = adcheck.make_target("1.2.3.4", "443", "ab" * 16)
        with mock.patch.dict("os.environ", {"TELEGRAM_SESSION": ""}):
            with self.assertRaises(SystemExit):
                adcheck.check_all([proxy], self._args(), NOW)


class MainTests(unittest.TestCase):
    def test_dry_run_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            working = Path(tmp) / "working.txt"
            working.write_text(f"{LINK}\n", encoding="utf-8")
            ads_path = Path(tmp) / "ads.json"
            with mock.patch.object(adcheck, "WORKING_FILE", working), mock.patch.object(
                adcheck, "ADS_FILE", ads_path
            ):
                code = adcheck.main(["--dry-run"])
            self.assertEqual(code, 0)
            self.assertFalse(ads_path.exists())

    def test_unknown_endpoint_returns_3(self):
        with tempfile.TemporaryDirectory() as tmp:
            working = Path(tmp) / "working.txt"
            working.write_text(f"{LINK}\n", encoding="utf-8")
            with mock.patch.object(adcheck, "WORKING_FILE", working), mock.patch.object(
                adcheck, "ENDPOINTS_FILE", Path(tmp) / "missing.json"
            ):
                code = adcheck.main(["--endpoint", "9.9.9.9:443", "--dry-run"])
            self.assertEqual(code, 3)


if __name__ == "__main__":
    unittest.main()
