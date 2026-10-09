#!/usr/bin/env python3
"""Tests for src/publish.py (the GitHub Pages site builder).

Stdlib only, no network: builds a site from synthetic data directories.

Run with:  python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import publish  # noqa: E402

NOW = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)


def write_fixture(data_dir: Path, *, stats_updated_at: str = "2026-10-09T11:59:00+00:00") -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "working.txt").write_text("tg://proxy?a=1\ntg://proxy?a=2\n", encoding="utf-8")
    (data_dir / "stable.txt").write_text("tg://proxy?a=1\n", encoding="utf-8")
    (data_dir / "best.txt").write_text("tg://proxy?a=1\n", encoding="utf-8")
    (data_dir / "all.txt").write_text("tg://proxy?a=1\ntg://proxy?a=2\ntg://proxy?a=3\n", encoding="utf-8")
    (data_dir / "stats.json").write_text(
        json.dumps(
            {
                "updated_at": stats_updated_at,
                "discovered": 3,
                "checked_candidates": 3,
                "mtproto_verified": 2,
                "stable_in_window": 1,
                "best_published": 1,
                "sources_ok": 2,
                "sources_total": 2,
                "average_rtt_ms": 123.45,
                "median_rtt_ms": 100.0,
                "published": True,
            }
        ),
        encoding="utf-8",
    )
    (data_dir / "endpoints.json").write_text(
        json.dumps({"count": 3, "verified": 2, "endpoints": []}), encoding="utf-8"
    )
    (data_dir / "badge.json").write_text(
        json.dumps({"schemaVersion": 1, "label": "verified proxies", "message": "2 now", "color": "orange"}),
        encoding="utf-8",
    )
    (data_dir / "ads.json").write_text(json.dumps({"results": {}}), encoding="utf-8")
    # Internal state must never end up on the public site.
    (data_dir / "state.json").write_text(json.dumps({"runs": 5}), encoding="utf-8")


class BuildSiteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.data = self.root / "proxies"
        self.site = self.root / "public"
        write_fixture(self.data)

    def test_copies_published_files_and_writes_site_scaffolding(self):
        manifest = publish.build_site(self.data, self.site, generated_at=NOW)

        for name in ("working.txt", "stable.txt", "best.txt", "all.txt", "stats.json", "endpoints.json", "badge.json", "ads.json"):
            self.assertTrue((self.site / name).is_file(), name)
        self.assertTrue((self.site / "index.html").is_file())
        self.assertTrue((self.site / "manifest.json").is_file())
        self.assertTrue((self.site / ".nojekyll").is_file())

        # Internal state is deliberately excluded from the site.
        self.assertFalse((self.site / "state.json").exists())
        self.assertNotIn("state.json", manifest["files"])

    def test_manifest_hashes_and_counts(self):
        manifest = publish.build_site(self.data, self.site, generated_at=NOW)

        working = self.data / "working.txt"
        entry = manifest["files"]["working.txt"]
        self.assertEqual(entry["sha256"], hashlib.sha256(working.read_bytes()).hexdigest())
        self.assertEqual(entry["bytes"], working.stat().st_size)
        self.assertEqual(entry["lines"], 2)
        self.assertNotIn("lines", manifest["files"]["stats.json"])

        self.assertEqual(manifest["counts"]["verified"], 2)
        self.assertEqual(manifest["counts"]["discovered"], 3)
        self.assertEqual(manifest["counts"]["median_rtt_ms"], 100.0)
        self.assertEqual(manifest["generated_at"], NOW.isoformat())
        self.assertEqual(manifest["data_branch"], "data")

    def test_index_shows_counts_and_usage(self):
        publish.build_site(
            self.data, self.site, site_url="https://example.github.io/repo", generated_at=NOW
        )
        page = (self.site / "index.html").read_text(encoding="utf-8")
        self.assertIn("MTProto proxy list", page)
        self.assertIn("https://example.github.io/repo/working.txt", page)
        self.assertIn("Verified now", page)
        self.assertIn("2", page)
        self.assertIn("manifest.json", page)
        # Telegram-specific caveats must stay on the page.
        self.assertIn("sponsored channel", page)
        self.assertIn("help.getPromoData", page)

    def test_dynamic_values_are_html_escaped(self):
        write_fixture(self.data, stats_updated_at='<script>alert("x")</script>')
        publish.build_site(self.data, self.site, generated_at=NOW)
        page = (self.site / "index.html").read_text(encoding="utf-8")
        self.assertNotIn("<script>alert", page)
        self.assertIn("&lt;script&gt;", page)

    def test_commit_from_argument_or_environment(self):
        manifest = publish.build_site(self.data, self.site, commit="abcdef1234567890", generated_at=NOW)
        self.assertEqual(manifest["commit"], "abcdef1234567890")
        page = (self.site / "index.html").read_text(encoding="utf-8")
        self.assertIn("code revision", page)
        self.assertIn("abcdef123456", page)

        with mock.patch.dict("os.environ", {"GITHUB_SHA": "deadbeefcafe1234"}):
            manifest = publish.build_site(self.data, self.site, generated_at=NOW)
        self.assertEqual(manifest["commit"], "deadbeefcafe1234")

    def test_data_commit_is_reported_separately(self):
        # commit = code revision, data_commit = data branch revision: consumers
        # need the second one to pin an exact dataset.
        manifest = publish.build_site(
            self.data,
            self.site,
            commit="coderev0000000000",
            data_commit="datarev1111111111",
            generated_at=NOW,
        )
        self.assertEqual(manifest["commit"], "coderev0000000000")
        self.assertEqual(manifest["data_commit"], "datarev1111111111")
        page = (self.site / "index.html").read_text(encoding="utf-8")
        self.assertIn("data revision", page)
        self.assertIn("datarev11111", page)
        self.assertIn("code revision", page)

        with mock.patch.dict("os.environ", {"DATA_COMMIT": "envrev2222222222"}):
            manifest = publish.build_site(self.data, self.site, generated_at=NOW)
        self.assertEqual(manifest["data_commit"], "envrev2222222222")

    def test_data_commit_is_null_when_unknown(self):
        manifest = publish.build_site(
            self.data, self.site, commit=None, data_commit=None, generated_at=NOW
        )
        with mock.patch.dict("os.environ", {"GITHUB_SHA": "", "DATA_COMMIT": ""}):
            manifest = publish.build_site(self.data, self.site, generated_at=NOW)
        self.assertIsNone(manifest["data_commit"])

    def test_missing_optional_files_are_skipped(self):
        (self.data / "ads.json").unlink()
        (self.data / "best.txt").unlink()
        manifest = publish.build_site(self.data, self.site, generated_at=NOW)
        self.assertNotIn("ads.json", manifest["files"])
        self.assertNotIn("best.txt", manifest["files"])
        self.assertTrue((self.site / "index.html").is_file())

    def test_broken_stats_json_still_produces_a_page(self):
        (self.data / "stats.json").write_text("{not json", encoding="utf-8")
        manifest = publish.build_site(self.data, self.site, generated_at=NOW)
        self.assertIsNone(manifest["counts"]["verified"])
        page = (self.site / "index.html").read_text(encoding="utf-8")
        self.assertIn("—", page)

    def test_empty_data_dir_still_produces_a_page(self):
        empty = self.root / "empty"
        empty.mkdir()
        site = self.root / "empty-site"
        manifest = publish.build_site(empty, site, generated_at=NOW)
        self.assertEqual(manifest["files"], {})
        self.assertTrue((site / "index.html").is_file())

    def test_rebuild_overwrites_stale_files(self):
        publish.build_site(self.data, self.site, generated_at=NOW)
        (self.data / "working.txt").write_text("tg://proxy?only=1\n", encoding="utf-8")
        manifest = publish.build_site(self.data, self.site, generated_at=NOW)
        self.assertEqual(manifest["files"]["working.txt"]["lines"], 1)
        self.assertEqual(
            (self.site / "working.txt").read_text(encoding="utf-8"), "tg://proxy?only=1\n"
        )


class CliTests(unittest.TestCase):
    def test_cli_builds_site_and_reports_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = root / "proxies"
            site = root / "public"
            write_fixture(data)
            code = publish.main(
                ["--data-dir", str(data), "--site-dir", str(site), "--site-url", "https://x.test/repo"]
            )
            self.assertEqual(code, 0)
            manifest = json.loads((site / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["counts"]["verified"], 2)

    def test_cli_reports_missing_data_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            code = publish.main(
                ["--data-dir", str(Path(tmp) / "nope"), "--site-dir", str(Path(tmp) / "site")]
            )
            self.assertEqual(code, 3)

    def test_cli_reads_data_dir_from_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = root / "proxies"
            site = root / "public"
            write_fixture(data)
            with mock.patch.dict("os.environ", {"DATA_DIR": str(data)}):
                code = publish.main(["--site-dir", str(site)])
            self.assertEqual(code, 0)
            self.assertTrue((site / "index.html").is_file())


if __name__ == "__main__":
    unittest.main()
