#!/usr/bin/env python3
"""Validate the published JSON files against docs/schema/*.json.

The repository ships JSON Schema files and this test validates real, produced
output against them using a small stdlib-only validator (no `jsonschema`
dependency). This catches accidental renames or removals of published fields —
the kind of change that silently breaks downstream consumers.

Run with:  python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "docs" / "schema"
sys.path.insert(0, str(ROOT / "src"))

import adcheck  # noqa: E402
import collector  # noqa: E402

LINK_A = "tg://proxy?server=1.2.3.4&port=443&secret=" + "ab" * 16
LINK_B = "tg://proxy?server=5.6.7.8&port=443&secret=" + "cd" * 16


# ---------------------------------------------------------------------------
# Minimal JSON Schema validator (only the keywords used by our schemas)
# ---------------------------------------------------------------------------
TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "null": type(None),
}


def validate(instance, schema: dict, path: str = "$") -> list[str]:
    """Return a list of human readable validation errors (empty = valid)."""
    errors: list[str] = []

    expected = schema.get("type")
    if expected is not None:
        allowed = expected if isinstance(expected, list) else [expected]
        matched = False
        for name in allowed:
            python_type = TYPES[name]
            if name in ("integer", "number") and isinstance(instance, bool):
                continue
            if isinstance(instance, python_type):
                matched = True
                break
        if not matched:
            return [f"{path}: expected {allowed}, got {type(instance).__name__}"]

    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: expected const {schema['const']!r}, got {instance!r}")

    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: {instance!r} is not one of {schema['enum']!r}")

    if "minimum" in schema and isinstance(instance, (int, float)) and instance < schema["minimum"]:
        errors.append(f"{path}: {instance} < minimum {schema['minimum']}")

    if "maximum" in schema and isinstance(instance, (int, float)) and instance > schema["maximum"]:
        errors.append(f"{path}: {instance} > maximum {schema['maximum']}")

    if isinstance(instance, dict):
        for name in schema.get("required", []):
            if name not in instance:
                errors.append(f"{path}: missing required property {name!r}")
        properties = schema.get("properties", {})
        for name, subschema in properties.items():
            if name in instance:
                errors.extend(validate(instance[name], subschema, f"{path}.{name}"))
        pattern_schemas = schema.get("additionalProperties")
        if isinstance(pattern_schemas, dict):
            for name, value in instance.items():
                if name not in properties:
                    errors.extend(validate(value, pattern_schemas, f"{path}.{name}"))

    if isinstance(instance, list) and isinstance(schema.get("items"), dict):
        for index, item in enumerate(instance):
            errors.extend(validate(item, schema["items"], f"{path}[{index}]"))

    return errors


def load_schema(name: str) -> dict:
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


class ValidatorSelfTests(unittest.TestCase):
    """The validator itself must reject what it is supposed to reject."""

    def test_type_mismatch(self):
        self.assertTrue(validate("x", {"type": "integer"}))

    def test_booleans_are_not_integers(self):
        self.assertTrue(validate(True, {"type": "integer"}))
        self.assertFalse(validate(True, {"type": "boolean"}))

    def test_required_and_nested(self):
        schema = {
            "type": "object",
            "required": ["a"],
            "properties": {"a": {"type": "object", "required": ["b"], "properties": {"b": {"type": "string"}}}},
        }
        self.assertTrue(validate({}, schema))
        self.assertTrue(validate({"a": {}}, schema))
        self.assertTrue(validate({"a": {"b": 1}}, schema))
        self.assertFalse(validate({"a": {"b": "ok"}}, schema))

    def test_nullable_union(self):
        schema = {"type": ["number", "null"]}
        self.assertFalse(validate(None, schema))
        self.assertFalse(validate(1.5, schema))
        self.assertTrue(validate("x", schema))

    def test_list_items_and_enum(self):
        schema = {"type": "array", "items": {"type": "string", "enum": ["a", "b"]}}
        self.assertFalse(validate(["a", "b"], schema))
        self.assertTrue(validate(["a", "c"], schema))

    def test_additional_properties_schema(self):
        schema = {"type": "object", "additionalProperties": {"type": "integer"}}
        self.assertFalse(validate({"x": 1}, schema))
        self.assertTrue(validate({"x": "no"}, schema))


class SchemaFileTests(unittest.TestCase):
    def test_schema_files_are_valid_json_draft7(self):
        for name in ("stats.schema.json", "endpoints.schema.json", "ads.schema.json", "badge.schema.json"):
            schema = load_schema(name)
            self.assertEqual(schema["$schema"], "http://json-schema.org/draft-07/schema#", name)
            self.assertEqual(schema["type"], "object", name)
            self.assertIn("required", schema, name)


class PublishedOutputTests(unittest.TestCase):
    """Run the collector and validate what it actually wrote."""

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

    def _run_collector(self):
        text = "\n".join([LINK_A, LINK_B])
        metadata = json.dumps(
            [{"host": "1.2.3.4", "port": 443, "latency": 3, "operator": {"mci": 85}}]
        )
        cfg = collector.Config(min_discovered=1, metadata_sources=["https://meta.example/p.json"])

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

    def test_stats_matches_schema(self):
        self._run_collector()
        stats = json.loads(self.paths["STATS_FILE"].read_text())
        errors = validate(stats, load_schema("stats.schema.json"))
        self.assertEqual(errors, [], "\n".join(errors))

    def test_endpoints_matches_schema(self):
        self._run_collector()
        endpoints = json.loads(self.paths["ENDPOINTS_FILE"].read_text())
        errors = validate(endpoints, load_schema("endpoints.schema.json"))
        self.assertEqual(errors, [], "\n".join(errors))

    def test_badge_matches_schema(self):
        self._run_collector()
        badge = json.loads(self.paths["BADGE_FILE"].read_text())
        errors = validate(badge, load_schema("badge.schema.json"))
        self.assertEqual(errors, [], "\n".join(errors))

    def test_ads_matches_schema(self):
        adcheck.save_ads(
            {
                "updated_at": "2026-10-09T12:00:00+00:00",
                "method": adcheck.METHOD_NOTE,
                "promo_method": adcheck.PROMO_METHOD,
                "cache_days": 7,
                "results": {
                    "1.2.3.4:443": {
                        "has_ads": True,
                        "proxy_flag": True,
                        "channel": "@spam",
                        "peer": "channel:1",
                        "expires": 60,
                        "psa_type": None,
                        "secret_kind": "dd",
                        "transport": "ConnectionTcpMTProxyRandomizedIntermediate",
                        "checked_at": "2026-10-09T12:00:00+00:00",
                        "url": LINK_A,
                        "error": None,
                    },
                    "5.6.7.8:443": {
                        "has_ads": None,
                        "error": "unsupported_transport:faketls",
                        "secret_kind": "faketls",
                        "checked_at": "2026-10-09T12:00:00+00:00",
                        "url": LINK_B,
                    },
                },
            },
            self.paths["ADS_FILE"],
        )
        ads = json.loads(self.paths["ADS_FILE"].read_text())
        errors = validate(ads, load_schema("ads.schema.json"))
        self.assertEqual(errors, [], "\n".join(errors))

    def test_collector_accepts_the_documented_ads_shape(self):
        # The collector must merge ads.json produced by adcheck.py without
        # knowing anything about Telethon objects.
        adcheck.save_ads(
            {"results": {"1.2.3.4:443": {"has_ads": True, "channel": "@spam"}}},
            self.paths["ADS_FILE"],
        )
        self._run_collector()
        endpoints = json.loads(self.paths["ENDPOINTS_FILE"].read_text())
        entry = next(item for item in endpoints["endpoints"] if item["endpoint"] == "1.2.3.4:443")
        self.assertEqual(entry["ads"]["status"], "present")
        self.assertEqual(entry["ads"]["channel"], "@spam")


if __name__ == "__main__":
    unittest.main()
