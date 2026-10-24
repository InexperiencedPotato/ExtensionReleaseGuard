"""Integration tests for the unified audit orchestrator."""

import json
import os
import tempfile
import zipfile
import unittest
from pathlib import Path

from src.extension_guard.audit import audit_extension


def _make_zip(entries: dict) -> str:
    """Create a temporary ZIP with the given *entries* mapping path -> bytes."""
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    with zipfile.ZipFile(tmp.name, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, content in entries.items():
            zf.writestr(path, content)
    return tmp.name


class TestAuditOrchestrator(unittest.TestCase):
    def _audit(self, entries):
        zip_path = _make_zip(entries)
        try:
            return audit_extension(zip_path)
        finally:
            os.unlink(zip_path)

    # 1. Minimal valid extension
    def test_minimal_valid(self):
        entries = {
            "manifest.json": json.dumps(
                {"manifest_version": 3, "name": "Test", "version": "1.0"}
            ).encode("utf-8"),
        }
        res = self._audit(entries)
        self.assertFalse(res["errors"])
        self.assertFalse(res["warnings"])
        self.assertFalse(res["info"])

    # 2. Combined findings from multiple validators
    def test_combined_findings(self):
        entries = {
            # Manifest missing required field "name"
            "manifest.json": json.dumps(
                {"manifest_version": 3, "version": "1.0"}
            ).encode("utf-8"),
            # Reference validator error – missing icon file
            "icons.json": json.dumps({"icons": {"48": "missing.png"}}).encode("utf-8"),
            # Locale error – default_locale missing but _locales present
            "_locales/en/messages.json": json.dumps({"hello": {"message": "Hi"}}).encode("utf-8"),
            # Icon validator error – malformed PNG signature
            "icon.png": b"\x00\x01\x02",
        }
        res = self._audit(entries)
        # Expect errors from manifest, reference, locale, icon
        self.assertTrue(any("Missing required field: name." in e for e in res["errors"]))
        self.assertTrue(any("icon file missing: missing.png" in e for e in res["errors"]))
        self.assertTrue(any("default_locale missing" in e for e in res["errors"]))
        self.assertTrue(any("PNG icon missing PNG signature" in e for e in res["errors"]))
        # No duplicate messages should appear
        seen = set()
        for level in ["errors", "warnings", "info"]:
            for msg in res[level]:
                self.assertNotIn(msg, seen)
                seen.add(msg)

    # 3. Malformed ZIP
    def test_malformed_zip(self):
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
        tmp.write(b"not a zip")
        tmp.close()
        try:
            res = audit_extension(tmp.name)
        finally:
            os.unlink(tmp.name)
        self.assertTrue(any("ZIP" in e for e in res["errors"]))

    # 4. Missing manifest
    def test_missing_manifest(self):
        entries = {"foo.txt": b"bar"}
        res = self._audit(entries)
        self.assertTrue(any("Missing root-level manifest.json" in e for e in res["errors"]))

    # 5. Invalid manifest JSON
    def test_invalid_manifest(self):
        entries = {"manifest.json": b'{"manifest_version": 3, "name": "Test", }'}
        res = self._audit(entries)
        self.assertTrue(any("manifest.json contains malformed JSON" in e for e in res["errors"]))

    # 6. Valid manifest but missing referenced file
    def test_missing_referenced_file(self):
        entries = {
            "manifest.json": json.dumps(
                {"manifest_version": 3, "name": "Test", "version": "1.0", "icons": {"48": "icon.png"}}
            ).encode("utf-8"),
        }
        res = self._audit(entries)
        self.assertTrue(any("icon file missing" in e for e in res["errors"]))
