"""Integration tests for the unified audit orchestrator."""

import json
import os
import tempfile
import zipfile
import unittest
from pathlib import Path
from unittest import mock

from src.extension_guard.audit import audit_extension


def _make_zip(entries: dict) -> str:
    """Create a temporary ZIP with the given *entries* mapping path -> bytes."""
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    with zipfile.ZipFile(tmp.name, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, content in entries.items():
            zf.writestr(path, content)
    return tmp.name


class TestAuditArchiveSafety(unittest.TestCase):
    MANIFEST_NO_VERSION = json.dumps({"manifest_version": 3, "name": "T"}).encode()  # one manifest finding

    def _path(self, entries, compression=zipfile.ZIP_DEFLATED):
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
        tmp.close()
        self.addCleanup(os.unlink, tmp.name)
        with zipfile.ZipFile(tmp.name, "w", compression) as zf:
            for path, content in entries.items():
                zf.writestr(path, content)
        return tmp.name

    def _no_validator_runs(self, path):
        from src.extension_guard import audit as audit_module

        names = ("validate_manifest", "validate_references", "validate_locales", "validate_icons")
        patches = [mock.patch.object(audit_module, n) for n in names]
        mocks = [p.start() for p in patches]
        for p in patches:
            self.addCleanup(p.stop)
        result = audit_extension(path)
        for m in mocks:
            m.assert_not_called()
        return result

    def test_entry_limit_stops_validators_from_reading_the_archive(self):
        entries = {f"f{i}.txt": b"" for i in range(1001)}
        entries["manifest.json"] = self.MANIFEST_NO_VERSION
        result = self._no_validator_runs(self._path(entries))
        self.assertTrue(any(e.startswith("Archive contains") for e in result["errors"]), result)

    def test_size_limit_stops_validators_from_reading_the_archive(self):
        result = self._no_validator_runs(self._path({"manifest.json": b"{}", "big.bin": b"\0" * (50 * 1024 * 1024 + 1)}))
        self.assertTrue(any(e.startswith("Total uncompressed size") for e in result["errors"]), result)

    def test_not_a_zip_and_missing_file_still_stop_early(self):
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
        tmp.write(b"not a zip")
        tmp.close()
        self.addCleanup(os.unlink, tmp.name)
        self._no_validator_runs(tmp.name)
        self._no_validator_runs(tmp.name + ".missing")

    def test_zip_in_an_entry_name_cannot_suppress_manifest_findings(self):
        result = audit_extension(self._path({"manifest.json": self.MANIFEST_NO_VERSION, "../ZIP.txt": b"x"}))
        self.assertTrue(any("path traversal component: ../ZIP.txt" in e for e in result["errors"]), result)
        self.assertIn("Missing required field: version.", result["errors"])

    def test_encrypted_entry_does_not_hide_other_findings(self):
        path = self._path({"manifest.json": self.MANIFEST_NO_VERSION, "a.js": b"x"}, zipfile.ZIP_STORED)
        with open(path, "rb") as fh:
            raw = bytearray(fh.read())
        raw[raw.find(b"PK\x03\x04", 10) + 6] |= 1
        raw[raw.rfind(b"PK\x01\x02") + 8] |= 1
        with open(path, "wb") as fh:
            fh.write(raw)
        result = audit_extension(path)
        self.assertTrue(any("is encrypted: a.js" in e for e in result["errors"]), result)
        self.assertIn("Missing required field: version.", result["errors"])

    def test_findings_for_hostile_names_stay_escaped_in_html_reports(self):
        from src.extension_guard.gui_core import AuditOutcome
        from src.extension_guard.report import build_report, to_html, to_json, to_txt

        path = self._path(
            {"manifest.json": self.MANIFEST_NO_VERSION, "<img src=x onerror=1>.js": b"1", "<IMG src=x onerror=1>.js": b"2"}
        )
        result = audit_extension(path)
        self.assertTrue(any("differ only by case" in w for w in result["warnings"]), result)
        report = build_report(AuditOutcome(result, 0.0), path)
        page = to_html(report)
        self.assertNotIn("<img", page.lower())
        self.assertIn("&lt;img src=x onerror=1&gt;.js", page)
        for text in (page, to_json(report), to_txt(report)):
            self.assertNotIn(os.path.dirname(path), text)


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
            # Manifest missing required field "name"; icons: 48 is missing
            # from the ZIP (reference error), 128 has a bad signature (icon error)
            "manifest.json": json.dumps(
                {
                    "manifest_version": 3,
                    "version": "1.0",
                    "icons": {"48": "missing.png", "128": "icon.png"},
                }
            ).encode("utf-8"),
            # Locale error – default_locale missing but _locales present
            "_locales/en/messages.json": json.dumps({"hello": {"message": "Hi"}}).encode("utf-8"),
            # Icon validator error – malformed PNG signature (long enough to
            # get past the truncation check)
            "icon.png": b"\x00" * 16,
        }
        res = self._audit(entries)
        diag = f"findings: {res}"
        # Expect errors from manifest, reference, locale, icon
        self.assertTrue(any("Missing required field: name." in e for e in res["errors"]), diag)
        self.assertTrue(any("icons[48] references missing file: missing.png" in e for e in res["errors"]), diag)
        self.assertTrue(any("Missing required field: default_locale." in e for e in res["errors"]), diag)
        self.assertTrue(any("PNG icon missing PNG signature" in e for e in res["errors"]), diag)
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
        self.assertTrue(any("references missing file: icon.png" in e for e in res["errors"]), res)

    # 7. Missing required field does not stop downstream validators
    def test_missing_name_still_runs_validators(self):
        entries = {
            "manifest.json": json.dumps(
                {"manifest_version": 3, "version": "1.0", "icons": {"48": "icon.png"}}
            ).encode("utf-8"),
        }
        res = self._audit(entries)
        self.assertIn("Missing required field: name.", res["errors"])
        self.assertTrue(any("references missing file: icon.png" in e for e in res["errors"]), res)

    # 8. Manifest that is valid JSON but not an object
    def test_manifest_root_array(self):
        res = self._audit({"manifest.json": b"[]"})
        self.assertEqual(res["errors"], ["manifest.json root must be a JSON object."])

    # 9. Missing manifest is reported once
    def test_missing_manifest_reported_once(self):
        res = self._audit({"foo.txt": b"bar"})
        self.assertEqual(res["errors"], ["Missing root-level manifest.json."])

    # 10. Duplicate manifest key is not misattributed to messages.json
    def test_duplicate_manifest_key(self):
        entries = {
            "manifest.json": b'{"manifest_version": 3, "name": "a", "name": "b", "version": "1.0"}'
        }
        res = self._audit(entries)
        self.assertIn("Duplicate key in manifest.json: 'name'.", res["errors"])
        self.assertFalse(any("messages.json" in e for e in res["errors"]), res)
