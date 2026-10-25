"""audit_extension must report malformed packages as findings, never raise."""

import json
import os
import tempfile
import unittest
import zipfile

from src.extension_guard.audit import audit_extension

BASE = {"manifest_version": 3, "name": "T", "version": "1.0"}


class TestMalformedInput(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _zip(self, files):
        path = os.path.join(self.tmp.name, "x.zip")
        with zipfile.ZipFile(path, "w") as zf:
            for name, data in files.items():
                zf.writestr(name, data)
        return path

    def _manifest(self, **extra):
        return self._zip({"manifest.json": json.dumps({**BASE, **extra})})

    @staticmethod
    def _read(path):
        with open(path, "rb") as fh:
            return bytearray(fh.read())

    @staticmethod
    def _write(path, raw):
        with open(path, "wb") as fh:
            fh.write(bytes(raw))

    def _patch_zip(self, path, offset_in_local, offset_in_central, value):
        raw = self._read(path)
        raw[offset_in_local] = value
        central = raw.rfind(b"PK\x01\x02")
        raw[central + offset_in_central] = value
        self._write(path, raw)

    def test_non_object_manifest_sections(self):
        for field in ("action", "background", "options_ui", "side_panel",
                      "chrome_url_overrides", "declarative_net_request", "sandbox"):
            for value in (5, "s", [1], True):
                with self.subTest(field=field, value=value):
                    result = audit_extension(self._manifest(**{field: value}))
                    self.assertEqual(set(result), {"errors", "warnings", "info"})

    def test_non_list_sections(self):
        result = audit_extension(
            self._manifest(declarative_net_request={"rule_resources": 1}, sandbox={"pages": "a"})
        )
        self.assertIsInstance(result["errors"], list)

    def test_unhashable_icon_values(self):
        result = audit_extension(self._manifest(icons={"16": ["a"], "48": None, "128": {"x": 1}}))
        self.assertIsInstance(result["errors"], list)
        self.assertIsInstance(result["warnings"], list)

    def test_default_icon_unhashable(self):
        result = audit_extension(self._manifest(action={"default_icon": {"16": ["a"]}}))
        self.assertIsInstance(result["errors"], list)

    def test_absurdly_nested_json_is_malformed_not_a_crash(self):
        result = audit_extension(self._zip({"manifest.json": "[" * 5000 + "]" * 5000}))
        self.assertEqual(result["errors"], ["manifest.json contains malformed JSON."])

    def test_encrypted_entry_is_reported(self):
        path = self._manifest()
        raw = bytearray(self._read(path))
        raw[6] |= 1  # local header: encrypted flag
        raw[raw.rfind(b"PK\x01\x02") + 8] |= 1  # central directory flag
        self._write(path, raw)
        result = audit_extension(path)
        self.assertTrue(result["errors"])

    def test_unsupported_compression_is_reported(self):
        path = self._manifest()
        self._patch_zip(path, 8, 10, 99)
        result = audit_extension(path)
        self.assertTrue(result["errors"])

    def test_valid_package_still_clean(self):
        result = audit_extension(self._manifest())
        self.assertEqual(result, {"errors": [], "warnings": [], "info": []})


if __name__ == "__main__":
    unittest.main()
