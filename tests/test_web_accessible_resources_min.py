"""Focused tests for web_accessible_resources validation."""

import os
import tempfile
import zipfile
import unittest
from src.extension_guard.reference_validator import validate_references


def _create_zip(entries: dict[str, bytes]) -> str:
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    with zipfile.ZipFile(tmp.name, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return tmp.name


class TestWebAccessibleResourcesMin(unittest.TestCase):
    def test_literal_present(self):
        import json
        manifest = {"manifest_version": 3, "web_accessible_resources": [{"resources": ["foo.txt"]}]}
        zip_path = _create_zip({"manifest.json": json.dumps(manifest).encode(), "foo.txt": b""})
        res = validate_references(str(zip_path))
        self.assertFalse(res["errors"])
        os.remove(zip_path)

    def test_literal_missing(self):
        zip_path = _create_zip({"manifest.json": b'{"manifest_version":3,"web_accessible_resources":[{"resources":["foo.txt"]}]}'})
        res = validate_references(str(zip_path))
        self.assertTrue(any("missing file" in e for e in res["errors"]))
        os.remove(zip_path)

    def test_wildcard_single(self):
        import json
        manifest = {"manifest_version": 3, "web_accessible_resources": [{"resources": ["assets/*.txt"]}]}
        zip_path = _create_zip({"manifest.json": json.dumps(manifest).encode(), "assets/a.txt": b""})
        res = validate_references(str(zip_path))
        self.assertFalse(res["errors"])
        os.remove(zip_path)

    def test_wildcard_multiple(self):
        import json
        manifest = {"manifest_version": 3, "web_accessible_resources": [{"resources": ["assets/*"]}]}
        zip_path = _create_zip({"manifest.json": json.dumps(manifest).encode(), "assets/a.txt": b"", "assets/b.txt": b""})
        res = validate_references(str(zip_path))
        self.assertFalse(res["errors"])
        os.remove(zip_path)

    def test_wildcard_no_match(self):
        zip_path = _create_zip({"manifest.json": b'{"manifest_version":3,"web_accessible_resources":[{"resources":["assets/*.png"]}]}'})
        res = validate_references(str(zip_path))
        self.assertTrue(any("matches no entries" in w for w in res["warnings"]))
        os.remove(zip_path)

    def test_duplicate_entry(self):
        import json
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
        with zipfile.ZipFile(tmp.name, "w") as zf:
            zf.writestr("dup.txt", b"")
            zf.writestr("dup.txt", b"")
            zf.writestr("manifest.json", json.dumps({"manifest_version": 3, "web_accessible_resources": [{"resources": ["dup.txt"]}]}).encode())
        tmp.close()
        res = validate_references(tmp.name)
        self.assertTrue(any("ambiguous duplicate" in e for e in res["errors"]))
        os.remove(tmp.name)

    def test_traversal_path(self):
        zip_path = _create_zip({"manifest.json": b'{"manifest_version":3,"web_accessible_resources":[{"resources":["../bad.txt"]}]}'})
        res = validate_references(str(zip_path))
        self.assertTrue(any("unsafe path" in e for e in res["errors"]))
        os.remove(zip_path)

    def test_malformed_declaration(self):
        zip_path = _create_zip({"manifest.json": b'{"manifest_version":3,"web_accessible_resources":"not a list"}'} )
        res = validate_references(str(zip_path))
        self.assertTrue(any("not a list" in w for w in res["warnings"]))
        os.remove(zip_path)