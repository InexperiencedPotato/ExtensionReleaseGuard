"""Tests for web_accessible_resources reference validation."""

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


class TestWebAccessibleResources(unittest.TestCase):
    def test_literal_resource_present(self):
        import json
        manifest = {
            "manifest_version":3,
            "web_accessible_resources": [
                {"resources": ["foo.txt"]}
            ]
        }
        zip_path = _create_zip({
            "manifest.json": json.dumps(manifest).encode(),
            "foo.txt": b"",
        })
        res = validate_references(str(zip_path))
        self.assertFalse(res["errors"])
        os.remove(zip_path)

    def test_literal_resource_missing(self):
        import json
        manifest = {
            "manifest_version":3,
            "web_accessible_resources": [
                {"resources": ["foo.txt"]}
            ]
        }
        zip_path = _create_zip({"manifest.json": json.dumps(manifest).encode()})
        res = validate_references(str(zip_path))
        self.assertTrue(any("missing file" in e for e in res["errors"]))
        os.remove(zip_path)

    def test_wildcard_multiple_matches(self):
        import json
        manifest = {
            "manifest_version":3,
            "web_accessible_resources": [
                {"resources": ["assets/*"]}
            ]
        }
        zip_path = _create_zip({
            "manifest.json": json.dumps(manifest).encode(),
            "assets/a.txt": b"",
            "assets/b.txt": b"",
        })
        res = validate_references(str(zip_path))
        self.assertFalse(res["errors"])
        os.remove(zip_path)

    def test_wildcard_single_match(self):
        import json
        manifest = {
            "manifest_version":3,
            "web_accessible_resources": [
                {"resources": ["assets/*.txt"]}
            ]
        }
        zip_path = _create_zip({
            "manifest.json": json.dumps(manifest).encode(),
            "assets/a.txt": b"",
        })
        res = validate_references(str(zip_path))
        self.assertFalse(res["errors"])
        os.remove(zip_path)

    def test_wildcard_no_match(self):
        import json
        manifest = {
            "manifest_version":3,
            "web_accessible_resources": [
                {"resources": ["assets/*.txt"]}
            ]
        }
        zip_path = _create_zip({"manifest.json": json.dumps(manifest).encode()})
        res = validate_references(str(zip_path))
        self.assertTrue(any("matches no entries" in w for w in res["warnings"]))
        os.remove(zip_path)
    def test_duplicate_entries(self):
        import json
        # Create a ZIP with duplicate entries and manifest
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
        with zipfile.ZipFile(tmp.name, "w") as zf:
            # Add duplicate entries first - zipfile will keep them
            zf.writestr("dup.txt", b"")
            zf.writestr("dup.txt", b"")
            # Now add manifest
            manifest = {
                "manifest_version": 3,
                "web_accessible_resources": [{"resources": ["dup.txt"]}]
            }
            zf.writestr("manifest.json", json.dumps(manifest).encode())
        tmp.close()
        # The zipfile module keeps duplicate entries in the archive.
        # The test expects validate_references to detect them via entry_counts > 1.
        res = validate_references(tmp.name)
        self.assertTrue(any("ambiguous duplicate" in e for e in res["errors"]))
        os.remove(tmp.name)

    def test_absolute_path(self):
        import json
        manifest = {
            "manifest_version":3,
            "web_accessible_resources": [
                {"resources": ["/abs.txt"]}
            ]
        }
        zip_path = _create_zip({"manifest.json": json.dumps(manifest).encode()})
        res = validate_references(str(zip_path))
        self.assertTrue(any("unsafe path" in e for e in res["errors"]))
        os.remove(zip_path)

    def test_traversal_path(self):
        import json
        manifest = {
            "manifest_version":3,
            "web_accessible_resources": [
                {"resources": ["../bad.txt"]}
            ]
        }
        zip_path = _create_zip({"manifest.json": json.dumps(manifest).encode()})
        res = validate_references(str(zip_path))
        self.assertTrue(any("unsafe path" in e for e in res["errors"]))
        os.remove(zip_path)

    def test_malformed_declaration(self):
        zip_path = _create_zip({"manifest.json": b'{"manifest_version":3,"web_accessible_resources":"not a list"}'} )
        res = validate_references(str(zip_path))
        self.assertTrue(any("not a list" in w for w in res["warnings"]))
        os.remove(zip_path)

    def test_empty_resource_array(self):
        import json
        manifest = {
            "manifest_version":3,
            "web_accessible_resources": [
                {"resources": []}
            ]
        }
        zip_path = _create_zip({"manifest.json": json.dumps(manifest).encode()})
        res = validate_references(str(zip_path))
        self.assertFalse(res["errors"])
        os.remove(zip_path)

    # Regression of existing tests
    def test_regression(self):
        from tests.test_reference_validator import TestReferenceValidator
        # Run a couple of baseline tests
        t = TestReferenceValidator()
        t.setUp = lambda: None  # no setup
        t.test_devtools_page()
        t.test_side_panel_default_path()
        t.test_chrome_url_overrides()
        t.test_declarative_net_request_rule_resources()
        t.test_sandbox_pages()