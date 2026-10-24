"""Unit tests for reference file validation."""

import unittest
import os
import tempfile
import zipfile
from pathlib import Path
from src.extension_guard.reference_validator import validate_references

def _create_zip(entries: dict[str, bytes]) -> Path:
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    with zipfile.ZipFile(tmp.name, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return Path(tmp.name)

class TestReferenceValidator(unittest.TestCase):
    def test_existing_and_missing_popup(self):
        zip_path = _create_zip({
            "manifest.json": b'{"manifest_version":3,"action":{"default_popup":"popup.html"}}',
            "popup.html": b"<html></html>",
        })
        res = validate_references(str(zip_path))
        self.assertFalse(res["errors"])  # present
        os.remove(zip_path)

        zip_path = _create_zip({"manifest.json": b'{"manifest_version":3,"action":{"default_popup":"popup.html"}}'})
        res = validate_references(str(zip_path))
        self.assertTrue(any("missing file" in e for e in res["errors"]))
        os.remove(zip_path)

    def test_service_worker(self):
        zip_path = _create_zip({
            "manifest.json": b'{"manifest_version":3,"background":{"service_worker":"worker.js"}}',
            "worker.js": b"",
        })
        res = validate_references(str(zip_path))
        self.assertFalse(res["errors"])
        os.remove(zip_path)

        zip_path = _create_zip({"manifest.json": b'{"manifest_version":3,"background":{"service_worker":"worker.js"}}'})
        res = validate_references(str(zip_path))
        self.assertTrue(any("missing file" in e for e in res["errors"]))
        os.remove(zip_path)

    def test_content_scripts(self):
        zip_path = _create_zip({
            "manifest.json": b'{"manifest_version":3,"content_scripts":[{"js":["a.js"],"css":["b.css"]}]}',
            "a.js": b"",
            "b.css": b"",
        })
        res = validate_references(str(zip_path))
        self.assertFalse(res["errors"])
        os.remove(zip_path)

        zip_path = _create_zip({"manifest.json": b'{"manifest_version":3,"content_scripts":[{"js":["a.js"],"css":["b.css"]}]}'})
        res = validate_references(str(zip_path))
        self.assertTrue(any("missing file" in e for e in res["errors"]))
        os.remove(zip_path)

    def test_icons(self):
        zip_path = _create_zip({
            "manifest.json": b'{"manifest_version":3,"icons":{"128":"icon.png"}}',
            "icon.png": b"",
        })
        res = validate_references(str(zip_path))
        self.assertFalse(res["errors"])
        os.remove(zip_path)

        zip_path = _create_zip({"manifest.json": b'{"manifest_version":3,"icons":{"128":"icon.png"}}'})
        res = validate_references(str(zip_path))
        self.assertTrue(any("missing file" in e for e in res["errors"]))
        os.remove(zip_path)

    def test_duplicate_entries(self):
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
        tmp.close()
        with zipfile.ZipFile(tmp.name, "w") as zf:
            zf.writestr("worker.js", b"")
            zf.writestr("worker.js", b"")
            zf.writestr("manifest.json", b'{"manifest_version":3,"background":{"service_worker":"worker.js"}}')
        res = validate_references(tmp.name)
        self.assertTrue(any("duplicate file" in e for e in res["errors"]))
        os.remove(tmp.name)

    def test_absolute_and_traversal(self):
        zip_path = _create_zip({
            "manifest.json": b'{"manifest_version":3,"action":{"default_popup":"../popup.html"}}',
            "popup.html": b"",
        })
        res = validate_references(str(zip_path))
        self.assertTrue(any("unsafe path" in e for e in res["errors"]))
        os.remove(zip_path)

    def test_malformed_optional(self):
        zip_path = _create_zip({"manifest.json": b'{"manifest_version":3,"action":{"default_popup":123}}'})
        res = validate_references(str(zip_path))
        self.assertTrue(any("not a string" in e for e in res["warnings"]))
        os.remove(zip_path)

    def test_no_optional_icons(self):
        zip_path = _create_zip({"manifest.json": b'{"manifest_version":3}'})
        res = validate_references(str(zip_path))
        self.assertFalse(res["errors"])
        os.remove(zip_path)

    # Regression of Phase 1 and 2
    def test_phase1_2_regression(self):
        from src.extension_guard.zip_inspector import inspect_zip
        zip_path = _create_zip({"manifest.json": b"{}"})
        self.assertFalse(inspect_zip(str(zip_path))["errors"])  # Phase1
        from src.extension_guard.manifest_validator import validate_manifest
        # Phase2 should report missing required fields for an empty manifest
        self.assertTrue(validate_manifest(str(zip_path))["errors"])
        os.remove(zip_path)

    # New reference tests
    def test_devtools_page(self):
        zip_path = _create_zip({
            "manifest.json": b'{"manifest_version":3,"devtools_page":"devtools.html"}',
            "devtools.html": b"",
        })
        res = validate_references(str(zip_path))
        self.assertFalse(res["errors"])
        os.remove(zip_path)

        zip_path = _create_zip({"manifest.json": b'{"manifest_version":3,"devtools_page":"devtools.html"}'})
        res = validate_references(str(zip_path))
        self.assertTrue(any("missing file" in e for e in res["errors"]))
        os.remove(zip_path)

    def test_side_panel_default_path(self):
        zip_path = _create_zip({
            "manifest.json": b'{"manifest_version":3,"side_panel":{"default_path":"panel.html"}}',
            "panel.html": b"",
        })
        res = validate_references(str(zip_path))
        self.assertFalse(res["errors"])
        os.remove(zip_path)

        zip_path = _create_zip({"manifest.json": b'{"manifest_version":3,"side_panel":{"default_path":"panel.html"}}'})
        res = validate_references(str(zip_path))
        self.assertTrue(any("missing file" in e for e in res["errors"]))
        os.remove(zip_path)

    def test_chrome_url_overrides(self):
        zip_path = _create_zip({
            "manifest.json": b'{"manifest_version":3,"chrome_url_overrides":{"newtab":"override.html"}}',
            "override.html": b"",
        })
        res = validate_references(str(zip_path))
        self.assertFalse(res["errors"])
        os.remove(zip_path)

        zip_path = _create_zip({"manifest.json": b'{"manifest_version":3,"chrome_url_overrides":{"newtab":"override.html"}}'})
        res = validate_references(str(zip_path))
        self.assertTrue(any("missing file" in e for e in res["errors"]))
        os.remove(zip_path)

    def test_declarative_net_request_rule_resources(self):
        zip_path = _create_zip({
            "manifest.json": b'{"manifest_version":3,"declarative_net_request":{"rule_resources":[{"path":"rules.json"}]}}',
            "rules.json": b"",
        })
        res = validate_references(str(zip_path))
        self.assertFalse(res["errors"])
        os.remove(zip_path)

        zip_path = _create_zip({"manifest.json": b'{"manifest_version":3,"declarative_net_request":{"rule_resources":[{"path":"rules.json"}]}}'})
        res = validate_references(str(zip_path))
        self.assertTrue(any("missing file" in e for e in res["errors"]))
        os.remove(zip_path)

    def test_sandbox_pages(self):
        zip_path = _create_zip({
            "manifest.json": b'{"manifest_version":3,"sandbox":{"pages":["sandbox.html"]}}',
            "sandbox.html": b"",
        })
        res = validate_references(str(zip_path))
        self.assertFalse(res["errors"])
        os.remove(zip_path)

        zip_path = _create_zip({"manifest.json": b'{"manifest_version":3,"sandbox":{"pages":["sandbox.html"]}}'})
        res = validate_references(str(zip_path))
        self.assertTrue(any("missing file" in e for e in res["errors"]))
        os.remove(zip_path)


if __name__ == "__main__":
    unittest.main()