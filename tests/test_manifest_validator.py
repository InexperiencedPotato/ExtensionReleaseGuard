"""Unit tests for :mod:`extension_guard.manifest_validator`.

All tests use the same temporary ZIP creation helper as the
`zip_inspector` tests.
"""
import unittest
import os
import tempfile
import zipfile
from pathlib import Path
from src.extension_guard.manifest_validator import validate_manifest


def _create_zip(entries: dict[str, bytes]) -> Path:
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    with zipfile.ZipFile(tmp.name, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return Path(tmp.name)


class TestManifestValidator(unittest.TestCase):
    def test_valid_v3(self):
        zip_path = _create_zip({"manifest.json": b'{"manifest_version":3,"name":"X","version":"1.0"}'})
        result = validate_manifest(str(zip_path))
        self.assertFalse(result["errors"])
        os.remove(zip_path)

    def test_missing_root_manifest(self):
        zip_path = _create_zip({"sub/manifest.json": b'{"manifest_version":3}'})
        result = validate_manifest(str(zip_path))
        self.assertTrue(any("Missing root-level" in e for e in result["errors"]))
        os.remove(zip_path)

    def test_nested_manifest(self):
        zip_path = _create_zip({"sub/manifest.json": b'{"manifest_version":3}'})
        result = validate_manifest(str(zip_path))
        self.assertTrue(any("Missing root-level" in e for e in result["errors"]))
        os.remove(zip_path)

    def test_duplicate_root_manifests(self):
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
        tmp.close()
        with zipfile.ZipFile(tmp.name, "w") as zf:
            zf.writestr("manifest.json", b'{"manifest_version":3}')
            zf.writestr("manifest.json", b'{"manifest_version":3}')
        result = validate_manifest(tmp.name)
        self.assertTrue(any("Ambiguous package" in e for e in result["errors"]))
        os.remove(tmp.name)

    def test_malformed_json(self):
        zip_path = _create_zip({"manifest.json": b'{"manifest_version":3,}'})
        result = validate_manifest(str(zip_path))
        self.assertTrue(any("malformed JSON" in e for e in result["errors"]))
        os.remove(zip_path)

    def test_invalid_utf8(self):
        zip_path = _create_zip({"manifest.json": b'\xff\xfe\x00'})
        result = validate_manifest(str(zip_path))
        self.assertTrue(any("invalid UTF‑8" in e for e in result["errors"]))
        os.remove(zip_path)

    def test_empty_manifest(self):
        zip_path = _create_zip({"manifest.json": b""})
        result = validate_manifest(str(zip_path))
        self.assertTrue(any("empty" in e.lower() for e in result["errors"]))
        os.remove(zip_path)

    def test_non_object_root(self):
        for data in [b"[]", b"\"text\"", b"123", b"null"]:
            zip_path = _create_zip({"manifest.json": data})
            result = validate_manifest(str(zip_path))
            self.assertTrue(any("root must be a JSON object" in e for e in result["errors"]))
            os.remove(zip_path)

    def test_missing_required_fields(self):
        zip_path = _create_zip({"manifest.json": b'{"manifest_version":3,"name":"X"}'})
        result = validate_manifest(str(zip_path))
        self.assertTrue(any("Missing required field: version" in e for e in result["errors"]))
        os.remove(zip_path)

    def test_empty_name_or_version(self):
        for payload in [b'{"manifest_version":3,"name":"","version":"1"}',
                        b'{"manifest_version":3,"name":"X","version":""}']:
            zip_path = _create_zip({"manifest.json": payload})
            result = validate_manifest(str(zip_path))
            self.assertTrue(any("non‑empty string" in e for e in result["errors"]))
            os.remove(zip_path)

    def test_wrong_field_types(self):
        zip_path = _create_zip({"manifest.json": b'{"manifest_version":true,"name":123,"version":false}'})
        result = validate_manifest(str(zip_path))
        self.assertTrue(any("Unsupported manifest_version" in e for e in result["errors"]))
        self.assertTrue(any("non‑empty string" in e for e in result["errors"]))
        os.remove(zip_path)

    def test_manifest_v2(self):
        zip_path = _create_zip({"manifest.json": b'{"manifest_version":2,"name":"X","version":"1"}'})
        result = validate_manifest(str(zip_path))
        self.assertTrue(any("Unsupported manifest_version" in e for e in result["errors"]))
        os.remove(zip_path)

    def test_oversized_manifest(self):
        # 1 MiB + 1 byte of valid JSON
        big = (b'{"manifest_version":3,"name":"X","version":"1"}' * ((1 * 1024 * 1024) // 10)) + b"a"
        zip_path = _create_zip({"manifest.json": big})
        result = validate_manifest(str(zip_path))
        self.assertTrue(any("size .* exceeds limit" in e for e in result["errors"]))
        os.remove(zip_path)

    def test_duplicate_keys(self):
        zip_path = _create_zip({"manifest.json": b'{"name":"X","name":"Y","manifest_version":3,"version":"1"}'})
        result = validate_manifest(str(zip_path))
        self.assertTrue(any("Duplicate key" in e for e in result["errors"]))
        os.remove(zip_path)

    def test_phase1_behavior_unchanged(self):
        # Ensure zip_inspector still works after adding validator
        from src.extension_guard.zip_inspector import inspect_zip
        zip_path = _create_zip({"manifest.json": b"{}"})
        res = inspect_zip(str(zip_path))
        self.assertFalse(res["errors"])
        os.remove(zip_path)


if __name__ == "__main__":
    unittest.main()