import os
import tempfile
import zipfile
import json
import unittest
from pathlib import Path

from src.extension_guard.locale_validator import validate_locales

class TestLocaleValidator(unittest.TestCase):
    def _make_zip(self, entries):
        """Create a temporary ZIP file with the given entries.

        ``entries`` is a dict mapping path -> bytes content.
        Returns the path to the ZIP file.
        """
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
        with zipfile.ZipFile(tmp.name, "w", zipfile.ZIP_DEFLATED) as zf:
            for path, content in entries.items():
                zf.writestr(path, content)
        return tmp.name

    def _validate(self, entries):
        zip_path = self._make_zip(entries)
        try:
            return validate_locales(zip_path)
        finally:
            os.unlink(zip_path)

    def test_missing_default_locale_with_locales(self):
        entries = {
            "manifest.json": json.dumps({"manifest_version":3, "name":"Test", "version":"1.0"}).encode("utf-8"),
            "_locales/en/messages.json": json.dumps({"hello": {"message": "Hello"}}).encode("utf-8"),
        }
        result = self._validate(entries)
        self.assertIn("Missing required field: default_locale.", result["errors"])

    def test_invalid_default_locale(self):
        entries = {
            "manifest.json": json.dumps({"manifest_version":3, "name":"Test", "version":"1.0", "default_locale":123}).encode("utf-8"),
            "_locales/en/messages.json": json.dumps({"hello": {"message": "Hello"}}).encode("utf-8"),
        }
        result = self._validate(entries)
        self.assertIn("Field 'default_locale' must be a non‑empty string.", result["errors"])

    def test_missing_messages_json(self):
        entries = {
            "manifest.json": json.dumps({"manifest_version":3, "name":"Test", "version":"1.0", "default_locale":"en"}).encode("utf-8"),
            # no messages.json
        }
        result = self._validate(entries)
        self.assertIn("Missing file: _locales/en/messages.json.", result["errors"])

    def test_malformed_json(self):
        entries = {
            "manifest.json": json.dumps({"manifest_version":3, "name":"Test", "version":"1.0", "default_locale":"en"}).encode("utf-8"),
            "_locales/en/messages.json": b'{"hello": {"message": "Hello",}',  # trailing comma invalid
        }
        result = self._validate(entries)
        self.assertIn("messages.json contains malformed JSON.", result["errors"])

    def test_invalid_utf8(self):
        entries = {
            "manifest.json": json.dumps({"manifest_version":3, "name":"Test", "version":"1.0", "default_locale":"en"}).encode("utf-8"),
            "_locales/en/messages.json": b'\xff\xfe\xfd',
        }
        result = self._validate(entries)
        self.assertIn("messages.json contains invalid UTF‑8.", result["errors"])

    def test_non_object_root(self):
        entries = {
            "manifest.json": json.dumps({"manifest_version":3, "name":"Test", "version":"1.0", "default_locale":"en"}).encode("utf-8"),
            "_locales/en/messages.json": json.dumps([1,2,3]).encode("utf-8"),
        }
        result = self._validate(entries)
        self.assertIn("messages.json root must be a JSON object.", result["errors"])

    def test_missing_message_field(self):
        entries = {
            "manifest.json": json.dumps({"manifest_version":3, "name":"Test", "version":"1.0", "default_locale":"en"}).encode("utf-8"),
            "_locales/en/messages.json": json.dumps({"hello": {}}).encode("utf-8"),
        }
        result = self._validate(entries)
        self.assertIn("message entry 'hello' missing 'message' field.", result["errors"])

    def test_non_string_message(self):
        entries = {
            "manifest.json": json.dumps({"manifest_version":3, "name":"Test", "version":"1.0", "default_locale":"en"}).encode("utf-8"),
            "_locales/en/messages.json": json.dumps({"hello": {"message": 123}}).encode("utf-8"),
        }
        result = self._validate(entries)
        self.assertIn("message entry 'hello' has non‑string 'message' field.", result["errors"])

    def test_large_messages_file(self):
        # Create a messages.json larger than 1 MiB
        large_content = "{\n" + ',\n'.join([f'"key{i}": {{"message": "text"}}' for i in range(50000)]) + "\n}"
        entries = {
            "manifest.json": json.dumps({"manifest_version":3, "name":"Test", "version":"1.0", "default_locale":"en"}).encode("utf-8"),
            "_locales/en/messages.json": large_content.encode("utf-8"),
        }
        result = self._validate(entries)
        # Expect size error message
        self.assertTrue(any("messages.json size" in err for err in result["errors"]))

if __name__ == "__main__":
    unittest.main()

