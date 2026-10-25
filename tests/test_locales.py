import os
import tempfile
import zipfile
import json
import unittest
from pathlib import Path
from unittest import mock

from src.extension_guard.locale_validator import MAX_MESSAGES_SIZE as MAX, validate_locales

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

class TestMessagesSizeIsCheckedBeforeReading(unittest.TestCase):
    MANIFEST = json.dumps({"manifest_version": 3, "name": "T", "version": "1.0", "default_locale": "en"}).encode()

    def _zip(self, messages: bytes) -> str:
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
        tmp.close()
        self.addCleanup(os.unlink, tmp.name)
        with zipfile.ZipFile(tmp.name, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("manifest.json", self.MANIFEST)
            zf.writestr("_locales/en/messages.json", messages)
        return tmp.name

    def _validate_without_opening(self, messages: bytes):
        path = self._zip(messages)
        real_open = zipfile.ZipFile.open

        def guarded(zf, name, *args, **kwargs):  # manifest.json may be read; messages.json must not be
            self.assertNotIn("messages.json", str(getattr(name, "filename", name)), "messages.json was opened")
            return real_open(zf, name, *args, **kwargs)

        with mock.patch.object(zipfile.ZipFile, "open", guarded):
            return validate_locales(path)

    def test_oversized_declared_file_is_rejected_without_opening_it(self):
        result = self._validate_without_opening(b"a" * (MAX + 1))
        self.assertEqual(result["errors"], [f"messages.json size {MAX + 1} bytes exceeds limit of {MAX} bytes."])

    def test_huge_compressed_file_is_rejected_cheaply(self):
        result = self._validate_without_opening(b"a" * (64 * 1024 * 1024))
        self.assertTrue(any("messages.json size" in e for e in result["errors"]), result)

    def test_file_exactly_at_the_limit_is_still_read_and_parsed(self):
        head = b'{"k": {"message": "'
        body = head + b"a" * (MAX - len(head) - 3) + b'"}}'
        self.assertEqual(len(body), MAX)
        self.assertEqual(validate_locales(self._zip(body))["errors"], [])


if __name__ == "__main__":
    unittest.main()

