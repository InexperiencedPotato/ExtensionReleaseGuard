import unittest
import os
import tempfile
import zipfile
from pathlib import Path
from src.extension_guard.zip_inspector import inspect_zip


def _create_zip(entries: dict[str, bytes]) -> Path:
    """Create a temporary ZIP file from a mapping of ``filename -> data``.

    Returns the path to the file.
    """
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    with zipfile.ZipFile(tmp.name, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return Path(tmp.name)


class TestZipInspector(unittest.TestCase):

    def test_valid_zip(self):
        zip_path = _create_zip({"manifest.json": b"{}", "icon.png": b"\x89PNG\r\n"})
        result = inspect_zip(str(zip_path))
        self.assertFalse(result["errors"])
        self.assertFalse(result["warnings"])
        self.assertFalse(result["info"])
        os.remove(zip_path)

    def test_malformed_zip(self):
        bad_zip = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
        bad_zip.write(b"not a zip")
        bad_zip.close()
        result = inspect_zip(bad_zip.name)
        self.assertIn("not a valid ZIP", result["errors"][0])
        os.remove(bad_zip.name)

    def test_traversal_entry(self):
        zip_path = _create_zip({"../secret.txt": b"topsecret"})
        result = inspect_zip(str(zip_path))
        self.assertTrue(any("path traversal" in e for e in result["errors"]))
        os.remove(zip_path)

    def test_duplicate_entries(self):
        # zipfile overwrites; create a zip with explicit duplicates
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
        # Close the underlying file handle so Windows can delete it.
        tmp.close()
        with zipfile.ZipFile(tmp.name, "w") as zf:
            zf.writestr("dup.txt", b"first")
            zf.writestr("dup.txt", b"second")
        result = inspect_zip(tmp.name)
        self.assertTrue(any("Duplicate entry" in w for w in result["warnings"]))
        os.remove(tmp.name)

    def test_size_limits(self):
        entries = {f"file{i}.txt": b"a" for i in range(1100)}
        zip_path = _create_zip(entries)
        result = inspect_zip(str(zip_path))
        self.assertTrue(any("exceeds limit" in e for e in result["errors"]))
        os.remove(zip_path)


if __name__ == "__main__":
    unittest.main()
    os.remove(tmp.name)


def test_size_limits(tmp_path):
    # Create many small files to exceed MAX_ENTRIES
    entries = {f"file{i}.txt": b"a" for i in range(1100)}
    zip_path = _create_zip(entries)
    result = inspect_zip(str(zip_path))
    assert any("exceeds limit" in e for e in result["errors"])
    os.remove(zip_path)
