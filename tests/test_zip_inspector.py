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


MIB = 1024 * 1024


class TestZipSafety(unittest.TestCase):
    """Metadata-only checks: encryption, symlinks, headers, case collisions, ratios, limits."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _zip(self, entries, compression=zipfile.ZIP_DEFLATED, name="t.zip"):
        path = os.path.join(self.tmp.name, name)
        with zipfile.ZipFile(path, "w", compression=compression) as zf:
            for entry, data in entries.items():
                zf.writestr(entry, data)
        return path

    def _patched(self, path, edit):
        with open(path, "rb") as fh:
            raw = bytearray(fh.read())
        edit(raw)
        with open(path, "wb") as fh:
            fh.write(raw)
        return path

    def _inspect(self, path):
        result = inspect_zip(path)
        for msg in sum(result.values(), []):
            self.assertNotIn(self.tmp.name, msg)  # findings never carry host paths
        return result

    # ---- normal archives -------------------------------------------------

    def test_ordinary_extension_has_no_findings(self):
        js = ("function f(a, b) { return a + b; }\n" * 2000).encode()
        path = self._zip({"manifest.json": b"{}", "a.js": js, "img/icon.png": os.urandom(5000)})
        self.assertEqual(self._inspect(path), {"errors": [], "warnings": [], "info": []})

    def test_real_archive_is_clean(self):
        store = os.environ.get("REAL_EXTENSION_ZIP", "")
        if not store or not os.path.exists(store):
            self.skipTest("REAL_EXTENSION_ZIP not set or not on disk")
        self.assertEqual(inspect_zip(store), {"errors": [], "warnings": [], "info": []})

    # ---- encryption, symlinks ---------------------------------------------

    def test_encrypted_entry_is_an_error(self):
        path = self._zip({"manifest.json": b"{}", "a.js": b"x"}, zipfile.ZIP_STORED)

        def edit(raw):
            local = raw.find(b"PK\x03\x04", 10)
            raw[local + 6] |= 1
            raw[raw.rfind(b"PK\x01\x02") + 8] |= 1

        result = self._inspect(self._patched(path, edit))
        self.assertTrue(any("is encrypted: a.js" in e for e in result["errors"]), result)

    def test_unix_symlink_is_an_error_but_regular_file_is_not(self):
        path = os.path.join(self.tmp.name, "s.zip")
        with zipfile.ZipFile(path, "w") as zf:
            link = zipfile.ZipInfo("link.js")
            link.create_system = 3
            link.external_attr = 0o120777 << 16
            zf.writestr(link, "../../secret")
            plain = zipfile.ZipInfo("plain.js")
            plain.create_system = 3
            plain.external_attr = 0o100644 << 16
            zf.writestr(plain, "x")
        result = self._inspect(path)
        self.assertEqual(len(result["errors"]), 1, result)
        self.assertIn("symbolic link: link.js", result["errors"][0])

    # ---- local header vs central directory ---------------------------------

    def test_local_header_name_mismatch_is_an_error(self):
        path = self._zip({"manifest.json": b"{}", "a.js": b"x"}, zipfile.ZIP_STORED)
        result = self._inspect(self._patched(path, lambda raw: raw.__setitem__(raw.find(b"a.js"), ord("b"))))
        self.assertTrue(any("does not match the central directory: a.js" in e for e in result["errors"]), result)

    def test_malformed_local_headers_are_findings_not_exceptions(self):
        def bad_signature(raw):
            raw[0:4] = b"XXXX"

        def offset_past_end(raw):  # central directory points beyond the file
            central = raw.rfind(b"PK\x01\x02")
            raw[central + 42 : central + 46] = (len(raw) + 1000).to_bytes(4, "little")

        def offset_inside_last_30(raw):  # header would start inside the file but run past its end
            central = raw.rfind(b"PK\x01\x02")
            raw[central + 42 : central + 46] = (len(raw) - 10).to_bytes(4, "little")

        def name_length_past_end(raw):
            raw[26:28] = (0xFFFF).to_bytes(2, "little")

        for edit in (bad_signature, offset_past_end, offset_inside_last_30, name_length_past_end):
            with self.subTest(edit=edit.__name__):
                path = self._zip({"manifest.json": b"{}"}, zipfile.ZIP_STORED, name=edit.__name__ + ".zip")
                result = self._inspect(self._patched(path, edit))
                self.assertTrue(any("malformed local header" in e for e in result["errors"]), result)

    # ---- names -------------------------------------------------------------

    def test_case_only_collision_is_a_warning(self):
        result = self._inspect(self._zip({"manifest.json": b"{}", "A.js": b"1", "a.js": b"2"}))
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["warnings"], ["Entry names differ only by case: A.js and a.js."])

    def test_names_that_only_casefold_equal_are_not_collisions(self):
        # "ss" and "ß" are different names on NTFS, so they must not be reported as a case collision.
        result = self._inspect(self._zip({"manifest.json": b"{}", "ss.js": b"1", "ß.js": b"2"}))
        self.assertEqual(result["warnings"], [])

    def test_header_comparison_has_no_false_positives(self):
        def clear_utf8_flag(raw):  # same name bytes, now read as cp437 in both headers
            for sig, at in ((b"PK\x03\x04", 7), (b"PK\x01\x02", 9)):
                i = 0
                while (i := raw.find(sig, i)) >= 0:
                    raw[i + at] &= ~0x08
                    i += 4

        non_ascii = self._zip({"manifest.json": b"{}", "é.js": b"1", "日本/x.js": b"2"})
        self.assertEqual(self._inspect(non_ascii), {"errors": [], "warnings": [], "info": []})
        legacy = self._zip({"manifest.json": b"{}", "é.js": b"1"}, name="legacy.zip")
        self.assertEqual(self._inspect(self._patched(legacy, clear_utf8_flag)), {"errors": [], "warnings": [], "info": []})
        with open(non_ascii, "rb") as fh:  # self-extractor style: data in front of the archive
            body = fh.read()
        prefixed = os.path.join(self.tmp.name, "prefixed.zip")
        with open(prefixed, "wb") as fh:
            fh.write(b"MZ" + b"\x00" * 1000 + body)
        self.assertEqual(self._inspect(prefixed), {"errors": [], "warnings": [], "info": []})

    def test_exact_duplicate_keeps_its_own_warning_only(self):
        path = os.path.join(self.tmp.name, "d.zip")
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("dup.txt", b"1")
            with self.assertWarns(UserWarning):
                zf.writestr("dup.txt", b"2")
        self.assertEqual(self._inspect(path)["warnings"], ["Duplicate entry detected: dup.txt."])

    # ---- compression ratio (>= 1 MiB and >= 100:1) -------------------------

    def test_ratio_warning_boundaries(self):
        for size, expected in ((MIB, True), (MIB - 1, False), (2 * MIB, True)):
            with self.subTest(size=size):
                result = self._inspect(self._zip({"manifest.json": b"{}", "pad.bin": b"\0" * size}))
                self.assertEqual(any("compression ratio" in w for w in result["warnings"]), expected, result)
        self.assertEqual(self._inspect(self._zip({"r.bin": os.urandom(2 * MIB)}))["warnings"], [])

    def test_ratio_at_and_just_under_100_to_1(self):
        path = self._zip({"pad.bin": b"\0" * MIB}, zipfile.ZIP_STORED)
        # 1048576 / 10485 = 100.007 (warn); 1048576 / 10486 = 99.997 (no warn)
        for compressed, expected in ((10485, True), (10486, False)):
            def edit(raw, value=compressed):
                central = raw.rfind(b"PK\x01\x02")
                raw[central + 20 : central + 24] = value.to_bytes(4, "little")

            with self.subTest(compressed=compressed):
                result = self._inspect(self._patched(path, edit))
                self.assertEqual(any("compression ratio" in w for w in result["warnings"]), expected, result)

    # ---- limits (unchanged: 1000 entries, 50 MiB) --------------------------

    def test_entry_count_boundary(self):
        ok = self._inspect(self._zip({f"f{i}.txt": b"" for i in range(1000)}, name="k.zip"))
        self.assertFalse(any("exceeds limit" in e for e in ok["errors"]), ok)
        over = self._inspect(self._zip({f"f{i}.txt": b"" for i in range(1001)}, name="k1.zip"))
        self.assertTrue(any(e.startswith("Archive contains 1001") for e in over["errors"]), over)

    def test_total_size_boundary(self):
        limit = 50 * MIB
        ok = self._inspect(self._zip({"a.bin": b"\0" * limit}, name="s.zip"))
        self.assertFalse(any("Total uncompressed" in e for e in ok["errors"]), ok)
        over = self._inspect(self._zip({"a.bin": b"\0" * (limit + 1)}, name="s1.zip"))
        self.assertTrue(any(e.startswith("Total uncompressed size") for e in over["errors"]), over)

    # ---- fatal classification ----------------------------------------------

    def test_is_fatal_only_for_explicit_conditions(self):
        from src.extension_guard.zip_inspector import is_fatal

        def f(*errors):
            return {"errors": list(errors), "warnings": [], "info": []}

        self.assertTrue(is_fatal(f("File is not a valid ZIP archive (BadZipFile).")))
        self.assertTrue(is_fatal(f("Archive contains 1001 files; exceeds limit of 1000.")))
        self.assertTrue(is_fatal(f("Total uncompressed size 1 bytes exceeds limit of 0.")))
        self.assertTrue(is_fatal(f("Unexpected error during ZIP inspection: boom")))
        self.assertFalse(is_fatal(f("Entry 2 contains a path traversal component: ../ZIP.txt.")))
        self.assertFalse(is_fatal(f("Entry 1 is encrypted: ZIP.js.")))
        self.assertFalse(is_fatal(f()))


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
