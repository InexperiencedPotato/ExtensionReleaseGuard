import json
import os
import tempfile
import unittest
import zipfile

from src.extension_guard.audit import audit_extension
from src.extension_guard.guidance import RULE_IDS, explain

SAMPLES = {
    "ZIP_INVALID": "File is not a valid ZIP archive (BadZipFile).",
    "ZIP_INSPECT_ERROR": "Unexpected error during ZIP inspection: boom",
    "ZIP_TOO_MANY_ENTRIES": "Archive contains 1001 files; exceeds limit of 1000.",
    "ZIP_TOO_LARGE": "Total uncompressed size 99 bytes exceeds limit of 50.",
    "ZIP_LONG_NAME": "Entry 3 has an unusually long name (300 chars).",
    "ZIP_ABSOLUTE_PATH": "Entry 2 uses an absolute path: /etc/x.",
    "ZIP_TRAVERSAL": "Entry 2 contains a path traversal component: ../x.js.",
    "ZIP_DUPLICATE_ENTRY": "Duplicate entry detected: a.js.",
    "ZIP_CASE_COLLISION": "Entry names differ only by case: A.js and a.js.",
    "ZIP_ENCRYPTED": "Entry 1 is encrypted: a.js.",
    "ZIP_SYMLINK": "Entry 1 is a symbolic link: a.js.",
    "ZIP_COMPRESSION_RATIO": "Entry 1 has an unusually high compression ratio (500:1): big.bin.",
    "ZIP_LOCAL_HEADER_MALFORMED": "Entry 1 has a malformed local header: a.js.",
    "ZIP_LOCAL_HEADER_MISMATCH": "Entry 1 local header name does not match the central directory: a.js.",
    "LOCALE_DEFAULT_MISSING": "Missing required field: default_locale.",
    "LOCALE_DEFAULT_INVALID": "Field 'default_locale' must be a non‑empty string.",
    "LOCALE_FILE_MISSING": "Missing file: _locales/en/messages.json.",
    "LOCALE_FILE_DUPLICATE": "Duplicate file: _locales/en/messages.json.",
    "LOCALE_MESSAGES_TOO_LARGE": "messages.json size 2000000 bytes exceeds limit of 1048576 bytes.",
    "LOCALE_MESSAGES_ENCODING": "messages.json contains invalid UTF‑8.",
    "LOCALE_MESSAGES_JSON": "messages.json contains malformed JSON.",
    "LOCALE_MESSAGES_DUP_KEY": "Duplicate key in messages.json: 'a'.",
    "LOCALE_MESSAGES_NOT_OBJECT": "messages.json root must be a JSON object.",
    "LOCALE_ENTRY_INVALID": "message entry 'k' missing 'message' field.",
    "MANIFEST_MISSING": "Missing root-level manifest.json.",
    "MANIFEST_AMBIGUOUS": "Ambiguous package: multiple root-level manifest.json entries.",
    "MANIFEST_TOO_LARGE": "manifest.json size 2000000 bytes exceeds limit of 1048576. size .* exceeds limit",
    "MANIFEST_READ_ERROR": "Unexpected error reading manifest.json: x",
    "MANIFEST_EMPTY": "manifest.json is empty.",
    "MANIFEST_ENCODING": "manifest.json contains invalid UTF‑8.",
    "MANIFEST_JSON": "manifest.json contains malformed JSON.",
    "MANIFEST_NOT_OBJECT": "manifest.json root must be a JSON object.",
    "MANIFEST_DUP_KEY": "Duplicate key in manifest.json: 'name'.",
    "MANIFEST_VERSION_UNSUPPORTED": "Unsupported manifest_version: 2. Expected integer 3 for MV3.",
    "MANIFEST_FIELD_MISSING": "Missing required field: name.",
    "MANIFEST_FIELD_INVALID": "Field 'version' must be a non‑empty string.",
    "REF_UNSAFE_PATH": "action.default_popup contains unsafe path: ../x.html.",
    "REF_MISSING_FILE": "content_scripts[0].js references missing file: a.js.",
    "REF_DUPLICATE_FILE": "icons references duplicate file: a.png.",
    "REF_WILDCARD_EMPTY": "web_accessible_resources[0].resources wildcard 'x*' matches no entries.",
    "REF_MALFORMED_FIELD": "content_scripts is not a list.",
    "ICON_SVG": "SVG icons are not supported; found in icons[16].",
    "ICON_UNRECOGNIZED_EXT": "Unrecognized icon file extension '.webp' for icons[16].",
    "ICON_NO_CHECKER": "No signature checker for extension '.svg' in icons[16].",
    "ICON_UNREADABLE": "Could not read a.png: boom",
    "ICON_INSPECTION_SKIPPED": "Icon a.png exceeds 5242880 bytes; content inspection skipped.",
    "ICON_NON_SQUARE": "PNG icon non‑square dimensions 16x17. in icons[16]",
    "ICON_INVALID_FILE": "PNG icon missing PNG signature. in icons[16]",
}


class TestRules(unittest.TestCase):
    def test_every_rule_has_a_sample_and_matches_it(self):
        self.assertEqual(set(SAMPLES), set(RULE_IDS))
        for rid, msg in SAMPLES.items():
            for sev in ("error", "warning", "info"):
                self.assertEqual(explain(sev, msg).id, rid, msg)

    def test_guidance_text_is_filled_and_never_overpromises(self):
        for msg in SAMPLES.values():
            g = explain("error", msg)
            self.assertTrue(g.title and g.why and g.action)
            blob = f"{g.title} {g.why} {g.action}".lower()
            for banned in ("guarantee", "secure", "certified", "will pass"):
                self.assertNotIn(banned, blob)

    def test_level_follows_severity(self):
        m = SAMPLES["ZIP_DUPLICATE_ENTRY"]
        self.assertEqual(
            [explain(s, m).level for s in ("error", "warning", "info")], ["blocks", "review", "info"]
        )
        self.assertEqual(explain("warning", m).level_label, "Review recommended")


class TestIdentity(unittest.TestCase):
    def test_id_ignores_entry_index_and_counts(self):
        a = explain("error", "Entry 3 is encrypted: a.js.")
        b = explain("error", "Entry 9 is encrypted: a.js.")
        self.assertEqual((a.id, a.subject), (b.id, b.subject))
        r1 = explain("warning", "Entry 1 has an unusually high compression ratio (100:1): big.bin.")
        r2 = explain("warning", "Entry 2 has an unusually high compression ratio (900:1): big.bin.")
        self.assertEqual((r1.id, r1.subject), (r2.id, r2.subject))

    def test_subject_distinguishes_files_and_ignores_array_index(self):
        a = explain("error", "content_scripts[0].js references missing file: a.js.")
        b = explain("error", "content_scripts[4].js references missing file: a.js.")
        c = explain("error", "content_scripts[0].js references missing file: b.js.")
        self.assertEqual((a.id, a.subject), (b.id, b.subject))
        self.assertNotEqual(a.subject, c.subject)

    def test_unmatched_messages_are_stable_and_distinct(self):
        a = explain("error", "A brand new problem at 12.")
        b = explain("error", "A brand new problem at 99.")
        c = explain("error", "A completely different problem.")
        self.assertTrue(a.id.startswith("UNCLASSIFIED:"))
        self.assertEqual(a.id, b.id)  # digits are normalised
        self.assertNotEqual(a.id, c.id)

    def test_hostile_text_does_not_break_matching(self):
        g = explain("error", "Entry 1 is encrypted: <script>%s{x}</script>.")
        self.assertEqual(g.id, "ZIP_ENCRYPTED")
        explain("error", "")
        explain("warning", "\ud800 lone surrogate")


class TestLiveMessagesAreClassified(unittest.TestCase):
    """Real validator output must never fall through to UNCLASSIFIED."""

    def audit(self, files, manifest=None):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        path = os.path.join(d, "x.zip")
        with zipfile.ZipFile(path, "w") as z:
            if manifest is not None:
                z.writestr("manifest.json", json.dumps(manifest))
            for name, data in files.items():
                z.writestr(name, data)
        return audit_extension(path)

    def assertClassified(self, findings):
        n = 0
        for sev, msgs in findings.items():
            for msg in msgs:
                n += 1
                self.assertFalse(explain(sev[:-1] if sev != "info" else sev, msg).id.startswith("UNCLASSIFIED"), msg)
        return n

    def test_broken_extension(self):
        manifest = {
            "manifest_version": 3, "name": "T", "version": "1", "default_locale": "en",
            "icons": {"16": "i.svg", "32": "i.png", "48": "i.gif"},
            "action": {"default_popup": "../p.html", "default_icon": 5},
            "content_scripts": [{"js": ["a.js"], "css": 3}, 4],
            "web_accessible_resources": [{"resources": ["z*", "m.js", "/abs"]}],
            "devtools_page": 3,
        }
        findings = self.audit({"i.svg": "<svg/>", "i.png": b"\x89PNG" + b"0" * 30, "i.gif": b"nope",
                               "_locales/en/messages.json": '{"a": 1, "b": {}}'}, manifest)
        self.assertGreaterEqual(self.assertClassified(findings), 8)

    def test_bad_manifests(self):
        for raw in ("", "[]", "{", "\xff"):
            d = tempfile.mkdtemp()
            self.addCleanup(lambda d=d: __import__("shutil").rmtree(d, ignore_errors=True))
            path = os.path.join(d, "x.zip")
            with zipfile.ZipFile(path, "w") as z:
                z.writestr("manifest.json", raw.encode("latin-1"))
            self.assertGreaterEqual(self.assertClassified(audit_extension(path)), 1)
        self.assertClassified(self.audit({}, None))
        self.assertClassified(self.audit({}, {"manifest_version": 2}))


if __name__ == "__main__":
    unittest.main()
