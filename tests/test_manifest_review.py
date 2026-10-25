import json
import os
import shutil
import tempfile
import unittest
import zipfile

from src.extension_guard.manifest_review import MAX_LISTED, build_review, review_manifest


def titles(review, kind=None):
    return [i.title for i in review.items if kind in (None, i.kind)]


class TestBuildReview(unittest.TestCase):
    def test_summary_fields(self):
        r = build_review({
            "manifest_version": 3, "name": "N", "version": "1.2",
            "permissions": ["storage", "tabs"], "optional_permissions": ["history"],
            "host_permissions": ["https://a.com/*"],
            "content_scripts": [{"matches": ["https://a.com/*", "https://b.com/*"], "js": ["a.js"]}],
        })
        self.assertEqual((r.manifest_version, r.name, r.version), ("3", "N", "1.2"))
        self.assertEqual(r.permissions, ["storage", "tabs"])
        self.assertEqual(r.optional_permissions, ["history"])
        self.assertEqual(r.host_permissions, ["https://a.com/*"])
        self.assertEqual(r.content_script_matches, ["https://a.com/*", "https://b.com/*"])
        self.assertIn("Permissions that warrant developer review", titles(r))
        self.assertIn("Optional permissions that warrant review", titles(r))
        self.assertEqual(titles(r, "inconsistency"), [])

    def test_routine_permissions_are_not_flagged(self):
        self.assertEqual(build_review({"permissions": ["storage", "alarms", "activeTab"]}).items, [])

    def test_broad_access_is_observation_not_defect(self):
        r = build_review({"host_permissions": ["<all_urls>"], "content_scripts": [{"matches": ["*://*/*"]}]})
        self.assertIn("Access to all websites", titles(r, "observation"))
        self.assertIn("Content scripts run on all websites", titles(r, "observation"))
        self.assertEqual(titles(r, "inconsistency"), [])

    def test_inconsistencies(self):
        r = build_review({"permissions": ["tabs", "https://a.com/*"], "optional_permissions": ["tabs"],
                          "host_permissions": ["not a pattern"]})
        inc = titles(r, "inconsistency")
        self.assertIn("Host patterns listed under permissions", inc)
        self.assertIn("Permissions listed as both required and optional", inc)
        self.assertIn("Entries in host_permissions that are not host patterns", inc)

    def test_unusual_types_do_not_crash(self):
        for m in ({"permissions": "tabs"}, {"permissions": [1, None, {"a": 1}]}, {"host_permissions": 5},
                  {"content_scripts": "x"}, {"content_scripts": [None, 3, {"matches": 4}]},
                  {"web_accessible_resources": [3, {"matches": None}]}, {"action": 7, "icons": []},
                  {"name": {"a": [1]}, "version": 1.5, "manifest_version": "3"}):
            self.assertTrue(build_review(m).available)

    def test_non_string_lists_are_reported(self):
        r = build_review({"permissions": ["tabs", 5]})
        self.assertIn("permissions is not a list of strings", titles(r, "inconsistency"))
        self.assertEqual(r.permissions, ["tabs"])

    def test_lists_are_capped(self):
        r = build_review({"permissions": [f"p{i}" for i in range(500)],
                          "host_permissions": [f"https://h{i}.com/*" for i in range(500)]})
        self.assertEqual(len(r.permissions), MAX_LISTED)
        self.assertEqual(len(r.host_permissions), MAX_LISTED)

    def test_long_values_are_truncated(self):
        self.assertLessEqual(len(build_review({"name": "x" * 5000}).name), 120)

    def test_declarations(self):
        self.assertFalse(build_review({}).declares_icons)
        self.assertTrue(build_review({"icons": {"16": "a.png"}}).declares_icons)
        self.assertTrue(build_review({"action": {"default_icon": "a.png"}}).declares_icons)
        self.assertTrue(build_review({"default_locale": "en"}).declares_locale)
        self.assertTrue(build_review({"background": {"service_worker": "b.js"}}).declares_references)
        self.assertFalse(build_review({"name": "x"}).declares_references)

    def test_wording_is_conservative(self):
        r = build_review({"permissions": ["debugger", "cookies"], "host_permissions": ["<all_urls>"]})
        text = " ".join(f"{i.title} {i.detail} {' '.join(i.entries)}" for i in r.items).lower()
        for banned in ("vulnerab", "malicious", "dangerous", "insecure", "exploit"):
            self.assertNotIn(banned, text)


class TestReviewFromZip(unittest.TestCase):
    def make(self, entries):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        p = os.path.join(d, "x.zip")
        with zipfile.ZipFile(p, "w") as z:
            for n, data in entries.items():
                z.writestr(n, data)
        return p

    def test_reads_root_manifest(self):
        p = self.make({"manifest.json": json.dumps({"manifest_version": 3, "name": "T", "permissions": ["cookies"]})})
        r = review_manifest(p)
        self.assertTrue(r.available)
        self.assertEqual(r.permissions, ["cookies"])

    def test_unavailable_cases_do_not_raise(self):
        cases = [
            {},  # missing
            {"manifest.json": "{"},  # malformed
            {"manifest.json": "[]"},  # not an object
            {"manifest.json": b"\xff\xfe"},  # not utf-8
            {"sub/manifest.json": "{}"},  # not at the root
            {"manifest.json": "x" * (1024 * 1024 + 1)},  # over the size cap
            {"manifest.json": "[" * 100000},  # nesting deeper than the parser allows
        ]
        for entries in cases:
            r = review_manifest(self.make(entries))
            self.assertFalse(r.available)
            self.assertTrue(r.reason)

    def test_not_a_zip_and_missing_file(self):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        bad = os.path.join(d, "b.zip")
        with open(bad, "wb") as fh:
            fh.write(b"nope")
        self.assertFalse(review_manifest(bad).available)
        self.assertFalse(review_manifest(os.path.join(d, "none.zip")).available)

    def test_nothing_is_extracted(self):
        p = self.make({"manifest.json": "{}"})
        before = set(os.listdir(os.path.dirname(p)))
        review_manifest(p)
        self.assertEqual(set(os.listdir(os.path.dirname(p))), before)


if __name__ == "__main__":
    unittest.main()
