"""Tests for the Tk-free report export."""

import datetime
import json
import os
import re
import tempfile
import unittest

from src.extension_guard.gui_core import AuditOutcome
from src.extension_guard.report import FORMATS, build_report, render, to_html, to_json, to_txt, write_report

WHEN = datetime.datetime(2026, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc)
FINDINGS = {"errors": ["a/b.js missing", "é ünï"], "warnings": ["w1"], "info": ["i1"]}


def _report(findings=FINDINGS, path=r"C:\secret dir\sub\ext.zip", **kw):
    return build_report(AuditOutcome(findings, 0.1234, **kw), path, WHEN)


class TestBuildReport(unittest.TestCase):
    def test_schema_and_counts(self):
        r = _report()
        self.assertEqual(
            list(r),
            ["schema_version", "tool", "file", "generated_at", "duration_seconds", "result", "summary", "findings",
             "readiness", "manifest_review"],
        )
        self.assertEqual(r["schema_version"], 2)
        self.assertEqual(r["summary"], {"errors": 2, "warnings": 1, "info": 1})
        self.assertEqual(r["result"], "findings")
        self.assertEqual(r["generated_at"], "2026-01-02T03:04:05+00:00")
        self.assertEqual({k: r["findings"][0][k] for k in ("severity", "message")},
                         {"severity": "error", "message": "a/b.js missing"})  # schema-1 keys unchanged
        self.assertEqual([f["severity"] for f in r["findings"]], ["error", "error", "warning", "info"])

    def test_only_base_name_in_every_format(self):
        for path in (r"C:\secret dir\sub\ext.zip", "/home/secret dir/ext.zip", "ext.zip"):
            r = _report(path=path)
            self.assertEqual(r["file"], "ext.zip")
            for fmt in FORMATS:
                self.assertNotIn("secret", render(r, fmt))

    def test_clean_and_info_only(self):
        clean = _report({"errors": [], "warnings": [], "info": []})
        self.assertEqual(clean["result"], "clean")
        self.assertIn("No issues found", to_txt(clean))
        self.assertIn("No issues found", to_html(clean))
        self.assertEqual(_report({"errors": [], "warnings": [], "info": ["i"]})["result"], "clean")

    def test_os_error_text_does_not_leak_the_folder(self):
        path = r"C:\secret dir\sub\ext.zip"
        errs = [
            f"Unexpected error during ZIP inspection: [Errno 2] No such file or directory: {path!r}",  # repr doubles backslashes, as str(OSError) does
            f"Could not read {path}",
        ]
        r = build_report(AuditOutcome({"errors": errs, "warnings": [], "info": []}), path, WHEN)
        for fmt in FORMATS:
            self.assertNotIn("secret", render(r, fmt))
        self.assertIn("ext.zip", r["findings"][0]["message"])

    def test_folder_audited_as_zip_does_not_leak_parents(self):
        r = build_report(
            AuditOutcome({"errors": [r"Permission denied: 'C:\\secret dir\\sub'"], "warnings": [], "info": []}),
            "C:\\secret dir\\sub\\",
            WHEN,
        )
        self.assertNotIn("secret", to_json(r))

    def test_trailing_separators_never_give_an_empty_file_name(self):
        cases = {
            "C:\\secret dir\\sub\\": "sub",
            "C:\\secret dir\\sub/": "sub",
            "C:\\": "C:",
            "\\\\srv\\share\\": "share",
            "/": "(unnamed)",
            "\\": "(unnamed)",
        }
        for path, expected in cases.items():
            msg = f"Permission denied: {path.rstrip(chr(92) + '/')!r} and {path}"
            r = build_report(AuditOutcome({"errors": [msg], "warnings": [], "info": []}), path, WHEN)
            self.assertEqual(r["file"], expected, path)
            for fmt in FORMATS:
                out = render(r, fmt)
                self.assertNotIn("secret", out, (path, fmt))
                self.assertNotIn("srv", out, (path, fmt))
            self.assertIn(f"Audit report - {expected}", to_html(r))

    def test_failed_audit_has_no_report(self):
        with self.assertRaises(ValueError):
            build_report(AuditOutcome(crash="RuntimeError: secret-boom"), "x.zip")

    def test_large_list(self):
        r = _report({"errors": [f"e{i}" for i in range(5000)], "warnings": [], "info": []})
        self.assertEqual(len(r["findings"]), 5000)
        self.assertEqual(len(re.findall("<li ", to_html(r))), 5000)


class TestFormats(unittest.TestCase):
    def test_json_round_trip_keeps_unicode(self):
        text = to_json(_report())
        self.assertIn("é ünï", text)  # not \u-escaped
        self.assertEqual(json.loads(text), _report())

    def test_txt_lists_sections(self):
        text = to_txt(_report())
        self.assertIn("Summary:   2 errors, 1 warnings, 1 info", text)
        self.assertIn("[ERROR] a/b.js missing", text)
        self.assertIn("[WARNING] w1", text)
        self.assertIn("[INFO] i1", text)

    def test_html_escapes_untrusted_content(self):
        evil = '<script>alert(1)</script>&"\''
        r = _report({"errors": [evil], "warnings": [], "info": []}, path='<img src=x onerror=1>.zip')
        page = to_html(r)
        self.assertNotIn("<script", page)
        self.assertNotIn("<img", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;&amp;", page)
        self.assertIn("&lt;img src=x onerror=1&gt;.zip", page)

    def test_html_has_no_scripts_or_external_resources(self):
        page = to_html(_report())
        self.assertNotRegex(page, r"(?i)<script|<link|<img|<iframe|src=|href=|https?://|@import|url\(")


class TestWrite(unittest.TestCase):
    def test_writes_utf8_for_each_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            for fmt, ext in FORMATS.items():
                path = os.path.join(tmp, "out" + ext)
                write_report(path, _report(), fmt)
                with open(path, encoding="utf-8") as fh:
                    self.assertIn("é ünï", fh.read())

    def test_lone_surrogate_does_not_break_writing(self):
        r = _report({"errors": ["bad \ud800 name"], "warnings": [], "info": []})
        with tempfile.TemporaryDirectory() as tmp:
            for fmt, ext in FORMATS.items():
                path = os.path.join(tmp, "s" + ext)
                write_report(path, r, fmt)
                with open(path, encoding="utf-8") as fh:
                    self.assertIn("bad ", fh.read())

    def test_unwritable_path_raises_oserror(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(OSError):
                write_report(os.path.join(tmp, "missing", "out.json"), _report(), "json")


if __name__ == "__main__":
    unittest.main()
