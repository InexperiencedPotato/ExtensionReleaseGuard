import json
import os
import shutil
import tempfile
import unittest

from src.extension_guard import compare as C
from src.extension_guard.gui_core import AuditOutcome
from src.extension_guard.manifest_review import build_review
from src.extension_guard.report import build_report, to_html, to_json, to_txt

ENC = "Entry 1 is encrypted: a.js."
DUP = "Duplicate entry detected: b.js."
MISSING = "content_scripts[0].js references missing file: c.js."


def report(errors=(), warnings=(), info=(), path=r"C:\x\ext.zip", review=None):
    out = AuditOutcome({"errors": list(errors), "warnings": list(warnings), "info": list(info)}, 0.2, None, review)
    return build_report(out, path)


def cmp(old, new):
    return C.compare_reports(C.validate_report(old), C.validate_report(new))


def texts(items):
    return [f["message"] for f in items]


class TestMatching(unittest.TestCase):
    def test_new_fixed_unchanged(self):
        c = cmp(report([ENC], [DUP]), report([MISSING], [DUP]))
        self.assertEqual(texts(c.new), [MISSING])
        self.assertEqual(texts(c.fixed), [ENC])
        self.assertEqual(texts(c.unchanged), [DUP])
        self.assertEqual((c.old_counts["error"], c.new_counts["error"]), (1, 1))

    def test_both_directions(self):
        a, b = report([ENC]), report([ENC, MISSING])
        self.assertEqual(texts(cmp(a, b).new), [MISSING])
        self.assertEqual(texts(cmp(b, a).fixed), [MISSING])

    def test_identical_reports_have_no_changes(self):
        c = cmp(report([ENC], [DUP]), report([ENC], [DUP]))
        self.assertEqual((len(c.new), len(c.fixed), len(c.unchanged)), (0, 0, 2))

    def test_reworded_message_and_entry_number_still_match(self):
        old, new = report([ENC]), report(["Entry 7 is encrypted: a.js."])
        c = cmp(old, new)
        self.assertEqual((len(c.new), len(c.fixed), len(c.unchanged)), (0, 0, 1))
        # a rewording that keeps the stored id: matching ignores the text
        new["findings"][0]["message"] = "a.js is password protected"
        self.assertEqual(len(cmp(old, new).unchanged), 1)

    def test_same_rule_different_file_is_a_change(self):
        c = cmp(report([ENC]), report(["Entry 1 is encrypted: other.js."]))
        self.assertEqual((len(c.new), len(c.fixed)), (1, 1))

    def test_severity_change_is_not_unchanged(self):
        c = cmp(report(warnings=[DUP]), report(errors=[DUP]))
        self.assertEqual((len(c.new), len(c.fixed), len(c.unchanged)), (1, 1, 0))

    def test_repeated_findings_are_counted_not_collapsed(self):
        c = cmp(report(warnings=[DUP]), report(warnings=[DUP, DUP]))
        self.assertEqual((len(c.new), len(c.unchanged)), (1, 1))

    def test_unrecognised_messages_match_only_themselves(self):
        c = cmp(report(["Some future problem 4."]), report(["Some future problem 9.", "A different future problem."]))
        self.assertEqual((len(c.unchanged), len(c.new), len(c.fixed)), (1, 1, 0))


class TestSchemaOne(unittest.TestCase):
    def v1(self, rep):
        return {
            "schema_version": 1, "tool": "ExtensionRelease Guard", "file": rep["file"], "generated_at": rep["generated_at"],
            "duration_seconds": 1, "result": rep["result"], "summary": rep["summary"],
            "findings": [{"severity": f["severity"], "message": f["message"]} for f in rep["findings"]],
        }

    def test_v1_against_v2_and_v1(self):
        new = report([ENC, MISSING], [DUP])
        old = self.v1(report([ENC], [DUP]))
        c = cmp(old, new)
        self.assertEqual((texts(c.new), len(c.unchanged), len(c.fixed)), ([MISSING], 2, 0))
        self.assertTrue(any("schema-1" in n for n in c.notes))
        self.assertEqual(len(cmp(old, self.v1(new)).unchanged), 2)

    def test_v1_missing_optional_fields(self):
        c = cmp({"schema_version": 1, "findings": [{"severity": "info", "message": "n"}]}, report(info=["n"]))
        self.assertEqual(len(c.unchanged), 1)


class TestRejection(unittest.TestCase):
    def bad(self, data, fragment):
        with self.assertRaises(C.CompareError) as ctx:
            C.validate_report(data)
        self.assertIn(fragment, str(ctx.exception))

    def test_incompatible_inputs(self):
        self.bad([], "not an audit report")
        self.bad("x", "not an audit report")
        self.bad({}, "schema_version")
        self.bad({"schema_version": "2", "findings": []}, "schema_version")
        self.bad({"schema_version": True, "findings": []}, "schema_version")
        self.bad({"schema_version": 3, "findings": []}, "Unsupported report schema version 3")
        self.bad({"schema_version": 0, "findings": []}, "Unsupported")
        self.bad({"schema_version": 2}, "no findings list")
        self.bad({"schema_version": 2, "findings": "x"}, "no findings list")
        self.bad({"schema_version": 2, "findings": [1]}, "malformed finding")
        self.bad({"schema_version": 2, "findings": [{"severity": "fatal", "message": "x"}]}, "malformed finding")
        self.bad({"schema_version": 2, "findings": [{"severity": "error"}]}, "malformed finding")
        self.bad({"schema_version": 2, "findings": [{"severity": "error", "message": 5}]}, "malformed finding")

    def test_inconsistent_summary_is_rejected(self):
        self.bad({"schema_version": 2, "summary": {"errors": 3, "warnings": 0, "info": 0}, "findings": []}, "inconsistent")

    def test_odd_optional_fields_are_tolerated(self):
        v = C.validate_report({"schema_version": 2, "file": 5, "generated_at": None, "findings": [
            {"severity": "info", "message": "x", "id": 7, "subject": None}]})
        self.assertEqual((v["file"], v["findings"][0]["id"].startswith("UNCLASSIFIED")), ("", True))


class TestLoad(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(self.d, ignore_errors=True))

    def write(self, data, name="r.json"):
        p = os.path.join(self.d, name)
        with open(p, "wb") as fh:
            fh.write(data)
        return p

    def test_round_trip_and_bom(self):
        rep = report([ENC])
        self.assertEqual(len(C.load_report(self.write(to_json(rep).encode("utf-8")))["findings"]), 1)
        self.assertEqual(len(C.load_report(self.write(b"\xef\xbb\xbf" + to_json(rep).encode("utf-8")))["findings"]), 1)

    def test_unreadable_inputs_raise_compare_error(self):
        for data in (b"", b"{", b"\xff\xfe\x00", b"[" * 200000, b"null"):
            with self.assertRaises(C.CompareError):
                C.load_report(self.write(data))
        with self.assertRaises(C.CompareError):
            C.load_report(os.path.join(self.d, "missing.json"))
        with self.assertRaises(C.CompareError):
            C.load_report(self.d)  # a directory

    def test_oversized_file_is_refused(self):
        with self.assertRaises(C.CompareError) as ctx:
            C.load_report(self.write(b" " * (C.MAX_REPORT_BYTES + 1)))
        self.assertIn("too large", str(ctx.exception))

    def test_comparison_writes_nothing(self):
        p = self.write(to_json(report([ENC])).encode("utf-8"))
        before = (set(os.listdir(self.d)), os.path.getmtime(p))
        C.compare_reports(C.load_report(p), C.load_report(p))
        self.assertEqual((set(os.listdir(self.d)), os.path.getmtime(p)), before)


class TestFormat(unittest.TestCase):
    def test_summary_text(self):
        text = C.format_comparison(cmp(report([ENC], [DUP]), report([MISSING], [DUP], ["n"])))
        self.assertIn("2 new, 1 fixed, 1 unchanged", text)
        self.assertIn("Errors", text)
        self.assertIn("(+1)", text)  # info 0 -> 1

    def test_different_files_are_flagged(self):
        c = cmp(report(path=r"C:\a.zip"), report(path=r"C:\b.zip"))
        self.assertTrue(any("different files" in n for n in c.notes))

    def test_long_lists_are_capped(self):
        many = [f"Duplicate entry detected: f{i}." for i in range(C.MAX_LISTED + 50)]
        text = C.format_comparison(cmp(report(), report(warnings=many)))
        self.assertIn("and 50 more", text)


class TestReportV2(unittest.TestCase):
    REVIEW = build_review({"manifest_version": 3, "name": "<b>x</b>", "permissions": ["tabs"],
                           "host_permissions": ["<all_urls>"]})
    REVIEW.available = True

    def test_findings_carry_stable_ids_and_guidance(self):
        f = report([ENC])["findings"][0]
        self.assertEqual((f["id"], f["subject"], f["level"]), ("ZIP_ENCRYPTED", "a.js", "blocks"))
        self.assertTrue(f["title"] and f["why"] and f["action"])

    def test_readiness_and_review_are_included(self):
        r = report(review=self.REVIEW)
        self.assertEqual(r["readiness"]["state"], "clear")
        self.assertEqual(r["manifest_review"]["permissions"], ["tabs"])
        self.assertIsNone(report()["manifest_review"])

    def test_json_round_trips_through_the_validator(self):
        r = report([ENC], review=self.REVIEW)
        self.assertEqual(len(C.validate_report(json.loads(to_json(r)))["findings"]), 1)

    def test_html_escapes_everything_new(self):
        evil = '<img src=x onerror=alert(1)>'
        review = build_review({"name": evil, "version": evil, "permissions": [evil, "tabs"],
                               "host_permissions": [evil], "content_scripts": [{"matches": [evil]}]})
        r = report([f"Entry 1 is encrypted: {evil}."], review=review)
        for out in (to_html(r),):
            self.assertNotIn("<img", out)
            self.assertNotIn("<script", out)
            self.assertIn("&lt;img", out)
        self.assertIn("Manifest review", to_html(r))
        self.assertIn("Checks passed", to_html(report(review=self.REVIEW)))

    def test_no_host_path_in_new_fields(self):
        secret = r"C:\Users\secret person\ext.zip"
        out = AuditOutcome({"errors": [f"Entry 1 is encrypted: {secret}."], "warnings": [], "info": []}, 0.1)
        r = build_report(out, secret)
        for text in (to_json(r), to_txt(r), to_html(r)):
            self.assertNotIn("secret person", text)

    def test_txt_has_readiness_and_actions(self):
        text = to_txt(report([ENC]))
        self.assertIn("Readiness: Issues found", text)
        self.assertIn("Action:", text)


if __name__ == "__main__":
    unittest.main()
