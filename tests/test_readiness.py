import unittest

from src.extension_guard import readiness as R
from src.extension_guard.gui_core import AuditOutcome
from src.extension_guard.manifest_review import ManifestReview


def outcome(errors=(), warnings=(), info=(), crash=None, review=None):
    return AuditOutcome({"errors": list(errors), "warnings": list(warnings), "info": list(info)}, 0.1, crash, review)


FULL = ManifestReview(available=True, declares_icons=True, declares_locale=True, declares_references=True)
SPARSE = ManifestReview(available=True)
ENC = "Entry 1 is encrypted: a.js."
DUP = "Duplicate entry detected: a.js."


class TestStates(unittest.TestCase):
    def test_crash_is_incomplete_and_claims_nothing(self):
        r = R.assess(outcome(crash="ValueError: x", review=FULL))
        self.assertEqual((r.state, r.passed), (R.INCOMPLETE, []))
        self.assertIn("could not complete", r.headline.lower())

    def test_fatal_archive_is_incomplete(self):
        for msg in ("File is not a valid ZIP archive (BadZipFile).", "Archive contains 1001 files; exceeds limit of 1000.",
                    "Total uncompressed size 9 bytes exceeds limit of 5."):
            r = R.assess(outcome(errors=[msg]))
            self.assertEqual((r.state, r.passed, r.errors), (R.INCOMPLETE, [], 1), msg)

    def test_non_fatal_zip_errors_are_findings_not_incomplete(self):
        self.assertEqual(R.assess(outcome(errors=[ENC])).state, R.ISSUES)

    def test_priority_errors_over_warnings_over_info(self):
        self.assertEqual(R.assess(outcome([ENC], [DUP], ["n"])).state, R.ISSUES)
        self.assertEqual(R.assess(outcome([], [DUP], ["n"])).state, R.REVIEW)
        self.assertEqual(R.assess(outcome([], [], ["n"])).state, R.INFORMATIONAL)
        self.assertEqual(R.assess(outcome()).state, R.CLEAR)

    def test_warning_is_not_called_an_error(self):
        r = R.assess(outcome(warnings=[DUP]))
        self.assertTrue(r.reason.startswith("No errors."))
        self.assertEqual((r.state, r.errors), (R.REVIEW, 0))

    def test_counts_match_findings(self):
        r = R.assess(outcome([ENC], [DUP, "Duplicate entry detected: b."], ["i"]))
        self.assertEqual((r.errors, r.warnings, r.info), (1, 2, 1))

    def test_no_overclaiming_wording(self):
        for o in (outcome(), outcome(warnings=[DUP]), outcome([ENC])):
            r = R.assess(o)
            text = f"{r.headline} {r.reason}".lower()
            for banned in ("secure", "certified", "guarantee", "will pass", "approved"):
                if banned in text:  # the disclaimer may only mention them negated
                    self.assertIn("not a security review", text)


class TestPassedChecks(unittest.TestCase):
    def test_clean_with_full_manifest_lists_every_check(self):
        self.assertEqual(R.assess(outcome(review=FULL)).passed, list(R.CHECK_LABELS.values()))

    def test_declaration_dependent_checks_need_something_to_check(self):
        self.assertEqual(R.assess(outcome(review=SPARSE)).passed, [R.CHECK_LABELS["zip"], R.CHECK_LABELS["manifest"]])

    def test_no_review_means_no_downstream_claims(self):
        self.assertEqual(R.assess(outcome()).passed, [R.CHECK_LABELS["zip"], R.CHECK_LABELS["manifest"]])

    def test_failing_check_is_not_listed_but_others_are(self):
        r = R.assess(outcome(errors=["Missing file: _locales/en/messages.json."], review=FULL))
        self.assertNotIn(R.CHECK_LABELS["locales"], r.passed)
        self.assertIn(R.CHECK_LABELS["references"], r.passed)
        self.assertIn(R.CHECK_LABELS["manifest"], r.passed)

    def test_missing_referenced_file_withholds_references_and_icons(self):
        r = R.assess(outcome(errors=["icons references missing file: a.png."], review=FULL))
        self.assertNotIn(R.CHECK_LABELS["references"], r.passed)
        self.assertNotIn(R.CHECK_LABELS["icons"], r.passed)

    def test_unusable_manifest_skips_downstream_and_says_so(self):
        r = R.assess(outcome(errors=["manifest.json contains malformed JSON."], review=FULL))
        self.assertEqual(r.state, R.ISSUES)
        self.assertEqual(r.passed, [R.CHECK_LABELS["zip"]])
        self.assertEqual(len(r.skipped), 3)
        self.assertIn("skipped", r.reason)

    def test_missing_required_field_does_not_skip_downstream(self):
        r = R.assess(outcome(errors=["Missing required field: name."], review=FULL))
        self.assertEqual(r.skipped, [])
        self.assertIn(R.CHECK_LABELS["icons"], r.passed)

    def test_unclassified_finding_withholds_all_claims(self):
        self.assertEqual(R.assess(outcome(warnings=["Some message from the future."], review=FULL)).passed, [])

    def test_info_findings_do_not_block_passed(self):
        self.assertEqual(len(R.assess(outcome(info=["note"], review=FULL)).passed), 5)


if __name__ == "__main__":
    unittest.main()
