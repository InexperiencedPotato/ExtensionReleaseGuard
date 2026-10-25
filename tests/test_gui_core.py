"""Tests for the Tk-free UI helpers."""

import json
import os
import tempfile
import threading
import time
import unittest
import zipfile
from unittest import mock

from src.extension_guard.gui_core import (
    AuditOutcome,
    AuditRunner,
    filter_findings,
    flatten,
    format_status,
    log_path,
    result_state,
    run_audit_safe,
    summarize,
)


class TestRunAuditSafe(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        # Keep crash logs out of the real LocalAppData.
        patcher = mock.patch.dict(os.environ, {"LOCALAPPDATA": os.path.join(self.tmp.name, "lad")})
        patcher.start()
        self.addCleanup(patcher.stop)

    def _path(self, name):
        return os.path.join(self.tmp.name, name)

    def test_valid_zip(self):
        path = self._path("ok.zip")
        manifest = {"manifest_version": 3, "name": "T", "version": "1.0"}
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("manifest.json", json.dumps(manifest))
        out = run_audit_safe(path)
        self.assertIsNone(out.crash)
        self.assertEqual(summarize(out.findings), {"errors": 0, "warnings": 0, "info": 0})
        self.assertGreaterEqual(out.elapsed, 0.0)

    def test_non_zip_file(self):
        path = self._path("bad.zip")
        with open(path, "wb") as fh:
            fh.write(b"not a zip")
        out = run_audit_safe(path)
        self.assertIsNone(out.crash)
        self.assertGreater(summarize(out.findings)["errors"], 0)

    def test_missing_path(self):
        out = run_audit_safe(self._path("nope.zip"))
        self.assertIsNone(out.crash)
        self.assertGreater(summarize(out.findings)["errors"], 0)

    def test_unexpected_exception_is_captured(self):
        with mock.patch(
            "src.extension_guard.gui_core.audit_extension",
            side_effect=RuntimeError("boom"),
        ):
            out = run_audit_safe("whatever.zip")
        self.assertEqual(out.crash, "RuntimeError: boom")
        self.assertEqual(out.findings, {"errors": [], "warnings": [], "info": []})
        self.assertGreaterEqual(out.elapsed, 0.0)

    def test_crash_is_logged_without_directory_or_contents(self):
        with mock.patch(
            "src.extension_guard.gui_core.audit_extension", side_effect=RuntimeError("boom")
        ):
            run_audit_safe(r"C:\secret dir\mine.zip")
        with open(log_path(), encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("RuntimeError: boom", text)
        self.assertIn("mine.zip", text)
        self.assertNotIn("secret dir", text)

    def test_expected_findings_are_not_logged_or_crashes(self):
        bad = self._path("bad.zip")
        with open(bad, "wb") as fh:
            fh.write(b"not a zip")
        out = run_audit_safe(bad)
        self.assertIsNone(out.crash)
        self.assertFalse(os.path.exists(log_path()))

    def test_unwritable_log_never_raises(self):
        with mock.patch.dict(os.environ, {"LOCALAPPDATA": os.path.join(self.tmp.name, "f")}):
            open(os.path.join(self.tmp.name, "f"), "w").close()  # a file where a dir is needed
            with mock.patch(
                "src.extension_guard.gui_core.audit_extension", side_effect=ValueError("x")
            ):
                out = run_audit_safe("a.zip")
        self.assertEqual(out.crash, "ValueError: x")

    def test_findings_passed_through(self):
        fake = {"errors": ["e"], "warnings": [], "info": ["i"]}
        with mock.patch("src.extension_guard.gui_core.audit_extension", return_value=fake):
            out = run_audit_safe("x.zip")
        self.assertIsInstance(out, AuditOutcome)
        self.assertIs(out.findings, fake)
        self.assertIsNone(out.crash)


class TestSummarizeFlatten(unittest.TestCase):
    FINDINGS = {
        "errors": ["e1", "e2"],
        "warnings": ["w1"],
        "info": ["i1", "i2", "i3"],
    }

    def test_counts(self):
        self.assertEqual(
            summarize(self.FINDINGS), {"errors": 2, "warnings": 1, "info": 3}
        )

    def test_order_errors_warnings_info(self):
        self.assertEqual(
            flatten(self.FINDINGS),
            [
                ("error", "e1"),
                ("error", "e2"),
                ("warning", "w1"),
                ("info", "i1"),
                ("info", "i2"),
                ("info", "i3"),
            ],
        )

    def test_empty(self):
        empty = {"errors": [], "warnings": [], "info": []}
        self.assertEqual(flatten(empty), [])
        self.assertEqual(summarize(empty), {"errors": 0, "warnings": 0, "info": 0})


def _wait_for(runner, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        outcome = runner.poll()
        if outcome is not None:
            return outcome
        time.sleep(0.005)
    raise AssertionError("runner produced no outcome")


class TestAuditRunner(unittest.TestCase):
    def test_result_delivered_and_busy_cleared(self):
        done = AuditOutcome({"errors": ["e"], "warnings": [], "info": []}, 0.5)
        runner = AuditRunner(audit=lambda path: done)
        self.assertTrue(runner.start("a.zip"))
        self.assertTrue(runner.busy)
        self.assertIs(_wait_for(runner), done)
        self.assertFalse(runner.busy)
        self.assertIsNone(runner.poll())

    def test_start_rejected_while_busy(self):
        gate = threading.Event()
        runner = AuditRunner(audit=lambda path: (gate.wait(5), AuditOutcome())[1])
        self.assertTrue(runner.start("a.zip"))
        self.assertFalse(runner.start("b.zip"))
        self.assertIsNone(runner.poll())  # still running
        gate.set()
        _wait_for(runner)
        self.assertTrue(runner.start("c.zip"))
        gate.set()
        _wait_for(runner)

    def test_runs_off_the_calling_thread(self):
        seen = []
        runner = AuditRunner(audit=lambda p: (seen.append(threading.current_thread()), AuditOutcome())[1])
        runner.start("a.zip")
        _wait_for(runner)
        self.assertIsNot(seen[0], threading.current_thread())
        self.assertTrue(seen[0].daemon)


class TestFormatStatus(unittest.TestCase):
    def test_passed(self):
        self.assertEqual(
            format_status(AuditOutcome(elapsed=0.123)),
            "Audit passed — no issues detected. (0.12 s)",
        )

    def test_info_only_is_completed_not_empty(self):
        text = format_status(AuditOutcome({"errors": [], "warnings": [], "info": ["a", "b"]}, 1.0))
        self.assertEqual(text, "Audit completed: no errors or warnings, 2 informational notes (1.00 s)")

    def test_finished_with_findings_and_plurals(self):
        f = {"errors": ["e"], "warnings": ["a", "b"], "info": []}
        self.assertEqual(
            format_status(AuditOutcome(f, 1.0)),
            "Audit finished: 1 error, 2 warnings (1.00 s)",
        )

    def test_crash_has_no_technical_detail(self):
        text = format_status(AuditOutcome(crash="RuntimeError: boom"))
        self.assertTrue(text.startswith("Audit failed unexpectedly"))
        self.assertNotIn("boom", text)
        self.assertNotIn("Traceback", text)


class TestFilterAndState(unittest.TestCase):
    ROWS = flatten({"errors": ["e1", "e2"], "warnings": ["w1"], "info": ["i1"]})

    def test_filter_each_level(self):
        self.assertEqual(len(filter_findings(self.ROWS, "all")), 4)
        self.assertEqual(filter_findings(self.ROWS, "error"), [("error", "e1"), ("error", "e2")])
        self.assertEqual(filter_findings(self.ROWS, "warning"), [("warning", "w1")])
        self.assertEqual(filter_findings(self.ROWS, "info"), [("info", "i1")])

    def test_filter_empty_and_unknown(self):
        self.assertEqual(filter_findings([], "error"), [])
        self.assertEqual(filter_findings(self.ROWS, "nope"), [])

    def test_filter_does_not_mutate_input(self):
        rows = list(self.ROWS)
        filter_findings(rows, "info")
        self.assertEqual(rows, self.ROWS)

    def test_large_findings_list(self):
        big = {"errors": [f"e{i}" for i in range(5000)], "warnings": ["w"], "info": []}
        rows = flatten(big)
        self.assertEqual(len(rows), 5001)
        self.assertEqual(len(filter_findings(rows, "error")), 5000)
        self.assertEqual(summarize(big)["errors"], 5000)

    def test_result_state(self):
        self.assertEqual(result_state(AuditOutcome()), "clean")
        self.assertEqual(result_state(AuditOutcome({"errors": [], "warnings": [], "info": ["i"]})), "clean")
        self.assertEqual(result_state(AuditOutcome({"errors": [], "warnings": ["w"], "info": []})), "findings")
        self.assertEqual(result_state(AuditOutcome({"errors": ["e"], "warnings": [], "info": []})), "findings")
        self.assertEqual(result_state(AuditOutcome(crash="X: y")), "failed")


if __name__ == "__main__":
    unittest.main()
