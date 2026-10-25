"""GUI behaviour for readiness, guidance, manifest review, report comparison and file drops."""

import json
import os
import tempfile
import threading
import time
import unittest
from unittest import mock

try:
    import customtkinter as ctk
    from src.extension_guard import gui
    from src.extension_guard.gui import App
    import tkinter

    _probe = tkinter.Tk()
    _probe.destroy()
    _SKIP = ""
except Exception as exc:  # missing customtkinter, or no display
    _SKIP = f"GUI unavailable: {exc}"

from src.extension_guard.gui_core import AuditOutcome, AuditRunner
from src.extension_guard.manifest_review import ManifestReview, build_review
from src.extension_guard.report import build_report, to_json

ENC = "Entry 1 is encrypted: a.js."
DUP = "Duplicate entry detected: b.js."


def findings(errors=(), warnings=(), info=()):
    return {"errors": list(errors), "warnings": list(warnings), "info": list(info)}


@unittest.skipIf(_SKIP, _SKIP)
class TestFeatures(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name
        patcher = mock.patch.dict(os.environ, {"LOCALAPPDATA": tmp.name})
        patcher.start()
        self.addCleanup(patcher.stop)

    def _app(self, outcome, audit=None):
        app = App(runner=AuditRunner(audit=audit or (lambda path: outcome)))
        app.withdraw()
        self.addCleanup(self._close, app)
        return app

    @staticmethod
    def _close(app):
        try:
            app.destroy()
        except Exception:
            pass

    def _pump(self, app, timeout=5.0):
        deadline = time.monotonic() + timeout
        while app._runner.busy and time.monotonic() < deadline:
            app.update()
            time.sleep(0.01)
        app.update()

    def _audit(self, app, path="x.zip"):
        app.path_entry.delete(0, "end")
        app.path_entry.insert(0, path)
        app._run()
        self._pump(app)

    @staticmethod
    def _texts(widget):
        found = []
        for child in widget.winfo_children():
            try:
                found.append(str(child.cget("text")))
            except Exception:
                pass
            found += TestFeatures._texts(child)
        return found

    # ---- readiness --------------------------------------------------------

    def test_readiness_states_in_the_card(self):
        cases = [
            (AuditOutcome(findings(), 0.1), "No issues detected"),
            (AuditOutcome(findings(warnings=[DUP]), 0.1), "Review recommended"),
            (AuditOutcome(findings(info=["n"]), 0.1), "Informational notes only"),
            (AuditOutcome(findings([ENC]), 0.1), "Issues found"),
            (AuditOutcome(crash="RuntimeError: x"), "Audit could not complete"),
            (AuditOutcome(findings(["File is not a valid ZIP archive (BadZipFile)."]), 0.1), "Audit could not complete"),
        ]
        for outcome, headline in cases:
            app = self._app(outcome)
            self._audit(app)
            self.assertEqual(app.ready_head.cget("text"), headline)
            self._close(app)

    def test_card_before_during_and_after_an_audit(self):
        gate = threading.Event()
        app = self._app(None, audit=lambda p: (gate.wait(5), AuditOutcome(findings(), 0.1))[1])
        self.assertEqual(app.ready_head.cget("text"), "Release readiness")
        app.path_entry.insert(0, "x.zip")
        app._run()
        self.assertIn("in progress", app.ready_reason.cget("text"))
        self.assertEqual(app.compare_button.cget("state"), "disabled")
        gate.set()
        self._pump(app)
        self.assertEqual(app.ready_head.cget("text"), "No issues detected")

    def test_passed_checks_are_shown_only_with_evidence(self):
        review = ManifestReview(available=True, declares_icons=True, declares_locale=True, declares_references=True)
        app = self._app(AuditOutcome(findings(), 0.1, None, review))
        self._audit(app)
        self.assertIn("Icons", app.ready_passed.cget("text"))
        self._close(app)
        app = self._app(AuditOutcome(findings(warnings=["Unknown future message."]), 0.1, None, review))
        self._audit(app)
        self.assertEqual(app.ready_passed.winfo_manager(), "")  # nothing claimed

    def test_no_overclaiming_text_anywhere(self):
        app = self._app(AuditOutcome(findings(), 0.1))
        self._audit(app)
        blob = " ".join(self._texts(app)).lower()
        for banned in ("certified", "guaranteed", "will pass", "is secure", "100%"):
            self.assertNotIn(banned, blob)

    # ---- guidance ---------------------------------------------------------

    def test_finding_card_shows_level_why_and_action(self):
        app = self._app(AuditOutcome(findings([ENC]), 0.1))
        self._audit(app)
        text = " ".join(self._texts(app.list))
        self.assertIn(ENC, text)
        self.assertIn("Fix before release", text)
        self.assertIn("Why it matters:", text)
        self.assertIn("What to do:", text)

    def test_unclassified_finding_gets_no_invented_advice(self):
        app = self._app(AuditOutcome(findings(warnings=["Unknown future message."]), 0.1))
        self._audit(app)
        text = " ".join(self._texts(app.list))
        self.assertIn("Unknown future message.", text)
        self.assertNotIn("Why it matters:", text)

    def test_counts_and_filters_still_match_findings(self):
        app = self._app(AuditOutcome(findings([ENC], [DUP, "Duplicate entry detected: c."], ["n"]), 0.1))
        self._audit(app)
        self.assertEqual([app.counts[k].cget("text") for k in ("errors", "warnings", "info")], ["1", "2", "1"])
        app._set_filter("Warnings")
        app.update()
        self.assertEqual(len(app.list.winfo_children()), 2)

    # ---- manifest tab -----------------------------------------------------

    def test_manifest_tab_states(self):
        review = build_review({"manifest_version": 3, "name": "N", "version": "1", "permissions": ["tabs"],
                               "host_permissions": ["<all_urls>"]})
        app = self._app(AuditOutcome(findings(), 0.1, None, review))
        app._set_filter("Manifest")
        app.update()
        self.assertIn("No audit yet", self._texts(app.empty))
        self._audit(app)
        self.assertEqual(app._filter, "manifest")  # the audit finished while the tab was open
        text = " ".join(self._texts(app.list))
        self.assertIn("Manifest summary", text)
        self.assertIn("tabs", text)
        self.assertIn("Access to all websites", text)
        self.assertIn("OBSERVATION", text)
        app._set_filter("All")
        app.update()
        self.assertIn("No issues found", self._texts(app.empty))  # findings view restored

    def test_manifest_tab_when_review_unavailable_and_when_failed(self):
        app = self._app(AuditOutcome(findings(["Missing root-level manifest.json."]), 0.1,
                                     None, ManifestReview(reason="manifest.json is missing")))
        self._audit(app)
        app._set_filter("Manifest")
        app.update()
        self.assertIn("Manifest review unavailable", self._texts(app.empty))
        app = self._app(AuditOutcome(crash="RuntimeError: x"))
        self._audit(app)
        app._set_filter("Manifest")
        app.update()
        self.assertIn("No audit yet", self._texts(app.empty))

    def test_manifest_text_cannot_inject_widgets_or_crash(self):
        evil = "<script>alert(1)</script>\n%s{x}"
        review = build_review({"name": evil, "permissions": [evil, "tabs"], "host_permissions": [evil]})
        app = self._app(AuditOutcome(findings(), 0.1, None, review))
        self._audit(app)
        app._set_filter("Manifest")
        app.update()
        self.assertTrue(app.list.winfo_children())

    # ---- compare ----------------------------------------------------------

    def _report_file(self, name, outcome, zip_name="ext.zip"):
        path = os.path.join(self.tmp, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(to_json(build_report(outcome, zip_name)))
        return path

    def _compare(self, app, path):
        shown = []
        with mock.patch("src.extension_guard.gui.filedialog.askopenfilename", return_value=path), \
                mock.patch.object(app, "_show_text", side_effect=lambda t, x: shown.append((t, x))):
            app._compare()
        return shown

    def test_compare_is_disabled_until_an_audit_and_cancel_is_silent(self):
        app = self._app(AuditOutcome(findings([ENC]), 0.1))
        self.assertEqual(app.compare_button.cget("state"), "disabled")
        self._audit(app)
        self.assertEqual(app.compare_button.cget("state"), "normal")
        before = app.status.cget("text")
        self.assertEqual(self._compare(app, ""), [])
        self.assertEqual(app.status.cget("text"), before)

    def test_compare_reports_new_and_fixed(self):
        old = self._report_file("old.json", AuditOutcome(findings([ENC], [DUP]), 0.1))
        app = self._app(AuditOutcome(findings(["content_scripts[0].js references missing file: c.js."], [DUP]), 0.1))
        self._audit(app)
        shown = self._compare(app, old)
        self.assertEqual(shown[0][0], "Report comparison")
        self.assertIn("1 new, 1 fixed, 1 unchanged", shown[0][1])
        self.assertIn("1 new, 1 fixed", app.status.cget("text"))

    def test_incompatible_files_are_reported_not_compared(self):
        app = self._app(AuditOutcome(findings([ENC]), 0.1))
        self._audit(app)
        bad = {
            "malformed.json": "{",
            "future.json": json.dumps({"schema_version": 9, "findings": []}),
            "list.json": "[]",
            "nofindings.json": json.dumps({"schema_version": 2}),
        }
        for name, content in bad.items():
            path = os.path.join(self.tmp, name)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
            shown = self._compare(app, path)
            self.assertEqual(shown[0][0], "Cannot compare reports", name)
            self.assertIn("cannot be compared", shown[0][1])
            self.assertIn("could not be compared", app.status.cget("text"))
        self.assertEqual(self._compare(app, os.path.join(self.tmp, "missing.json"))[0][0], "Cannot compare reports")

    def test_compare_leaves_window_state_and_results_alone(self):
        old = self._report_file("old.json", AuditOutcome(findings([ENC]), 0.1))
        app = self._app(AuditOutcome(findings([ENC], [DUP]), 0.1))
        self._audit(app)
        before = (app.state(), app.winfo_id(), app.path_entry.get(), list(app._rows), app._filter, os.listdir(self.tmp))
        with mock.patch.object(App, "withdraw") as w, mock.patch.object(App, "deiconify") as d, \
                mock.patch.object(App, "iconify") as i:
            self._compare(app, old)
            app._show_text("t", "body")  # the real window too
            app.update()
        for m in (w, d, i):
            m.assert_not_called()
        after = (app.state(), app.winfo_id(), app.path_entry.get(), list(app._rows), app._filter, os.listdir(self.tmp))
        self.assertEqual(before, after)

    def test_text_window_is_replaced_not_stacked_and_closed_with_the_app(self):
        app = self._app(AuditOutcome())
        app._show_text("a", "one")
        first = app._compare_win
        app._show_text("b", "two")
        app.update()
        self.assertFalse(first.winfo_exists())
        self.assertTrue(app._compare_win.winfo_exists())
        app.destroy()  # must not raise with the child window open

    # ---- drag and drop ----------------------------------------------------

    def _zip(self, name="drop me (v2) επέκταση.zip"):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as fh:
            fh.write(b"PK")
        return path

    def test_drop_starts_an_audit_and_shows_the_file(self):
        seen = []
        app = self._app(None, audit=lambda p: seen.append(p) or AuditOutcome(findings(), 0.1))
        path = self._zip()
        app._on_drop([path])
        self.assertEqual(app.path_entry.get(), path)
        self.assertEqual(app.file_label.cget("text"), os.path.basename(path))
        self.assertEqual(app.status.cget("text"), "Running audit…")
        self._pump(app)
        self.assertEqual(seen, [path])
        self.assertEqual(app.ready_head.cget("text"), "No issues detected")

    def test_drop_flashes_the_picker_then_restores_it(self):
        app = self._app(AuditOutcome(findings(), 0.1))
        app._on_drop([self._zip()])
        self.assertEqual(app._picker.cget("border_color"), gui.ACCENT)
        app._end_flash()
        self.assertEqual(app._picker.cget("border_color"), gui.CARD_BORDER)

    def test_unsupported_drops_are_explained_and_start_nothing(self):
        calls = []
        app = self._app(None, audit=lambda p: calls.append(p) or AuditOutcome())
        txt = os.path.join(self.tmp, "a.txt")
        open(txt, "w").close()
        for paths, fragment in (([txt], "not a .zip"), ([self.tmp], "folder"), ([], "Nothing"),
                                ([self._zip("a.zip"), self._zip("b.zip")], "one ZIP")):
            app._on_drop(paths)
            self.assertIn(fragment, app.status.cget("text"))
        self.assertEqual(calls, [])
        self.assertFalse(app._runner.busy)
        self.assertEqual(app.path_entry.get(), "")

    def test_drop_during_an_audit_is_ignored(self):
        gate = threading.Event()
        calls = []

        def audit(path):
            calls.append(path)
            gate.wait(5)
            return AuditOutcome(findings(), 0.1)

        app = self._app(None, audit=audit)
        first, second = self._zip("one.zip"), self._zip("two.zip")
        app._on_drop([first])
        app._on_drop([second])
        self.assertIn("already running", app.status.cget("text"))
        self.assertEqual(app.path_entry.get(), first)  # the running audit's file is not replaced
        gate.set()
        self._pump(app)
        self.assertEqual(calls, [first])

    def test_destroy_restores_window_procedures_and_cancels_the_flash(self):
        app = self._app(AuditOutcome(findings(), 0.1))
        app._on_drop([self._zip()])
        self.assertIsNotNone(app._flash_id)
        app.destroy()
        self.assertIsNone(app._flash_id)
        self.assertFalse(app._drop.active)

    def test_app_is_usable_when_drop_support_is_unavailable(self):
        with mock.patch.object(gui.DropFiles, "install", return_value=False):
            app = self._app(AuditOutcome(findings(), 0.1))
        self.assertNotIn("drop", app.path_entry.cget("placeholder_text"))
        self._audit(app)
        self.assertEqual(app.ready_head.cget("text"), "No issues detected")

    def test_window_identity_is_kept_across_everything(self):
        app = self._app(AuditOutcome(findings([ENC]), 0.1))
        ident = app.winfo_id()
        with mock.patch.object(App, "withdraw") as w, mock.patch.object(App, "deiconify") as d:
            self._audit(app)
            app._set_filter("Manifest")
            app._set_filter("All")
            app._on_drop([self._zip()])
            self._pump(app)
        w.assert_not_called()
        d.assert_not_called()
        self.assertEqual(app.winfo_id(), ident)


if __name__ == "__main__":
    unittest.main()
