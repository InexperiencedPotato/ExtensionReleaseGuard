"""Window smoke tests; skipped without CustomTkinter or a usable display."""

import os
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

try:
    import customtkinter as ctk
    from src.extension_guard.gui import App
    import tkinter

    _probe = tkinter.Tk()
    _probe.destroy()
    _SKIP = ""
except Exception as exc:  # missing customtkinter, or no display
    _SKIP = f"GUI unavailable: {exc}"

from src.extension_guard.gui_core import AuditOutcome, AuditRunner


@unittest.skipIf(_SKIP, _SKIP)
class TestApp(unittest.TestCase):
    def setUp(self):
        # Keep settings and crash logs out of the real LocalAppData.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.lad = tmp.name
        patcher = mock.patch.dict(os.environ, {"LOCALAPPDATA": tmp.name})
        patcher.start()
        self.addCleanup(patcher.stop)

    def _app(self, outcome):
        app = App(runner=AuditRunner(audit=lambda path: outcome))
        app.withdraw()
        self.addCleanup(self._close, app)
        return app

    @staticmethod
    def _close(app):
        try:
            app.destroy()
        except Exception:
            pass

    def _pump_until_idle(self, app, timeout=5.0):
        deadline = time.monotonic() + timeout
        while app._runner.busy and time.monotonic() < deadline:
            app.update()
            time.sleep(0.01)
        app.update()

    def test_empty_path_does_not_start(self):
        app = self._app(AuditOutcome())
        app._run()
        self.assertFalse(app._runner.busy)
        self.assertIn("Choose a ZIP", app.status.cget("text"))

    def test_run_disables_button_then_restores_and_reports(self):
        app = self._app(AuditOutcome(elapsed=0.0))
        app.path_entry.insert(0, "x.zip")
        app._run()
        self.assertEqual(app.run_button.cget("state"), "disabled")
        self.assertEqual(app.status.cget("text"), "Running audit…")
        self._pump_until_idle(app)
        self.assertEqual(app.run_button.cget("state"), "normal")
        self.assertTrue(app.status.cget("text").startswith("Audit passed"))

    def test_crash_status_shown(self):
        app = self._app(AuditOutcome(crash="RuntimeError: boom"))
        app.path_entry.insert(0, "x.zip")
        app._run()
        self._pump_until_idle(app)
        self.assertIn("failed unexpectedly", app.status.cget("text"))
        self.assertEqual(app.run_button.cget("state"), "normal")

    def _cards(self, app):
        return [w for w in app.list.winfo_children() if w.winfo_children() and len(w.winfo_children()) == 3]

    def _texts(self, app):
        out = []
        for w in app.list.winfo_children():
            for c in w.winfo_children():
                if hasattr(c, "cget"):
                    try:
                        out.append(c.cget("text"))
                    except Exception:
                        pass
        return out

    def _finish(self, app, outcome):
        app.path_entry.insert(0, "x.zip")
        app._run()
        self._pump_until_idle(app)
        app.update()

    def test_initial_empty_state(self):
        app = self._app(AuditOutcome())
        app.update()
        self.assertIn("No audit yet", self._texts_deep(app))

    def _texts_deep(self, app):
        found = []

        def walk(w):
            for c in w.winfo_children():
                try:
                    found.append(c.cget("text"))
                except Exception:
                    pass
                walk(c)

        walk(app.list)
        walk(app.empty)
        return " | ".join(found)

    def test_findings_render_with_counts_and_filter(self):
        f = {"errors": ["a/b.js missing", "e2"], "warnings": ["w1"], "info": ["i1"]}
        app = self._app(AuditOutcome(f, 0.1))
        self._finish(app, None)
        self.assertEqual([app.counts[k].cget("text") for k in ("errors", "warnings", "info")], ["2", "1", "1"])
        text = self._texts_deep(app)
        self.assertIn("a/b.js missing", text)
        self.assertEqual(len(app.list.winfo_children()), 4)
        app.tabs.set("Errors")
        app._set_filter("Errors")
        app.update()
        self.assertEqual(len(app.list.winfo_children()), 2)
        app._set_filter("Info")
        app.update()
        self.assertIn("i1", self._texts_deep(app))
        self.assertEqual(len(app.list.winfo_children()), 1)

    def test_clean_audit_state(self):
        app = self._app(AuditOutcome())
        self._finish(app, None)
        self.assertIn("No issues found", self._texts_deep(app))
        self.assertEqual(app.counts["errors"].cget("text"), "0")

    def test_filter_with_no_matches(self):
        app = self._app(AuditOutcome({"errors": ["e"], "warnings": [], "info": []}))
        self._finish(app, None)
        app._set_filter("Warnings")
        app.update()
        self.assertIn("Nothing to show", self._texts_deep(app))

    def test_failure_state_hides_technical_detail(self):
        app = self._app(AuditOutcome(crash="RuntimeError: secret-boom"))
        self._finish(app, None)
        shown = self._texts_deep(app) + app.status.cget("text")
        self.assertIn("could not be completed", shown)
        self.assertNotIn("secret-boom", shown)
        self.assertNotIn("Traceback", shown)
        self.assertEqual(app.counts["errors"].cget("text"), "–")

    def test_large_list_renders_in_chunks_and_completes(self):
        n = 400
        app = self._app(AuditOutcome({"errors": [f"e{i}" for i in range(n)], "warnings": [], "info": []}))
        self._finish(app, None)
        deadline = time.monotonic() + 10
        while len(app.list.winfo_children()) < n and time.monotonic() < deadline:
            app.update()
            time.sleep(0.01)
        self.assertEqual(len(app.list.winfo_children()), n)

    def test_destroy_while_rendering_is_safe(self):
        n = 400
        app = self._app(AuditOutcome({"errors": [f"e{i}" for i in range(n)], "warnings": [], "info": []}))
        self._finish(app, None)
        app.destroy()
        self.assertIsNone(app._render_id)

    # ---- appearance ---------------------------------------------------

    def test_app_is_dark_only(self):
        from src.extension_guard import gui

        app = self._app(AuditOutcome())
        app.update()
        self.assertEqual(ctk.get_appearance_mode(), "Dark")
        self.assertEqual(app.cget("bg"), gui.BG[1])
        self.assertFalse(hasattr(app, "theme_button"))
        self.assertFalse(os.path.exists(os.path.join(self.lad, "ExtensionReleaseGuard", "settings.json")))

        def texts(node):
            out = []
            for kid in node.winfo_children():
                try:
                    out.append(str(kid.cget("text")))
                except Exception:
                    pass
                out += texts(kid)
            return out

        self.assertFalse([t for t in texts(app) if "Light" in t or "☀" in t or "☾" in t])

    def test_title_bar_reapplied_once_when_first_shown(self):
        app = App(runner=AuditRunner(audit=lambda p: AuditOutcome()))
        self.addCleanup(self._close, app)
        with mock.patch.object(App, "_set_titlebar") as bar:
            app.update()  # the window is mapped here
            app.update()
            app.withdraw()
            app.deiconify()
            app.update()
        self.assertEqual(bar.call_count, 1)

    def test_dark_title_bar_set_without_hiding_the_window(self):
        import tkinter

        with mock.patch.object(tkinter.Wm, "withdraw") as hide, mock.patch.object(
            tkinter.Wm, "deiconify"
        ) as show, mock.patch.object(tkinter.Wm, "iconify") as icon:
            app = self._app(AuditOutcome())  # _app itself calls withdraw after construction
            app.update()
        self.assertEqual((show.call_count, icon.call_count), (0, 0))
        self.assertEqual(hide.call_count, 1)  # only the test's own app.withdraw()

    def test_empty_state_and_scrollbar_visibility(self):
        app = self._app(AuditOutcome({"errors": ["e"], "warnings": [], "info": []}))
        app.update()
        # grid_info() of a CTkScrollableFrame is its outer frame, which holds the scrollbar
        self.assertFalse(app.list.grid_info())  # no scrollbar before any audit
        self.assertTrue(app.empty.winfo_manager())
        self._finish(app, None)
        self.assertTrue(app.list.grid_info())
        self.assertFalse(app.empty.winfo_manager())
        app._set_filter("Info")
        self.assertFalse(app.list.grid_info())  # filtered to nothing
        self.assertIn("Nothing to show", self._texts_deep(app))

    def test_progress_only_visible_while_running(self):
        gate = threading.Event()
        app = App(runner=AuditRunner(audit=lambda p: (gate.wait(5), AuditOutcome())[1]))
        app.withdraw()
        self.addCleanup(self._close, app)
        self.assertFalse(app.progress.winfo_manager())
        app.path_entry.insert(0, "x.zip")
        app._run()
        self.assertTrue(app.progress.winfo_manager())
        gate.set()
        self._pump_until_idle(app)
        self.assertFalse(app.progress.winfo_manager())

    def test_success_empty_state_has_icon_and_text(self):
        app = self._app(AuditOutcome())
        self._finish(app, None)
        text = self._texts_deep(app)
        self.assertIn("✓", text)
        self.assertIn("No issues found", text)

    # ---- export -------------------------------------------------------

    def _save_as(self, app, path):
        with mock.patch("src.extension_guard.gui.filedialog.asksaveasfilename", return_value=path) as dlg:
            app._export()
        return dlg

    def test_export_disabled_until_a_valid_result(self):
        app = self._app(AuditOutcome(crash="RuntimeError: boom"))
        app.update()
        self.assertEqual(app.export_button.cget("state"), "disabled")
        self._finish(app, None)  # failed audit
        self.assertEqual(app.export_button.cget("state"), "disabled")
        self.assertEqual(self._save_as(app, "x.json").call_count, 0)  # _export is a no-op

    def test_export_enabled_after_audit_and_disabled_while_rerunning(self):
        gate = threading.Event()
        calls = []

        def audit(path):
            calls.append(path)
            if len(calls) > 1:
                gate.wait(5)
            return AuditOutcome({"errors": ["e"], "warnings": [], "info": []}, 0.1)

        app = App(runner=AuditRunner(audit=audit))
        app.withdraw()
        self.addCleanup(self._close, app)
        app.path_entry.insert(0, "x.zip")
        app._run()
        self._pump_until_idle(app)
        self.assertEqual(app.export_button.cget("state"), "normal")
        app._run()
        self.assertEqual(app.export_button.cget("state"), "disabled")
        gate.set()
        self._pump_until_idle(app)
        self.assertEqual(app.export_button.cget("state"), "normal")

    def test_export_writes_each_format_with_base_name_only(self):
        import json

        app = self._app(AuditOutcome({"errors": ["e<b>"], "warnings": [], "info": []}, 0.1))
        app.path_entry.insert(0, os.path.join(self.lad, "private dir", "ext.zip"))
        app._run()
        self._pump_until_idle(app)
        for ext in (".json", ".txt", ".html"):
            out = os.path.join(self.lad, "report" + ext)
            self._save_as(app, out)
            with open(out, encoding="utf-8") as fh:
                text = fh.read()
            self.assertIn("ext.zip", text)
            self.assertNotIn("private dir", text)
            self.assertTrue(app.status.cget("text").startswith("Report saved"))
            if ext == ".json":
                self.assertEqual(json.loads(text)["summary"]["errors"], 1)
            if ext == ".html":
                self.assertIn("e&lt;b&gt;", text)

    def test_export_cancel_and_write_error_are_graceful(self):
        app = self._app(AuditOutcome())
        self._finish(app, None)
        before = app.status.cget("text")
        self._save_as(app, "")  # cancelled
        self.assertEqual(app.status.cget("text"), before)
        self._save_as(app, os.path.join(self.lad, "missing dir", "r.json"))
        shown = app.status.cget("text")
        self.assertIn("could not be saved", shown)
        self.assertNotIn("Traceback", shown)
        self.assertNotIn("missing dir", shown)

    def test_export_unknown_extension_saved_as_html(self):
        app = self._app(AuditOutcome())
        self._finish(app, None)
        out = os.path.join(self.lad, "report.bin")
        self._save_as(app, out)
        self.assertTrue(os.path.exists(out + ".html"))

    def test_export_button_fits_at_minimum_window_size(self):
        from src.extension_guard import gui

        app = self._app(AuditOutcome())
        app.geometry(f"{gui.MIN_SIZE[0]}x{gui.MIN_SIZE[1]}")
        app.update()
        head = app.export_button.master
        needed = sum(w.winfo_reqwidth() for w in head.winfo_children()) + 10
        self.assertLessEqual(needed, head.winfo_width())

    def test_destroy_while_running_cancels_poll(self):
        app = self._app(AuditOutcome())
        app.path_entry.insert(0, "x.zip")
        app._run()
        self.assertIsNotNone(app._poll_id)
        app.destroy()
        self.assertIsNone(app._poll_id)


if __name__ == "__main__":
    unittest.main()
