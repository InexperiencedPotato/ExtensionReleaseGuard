"""CustomTkinter window for ExtensionRelease Guard.

Run with ``python -m extension_guard.gui`` (needs the ``gui`` extra).
The audit runs on a worker thread (see :class:`gui_core.AuditRunner`); only
this module's main-thread ``after`` poll touches widgets.

Every colour below is a ``(light, dark)`` pair, so CustomTkinter restyles the
whole window in place when the appearance mode changes.
"""

from __future__ import annotations

import os
import sys
import tkinter
from tkinter import filedialog
from typing import List, Optional, Tuple

import customtkinter as ctk

from .compare import CompareError, compare_reports, format_comparison, load_report, validate_report
from .dropfiles import DropFiles, validate_drop
from .guidance import LEVEL_LABEL, explain
from .readiness import CHECK_SHORT, CLEAR, INCOMPLETE, INFORMATIONAL, ISSUES, REVIEW, Readiness, assess
from .report import FORMATS, build_report, write_report
from .gui_core import (
    AuditOutcome,
    AuditRunner,
    filter_findings,
    flatten,
    format_status,
    log_failure,
    log_path,
    result_state,
    summarize,
)

POLL_MS = 100
START_SIZE = (1150, 750)
MIN_SIZE = (900, 660)
SIDEBAR_W = 270
CHUNK = 30  # finding cards built per UI tick, so huge result lists never freeze the window

# Design tokens: (light, dark). Dark is layered charcoal (BG < SIDEBAR < CARD < SECONDARY);
# light is a soft grey page with white surfaces.
BG = ("#eef1f4", "#15171a")
SIDEBAR = ("#ffffff", "#1b1e21")
CARD = ("#ffffff", "#212529")
CARD_BORDER = ("#dde2e8", "#30353a")
INSET = ("#f3f5f8", "#191c1f")
ACCENT = ("#1f8a80", "#2a8f86")
ACCENT_HOVER = ("#187268", "#33a79d")
ACCENT_TINT = ("#d8eeeb", "#1b3837")
SECONDARY = ("#e8ecf0", "#2d3237")
SECONDARY_HOVER = ("#d9dfe5", "#3a4046")
TEXT = ("#18222d", "#eef1f3")
MUTED = ("#58646f", "#a9b2ba")
ON_ACCENT = "#ffffff"
FONT = "Segoe UI"
RADIUS = 14

# severity -> (label, accent, tinted background, glyph)
SEVERITY = {
    "error": ("ERROR", ("#c62f3b", "#ff6b6b"), ("#fbe4e6", "#3a2427"), "✕"),
    "warning": ("WARNING", ("#9a6700", "#f5b942"), ("#fff1cc", "#38301b"), "!"),
    "info": ("INFO", ("#1d62c4", "#5aa9ff"), ("#dbe9fb", "#1f3045"), "i"),
}
STATE_COLOR = {
    "clean": ("#1b8a5a", "#4cc38a"),
    "findings": ("#9a6700", "#f5b942"),
    "failed": ("#c62f3b", "#ff6b6b"),
}
SUCCESS_TINT = ("#dff3e9", "#1c352a")
TABS = {"All": "all", "Errors": "error", "Warnings": "warning", "Info": "info", "Manifest": "manifest"}
# readiness state -> (glyph, colour)
READY_STYLE = {
    INCOMPLETE: ("!", SEVERITY["error"][1]),
    ISSUES: ("✕", SEVERITY["error"][1]),
    REVIEW: ("!", SEVERITY["warning"][1]),
    INFORMATIONAL: ("i", SEVERITY["info"][1]),
    CLEAR: ("✓", STATE_COLOR["clean"]),
}
# manifest review item kind -> (label, severity style)
REVIEW_KIND = {"observation": ("OBSERVATION", "info"), "inconsistency": ("INCONSISTENCY", "warning")}
CHECKS = (
    ("Manifest", "Required fields and structure"),
    ("References", "Every referenced file exists"),
    ("Locales", "messages.json and default locale"),
    ("Icons", "Valid image signatures and sizes"),
)
IDLE_READY = "Run an audit to see whether the package is ready to release."
STEPS = ("Choose a ZIP", "Run the audit", "Review findings")


def _font(size: int, weight: str = "normal") -> ctk.CTkFont:
    return ctk.CTkFont(family=FONT, size=size, weight=weight)


class App(ctk.CTk):
    # CustomTkinter's own title-bar handling withdraws and re-shows the window on every
    # appearance change, which makes the taskbar button vanish and return. Switch it off
    # and set the title bar in place instead (see _set_titlebar).
    _deactivate_windows_window_header_manipulation = True

    def __init__(self, runner: Optional[AuditRunner] = None):
        ctk.set_appearance_mode("dark")  # dark only
        super().__init__(fg_color=BG)
        self.title("ExtensionRelease Guard")
        self.minsize(*MIN_SIZE)
        self._place_window(*START_SIZE)
        self._runner = runner or AuditRunner()
        self._poll_id: Optional[str] = None
        self._render_id: Optional[str] = None
        self._resize_id: Optional[str] = None
        self._rows: List[Tuple[str, str]] = []
        self._outcome: Optional[AuditOutcome] = None  # last successful audit, for export
        self._zip_path = ""
        self._filter = "all"
        self._wrap = 600
        self._panel_h = 10_000  # until the panel reports its real height
        self._steps = None
        self._state = "idle"  # idle | running | clean | findings | failed
        self._flash_id: Optional[str] = None
        self._compare_win = None
        self._drop = DropFiles(self, self._on_drop)

        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)
        self._build_sidebar()
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.grid(row=0, column=1, sticky="nsew", padx=32, pady=24)
        main.columnconfigure(0, weight=1)
        main.rowconfigure(4, weight=1)  # the findings panel takes all spare space
        self._build_header(main)
        self._build_picker(main)
        self._build_summary(main)
        self._build_findings(main)
        self._show_empty("No audit yet", "Pick an extension ZIP above, then run the audit.", "idle")
        self._set_titlebar()
        self._titlebar_done = False
        self.bind("<Map>", self._on_first_map, add="+")
        if self._drop.install():  # file drops; the app is fully usable through Browse if this is unavailable
            self.path_entry.configure(placeholder_text="Path to extension .zip, or drop a .zip on this window")

    def _on_first_map(self, event) -> None:
        # The frame cannot be repainted before the window is on screen, so the bar would stay light
        # until the first minimise/restore; apply the dark title bar again now that it is shown.
        if event.widget is self and not self._titlebar_done:
            self._titlebar_done = True
            self._set_titlebar()

    # ---- construction -------------------------------------------------

    def _build_sidebar(self) -> None:
        bar = ctk.CTkFrame(self, width=SIDEBAR_W, corner_radius=0, fg_color=SIDEBAR)
        bar.grid(row=0, column=0, sticky="nsw")
        bar.grid_propagate(False)
        bar.columnconfigure(0, weight=1)

        brand = ctk.CTkFrame(bar, fg_color="transparent")
        brand.grid(row=0, column=0, sticky="w", padx=26, pady=(30, 0))
        ctk.CTkLabel(
            brand, text="✓", width=46, height=46, corner_radius=13, fg_color=ACCENT, text_color=ON_ACCENT,
            font=_font(23, "bold"),
        ).grid(row=0, column=0, rowspan=2)
        ctk.CTkLabel(brand, text="ExtensionRelease", font=_font(18, "bold"), text_color=TEXT, anchor="w").grid(
            row=0, column=1, sticky="sw", padx=(13, 0)
        )
        ctk.CTkLabel(brand, text="Guard", font=_font(15, "bold"), text_color=ACCENT, anchor="w").grid(
            row=1, column=1, sticky="nw", padx=(13, 0)
        )
        ctk.CTkLabel(
            bar, text="Check your Chrome extension ZIP before you release it.", font=_font(14), text_color=MUTED,
            justify="left", anchor="w", wraplength=SIDEBAR_W - 52,
        ).grid(row=1, column=0, sticky="w", padx=26, pady=(18, 0))

        ctk.CTkLabel(bar, text="WHAT IT CHECKS", font=_font(12, "bold"), text_color=MUTED, anchor="w").grid(
            row=2, column=0, sticky="w", padx=26, pady=(34, 10)
        )
        for i, (name, detail) in enumerate(CHECKS):
            item = ctk.CTkFrame(bar, fg_color=INSET, corner_radius=10)
            item.grid(row=3 + i, column=0, sticky="ew", padx=20, pady=3)
            item.columnconfigure(1, weight=1)
            ctk.CTkLabel(
                item, text="✓", width=26, height=26, corner_radius=8, fg_color=ACCENT_TINT, text_color=ACCENT,
                font=_font(13, "bold"),
            ).grid(row=0, column=0, rowspan=2, padx=(10, 10), pady=9)
            ctk.CTkLabel(item, text=name, font=_font(14, "bold"), text_color=TEXT, anchor="w").grid(
                row=0, column=1, sticky="w", pady=(8, 0)
            )
            ctk.CTkLabel(item, text=detail, font=_font(12), text_color=MUTED, anchor="w").grid(
                row=1, column=1, sticky="w", pady=(0, 8), padx=(0, 8)
            )
        bar.rowconfigure(8, weight=1)
        ctk.CTkLabel(
            bar, text="Audits run locally.\nYour ZIP is never uploaded.", font=_font(12), text_color=MUTED,
            justify="left", anchor="w",
        ).grid(row=9, column=0, sticky="sw", padx=26, pady=24)

    def _card(self, parent, fg=CARD, border=CARD_BORDER, **kw) -> ctk.CTkFrame:
        return ctk.CTkFrame(parent, fg_color=fg, border_color=border, border_width=1, corner_radius=RADIUS, **kw)

    def _build_header(self, parent) -> None:
        head = ctk.CTkFrame(parent, fg_color="transparent")
        head.grid(row=0, column=0, sticky="ew", pady=(0, 14))
        head.columnconfigure(0, weight=1)
        ctk.CTkLabel(head, text="Audit dashboard", font=_font(28, "bold"), text_color=TEXT, anchor="w").grid(
            row=0, column=0, sticky="w"
        )
        ctk.CTkLabel(
            head, text="Validate a packaged extension and review every finding.", font=_font(14), text_color=MUTED,
            anchor="w",
        ).grid(row=1, column=0, sticky="w")
    def _set_titlebar(self) -> None:
        """Make the Windows title bar dark without hiding the window."""
        if sys.platform != "win32":
            return
        try:
            import ctypes
            from ctypes import wintypes

            user32, dwm = ctypes.windll.user32, ctypes.windll.dwmapi
            hwnd = user32.GetParent(self.winfo_id())
            value = ctypes.c_int(1)
            for attribute in (20, 19):  # DWMWA_USE_IMMERSIVE_DARK_MODE, and its pre-20H1 id
                if dwm.DwmSetWindowAttribute(hwnd, attribute, ctypes.byref(value), ctypes.sizeof(value)) == 0:
                    break
            # Repaint the caption in place: a frame-change request does not, but toggling the
            # non-client activation state does (like minimise/restore, without hiding the window).
            send = user32.SendMessageW
            send.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
            active = user32.GetForegroundWindow() == hwnd
            send(hwnd, 0x0086, not active, 0)  # WM_NCACTIVATE
            send(hwnd, 0x0086, active, 0)
        except (AttributeError, OSError):  # cosmetic only; never break the app over it
            pass

    def _build_picker(self, parent) -> None:
        card = self._picker = self._card(parent)
        card.grid(row=1, column=0, sticky="ew")
        card.columnconfigure(0, weight=1)

        pick = ctk.CTkFrame(card, fg_color="transparent")
        pick.grid(row=0, column=0, sticky="ew", padx=22, pady=(18, 0))
        pick.columnconfigure(1, weight=1)
        ctk.CTkLabel(
            pick, text="ZIP", width=46, height=46, corner_radius=12, fg_color=ACCENT_TINT, text_color=ACCENT,
            font=_font(13, "bold"),
        ).grid(row=0, column=0, rowspan=2, padx=(0, 14))
        self.file_label = ctk.CTkLabel(
            pick, text="No file selected", font=_font(16, "bold"), text_color=MUTED, anchor="w"
        )
        self.file_label.grid(row=0, column=1, sticky="ew", columnspan=2)
        self.path_entry = ctk.CTkEntry(
            pick, height=38, corner_radius=10, placeholder_text="Path to extension .zip", font=_font(14),
            fg_color=INSET, border_color=CARD_BORDER, text_color=TEXT, placeholder_text_color=MUTED,
        )
        self.path_entry.grid(row=1, column=1, sticky="ew", pady=(6, 0))
        self.path_entry.bind("<KeyRelease>", lambda _e: self._show_file())
        self.browse_button = ctk.CTkButton(
            pick, text="Browse…", width=110, height=38, corner_radius=10, font=_font(14, "bold"),
            fg_color=SECONDARY, hover_color=SECONDARY_HOVER, text_color=TEXT, command=self._browse,
        )
        self.browse_button.grid(row=1, column=2, padx=(10, 0), pady=(6, 0))

        # Second step: a separate band, so choosing a file and running the audit read as two actions.
        band = ctk.CTkFrame(card, fg_color=INSET, corner_radius=10)
        band.grid(row=1, column=0, sticky="ew", padx=12, pady=(16, 12))
        band.columnconfigure(0, weight=1)
        band.rowconfigure((0, 1), weight=1)
        self.status = ctk.CTkLabel(
            band, text="Choose a ZIP file to audit.", anchor="w", font=_font(15, "bold"), text_color=MUTED
        )
        self.status.grid(row=0, column=0, sticky="sew", padx=14, pady=(12, 2))
        self.progress = ctk.CTkProgressBar(band, mode="indeterminate", height=5, progress_color=ACCENT, fg_color=CARD)
        self.progress.grid(row=1, column=0, sticky="new", padx=14, pady=(0, 12))
        self.progress.grid_remove()  # only visible (and animating) while an audit runs
        self.run_button = ctk.CTkButton(
            band, text="Run Audit", width=150, height=46, corner_radius=10, font=_font(16, "bold"), fg_color=ACCENT,
            hover_color=ACCENT_HOVER, text_color=ON_ACCENT, command=self._run,
        )
        self.run_button.grid(row=0, column=1, rowspan=2, padx=12, pady=12)

    def _build_summary(self, parent) -> None:
        """One card: release readiness on the left, the three severity counts on the right."""
        card = self._card(parent)
        card.grid(row=2, column=0, sticky="ew", pady=(14, 0))
        card.columnconfigure(1, weight=1)
        self.ready_icon = ctk.CTkLabel(
            card, text="–", width=44, height=44, corner_radius=22, fg_color=SECONDARY, text_color=MUTED,
            font=_font(20, "bold"),
        )
        self.ready_icon.grid(row=0, column=0, rowspan=3, padx=(16, 14), pady=14, sticky="n")
        self.ready_head = ctk.CTkLabel(card, text="Release readiness", font=_font(18, "bold"), text_color=TEXT, anchor="w")
        self.ready_head.grid(row=0, column=1, sticky="sw", pady=(12, 0))
        self.ready_reason = ctk.CTkLabel(
            card, text=IDLE_READY, font=_font(14), text_color=MUTED, anchor="w", justify="left", wraplength=self._wrap
        )
        self.ready_reason.grid(row=1, column=1, sticky="ew")
        self.ready_passed = ctk.CTkLabel(
            card, text="", font=_font(13), text_color=MUTED, anchor="w", justify="left", wraplength=self._wrap
        )
        self.ready_passed.grid(row=2, column=1, sticky="ew", pady=(2, 12))
        self.ready_passed.grid_remove()
        chips = ctk.CTkFrame(card, fg_color="transparent")
        chips.grid(row=0, column=2, rowspan=3, padx=(8, 16), pady=14, sticky="e")
        self.counts = {}
        for col, (key, title) in enumerate((("errors", "Errors"), ("warnings", "Warnings"), ("info", "Info"))):
            _, accent, tint, _ = SEVERITY[key[:-1] if key != "info" else key]
            chip = ctk.CTkFrame(chips, fg_color=INSET, corner_radius=10, width=78, height=64)
            chip.grid(row=0, column=col, padx=(0 if col == 0 else 6, 0))
            chip.grid_propagate(False)
            chip.columnconfigure(0, weight=1)
            self.counts[key] = ctk.CTkLabel(chip, text="–", font=_font(24, "bold"), text_color=MUTED)
            self.counts[key].grid(row=0, column=0, pady=(6, 0))
            ctk.CTkLabel(chip, text=title, font=_font(12, "bold"), text_color=accent).grid(row=1, column=0, pady=(0, 6))

    def _set_ready(self, ready: Optional[Readiness], idle: str = IDLE_READY) -> None:
        if ready is None:
            self.ready_icon.configure(text="–", fg_color=SECONDARY, text_color=MUTED)
            self.ready_head.configure(text="Release readiness")
            self.ready_reason.configure(text=idle)
            self.ready_passed.grid_remove()
            return
        glyph, colour = READY_STYLE[ready.state]
        self.ready_icon.configure(text=glyph, fg_color=colour, text_color=ON_ACCENT)
        self.ready_head.configure(text=ready.headline)
        self.ready_reason.configure(text=ready.reason)
        if ready.passed:
            self.ready_passed.configure(text="Checks passed:  ✓ " + "   ✓ ".join(CHECK_SHORT[c] for c in ready.passed))
            self.ready_passed.grid()
        else:
            self.ready_passed.grid_remove()

    def _build_findings(self, parent) -> None:
        head = ctk.CTkFrame(parent, fg_color="transparent")
        head.grid(row=3, column=0, sticky="ew", pady=(16, 8))
        head.columnconfigure(0, weight=1)
        ctk.CTkLabel(head, text="Findings", font=_font(20, "bold"), text_color=TEXT).grid(row=0, column=0, sticky="w")
        self.tabs = ctk.CTkSegmentedButton(
            head, values=list(TABS), command=self._set_filter, font=_font(14, "bold"), height=34, text_color=TEXT,
            selected_color=ACCENT, selected_hover_color=ACCENT_HOVER, unselected_color=SECONDARY,
            unselected_hover_color=SECONDARY_HOVER, fg_color=SECONDARY,
        )
        self.tabs.set("All")
        self.tabs.grid(row=0, column=1, sticky="e")
        self.export_button = ctk.CTkButton(
            head, text="Export…", width=96, height=34, corner_radius=10, font=_font(14, "bold"), fg_color=SECONDARY,
            hover_color=SECONDARY_HOVER, text_color=TEXT, state="disabled", command=self._export,
        )
        self.export_button.grid(row=0, column=2, sticky="e", padx=(10, 0))
        self.compare_button = ctk.CTkButton(
            head, text="Compare…", width=104, height=34, corner_radius=10, font=_font(14, "bold"), fg_color=SECONDARY,
            hover_color=SECONDARY_HOVER, text_color=TEXT, state="disabled", command=self._compare,
        )
        self.compare_button.grid(row=0, column=3, sticky="e", padx=(8, 0))
        panel =self._card(parent)
        panel.grid(row=4, column=0, sticky="nsew")
        panel.columnconfigure(0, weight=1)
        panel.rowconfigure(0, weight=1)
        self.list = ctk.CTkScrollableFrame(panel, fg_color="transparent", corner_radius=0)
        self.list.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        self.list.columnconfigure(0, weight=1)
        # Shown instead of the list (and its scrollbar) whenever there is nothing to scroll.
        self.empty = ctk.CTkFrame(panel, fg_color="transparent")
        self.empty.grid(row=0, column=0, sticky="nsew")
        self.empty.columnconfigure(0, weight=1)
        self.empty.rowconfigure(0, weight=1)
        panel.bind("<Configure>", self._on_resize)

    def _place_window(self, width: int, height: int) -> None:
        """Size the window (clamped to the screen) and centre it."""
        # CTk scales the size in geometry() by its DPI factor but not the offset,
        # so the size is clamped in logical units and the offset in screen pixels.
        scale = self._get_window_scaling()
        screen_w, screen_h = self.winfo_screenwidth(), self.winfo_screenheight()
        width = int(min(width, screen_w / scale - 40))
        height = int(min(height, screen_h / scale - 80))  # leave room for the taskbar
        x = int((screen_w - width * scale) / 2)
        y = int((screen_h - height * scale) / 2)
        self.geometry(f"{width}x{height}+{x}+{y}")

    # ---- file selection -----------------------------------------------

    def _show_file(self) -> None:
        path = self.path_entry.get().strip()
        self.file_label.configure(
            text=os.path.basename(path) or path if path else "No file selected",
            text_color=TEXT if path else MUTED,
        )

    def _browse(self) -> None:
        path = filedialog.askopenfilename(
            title="Select extension ZIP",
            filetypes=[("ZIP archives", "*.zip"), ("All files", "*.*")],
        )
        if path:
            self.path_entry.delete(0, "end")
            self.path_entry.insert(0, path)
            self._show_file()

    # ---- running ------------------------------------------------------

    def _run(self) -> None:
        path = self.path_entry.get().strip()
        if not path:
            self.status.configure(text="Choose a ZIP file first.", text_color=STATE_COLOR["findings"])
            return
        if not self._runner.start(path):
            return
        self.run_button.configure(state="disabled")
        self.export_button.configure(state="disabled")  # the previous result is about to be replaced
        self.compare_button.configure(state="disabled")
        self._set_ready(None, "Audit in progress…")
        self._state = "running"
        self._outcome = None
        self._zip_path = path
        self.status.configure(text="Running audit…", text_color=TEXT)
        self.progress.grid()
        self.progress.start()
        self._poll_id = self.after(POLL_MS, self._poll)

    def _poll(self) -> None:
        self._poll_id = None
        outcome = self._runner.poll()
        if outcome is None:
            self._poll_id = self.after(POLL_MS, self._poll)
            return
        self.progress.stop()
        self.progress.grid_remove()
        self.run_button.configure(state="normal")
        state = result_state(outcome)
        if state != "failed":
            self._outcome = outcome
            self.export_button.configure(state="normal")
            self.compare_button.configure(state="normal")
        self._set_ready(assess(outcome))
        self.status.configure(text=format_status(outcome), text_color=STATE_COLOR[state])
        self._rows = flatten(outcome.findings)
        counts = summarize(outcome.findings)
        for key, label in self.counts.items():
            sev = SEVERITY[key[:-1] if key != "info" else key]
            if state == "failed":
                label.configure(text="–", text_color=MUTED)
            else:
                label.configure(text=str(counts[key]), text_color=sev[1] if counts[key] else TEXT)
        self._state = state
        self._show_results()

    def _on_drop(self, paths: List[str]) -> None:
        path, problem = validate_drop(paths)
        if path is None:
            self.status.configure(text=problem, text_color=STATE_COLOR["findings"])
            return
        if self._runner.busy:
            self.status.configure(
                text="An audit is already running. Drop the file again when it finishes.",
                text_color=STATE_COLOR["findings"],
            )
            return
        self.path_entry.delete(0, "end")
        self.path_entry.insert(0, path)
        self._show_file()
        self._picker.configure(border_color=ACCENT)  # brief confirmation that the drop landed
        self._flash_id = self.after(900, self._end_flash)
        self._run()

    def _end_flash(self) -> None:
        self._flash_id = None
        self._picker.configure(border_color=CARD_BORDER)

    def _compare(self) -> None:
        if self._outcome is None:
            return
        path = filedialog.askopenfilename(
            title="Select a previous JSON report", filetypes=[("JSON report", "*.json"), ("All files", "*.*")]
        )
        if not path:  # cancelled
            return
        try:
            old = load_report(path)
            current = validate_report(build_report(self._outcome, self._zip_path))
            result = compare_reports(old, current)
        except CompareError as exc:
            self._show_text("Cannot compare reports", f"These reports cannot be compared.\n\n{exc}\n")
            self.status.configure(text="The reports could not be compared.", text_color=STATE_COLOR["findings"])
            return
        self._show_text("Report comparison", format_comparison(result))
        self.status.configure(
            text=f"Compared with the previous report: {len(result.new)} new, {len(result.fixed)} fixed, "
                 f"{len(result.unchanged)} unchanged.",
            text_color=STATE_COLOR["clean"],
        )

    def _show_text(self, title: str, text: str) -> None:
        """Read-only text window owned by the main window (no taskbar button of its own)."""
        if self._compare_win is not None and self._compare_win.winfo_exists():
            self._compare_win.destroy()
        win = self._compare_win = ctk.CTkToplevel(self, fg_color=BG)
        win.title(title)
        win.geometry("680x540")
        win.minsize(420, 320)
        win.transient(self)
        win.columnconfigure(0, weight=1)
        win.rowconfigure(0, weight=1)
        box = ctk.CTkTextbox(
            win, font=ctk.CTkFont(family="Consolas", size=13), fg_color=CARD, text_color=TEXT, border_width=1,
            border_color=CARD_BORDER, corner_radius=10, wrap="word",
        )
        box.grid(row=0, column=0, sticky="nsew", padx=16, pady=(16, 8))
        box.insert("1.0", text)
        box.configure(state="disabled")
        ctk.CTkButton(
            win, text="Close", width=96, height=34, corner_radius=10, font=_font(14, "bold"), fg_color=SECONDARY,
            hover_color=SECONDARY_HOVER, text_color=TEXT, command=win.destroy,
        ).grid(row=1, column=0, sticky="e", padx=16, pady=(0, 16))

    def _export(self) -> None:
        if self._outcome is None:
            return
        name = os.path.splitext(os.path.basename(self._zip_path))[0] or "audit"
        path = filedialog.asksaveasfilename(
            title="Export audit report",
            defaultextension=".html",
            initialfile=f"{name}-report",
            filetypes=[("HTML report", "*.html"), ("JSON report", "*.json"), ("Text report", "*.txt")],
        )
        if not path:  # cancelled
            return
        fmt = {ext: key for key, ext in FORMATS.items()}.get(os.path.splitext(path)[1].lower())
        if fmt is None:  # unknown extension typed by the user: save as HTML
            fmt, path = "html", path + ".html"
        try:
            write_report(path, build_report(self._outcome, self._zip_path), fmt)
        except OSError as exc:
            log_failure("export", exc, os.path.basename(path))
            self.status.configure(text="The report could not be saved. Check the location and try again.",
                                  text_color=STATE_COLOR["failed"])
            return
        self.status.configure(text=f"Report saved: {os.path.basename(path)}", text_color=STATE_COLOR["clean"])

    # ---- findings list ------------------------------------------------

    def _set_filter(self, label: str) -> None:
        self._filter = TABS[label]
        self._show_results()

    def _show_results(self) -> None:
        """Draw the panel for the current audit state and tab."""
        if self._filter == "manifest":
            self._render_manifest()
        elif self._state == "failed":
            self._show_empty(
                "The audit could not be completed", f"Diagnostic details were saved to:\n{log_path()}", "failed"
            )
        elif self._state == "idle":
            self._show_empty("No audit yet", "Pick an extension ZIP above, then run the audit.", "idle")
        elif self._state == "running":
            self._show_empty("Audit in progress", "Results will appear here when the audit finishes.", "none")
        elif not self._rows:
            self._show_empty("No issues found", "No check this tool runs reported a problem.", "ok")
        else:
            self._render()

    def _clear(self) -> None:
        if self._render_id is not None:
            self.after_cancel(self._render_id)
            self._render_id = None
        for widget in self.list.winfo_children():
            widget.destroy()
        for widget in self.empty.winfo_children():
            widget.destroy()

    def _show_empty(self, title: str, detail: str, kind: str = "idle") -> None:
        self._clear()
        self.list.grid_remove()  # also hides its scrollbar
        self.empty.grid()
        glyph, ring, core, ink = {
            "ok": ("✓", SUCCESS_TINT, STATE_COLOR["clean"], ON_ACCENT),
            "failed": ("!", SEVERITY["error"][2], STATE_COLOR["failed"], ON_ACCENT),
            "idle": ("↑", ACCENT_TINT, ACCENT, ON_ACCENT),
            "none": ("–", SECONDARY, SECONDARY, MUTED),
        }[kind]
        round_icon = kind in ("ok", "failed")
        box = ctk.CTkFrame(self.empty, fg_color="transparent")
        box.grid(row=0, column=0)
        # Icon: a soft outer ring around a solid core; shape differs per state.
        outer = ctk.CTkFrame(box, width=88, height=88, corner_radius=44 if round_icon else 26, fg_color=ring)
        outer.pack()
        outer.pack_propagate(False)
        ctk.CTkLabel(
            outer, text=glyph, width=56, height=56, corner_radius=28 if round_icon else 16, fg_color=core,
            text_color=ink, font=_font(26, "bold"),
        ).place(relx=0.5, rely=0.5, anchor="center")
        ctk.CTkLabel(box, text=title, font=_font(20, "bold"), text_color=TEXT).pack(pady=(14, 0))
        ctk.CTkLabel(box, text=detail, font=_font(14), text_color=MUTED, justify="center", wraplength=self._wrap).pack(
            pady=(6, 0)
        )
        self._drop.hook_tree(box)
        if kind == "idle":
            steps = self._steps = ctk.CTkFrame(box, fg_color="transparent")
            steps.pack(pady=(18, 0))
            self._fit_steps()
            for n, text in enumerate(STEPS, 1):
                chip = ctk.CTkFrame(steps, fg_color=INSET, corner_radius=16)
                chip.grid(row=0, column=n - 1, padx=5)
                ctk.CTkLabel(
                    chip, text=str(n), width=22, height=22, corner_radius=11, fg_color=ACCENT_TINT, text_color=ACCENT,
                    font=_font(12, "bold"),
                ).pack(side="left", padx=(8, 6), pady=7)
                ctk.CTkLabel(chip, text=text, font=_font(13), text_color=MUTED).pack(side="left", padx=(0, 12))

    def _render_manifest(self) -> None:
        review = self._outcome.review if self._outcome is not None else None
        if self._outcome is None:
            busy = self._state == "running"
            self._show_empty(
                "Audit in progress" if busy else "No audit yet",
                "The manifest review appears when the audit finishes." if busy
                else "Run an audit to review the manifest's permissions and host access.",
                "none" if busy else "idle",
            )
            return
        if review is None or not review.available:
            reason = review.reason if review is not None else "The archive could not be inspected."
            self._show_empty("Manifest review unavailable", reason, "none")
            return
        self._clear()
        self.empty.grid_remove()
        self.list.grid()
        lines = [f"manifest_version {review.manifest_version}  ·  version {review.version}  ·  {review.name}"]
        for title, values in (
            ("Permissions", review.permissions), ("Optional permissions", review.optional_permissions),
            ("Host permissions", review.host_permissions), ("Optional host permissions", review.optional_host_permissions),
            ("Content-script matches", review.content_script_matches),
        ):
            lines.append(f"{title}: " + (", ".join(values) if values else "none declared"))
        self._review_card(0, "info", "PACKAGE", "Manifest summary", lines, boxed=False)
        for idx, item in enumerate(review.items, start=1):
            label, sev = REVIEW_KIND[item.kind]
            self._review_card(idx, sev, label, item.title, [item.detail] + ["•  " + e for e in item.entries])
        if not review.items:
            self._review_card(1, "info", "NOTE", "Nothing flagged", [
                "No permissions or host patterns in the rules this tool applies were found. "
                "This is a static read of manifest.json, not an assessment of the extension's behaviour."
            ], boxed=False)

    def _review_card(self, idx, sev, label, title, lines, boxed=True) -> None:
        _, accent, tint, _ = SEVERITY[sev]
        card = self._card(self.list, fg=INSET)
        card.grid(row=idx, column=0, sticky="ew", pady=(0, 8))
        card.columnconfigure(2, weight=1)
        ctk.CTkFrame(card, width=4, fg_color=accent, corner_radius=2).grid(
            row=0, column=0, rowspan=len(lines) + 1, sticky="ns", padx=(10, 0), pady=10
        )
        ctk.CTkLabel(
            card, text=label, width=118, height=24, corner_radius=12, fg_color=tint, text_color=accent,
            font=_font(12, "bold"),
        ).grid(row=0, column=1, sticky="nw", padx=(14, 0), pady=(14, 0))
        ctk.CTkLabel(
            card, text=title, anchor="w", justify="left", font=_font(15, "bold"), text_color=TEXT, wraplength=self._wrap
        ).grid(row=0, column=2, sticky="ew", padx=(14, 18), pady=(14, 2))
        for n, line in enumerate(lines, start=1):
            ctk.CTkLabel(
                card, text=line, anchor="w", justify="left", font=_font(13), text_color=MUTED, wraplength=self._wrap
            ).grid(row=n, column=2, sticky="ew", padx=(14, 18), pady=(0, 10 if n == len(lines) else 2))
        self._drop.hook_tree(card)

    def _render(self) -> None:
        rows = filter_findings(self._rows, self._filter)
        if not rows:
            self._show_empty("Nothing to show", "No findings of this severity.", "none")
            return
        self._clear()
        self.empty.grid_remove()
        self.list.grid()
        self._render_chunk(rows, 0)

    def _render_chunk(self, rows: List[Tuple[str, str]], start: int) -> None:
        self._render_id = None
        for idx in range(start, min(start + CHUNK, len(rows))):
            self._finding_card(idx, *rows[idx])
        if start + CHUNK < len(rows):
            self._render_id = self.after(5, self._render_chunk, rows, start + CHUNK)

    def _finding_card(self, idx: int, severity: str, message: str) -> None:
        label, accent, tint, _ = SEVERITY[severity]
        guide = explain(severity, message)
        specific = not guide.id.startswith("UNCLASSIFIED")
        card = self._card(self.list, fg=INSET)
        card.grid(row=idx, column=0, sticky="ew", pady=(0, 8))
        card.columnconfigure(2, weight=1)
        ctk.CTkFrame(card, width=4, fg_color=accent, corner_radius=2).grid(
            row=0, column=0, rowspan=4, sticky="ns", padx=(10, 0), pady=10
        )
        ctk.CTkLabel(
            card, text=label, width=84, height=24, corner_radius=12, fg_color=tint, text_color=accent,
            font=_font(12, "bold"),
        ).grid(row=0, column=1, sticky="nw", padx=(14, 0), pady=(14, 0))
        meta = guide.level_label + (f"  ·  {guide.where}" if guide.where else "")
        ctk.CTkLabel(
            card, text=meta, anchor="w", justify="left", font=_font(12, "bold"), text_color=accent, wraplength=self._wrap
        ).grid(row=0, column=2, sticky="ew", padx=(14, 18), pady=(14, 0))
        ctk.CTkLabel(
            card, text=message, anchor="w", justify="left", font=_font(15), text_color=TEXT, wraplength=self._wrap
        ).grid(row=1, column=2, sticky="ew", padx=(14, 18), pady=(2, 0 if specific else 14))
        if specific:
            ctk.CTkLabel(
                card, text="Why it matters:  " + guide.why, anchor="w", justify="left", font=_font(13),
                text_color=MUTED, wraplength=self._wrap,
            ).grid(row=2, column=2, sticky="ew", padx=(14, 18), pady=(6, 0))
            ctk.CTkLabel(
                card, text="What to do:  " + guide.action, anchor="w", justify="left", font=_font(13),
                text_color=MUTED, wraplength=self._wrap,
            ).grid(row=3, column=2, sticky="ew", padx=(14, 18), pady=(2, 14))
        self._drop.hook_tree(card)

    def _on_resize(self, event) -> None:
        # Keep long paths/messages wrapped to the visible width; debounced.
        if self._resize_id is not None:
            self.after_cancel(self._resize_id)
        self._panel_h = event.height
        self._resize_id = self.after(120, self._apply_wrap, event.width)

    def _fit_steps(self) -> None:
        """Hide the step chips when the panel is too short to show them without clipping."""
        steps = getattr(self, "_steps", None)
        if steps is None or not steps.winfo_exists():
            return
        if self._panel_h / self._get_window_scaling() < 270:
            steps.pack_forget()
        elif not steps.winfo_manager():
            steps.pack(pady=(18, 0))

    def _apply_wrap(self, width: int) -> None:
        self._resize_id = None
        self._fit_steps()
        self._wrap = max(300, int(width / self._get_window_scaling()) - 190)
        for label in (self.ready_reason, self.ready_passed):
            label.configure(wraplength=self._wrap + 20)
        for card in self.list.winfo_children():
            for child in card.winfo_children():
                if isinstance(child, ctk.CTkLabel) and child.cget("wraplength"):
                    child.configure(wraplength=self._wrap)

    # ---- lifecycle ----------------------------------------------------

    def report_callback_exception(self, exc, val, tb) -> None:
        # Tk callbacks must never show a stack trace; log it and tell the user plainly.
        log_failure("ui-callback", val)
        try:
            self.status.configure(text="Something went wrong. Details were saved to the log.", text_color=STATE_COLOR["failed"])
        except Exception:  # noqa: BLE001 - widgets may already be gone
            pass

    def destroy(self) -> None:
        # Stop timers so a late result never touches destroyed widgets;
        # the worker itself never touches widgets and is a daemon thread.
        drop = getattr(self, "_drop", None)
        if drop is not None:
            drop.uninstall()  # restore the original window procedures before Tk tears the windows down
        for name in ("_poll_id", "_render_id", "_resize_id", "_flash_id"):
            handle = getattr(self, name, None)
            if handle is not None:
                self.after_cancel(handle)
                setattr(self, name, None)
        super().destroy()


def main() -> None:
    ctk.set_default_color_theme("blue")
    App().mainloop()


if __name__ == "__main__":
    main()
