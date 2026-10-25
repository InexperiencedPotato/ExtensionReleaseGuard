"""Tk-free helpers for the desktop UI.

Wraps :func:`audit.audit_extension` so a UI never has to deal with raw
exceptions or timing, and turns its ``errors`` / ``warnings`` / ``info``
result into counts and an ordered list of rows.
"""

from __future__ import annotations

import datetime
import os
import queue
import threading
import time
import traceback
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from .audit import audit_extension
from .manifest_review import ManifestReview, review_manifest
from .zip_inspector import is_fatal

Findings = Dict[str, List[str]]

# Display order: most severe first.
SEVERITIES = ("errors", "warnings", "info")


def _empty() -> Findings:
    return {level: [] for level in SEVERITIES}


LOG_LIMIT = 256 * 1024  # bytes; the log is rotated once to ``guard.log.1``


def log_path() -> str:
    """Location of the diagnostic log in the user's LocalAppData."""
    base = os.environ.get("LOCALAPPDATA") or os.path.join(
        os.path.expanduser("~"), "AppData", "Local"
    )
    return os.path.join(base, "ExtensionReleaseGuard", "logs", "guard.log")


def log_failure(context: str, exc: BaseException, subject: str = "") -> None:
    """Append an unexpected failure (with traceback) to the log; never raises.

    Only the exception, its traceback and *subject* (callers pass just the ZIP
    file name, never its directory or contents) are written.
    """
    try:
        path = log_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if os.path.exists(path) and os.path.getsize(path) > LOG_LIMIT:
            os.replace(path, path + ".1")
        stamp = datetime.datetime.now().isoformat(timespec="seconds")
        trace = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(f"[{stamp}] {context} {subject}\n{trace}\n")
    except Exception:  # noqa: BLE001 - logging must never break the app
        pass


@dataclass
class AuditOutcome:
    """Result of one audit run.

    ``findings`` is always a valid findings dict (empty when the audit
    crashed).  ``crash`` is ``None`` on a normal run, else a short
    description of the unexpected exception.
    """

    findings: Findings = field(default_factory=_empty)
    elapsed: float = 0.0
    crash: Optional[str] = None
    review: Optional[ManifestReview] = None  # static manifest review; None when unavailable


def run_audit_safe(path: str) -> AuditOutcome:
    """Run :func:`audit_extension` on *path*; never raises.

    ``audit_extension`` reports bad input through its findings, so ``crash``
    is only set for unexpected exceptions.
    """
    start = time.perf_counter()
    review = None
    try:
        findings = audit_extension(path)
        crash = None
        if not is_fatal(findings):  # never read the manifest of an archive the inspector rejected
            review = review_manifest(path)
    except Exception as exc:  # noqa: BLE001 - the UI must survive any audit bug
        findings = _empty()
        crash = f"{type(exc).__name__}: {exc}"
        log_failure("audit", exc, os.path.basename(path))
    return AuditOutcome(findings, time.perf_counter() - start, crash, review)


class AuditRunner:
    """Runs audits on a daemon thread and hands results back via a queue.

    The worker never touches any UI; the UI thread calls :meth:`poll`.
    ``audit`` is injectable so tests need no real archive.
    """

    def __init__(self, audit: Callable[[str], AuditOutcome] = run_audit_safe):
        self._audit = audit
        self._results: "queue.Queue[AuditOutcome]" = queue.Queue()
        self.busy = False

    def start(self, path: str) -> bool:
        """Start an audit; return ``False`` (and do nothing) if one is running."""
        if self.busy:
            return False
        self.busy = True
        threading.Thread(target=self._work, args=(path,), daemon=True).start()
        return True

    def _work(self, path: str) -> None:
        self._results.put(self._audit(path))

    def poll(self) -> Optional[AuditOutcome]:
        """Return the finished outcome (clearing ``busy``), or ``None``."""
        try:
            outcome = self._results.get_nowait()
        except queue.Empty:
            return None
        self.busy = False
        return outcome


def summarize(findings: Findings) -> Dict[str, int]:
    """Return ``{"errors": n, "warnings": n, "info": n}``."""
    return {level: len(findings.get(level, [])) for level in SEVERITIES}


def format_status(outcome: AuditOutcome) -> str:
    """One-line, human-readable completion status for *outcome*."""
    if outcome.crash:
        return "Audit failed unexpectedly. Details were saved to the log."
    counts = summarize(outcome.findings)
    e, w = counts["errors"], counts["warnings"]
    took = f"{outcome.elapsed:.2f} s"
    if not (e or w):
        i = counts["info"]
        if i:
            return f"Audit completed: no errors or warnings, {i} informational note{'s' * (i != 1)} ({took})"
        return f"Audit passed — no issues detected. ({took})"
    return (
        f"Audit finished: {e} error{'s' * (e != 1)}, "
        f"{w} warning{'s' * (w != 1)} ({took})"
    )


def flatten(findings: Findings) -> List[Tuple[str, str]]:
    """Return ``(severity, message)`` pairs: errors, then warnings, then info.

    ``severity`` is ``"error"``, ``"warning"`` or ``"info"``; order within a
    level is preserved.
    """
    return [
        (level[:-1] if level != "info" else level, msg)
        for level in SEVERITIES
        for msg in findings.get(level, [])
    ]


FILTERS = ("all", "error", "warning", "info")


def filter_findings(rows: List[Tuple[str, str]], level: str) -> List[Tuple[str, str]]:
    """Rows from :func:`flatten` whose severity is *level* (``"all"`` keeps every row)."""
    if level == "all":
        return list(rows)
    return [row for row in rows if row[0] == level]


def result_state(outcome: AuditOutcome) -> str:
    """``"failed"`` (unexpected crash), ``"findings"`` (errors/warnings) or ``"clean"``."""
    if outcome.crash:
        return "failed"
    counts = summarize(outcome.findings)
    return "findings" if counts["errors"] or counts["warnings"] else "clean"
