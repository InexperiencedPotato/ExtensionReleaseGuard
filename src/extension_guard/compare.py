"""Compare two audit reports (local only; reads JSON, writes nothing).

Findings are matched on ``(severity, rule id, subject)``, not on display text, so rewording a
message or a changed entry number does not make a finding look new. Schema-2 reports carry the
id and subject; schema-1 reports do not, so they are derived from the message with the same
rules (``guidance.explain``). A message no rule recognises is matched by its normalised text.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

from .guidance import explain
from .report import SUPPORTED_SCHEMAS

MAX_REPORT_BYTES = 10 * 1024 * 1024
MAX_LISTED = 200  # findings shown per section of the text summary
SEVERITIES = ("error", "warning", "info")
Key = Tuple[str, str, str]


class CompareError(Exception):
    """The reports cannot be compared; the message is safe to show to the user."""


@dataclass
class Comparison:
    old_file: str
    new_file: str
    old_generated: str
    new_generated: str
    new: List[Dict[str, Any]] = field(default_factory=list)
    fixed: List[Dict[str, Any]] = field(default_factory=list)
    unchanged: List[Dict[str, Any]] = field(default_factory=list)
    old_counts: Dict[str, int] = field(default_factory=dict)
    new_counts: Dict[str, int] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)


def load_report(path: str) -> Dict[str, Any]:
    """Read and validate a JSON report file; raises :class:`CompareError`."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read(MAX_REPORT_BYTES + 1)
    except OSError:
        raise CompareError("The report file could not be read.") from None
    if len(raw) > MAX_REPORT_BYTES:
        raise CompareError("The report file is too large to be an audit report.")
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise CompareError("The file is not valid JSON. Choose a report exported as JSON.") from None
    return validate_report(data)


def validate_report(data: Any) -> Dict[str, Any]:
    """Return *data* with normalised findings, or raise :class:`CompareError`."""
    if not isinstance(data, dict):
        raise CompareError("The file is not an audit report (the JSON root is not an object).")
    version = data.get("schema_version")
    if isinstance(version, bool) or not isinstance(version, int):
        raise CompareError("The file has no schema_version, so it is not an ExtensionRelease Guard report.")
    if version not in SUPPORTED_SCHEMAS:
        supported = ", ".join(str(v) for v in SUPPORTED_SCHEMAS)
        raise CompareError(f"Unsupported report schema version {version} (supported: {supported}).")
    raw = data.get("findings")
    if not isinstance(raw, list):
        raise CompareError("The report has no findings list.")
    findings: List[Dict[str, Any]] = []
    for item in raw:
        if not (isinstance(item, dict) and item.get("severity") in SEVERITIES and isinstance(item.get("message"), str)):
            raise CompareError("The report contains a malformed finding (needs a severity and a message).")
        guide = explain(item["severity"], item["message"])
        rid = item["id"] if isinstance(item.get("id"), str) and item["id"] else guide.id
        subject = item["subject"] if isinstance(item.get("subject"), str) else guide.subject
        findings.append({"severity": item["severity"], "message": item["message"], "id": rid, "subject": subject})
    counts = Counter(f["severity"] for f in findings)
    summary = data.get("summary")
    if isinstance(summary, dict):
        stated = {s: summary.get(k) for s, k in (("error", "errors"), ("warning", "warnings"), ("info", "info"))}
        if any(isinstance(v, int) and v != counts[s] for s, v in stated.items()):
            raise CompareError("The report is inconsistent: its summary does not match its findings.")
    return {
        "file": data["file"] if isinstance(data.get("file"), str) else "",
        "generated_at": data["generated_at"] if isinstance(data.get("generated_at"), str) else "",
        "schema_version": version,
        "findings": findings,
    }


def _key(f: Dict[str, Any]) -> Key:
    return (f["severity"], f["id"], f["subject"])


def compare_reports(old: Dict[str, Any], new: Dict[str, Any]) -> Comparison:
    """Compare two validated reports (see :func:`validate_report`)."""
    result = Comparison(old["file"], new["file"], old["generated_at"], new["generated_at"])
    remaining = Counter(_key(f) for f in old["findings"])
    for f in new["findings"]:
        if remaining[_key(f)] > 0:
            remaining[_key(f)] -= 1
            result.unchanged.append(f)
        else:
            result.new.append(f)
    leftover = Counter(remaining)
    for f in old["findings"]:
        if leftover[_key(f)] > 0:
            leftover[_key(f)] -= 1
            result.fixed.append(f)
    for attr, report in (("old_counts", old), ("new_counts", new)):
        c = Counter(f["severity"] for f in report["findings"])
        setattr(result, attr, {s: c[s] for s in SEVERITIES})
    if old["file"] and new["file"] and old["file"] != new["file"]:
        result.notes.append(
            f"The reports are for different files ({old['file']} and {new['file']}); "
            "the comparison shows how the findings differ, not necessarily two versions of one package."
        )
    if 1 in (old["schema_version"], new["schema_version"]):
        result.notes.append(
            "A schema-1 report has no finding ids; they were derived from the message text with the current rules."
        )
    return result


def format_comparison(c: Comparison) -> str:
    """Plain-text summary for display."""
    label = {"error": "errors", "warning": "warnings", "info": "info"}
    lines = [f"Previous: {c.old_file or '(unnamed)'}  {c.old_generated}", f"Current:  {c.new_file or '(unnamed)'}  {c.new_generated}", ""]
    for s in SEVERITIES:
        o, n = c.old_counts[s], c.new_counts[s]
        lines.append(f"{label[s].capitalize():9} {o} -> {n}  ({n - o:+d})")
    lines.append("")
    lines.append(f"{len(c.new)} new, {len(c.fixed)} fixed, {len(c.unchanged)} unchanged")
    for note in c.notes:
        lines += ["", f"Note: {note}"]
    for title, items in (("New", c.new), ("Fixed", c.fixed), ("Unchanged", c.unchanged)):
        if items:
            lines += ["", f"{title}:"]
            lines += [f"  [{f['severity'].upper()}] {f['message']}" for f in items[:MAX_LISTED]]
            if len(items) > MAX_LISTED:
                lines.append(f"  ... and {len(items) - MAX_LISTED} more")
    return "\n".join(lines) + "\n"
