"""Tk-free audit report export (JSON, TXT, HTML).

Reports carry only the ZIP's base file name, never its directory. The HTML is a
single self-contained page: every untrusted string is escaped, and it has no
scripts and no external resources.

Schema 2 only adds keys to schema 1 (per-finding ``id``, ``subject``, ``level``, ``title``,
``why``, ``action``; top-level ``readiness`` and ``manifest_review``). Every schema-1 key keeps
its name and meaning, so schema-1 files stay readable; see ``compare.py``.
"""

from __future__ import annotations

import datetime
import html
import json
import ntpath
from typing import Any, Dict, Optional

from .gui_core import AuditOutcome, flatten, result_state, summarize
from .guidance import explain
from .readiness import assess

SCHEMA_VERSION = 2
SUPPORTED_SCHEMAS = (1, 2)
FORMATS = {"json": ".json", "txt": ".txt", "html": ".html"}
_LABEL = {"error": "Error", "warning": "Warning", "info": "Info"}


def build_report(outcome: AuditOutcome, zip_path: str, when: Optional[datetime.datetime] = None) -> Dict[str, Any]:
    """Return the report as a plain dict (the JSON schema). Failed audits have no report."""
    state = result_state(outcome)
    if state == "failed":
        raise ValueError("a failed audit cannot be exported")
    when = when or datetime.datetime.now().astimezone()
    path = zip_path.strip().rstrip("\\/")  # a trailing separator must not empty the base name
    # Last component by hand: ntpath.basename("C:") and of a bare UNC share are "" (the drive swallows them).
    base = path.replace("/", "\\").rsplit("\\", 1)[-1] or "(unnamed)"  # "" only for pure separators
    # OS error text in findings embeds the full path (also in repr form, with doubled backslashes).
    # shortcut: only the audited path and its folder are scrubbed, not other paths an error might name.
    scrub = []
    if path:
        scrub = [(p, base) for p in (path, path.replace("\\", "\\\\"))]
        folder = ntpath.dirname(path)  # drive roots and UNC shares are their own "folder"
        if folder and folder != path:
            scrub += [(p, "…") for p in (folder, folder.replace("\\", "\\\\"))]

    def clean(msg: str) -> str:
        for old, new in scrub:
            msg = msg.replace(old, new)
        return msg

    findings = []
    for sev, msg in flatten(outcome.findings):
        g = explain(sev, msg)
        findings.append({
            "severity": sev, "message": clean(msg), "id": g.id, "subject": clean(g.subject), "level": g.level,
            "title": g.title, "why": g.why, "action": g.action,
        })
    ready = assess(outcome)
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": "ExtensionRelease Guard",
        "file": base,  # ntpath handles both / and \ separators
        "generated_at": when.isoformat(timespec="seconds"),
        "duration_seconds": round(outcome.elapsed, 3),
        "result": "clean" if state == "clean" else "findings",
        "summary": summarize(outcome.findings),
        "findings": findings,
        "readiness": {
            "state": ready.state, "headline": ready.headline, "reason": ready.reason,
            "passed": ready.passed, "skipped": ready.skipped,
        },
        "manifest_review": _review_dict(outcome.review, clean),
    }


def _review_dict(review, clean) -> Optional[Dict[str, Any]]:
    if review is None or not review.available:
        return None
    return {
        "manifest_version": clean(review.manifest_version), "name": clean(review.name), "version": clean(review.version),
        "permissions": [clean(x) for x in review.permissions],
        "optional_permissions": [clean(x) for x in review.optional_permissions],
        "host_permissions": [clean(x) for x in review.host_permissions],
        "optional_host_permissions": [clean(x) for x in review.optional_host_permissions],
        "content_script_matches": [clean(x) for x in review.content_script_matches],
        "items": [
            {"kind": i.kind, "title": i.title, "detail": i.detail, "entries": [clean(e) for e in i.entries]}
            for i in review.items
        ],
    }


def to_json(report: Dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


def to_txt(report: Dict[str, Any]) -> str:
    s = report["summary"]
    lines = [
        "ExtensionRelease Guard - audit report",
        f"File:      {report['file']}",
        f"Generated: {report['generated_at']}",
        f"Duration:  {report['duration_seconds']} s",
        f"Summary:   {s['errors']} errors, {s['warnings']} warnings, {s['info']} info",
        "",
    ]
    ready = report.get("readiness")
    if ready:
        lines += [f"Readiness: {ready['headline']}", f"           {ready['reason']}"]
        lines += [f"  passed: {name}" for name in ready["passed"]]
        lines.append("")
    if not report["findings"]:
        lines.append("No issues found.")
    for item in report["findings"]:
        lines.append(f"[{item['severity'].upper()}] {item['message']}")
        if item.get("action"):
            lines.append(f"    Why: {item['why']}")
            lines.append(f"    Action: {item['action']}")
    review = report.get("manifest_review")
    if review:
        lines += ["", "Manifest review (static observations, not confirmed defects)",
                  f"  manifest_version {review['manifest_version']}, version {review['version']}"]
        for key in ("permissions", "optional_permissions", "host_permissions", "optional_host_permissions",
                    "content_script_matches"):
            if review[key]:
                lines.append(f"  {key}: {', '.join(review[key])}")
        for item in review["items"]:
            lines.append(f"  [{item['kind']}] {item['title']}: {item['detail']}")
            lines += [f"      - {entry}" for entry in item["entries"]]
    return "\n".join(lines) + "\n"


_CSS = (
    "body{font:15px/1.5 'Segoe UI',Arial,sans-serif;background:#15171a;color:#eef1f3;margin:0;padding:32px}"
    "main{max-width:860px;margin:auto}h1{margin:0 0 4px}.meta{color:#a9b2ba;margin:0 0 20px}"
    ".sum{display:flex;gap:12px;margin-bottom:20px}.sum div{flex:1;background:#212529;border:1px solid #30353a;"
    "border-radius:12px;padding:12px 16px}.sum b{display:block;font-size:26px}"
    "ul{list-style:none;padding:0}li{background:#191c1f;border-left:4px solid;border-radius:8px;padding:10px 14px;"
    "margin-bottom:8px;overflow-wrap:anywhere}li span{font-weight:700;margin-right:8px}"
    ".error{border-color:#ff6b6b}.error span{color:#ff6b6b}.warning{border-color:#f5b942}.warning span{color:#f5b942}"
    ".info{border-color:#5aa9ff}.info span{color:#5aa9ff}"
    ".ready{background:#212529;border:1px solid #30353a;border-radius:12px;padding:12px 16px;margin-bottom:20px}"
    ".ready b{display:block;font-size:18px}.ready small,.g{color:#a9b2ba}.g{display:block;margin-top:4px}"
    "h2{font-size:17px;margin:24px 0 8px}.rv{background:#191c1f;border-radius:8px;padding:10px 14px;margin-bottom:8px}"
    ".rv ul{margin:6px 0 0;padding-left:18px;list-style:disc}"
)


def to_html(report: Dict[str, Any]) -> str:
    esc = html.escape
    s = report["summary"]
    cards = "".join(
        f"<div>{title}<b>{s[key]}</b></div>" for key, title in (("errors", "Errors"), ("warnings", "Warnings"), ("info", "Info"))
    )
    if report["findings"]:
        items = "".join(
            f"<li class=\"{esc(i['severity'])}\"><span>{_LABEL[i['severity']]}</span>{esc(i['message'])}"
            + (f"<em class=\"g\">Why: {esc(i['why'])}</em><em class=\"g\">Action: {esc(i['action'])}</em>"
               if i.get("action") else "")
            + "</li>"
            for i in report["findings"]
        )
        body = f"<ul>{items}</ul>"
    else:
        body = "<p>No issues found.</p>"
    return (
        "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<title>Audit report - {esc(report['file'])}</title><style>{_CSS}</style></head><body><main>"
        f"<h1>{esc(report['file'])}</h1>"
        f"<p class=\"meta\">ExtensionRelease Guard &middot; {esc(report['generated_at'])} &middot; "
        f"{esc(str(report['duration_seconds']))} s</p>"
        f'{_ready_html(report.get("readiness"), esc)}<div class="sum">{cards}</div>{body}'
        f"{_review_html(report.get('manifest_review'), esc)}</main></body></html>\n"
    )


def _ready_html(ready, esc) -> str:
    if not ready:
        return ""
    passed = "".join(f"<li>{esc(name)}</li>" for name in ready["passed"])
    return (
        f'<div class="ready"><b>{esc(ready["headline"])}</b>{esc(ready["reason"])}'
        + (f"<small>Checks passed:</small><ul>{passed}</ul>" if passed else "") + "</div>"
    )


def _review_html(review, esc) -> str:
    if not review:
        return ""
    rows = "".join(
        f'<div class="rv"><b>{esc(i["title"])}</b> <small>({esc(i["kind"])})</small><br>{esc(i["detail"])}'
        + ("<ul>" + "".join(f"<li>{esc(e)}</li>" for e in i["entries"]) + "</ul>" if i["entries"] else "") + "</div>"
        for i in review["items"]
    )
    return (
        '<h2>Manifest review</h2><p class="meta">Static observations for developer review; '
        f"not confirmed defects. manifest_version {esc(review['manifest_version'])}, version {esc(review['version'])}.</p>"
        + rows
    )


def render(report: Dict[str, Any], fmt: str) -> str:
    return {"json": to_json, "txt": to_txt, "html": to_html}[fmt](report)


def write_report(path: str, report: Dict[str, Any], fmt: str) -> None:
    """Write UTF-8 to *path*; raises OSError on failure."""
    # errors="replace": a manifest string can hold a lone surrogate, which strict UTF-8 cannot encode.
    with open(path, "w", encoding="utf-8", errors="replace", newline="\n") as fh:
        fh.write(render(report, fmt))
