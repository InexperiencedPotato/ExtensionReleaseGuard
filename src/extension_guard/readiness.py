"""Release-readiness rules, defined in one place.

The state comes only from the audit outcome and the finding counts. There is no numeric score,
and nothing here says an extension is secure or will be approved.

A check is listed as *passed* only when there is evidence it ran and was meaningful: it must be
reachable under the audit pipeline's own gating, produce no error or warning, and (for the
checks that depend on what the package declares) the manifest must actually declare something
for it to examine. Any finding this module cannot attribute to a check withholds every claim.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from .gui_core import AuditOutcome, summarize
from .guidance import ICONS, LOCALES, MANIFEST, REFERENCES, ZIP, explain
from .zip_inspector import is_fatal

INCOMPLETE, ISSUES, REVIEW, INFORMATIONAL, CLEAR = "incomplete", "issues", "review", "informational", "clear"

DISCLAIMER = "Automated checks only: this is not a security review and says nothing about Chrome Web Store review."

CHECK_LABELS = {
    ZIP: "Archive structure and safety limits",
    MANIFEST: "manifest.json required fields",
    REFERENCES: "Files referenced by the manifest exist",
    LOCALES: "Default locale messages",
    ICONS: "Icon files",
}

CHECK_SHORT = dict(zip(CHECK_LABELS.values(), ("Archive", "Manifest fields", "References", "Locales", "Icons")))


@dataclass
class Readiness:
    state: str
    headline: str
    reason: str
    errors: int = 0
    warnings: int = 0
    info: int = 0
    passed: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'s' * (n != 1)}"


def assess(outcome: AuditOutcome) -> Readiness:
    """Readiness for one finished audit outcome."""
    if outcome.crash:
        return Readiness(
            INCOMPLETE, "Audit could not complete",
            "An unexpected error stopped the audit before it finished, so there is no result to rely on. "
            "Details were saved to the log.",
        )
    findings = outcome.findings
    counts = summarize(findings)
    e, w, i = counts["errors"], counts["warnings"], counts["info"]
    base = dict(errors=e, warnings=w, info=i)
    if is_fatal(findings):
        return Readiness(
            INCOMPLETE, "Audit could not complete",
            "The archive could not be inspected (not a usable ZIP, or over a safety limit), so the other checks "
            "were skipped.", **base,
        )

    # Attribute each error/warning to the validator that produced it.
    flagged = {}
    unattributed = False
    for level, sev in (("errors", "error"), ("warnings", "warning")):
        for msg in findings[level]:
            check = explain(sev, msg).check
            if check is None:
                unattributed = True
            flagged.setdefault(check, []).append((level, msg))

    # The pipeline skips reference, locale and icon checks when the manifest file itself is
    # unusable (audit.py: an error naming manifest.json). Same predicate, same source.
    downstream = not any("manifest.json" in m.lower() for _, m in flagged.get(MANIFEST, []) if _ == "errors")
    review = outcome.review if outcome.review is not None and outcome.review.available else None

    passed: List[str] = []
    skipped: List[str] = []
    if not unattributed:
        if ZIP not in flagged:
            passed.append(CHECK_LABELS[ZIP])
        if MANIFEST not in flagged:
            passed.append(CHECK_LABELS[MANIFEST])
        if downstream and review is not None:
            refs_ok = REFERENCES not in flagged
            if refs_ok and review.declares_references:
                passed.append(CHECK_LABELS[REFERENCES])
            if LOCALES not in flagged and review.declares_locale:
                passed.append(CHECK_LABELS[LOCALES])
            if refs_ok and ICONS not in flagged and review.declares_icons:
                passed.append(CHECK_LABELS[ICONS])
    if not downstream:
        skipped = [CHECK_LABELS[c] for c in (REFERENCES, LOCALES, ICONS)]

    skip_note = " Reference, locale and icon checks were skipped because manifest.json is unusable." if skipped else ""
    if e:
        state, head = ISSUES, "Issues found"
        reason = f"{_plural(e, 'error')} should be fixed before release." + (
            f" {_plural(w, 'warning')} also need judgment." if w else "") + skip_note
    elif w:
        state, head = REVIEW, "Review recommended"
        reason = f"No errors. {_plural(w, 'warning')} to judge against what your extension is meant to do."
    elif i:
        state, head = INFORMATIONAL, "Informational notes only"
        reason = f"No errors or warnings; {_plural(i, 'note')} for your information."
    else:
        state, head = CLEAR, "No issues detected"
        reason = "None of the checks this tool runs reported a problem. " + DISCLAIMER
    return Readiness(state, head, reason, passed=passed, skipped=skipped, **base)
