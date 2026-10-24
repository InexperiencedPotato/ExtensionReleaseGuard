"""Unified audit orchestrator for the ExtensionRelease Guard.

The project contains a set of small, independent validators that each
operate on a Chrome extension ZIP archive:

* :func:`zip_inspector.inspect_zip`
* :func:`manifest_validator.validate_manifest`
* :func:`reference_validator.validate_references`
* :func:`locale_validator.validate_locales`
* :func:`icon_validator.validate_icons`

This module provides a single public entry point – :func:`audit_extension` –
that runs all validators in a safe order and aggregates their findings into
one result dictionary containing ``errors``, ``warnings`` and ``info``
lists.

Only *standard library* modules are used.  The function intentionally does
not raise exceptions – all failures are represented in the returned
structure.
"""

from __future__ import annotations

from typing import Dict, List

# Import validators – the modules expose the public functions only.
from .zip_inspector import inspect_zip
from .manifest_validator import validate_manifest
from .reference_validator import validate_references
from .locale_validator import validate_locales
from .icon_validator import validate_icons

Result = Dict[str, List[str]]


def _merge_findings(target: Result, source: Result) -> None:
    """Merge *source* findings into *target* while avoiding exact duplicates.

    The merge is performed in‑place.  Messages are considered duplicate
    if the exact string appears in the target list for the same severity.
    """

    for level in ("errors", "warnings", "info"):
        seen = set(target[level])
        for msg in source[level]:
            if msg not in seen:
                target[level].append(msg)
                seen.add(msg)


def audit_extension(zip_path: str) -> Result:
    """Run the full audit pipeline on a Chrome extension ZIP.

    Parameters
    ----------
    zip_path:
        Path to the ZIP archive.

    Returns
    -------
    dict
        ``errors``, ``warnings`` and ``info`` lists.
    """

    overall: Result = {"errors": [], "warnings": [], "info": []}

    # 1. ZIP structure inspection – always run first.
    zip_findings = inspect_zip(zip_path)
    _merge_findings(overall, zip_findings)

    # If the ZIP itself is not a valid archive, there is no point in
    # continuing.  The presence of any error related to ZIP handling
    # indicates a malformed archive.
    if any("ZIP" in e for e in zip_findings["errors"]):
        return overall

    # 2. Manifest validation – required for many other checks.
    manifest_findings = validate_manifest(zip_path)
    _merge_findings(overall, manifest_findings)

    # Determine whether the manifest file itself is present and well‑formed.
    # File-level errors (missing, malformed, non-object, duplicate key) all
    # name manifest.json; missing required fields do not and must not block
    # the downstream validators.
    manifest_invalid = any(
        "manifest.json" in msg.lower() for msg in manifest_findings["errors"]
    )

    if not manifest_invalid:
        # 3. Reference validation – requires a manifest but is safe to
        # run as long as the manifest file exists.
        ref_findings = validate_references(zip_path)
        _merge_findings(overall, ref_findings)

        # 4. Locale validation – also depends on the manifest.
        locale_findings = validate_locales(zip_path)
        _merge_findings(overall, locale_findings)

        # 5. Icon validation – similar dependency.
        icon_findings = validate_icons(zip_path)
        _merge_findings(overall, icon_findings)

    return overall
