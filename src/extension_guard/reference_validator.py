"""Reference validation for Chrome extension package files.

The module provides :func:`validate_references` which inspects a ZIP
archive containing a Chrome extension.  It validates a subset of
manifest fields that refer to package files:

* ``icons``
* ``action.default_icon``
* ``action.default_popup``
* ``background.service_worker``
* ``options_page``
* ``options_ui.page``
* ``content_scripts[].js`` and ``content_scripts[].css``

The function returns a dictionary with ``errors``, ``warnings`` and
``info`` lists, following the same structure used by the ZIP and
manifest validators.
"""

from __future__ import annotations

import json
import zipfile
from collections import Counter
from pathlib import Path
from typing import Dict, List, Tuple

# Result type
Result = Dict[str, List[str]]


def _load_manifest(zip_path: str) -> Tuple[Dict, Result]:
    """Load ``manifest.json`` from *zip_path*.

    Returns a tuple ``(manifest_dict, findings)`` where *findings* will
    contain errors related to missing or malformed manifest.
    """
    findings: Result = {"errors": [], "warnings": [], "info": []}
    try:
        with zipfile.ZipFile(zip_path, "r", allowZip64=True) as zf:
            manifest_info = zf.getinfo("manifest.json")
            raw = zf.read("manifest.json")
    except KeyError:
        findings["errors"].append("manifest.json missing in ZIP archive.")
        return {}, findings
    except zipfile.BadZipFile:
        findings["errors"].append("Not a valid ZIP archive.")
        return {}, findings
    except Exception as exc:
        findings["errors"].append(f"Unexpected error reading manifest.json: {exc}")
        return {}, findings
    # Decode
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        findings["errors"].append("manifest.json contains invalid UTF‑8.")
        return {}, findings
    # Parse JSON
    try:
        manifest_obj = json.loads(text)
    except json.JSONDecodeError:
        findings["errors"].append("manifest.json contains malformed JSON.")
        return {}, findings
    if not isinstance(manifest_obj, dict):
        findings["errors"].append("manifest.json root must be a JSON object.")
        return {}, findings
    return manifest_obj, findings


def _zip_entry_counts(zip_path: str) -> Counter:
    """Return a Counter of file names inside the ZIP."""
    with zipfile.ZipFile(zip_path, "r", allowZip64=True) as zf:
        return Counter(entry.filename for entry in zf.infolist())


def _is_safe_path(path: str) -> bool:
    """Return ``True`` if *path* is a relative, non‑traversal path.

    It must not start with a slash or drive letter and must not contain
    '..' components.
    """
    if Path(path).is_absolute() or ".." in Path(path).parts:
        return False
    return True


def validate_references(zip_path: str) -> Result:
    """Validate referenced files in the manifest.

    Parameters
    ----------
    zip_path:
        Path to the ZIP archive.

    Returns
    -------
    dict
        ``errors``, ``warnings`` and ``info`` lists.
    """
    findings: Result = {"errors": [], "warnings": [], "info": []}
    manifest, mfind = _load_manifest(zip_path)
    findings["errors"].extend(mfind["errors"])
    findings["warnings"].extend(mfind["warnings"])
    if mfind["errors"]:
        return findings  # Cannot continue without a valid manifest
    entry_counts = _zip_entry_counts(zip_path)
    # Helper to process single path
    def check_path(field: str, path: str):
        if not isinstance(path, str):
            findings["warnings"].append(
                f"{field} is not a string: {path!r}."
            )
            return
        if not _is_safe_path(path):
            findings["errors"].append(
                f"{field} contains unsafe path: {path}."
            )
            return
        count = entry_counts.get(path)
        if count is None:
            findings["errors"].append(f"{field} references missing file: {path}.")
        elif count > 1:
            findings["errors"].append(
                f"{field} references duplicate file: {path}."
            )

    # icons
    icons = manifest.get("icons")
    if icons is not None:
        if isinstance(icons, dict):
            for sz, path in icons.items():
                check_path(f"icons[{sz}]", path)
        else:
            findings["warnings"].append("icons is not a dictionary.")
    # action.default_icon
    action = manifest.get("action") or {}
    default_icon = action.get("default_icon")
    if default_icon is not None:
        if isinstance(default_icon, dict):
            for sz, path in default_icon.items():
                check_path(f"action.default_icon[{sz}]", path)
        elif isinstance(default_icon, str):
            check_path("action.default_icon", default_icon)
        else:
            findings["warnings"].append("action.default_icon has unexpected type.")
    # action.default_popup
    popup = action.get("default_popup")
    if popup is not None:
        check_path("action.default_popup", popup)
    # background.service_worker
    background = manifest.get("background") or {}
    worker = background.get("service_worker")
    if worker is not None:
        check_path("background.service_worker", worker)
    # options_page
    opts_page = manifest.get("options_page")
    if opts_page is not None:
        check_path("options_page", opts_page)
    # options_ui.page
    options_ui = manifest.get("options_ui") or {}
    page = options_ui.get("page")
    if page is not None:
        check_path("options_ui.page", page)
    # content_scripts
    scripts = manifest.get("content_scripts") or []
    if isinstance(scripts, list):
        for idx, sc in enumerate(scripts):
            if not isinstance(sc, dict):
                findings["warnings"].append(f"content_scripts[{idx}] is not a dict.")
                continue
            js_list = sc.get("js") or []
            css_list = sc.get("css") or []
            if not isinstance(js_list, list):
                findings["warnings"].append(f"content_scripts[{idx}].js is not a list.")
                js_list = []
            if not isinstance(css_list, list):
                findings["warnings"].append(f"content_scripts[{idx}].css is not a list.")
                css_list = []
            for js_path in js_list:
                check_path(f"content_scripts[{idx}].js", js_path)
            for css_path in css_list:
                check_path(f"content_scripts[{idx}].css", css_path)
    else:
        findings["warnings"].append("content_scripts is not a list.")
    return findings
