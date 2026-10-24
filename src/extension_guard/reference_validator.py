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

    # devtools_page
    devtools_page = manifest.get("devtools_page")
    if devtools_page is not None:
        if isinstance(devtools_page, str):
            check_path("devtools_page", devtools_page)
        else:
            findings["warnings"].append(
                f"devtools_page is not a string: {devtools_page!r}."
            )

    # side_panel.default_path
    side_panel = manifest.get("side_panel") or {}
    default_path = side_panel.get("default_path")
    if default_path is not None:
        if isinstance(default_path, str):
            check_path("side_panel.default_path", default_path)
        else:
            findings["warnings"].append(
                f"side_panel.default_path is not a string: {default_path!r}."
            )

    # chrome_url_overrides values
    chrome_overrides = manifest.get("chrome_url_overrides") or {}
    for key, path in chrome_overrides.items():
        if isinstance(path, str):
            check_path(f"chrome_url_overrides[{key}]", path)
        else:
            findings["warnings"].append(
                f"chrome_url_overrides[{key}] is not a string: {path!r}."
            )

    # declarative_net_request.rule_resources[].path
    dnr = manifest.get("declarative_net_request") or {}
    rule_resources = dnr.get("rule_resources") or []
    for idx, rr in enumerate(rule_resources):
        if isinstance(rr, dict):
            path = rr.get("path")
            if path:
                check_path(f"declarative_net_request.rule_resources[{idx}].path", path)
            else:
                findings["warnings"].append(
                    f"declarative_net_request.rule_resources[{idx}] missing path"
                )
        else:
            findings["warnings"].append(
                f"declarative_net_request.rule_resources[{idx}] is not a dict"
            )

    # sandbox.pages
    sandbox = manifest.get("sandbox") or {}
    pages = sandbox.get("pages") or []
    for idx, page_path in enumerate(pages):
        if isinstance(page_path, str):
            check_path(f"sandbox.pages[{idx}]", page_path)
        else:
            findings["warnings"].append(
                f"sandbox.pages[{idx}] is not a string: {page_path!r}."
            )

    # web_accessible_resources
    web_accessible = manifest.get("web_accessible_resources")
    if web_accessible is not None:
        if not isinstance(web_accessible, list):
            findings["warnings"].append(
                f"web_accessible_resources is not a list: {web_accessible!r}."
            )
        else:
            for idx, entry in enumerate(web_accessible):
                if not isinstance(entry, dict):
                    findings["warnings"].append(
                        f"web_accessible_resources[{idx}] is not a dict: {entry!r}."
                    )
                    continue
                resources = entry.get("resources")
                if not isinstance(resources, list):
                    findings["warnings"].append(
                        f"web_accessible_resources[{idx}].resources is not a list: {resources!r}."
                    )
                    continue
                for res in resources:
                    if not isinstance(res, str):
                        findings["warnings"].append(
                            f"web_accessible_resources[{idx}].resources contains non-string: {res!r}."
                        )
                        continue
                    # Reject absolute or traversal paths
                    if res.startswith("/") or ":" in res or ".." in res.split('/'):
                        findings["errors"].append(
                            f"web_accessible_resources[{idx}].resources contains unsafe path: {res}."
                        )
                        continue
                    # Wildcard handling
                    if "*" in res:
                        prefix, _, suffix = res.partition("*")
                        matches = [p for p in entry_counts if p.startswith(prefix) and p.endswith(suffix)]
                        if not matches:
                            findings["warnings"].append(
                                f"web_accessible_resources[{idx}].resources wildcard {res!r} matches no entries."
                            )
                        else:
                            for p in matches:
                                if entry_counts.get(p, 0) > 1:
                                    findings["errors"].append(
                                        f"web_accessible_resources[{idx}].resources wildcard {res!r} matches duplicate entry: {p}."
                                    )
                    # Literal (non-wildcard) - check existence
                    elif res not in entry_counts:
                        findings["errors"].append(
                            f"web_accessible_resources[{idx}].resources missing file: {res}."
                        )
                    elif entry_counts.get(res, 0) > 1:
                        findings["errors"].append(
                            f"web_accessible_resources[{idx}].resources ambiguous duplicate: {res}."
                        )
    return findings
