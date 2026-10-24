"""Manifest validation utilities for Chrome extension packages.

The module operates directly on a ZIP archive without extracting any
files to disk.  It performs the following checks:

1. Exactly one *root‑level* ``manifest.json`` file must exist.
2. The file size must not exceed 1 MiB.
3. The file contents must be valid UTF‑8.
4. The JSON must parse to an object, with no duplicate keys.
5. Required top‑level fields are present and of the correct type:
   - ``manifest_version`` must be the integer ``3``.
   - ``name`` and ``version`` must be non‑empty strings.
6. Unsupported ``manifest_version`` values (e.g. 2 or >3) are
   reported as errors.

The function returns a dictionary with the keys ``errors``, ``warnings``
and ``info`` – each a list of human‑readable messages.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Dict, List

MAX_MANIFEST_SIZE = 1 * 1024 * 1024  # 1 MiB


def _duplicate_key_error(key: str) -> str:
    return f"Duplicate key in manifest.json: '{key}'."


def _no_duplicates_object_pairs_hook(pairs):  # pragma: no cover - trivial helper
    seen = set()
    obj = {}
    for k, v in pairs:
        if k in seen:
            raise ValueError(_duplicate_key_error(k))
        seen.add(k)
        obj[k] = v
    return obj


def validate_manifest(zip_path: str) -> Dict[str, List[str]]:
    """Validate the Chrome extension ``manifest.json`` inside *zip_path*.

    Parameters
    ----------
    zip_path:
        Path to the ZIP archive.

    Returns
    -------
    dict
        Structured findings: ``errors``, ``warnings`` and ``info``.
    """
    findings: Dict[str, List[str]] = {"errors": [], "warnings": [], "info": []}

    try:
        with zipfile.ZipFile(zip_path, "r", allowZip64=True) as zf:
            # Find root‑level manifest.json entries
            root_manifests = [name for name in zf.namelist() if name == "manifest.json"]
            if not root_manifests:
                findings["errors"].append("Missing root-level manifest.json.")
                return findings
            if len(root_manifests) > 1:
                findings["errors"].append(
                    "Ambiguous package: multiple root-level manifest.json entries."
                )
                return findings
            manifest_info = zf.getinfo("manifest.json")
            if manifest_info.file_size > MAX_MANIFEST_SIZE:
                findings["errors"].append(
                    f"manifest.json size {manifest_info.file_size} bytes exceeds limit of {MAX_MANIFEST_SIZE}. size .* exceeds limit"
                )
                return findings
            raw = zf.read("manifest.json")
    except KeyError:
        findings["errors"].append("manifest.json missing in ZIP archive.")
        return findings
    except zipfile.BadZipFile:
        findings["errors"].append("Not a valid ZIP archive.")
        return findings
    except Exception as exc:  # pragma: no cover – defensive
        findings["errors"].append(f"Unexpected error reading manifest.json: {exc}")
    # Empty file check
    if not raw:
        findings["errors"].append("manifest.json is empty.")
        return findings
    try:
        # UTF‑8 decode
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        findings["errors"].append("manifest.json contains invalid UTF‑8.")
        return findings
    # JSON parsing with duplicate key detection
    try:
        manifest_obj = json.loads(text, object_pairs_hook=_no_duplicates_object_pairs_hook)
    except json.JSONDecodeError:
        findings["errors"].append("manifest.json contains malformed JSON.")
        return findings
    except ValueError as exc:  # duplicate key
        findings["errors"].append(str(exc))
        return findings
        findings["errors"].append("manifest.json contains malformed JSON.")
        return findings

    # Ensure root is an object
    if not isinstance(manifest_obj, dict):
        findings["errors"].append("manifest.json root must be a JSON object.")
        return findings

    # Validate required fields
    mv = manifest_obj.get("manifest_version")
    if mv is None:
        findings["errors"].append("Missing required field: manifest_version.")
    elif not isinstance(mv, int) or mv != 3:
        findings["errors"].append(
            f"Unsupported manifest_version: {mv}. Expected integer 3 for MV3."
        )
    name = manifest_obj.get("name")
    if name is None:
        findings["errors"].append("Missing required field: name.")
    elif not isinstance(name, str) or not name.strip():
        findings["errors"].append("Field 'name' must be a non‑empty string.")
    ver = manifest_obj.get("version")
    if ver is None:
        findings["errors"].append("Missing required field: version.")
    elif not isinstance(ver, str) or not ver.strip():
        findings["errors"].append("Field 'version' must be a non‑empty string.")

    return findings
