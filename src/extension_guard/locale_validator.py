"""Locale validation for Chrome extension packages.

The module operates directly on a ZIP archive without extracting any
files to disk.  It performs the following checks:

1. If the ZIP contains a top‑level ``_locales/`` directory but the
   ``default_locale`` field is missing from the manifest, an error is
   reported.
2. The ``default_locale`` field must be a non‑empty string.
3. The locale directory ``_locales/<default_locale>/`` must exist.
4. The locale directory must contain exactly one ``messages.json`` file.
5. The ``messages.json`` file must not exceed 1 MiB.
6. The file must contain valid UTF‑8.
7. The file must contain valid JSON with no duplicate keys.
8. The JSON root must be an object.
9. Each message entry must have a ``message`` field that is a string.
10. Duplicate keys in the root of the JSON are reported.

The function returns a dictionary with the keys ``errors``, ``warnings``
and ``info`` – each a list of human‑readable messages.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Dict, List, Tuple

# Result type
Result = Dict[str, List[str]]

# Max allowed size for messages.json (1 MiB)
MAX_MESSAGES_SIZE = 1 * 1024 * 1024

# Duplicate key error message helper

def _duplicate_key_error(key: str) -> str:
    return f"Duplicate key in messages.json: '{key}'."


def _no_duplicates_object_pairs_hook(pairs):  # pragma: no cover - trivial helper
    seen = set()
    obj = {}
    for k, v in pairs:
        if k in seen:
            raise ValueError(_duplicate_key_error(k))
        seen.add(k)
        obj[k] = v
    return obj


def _load_manifest(zip_path: str) -> Tuple[Dict, Result]:
    """Load ``manifest.json`` from *zip_path* and return its dict and any findings.

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
    except Exception as exc:  # pragma: no cover – defensive
        findings["errors"].append(f"Unexpected error reading manifest.json: {exc}")
        return {}, findings
    # Decode
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        findings["errors"].append("manifest.json contains invalid UTF‑8.")
        return {}, findings
    # Parse JSON with duplicate key detection
    try:
        manifest_obj = json.loads(text, object_pairs_hook=_no_duplicates_object_pairs_hook)
    except json.JSONDecodeError:
        findings["errors"].append("manifest.json contains malformed JSON.")
        return {}, findings
    except ValueError as exc:  # duplicate key
        findings["errors"].append(str(exc))
        return {}, findings
    return manifest_obj, findings


def validate_locales(zip_path: str) -> Result:
    """Validate default locale messages inside a Chrome extension ZIP.

    Parameters
    ----------
    zip_path:
        Path to the ZIP archive.

    Returns
    -------
    dict
        Structured findings: ``errors``, ``warnings`` and ``info``.
    """
    findings: Result = {"errors": [], "warnings": [], "info": []}

    # Load manifest to get default_locale
    manifest, mfind = _load_manifest(zip_path)
    findings["errors"].extend(mfind["errors"])
    findings["warnings"].extend(mfind["warnings"])
    if mfind["errors"]:
        # Cannot continue without a valid manifest
        return findings

    # Check default_locale (only required when _locales/ entries exist; see below)
    default_locale = manifest.get("default_locale")
    if default_locale is not None and (
        not isinstance(default_locale, str) or not default_locale.strip()
    ):
        findings["errors"].append("Field 'default_locale' must be a non‑empty string.")

    # Gather ZIP entries
    try:
        with zipfile.ZipFile(zip_path, "r", allowZip64=True) as zf:
            names = zf.namelist()
            # Identify _locales/ entries
            locales_entries = [n for n in names if n.startswith("_locales/")]
            # default_locale is required only when the package ships _locales/
            if locales_entries and default_locale is None:
                findings["errors"].append("Missing required field: default_locale.")
            # If default_locale present and is valid string
            if isinstance(default_locale, str) and default_locale.strip():
                locale_dir = f"_locales/{default_locale}/"
                # Ensure locale directory exists
                if not any(n.startswith(locale_dir) for n in names):
                    findings["errors"].append(f"Missing file: {locale_dir}messages.json.")
                else:
                    # Check messages.json existence
                    messages_path = f"{locale_dir}messages.json"
                    count = sum(1 for n in names if n == messages_path)
                    if count == 0:
                        findings["errors"].append(f"Missing file: {messages_path}.")
                    elif count > 1:
                        findings["errors"].append(f"Duplicate file: {messages_path}.")
                    else:
                        # Validate messages.json
                        with zf.open(messages_path) as fp:
                            data = fp.read()
                        if len(data) > MAX_MESSAGES_SIZE:
                            findings["errors"].append(f"messages.json size {len(data)} bytes exceeds limit of {MAX_MESSAGES_SIZE} bytes.")
                        else:
                            try:
                                text = data.decode("utf-8")
                            except UnicodeDecodeError:
                                findings["errors"].append("messages.json contains invalid UTF‑8.")
                                return findings
                            try:
                                messages_obj = json.loads(text, object_pairs_hook=_no_duplicates_object_pairs_hook)
                            except json.JSONDecodeError:
                                findings["errors"].append("messages.json contains malformed JSON.")
                                return findings
                            except ValueError as exc:  # duplicate key
                                findings["errors"].append(str(exc))
                                return findings
                            if not isinstance(messages_obj, dict):
                                findings["errors"].append("messages.json root must be a JSON object.")
                                return findings
                            # Validate each message entry
                            for key, entry in messages_obj.items():
                                if not isinstance(entry, dict):
                                    findings["errors"].append(f"message entry '{key}' is not an object.")
                                    continue
                                msg_val = entry.get("message")
                                if msg_val is None:
                                    findings["errors"].append(f"message entry '{key}' missing 'message' field.")
                                elif not isinstance(msg_val, str):
                                    findings["errors"].append(f"message entry '{key}' has non‑string 'message' field.")
    except zipfile.BadZipFile:
        findings["errors"].append("Not a valid ZIP archive.")
    except Exception as exc:  # pragma: no cover – defensive
        findings["errors"].append(f"Unexpected error during ZIP inspection: {exc}")

    return findings
