"""Icon content validation for Chrome extension packages.

This module implements :func:`validate_icons`, which inspects the icon
files referenced in the extension manifest.  It deliberately does *not*
re‑implement file‑existence checks – those are performed by
``reference_validator`` – and only performs light‑weight signature
validation and simple size checks.

The implementation follows the same result format used by the other
validators: a dictionary with ``errors``, ``warnings`` and ``info``
lists.
"""

from __future__ import annotations

import os
import zipfile
from pathlib import Path
from typing import Dict, List, Tuple

# Result type used by all validators.
Result = Dict[str, List[str]]

# Maximum number of bytes to read for signature checks.  Anything larger
# is skipped with a warning – this mirrors the behaviour of the
# ``locale_validator`` which imposes a 1 MiB limit on ``messages.json``.
MAX_INSPECTION_SIZE = 5 * 1024 * 1024  # 5 MiB

# Mapping of file extensions to expected signature check functions.
EXTENSION_MAP: Dict[str, str] = {
    ".png": "png",
    ".jpg": "jpg",
    ".jpeg": "jpg",
    ".gif": "gif",
    ".bmp": "bmp",
    ".ico": "ico",
}


def _load_manifest(zip_path: str) -> Tuple[Dict, Result]:
    """Load ``manifest.json`` from *zip_path*.

    The helper is duplicated from ``reference_validator`` to avoid a
    hard dependency on its internal implementation.  The semantics are
    identical – any errors are returned in the ``errors`` list.
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
    # Parse JSON
    try:
        manifest_obj = __import__("json").loads(text)
    except __import__("json").JSONDecodeError:
        findings["errors"].append("manifest.json contains malformed JSON.")
        return {}, findings
    if not isinstance(manifest_obj, dict):
        findings["errors"].append("manifest.json root must be a JSON object.")
        return {}, findings
    return manifest_obj, findings


def _signature_png(data: bytes) -> Tuple[bool, List[str]]:
    """Validate PNG signature and basic IHDR.

    Returns ``(valid, messages)`` where ``messages`` contain any
    warnings/errors found.  ``valid`` is ``False`` if the signature or
    dimensions are not acceptable.
    """

    msgs: List[str] = []
    if len(data) < 12:
        return False, ["PNG icon truncated or too small."]
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return False, ["PNG icon missing PNG signature."]
    # IHDR chunk should start at offset 12; ensure we have enough data.
    if len(data) < 16 or data[12:16] != b"IHDR":
        return False, ["PNG icon missing IHDR chunk."]
    if len(data) < 24:
        return False, ["PNG icon truncated or too small."]
    width = int.from_bytes(data[16:20], "big")
    height = int.from_bytes(data[20:24], "big")
    if width == 0 or height == 0:
        return False, ["PNG icon has zero dimension."]
    if width != height:
        msgs.append(f"PNG icon non‑square dimensions {width}x{height}.")
    height = int.from_bytes(data[20:24], "big")
    if width == 0 or height == 0:
        return False, ["PNG icon has zero dimension."]
    if width != height:
        msgs.append(f"PNG icon non‑square dimensions {width}x{height}.")
    return True, msgs


def _signature_jpg(data: bytes) -> Tuple[bool, List[str]]:
    if len(data) < 4:
        return False, ["JPEG icon too small."]
    if not (data.startswith(b"\xff\xd8") and data.endswith(b"\xff\xd9")):
        return False, ["JPEG icon missing start/end markers."]
    return True, []


def _signature_jpg(data: bytes) -> Tuple[bool, List[str]]:
    """Very small JPEG signature check – start/end markers only."""
    if len(data) < 4:
        return False, ["JPEG icon too small."]
    if not (data.startswith(b"\xff\xd8") and data.endswith(b"\xff\xd9")):
        return False, ["JPEG icon missing start/end markers."]
    return True, []


def _signature_gif(data: bytes) -> Tuple[bool, List[str]]:
    if len(data) < 6:
        return False, ["GIF icon too small."]
    if data[:6] not in (b"GIF87a", b"GIF89a"):
        return False, ["GIF icon missing GIF header."]
    return True, []


def _signature_bmp(data: bytes) -> Tuple[bool, List[str]]:
    if len(data) < 2:
        return False, ["BMP icon too small."]
    if data[:2] != b"BM":
        return False, ["BMP icon missing BMP signature."]
    return True, []


def _signature_ico(data: bytes) -> Tuple[bool, List[str]]:
    if len(data) < 4:
        return False, ["ICO icon too small."]
    if data[:4] != b"\x00\x00\x01\x00":
        return False, ["ICO icon missing ICO signature."]
    return True, []


SIGNATURE_CHECKS = {
    "png": _signature_png,
    "jpg": _signature_jpg,
    "gif": _signature_gif,
    "bmp": _signature_bmp,
    "ico": _signature_ico,
}


def _signature_gif(data: bytes) -> Tuple[bool, List[str]]:
    if len(data) < 6:
        return False, ["GIF icon too small."]
    if data[:6] not in (b"GIF87a", b"GIF89a"):
        return False, ["GIF icon missing GIF header."]
    return True, []


def _signature_bmp(data: bytes) -> Tuple[bool, List[str]]:
    if len(data) < 2:
        return False, ["BMP icon too small."]
    if data[:2] != b"BM":
        return False, ["BMP icon missing BMP signature."]
    return True, []


def _signature_ico(data: bytes) -> Tuple[bool, List[str]]:
    if len(data) < 4:
        return False, ["ICO icon too small."]
    if data[:4] != b"\x00\x00\x01\x00":
        return False, ["ICO icon missing ICO signature."]
    return True, []


SIGNATURE_CHECKS = {
    "png": _signature_png,
    "jpg": _signature_jpg,
    "gif": _signature_gif,
    "bmp": _signature_bmp,
    "ico": _signature_ico,
}


def validate_icons(zip_path: str) -> Result:
    """Validate icon files referenced in a Chrome extension manifest.

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
        # Cannot continue without a valid manifest.
        return findings

    # Build list of icon paths to check.  We intentionally skip missing
    # entries – reference_validator already records those.
    icon_entries: List[Tuple[str, str]] = []  # (path, declaration_name)
    # Manifest icons dict.
    icons = manifest.get("icons")
    if isinstance(icons, dict):
        for sz, path in icons.items():
            icon_entries.append((path, f"icons[{sz}]") )
    # action.default_icon
    action = manifest.get("action")
    default_icon = action.get("default_icon") if isinstance(action, dict) else None
    if isinstance(default_icon, dict):
        for sz, path in default_icon.items():
            icon_entries.append((path, f"action.default_icon[{sz}]") )
    elif isinstance(default_icon, str):
        icon_entries.append((default_icon, "action.default_icon") )

    # Quick lookup of existing zip entries.
    with zipfile.ZipFile(zip_path, "r", allowZip64=True) as zf:
        entry_set = {info.filename for info in zf.infolist()}
        for path, decl in icon_entries:
            # Skip if entry missing – duplicate errors avoided.
            if not isinstance(path, str) or path not in entry_set:
                continue
            # Read bounded bytes.
            try:
                with zf.open(path) as fp:
                    data = fp.read(MAX_INSPECTION_SIZE + 1)
            except Exception as exc:  # pragma: no cover – defensive
                findings["warnings"].append(f"Could not read {path}: {exc}")
                continue
            size = len(data)
            if size > MAX_INSPECTION_SIZE:
                findings["warnings"].append(
                    f"Icon {path} exceeds {MAX_INSPECTION_SIZE} bytes; content inspection skipped."
                )
                continue
            # Check extension support.
            ext = os.path.splitext(path)[1].lower()
            if ext == ".svg":
                findings["errors"].append(
                    f"SVG icons are not supported; found in {decl}."
                )
                continue
            if ext not in EXTENSION_MAP:
                findings["warnings"].append(
                    f"Unrecognized icon file extension '{ext}' for {decl}."
                )
                continue
            sig_name = EXTENSION_MAP[ext]
            check_func = SIGNATURE_CHECKS.get(sig_name)
            if not check_func:
                findings["warnings"].append(
                    f"No signature checker for extension '{ext}' in {decl}."
                )
                continue
            valid, msgs = check_func(data)
            if not valid:
                findings["errors"].extend([f"{msg} in {decl}" for msg in msgs])
            else:
                # Append any warnings from signature check
                findings["warnings"].extend([f"{msg} in {decl}" for msg in msgs])
    return findings
