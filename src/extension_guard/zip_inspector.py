"""Safe ZIP inspection utilities.

The goal of this module is to provide a lightweight, *non‑destructive*
inspection of a ZIP archive that is expected to contain a Chrome
extension.  The implementation avoids any extraction to the filesystem
and performs a limited set of checks that are useful for the early
phases of the audit.

The returned structure is a simple dictionary with the keys
``errors``, ``warnings`` and ``info`` – each a list of string
messages.  Tests in :mod:`tests.test_zip_inspector` exercise the
behaviour.
"""

from __future__ import annotations

import os
import zipfile
from pathlib import Path
from typing import Dict, List

# ---- Configuration limits ----
MAX_ENTRIES = 1000  # max number of files in the archive
MAX_UNCOMPRESSED_SIZE = 50 * 1024 * 1024  # 50 MB total uncompressed
MAX_ENTRY_NAME_LENGTH = 256

def _is_absolute_path(name: str) -> bool:
    """Return ``True`` if ``name`` looks like an absolute filesystem path.

    In ZIP archives a path that starts with ``/`` or ``\\`` or has a
    drive letter such as ``C:\`` is considered absolute and
    therefore unsafe.
    """
    if os.path.isabs(name):
        return True
    # Windows drive letter style
    if len(name) >= 2 and name[1] == ":" and name[0].isalpha():
        return True
    return False


def _has_traversal(name: str) -> bool:
    """Detect path traversal patterns (e.g., ``..\secret.txt``)."""
    parts = Path(name).parts
    return ".." in parts


def inspect_zip(file_path: str) -> Dict[str, List[str]]:
    """Inspect a ZIP archive and return findings.

    Parameters
    ----------
    file_path:
        Path to the ZIP file on disk.

    Returns
    -------
    dict
        Keys ``errors``, ``warnings`` and ``info``.  Each value is a
        list of human‑readable messages.
    """
    findings = {"errors": [], "warnings": [], "info": []}
    seen_names = set()
    total_uncompressed = 0

    try:
        with zipfile.ZipFile(file_path, "r", allowZip64=True) as zf:
            entries = zf.infolist()
            if len(entries) > MAX_ENTRIES:
                findings["errors"].append(
                    f"Archive contains {len(entries)} files; exceeds limit of {MAX_ENTRIES}."
                )
            for idx, zi in enumerate(entries, start=1):
                name = zi.filename
                # Basic sanity checks on entry name
                if len(name) > MAX_ENTRY_NAME_LENGTH:
                    findings["warnings"].append(
                        f"Entry {idx} has an unusually long name ({len(name)} chars)."
                    )
                if _is_absolute_path(name):
                    findings["errors"].append(
                        f"Entry {idx} uses an absolute path: {name}."
                    )
                if _has_traversal(name):
                    findings["errors"].append(
                        f"Entry {idx} contains a path traversal component: {name}."
                    )
                if name in seen_names:
                    findings["warnings"].append(
                        f"Duplicate entry detected: {name}."
                    )
                seen_names.add(name)
                total_uncompressed += zi.file_size
                if total_uncompressed > MAX_UNCOMPRESSED_SIZE:
                    findings["errors"].append(
                        f"Total uncompressed size {total_uncompressed} bytes exceeds limit of {MAX_UNCOMPRESSED_SIZE}."
                    )
                    # No need to continue counting once over limit
                    break
            else:
                # No errors found in entry loop
                pass
    except zipfile.BadZipFile:
        findings["errors"].append("File is not a valid ZIP archive (BadZipFile).")
    except Exception as exc:  # pragma: no cover – defensive
        findings["errors"].append(f"Unexpected error during ZIP inspection: {exc}")
    return findings
