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
import stat
import struct
import zipfile
from pathlib import Path
from typing import Dict, List

# ---- Configuration limits ----
MAX_ENTRIES = 1000  # max number of files in the archive
MAX_UNCOMPRESSED_SIZE = 50 * 1024 * 1024  # 50 MB total uncompressed
MAX_ENTRY_NAME_LENGTH = 256
RATIO_MIN_SIZE = 1024 * 1024  # a ratio is only meaningful for entries of at least 1 MiB
RATIO_WARN = 100  # uncompressed : compressed

# Inspection errors after which the archive must not be read any further: it is not a usable ZIP,
# or it exceeds a resource limit. audit_extension stops on these (explicitly, not by guessing from
# entry names, which an archive controls).
FATAL_PREFIXES = (
    "File is not a valid ZIP archive",
    "Unexpected error during ZIP inspection",
    "Archive contains",
    "Total uncompressed size",
)

_LOCAL_HEADER = struct.Struct("<4s5H3L2H")  # signature .. filename length, extra length (30 bytes)

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


def is_fatal(findings: Dict[str, List[str]]) -> bool:
    """True if *findings* (from :func:`inspect_zip`) say the archive must not be read further."""
    return any(msg.startswith(FATAL_PREFIXES) for msg in findings["errors"])


def _check_local_headers(file_path: str, entries, findings: Dict[str, List[str]]) -> None:
    """Compare each entry's local-header file name with the central directory (metadata only).

    Reads at most 30 bytes plus one name per entry, and only at offsets inside the file; a
    truncated or malformed header becomes a finding, never an exception.
    """
    size = os.path.getsize(file_path)
    with open(file_path, "rb") as fh:
        for idx, zi in enumerate(entries, start=1):
            name = zi.orig_filename
            offset = zi.header_offset
            try:
                if offset < 0 or offset + _LOCAL_HEADER.size > size:
                    raise ValueError("header outside the file")
                fh.seek(offset)
                head = fh.read(_LOCAL_HEADER.size)
                if len(head) != _LOCAL_HEADER.size:
                    raise ValueError("truncated header")
                fields = _LOCAL_HEADER.unpack(head)
                if fields[0] != b"PK\x03\x04":
                    raise ValueError("bad signature")
                name_len = fields[-2]
                if offset + _LOCAL_HEADER.size + name_len > size:
                    raise ValueError("name outside the file")
                local = fh.read(name_len)
            except (ValueError, struct.error, OSError):
                findings["errors"].append(f"Entry {idx} has a malformed local header: {name}.")
                continue
            central = name.encode("utf-8" if zi.flag_bits & 0x800 else "cp437", errors="replace")
            if local != central:
                findings["errors"].append(
                    f"Entry {idx} local header name does not match the central directory: {name}."
                )


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
    folded_names = {}  # case-folded name -> first spelling seen
    total_uncompressed = 0
    over_limit = False

    try:
        with zipfile.ZipFile(file_path, "r", allowZip64=True) as zf:
            entries = zf.infolist()
            if len(entries) > MAX_ENTRIES:
                findings["errors"].append(
                    f"Archive contains {len(entries)} files; exceeds limit of {MAX_ENTRIES}."
                )
                over_limit = True
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
                else:
                    first = folded_names.setdefault(name.lower(), name)  # not casefold: "ss" and "ß" are distinct on NTFS
                    if first != name:
                        findings["warnings"].append(
                            f"Entry names differ only by case: {first} and {name}."
                        )
                seen_names.add(name)
                if zi.flag_bits & 0x1:
                    findings["errors"].append(f"Entry {idx} is encrypted: {name}.")
                if zi.create_system == 3 and stat.S_ISLNK(zi.external_attr >> 16):
                    findings["errors"].append(f"Entry {idx} is a symbolic link: {name}.")
                if zi.file_size >= RATIO_MIN_SIZE and zi.file_size >= RATIO_WARN * max(zi.compress_size, 1):
                    findings["warnings"].append(
                        f"Entry {idx} has an unusually high compression ratio "
                        f"({zi.file_size // max(zi.compress_size, 1)}:1): {name}."
                    )
                total_uncompressed += zi.file_size
                if total_uncompressed > MAX_UNCOMPRESSED_SIZE:
                    findings["errors"].append(
                        f"Total uncompressed size {total_uncompressed} bytes exceeds limit of {MAX_UNCOMPRESSED_SIZE}."
                    )
                    # No need to continue counting once over limit
                    over_limit = True
                    break
        if not over_limit:
            _check_local_headers(file_path, entries, findings)
    except zipfile.BadZipFile:
        findings["errors"].append("File is not a valid ZIP archive (BadZipFile).")
    except Exception as exc:  # pragma: no cover – defensive
        findings["errors"].append(f"Unexpected error during ZIP inspection: {exc}")
    return findings
