"""Deterministic, local remediation guidance for audit findings.

Findings are plain strings produced by the validators (which this module never
changes). Each message is matched against an ordered table of explicit rules;
a rule gives a stable ``id`` that survives rewording of the message, the file or
field involved (``subject``) and fixed advice. Messages no rule recognises get
``UNCLASSIFIED:<hash>``, derived from the message with digits normalised, so they
stay comparable between reports without ever matching an unrelated finding.

The advice is general. It never claims a fix is safe for a specific extension.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# Which validator produced the finding (used by readiness to attribute checks).
ZIP, MANIFEST, REFERENCES, LOCALES, ICONS = "zip", "manifest", "references", "locales", "icons"

LEVELS = {"error": "blocks", "warning": "review", "info": "info"}
LEVEL_LABEL = {"blocks": "Fix before release", "review": "Review recommended", "info": "Informational"}

_NOIDX = re.compile(r"\[\d+\]")


@dataclass(frozen=True)
class Guidance:
    id: str
    check: Optional[str]
    subject: str
    where: str
    title: str
    why: str
    action: str
    level: str

    @property
    def level_label(self) -> str:
        return LEVEL_LABEL[self.level]


# (id, check, regex, where template, title, why, action). Order matters: first match wins.
# Named groups: s = subject, f = manifest field, p = path. "." stands in for the non-breaking
# hyphens the validators use in some messages.
_RULES: List[Tuple[str, str, str, str, str, str, str]] = [
    ("ZIP_INVALID", ZIP, r"(?:File is not a|Not a) valid ZIP archive", "",
     "Not a readable ZIP archive",
     "The package cannot be read as a ZIP, so no other checks could run.",
     "Re-create the ZIP from your extension folder (manifest.json at the top level) and audit it again."),
    ("ZIP_INSPECT_ERROR", ZIP, r"Unexpected error during ZIP inspection", "",
     "ZIP inspection failed unexpectedly",
     "The archive could not be inspected, so later checks were skipped.",
     "Confirm the file is a complete, uncorrupted ZIP and retry. The log file has technical details."),
    ("ZIP_TOO_MANY_ENTRIES", ZIP, r"Archive contains \d+ files; exceeds limit", "",
     "Too many files in the archive",
     "This tool stops at 1000 entries so a hostile archive cannot exhaust memory; no entries were read.",
     "Remove files that do not belong in the package (tests, source maps, dependency folders) and rebuild."),
    ("ZIP_TOO_LARGE", ZIP, r"Total uncompressed size", "",
     "Archive is too large when unpacked",
     "This tool stops at 50 MiB uncompressed so a hostile archive cannot exhaust memory; no entries were read.",
     "Remove or shrink large assets that are not needed at runtime and rebuild."),
    ("ZIP_LONG_NAME", ZIP, r"Entry \d+ has an unusually long name", "",
     "Unusually long file name",
     "Very long paths can fail to extract or install on some systems.",
     "Shorten the file or folder name and update every reference to it."),
    ("ZIP_ABSOLUTE_PATH", ZIP, r"Entry \d+ uses an absolute path: (?P<s>.*)\.$", "{s}",
     "Absolute path inside the archive",
     "Entry paths should be relative to the extension root; absolute paths can be written outside it by some tools.",
     "Rebuild the ZIP so every entry path is relative to the extension folder."),
    ("ZIP_TRAVERSAL", ZIP, r"Entry \d+ contains a path traversal component: (?P<s>.*)\.$", "{s}",
     "Path traversal in the archive",
     "A '..' component can place a file outside the extraction folder when some tools unpack the archive.",
     "Rebuild the ZIP from the extension folder so no entry path contains '..'."),
    ("ZIP_DUPLICATE_ENTRY", ZIP, r"Duplicate entry detected: (?P<s>.*)\.$", "{s}",
     "Duplicate archive entry",
     "Two entries share one path, so which copy is used depends on the tool that reads the archive.",
     "Rebuild the ZIP so each path appears exactly once."),
    ("ZIP_CASE_COLLISION", ZIP, r"Entry names differ only by case: (?P<s>.*)\.$", "{s}",
     "Names that differ only by case",
     "On case-insensitive file systems (such as Windows) these entries refer to the same file.",
     "Rename or remove one so the names differ by more than letter case."),
    ("ZIP_ENCRYPTED", ZIP, r"Entry \d+ is encrypted: (?P<s>.*)\.$", "{s}",
     "Encrypted archive entry",
     "Encrypted entries cannot be inspected, and extension packages are not expected to be password-protected.",
     "Rebuild the ZIP without a password."),
    ("ZIP_SYMLINK", ZIP, r"Entry \d+ is a symbolic link: (?P<s>.*)\.$", "{s}",
     "Symbolic link in the archive",
     "A link can point outside the package and may not survive installation.",
     "Replace the link with a real copy of the file it points to."),
    ("ZIP_COMPRESSION_RATIO", ZIP, r"Entry \d+ has an unusually high compression ratio \(\d+:1\): (?P<s>.*)\.$", "{s}",
     "Very high compression ratio",
     "Highly repetitive data can legitimately compress this well, but it is also how decompression-bomb archives look.",
     "Check what the file is. If it is expected, no action is needed; otherwise remove it."),
    ("ZIP_LOCAL_HEADER_MALFORMED", ZIP, r"Entry \d+ has a malformed local header: (?P<s>.*)\.$", "{s}",
     "Damaged entry header",
     "The header stored with this entry is damaged or does not line up with the archive index.",
     "Rebuild the ZIP with a standard tool."),
    ("ZIP_LOCAL_HEADER_MISMATCH", ZIP, r"Entry \d+ local header name does not match the central directory: (?P<s>.*)\.$", "{s}",
     "Entry name differs between headers",
     "The name stored with the data differs from the one in the archive index, so different tools may read different files.",
     "Rebuild the ZIP with a standard tool."),

    ("LOCALE_DEFAULT_MISSING", LOCALES, r"Missing required field: default_locale\.", "manifest.json: default_locale",
     "default_locale is missing",
     "Packages that ship a _locales folder declare which locale is the fallback.",
     "Add \"default_locale\" (for example \"en\") to manifest.json, or remove _locales if you do not localise."),
    ("LOCALE_DEFAULT_INVALID", LOCALES, r"Field 'default_locale' must be", "manifest.json: default_locale",
     "default_locale is not a valid value",
     "default_locale must be a non-empty string naming a folder under _locales.",
     "Set it to the folder name of your default locale, such as \"en\"."),
    ("LOCALE_FILE_MISSING", LOCALES, r"Missing file: (?P<s>.*)\.$", "{s}",
     "Locale messages file is missing",
     "The manifest names a default locale whose messages.json is not in the package.",
     "Add the file at that path, or correct default_locale to an existing locale folder."),
    ("LOCALE_FILE_DUPLICATE", LOCALES, r"Duplicate file: (?P<s>.*)\.$", "{s}",
     "Duplicate locale messages file", "The archive holds more than one copy of this file.",
     "Rebuild the ZIP so the file appears once."),
    ("LOCALE_MESSAGES_TOO_LARGE", LOCALES, r"messages\.json size", "_locales/<default_locale>/messages.json",
     "messages.json is too large",
     "This tool refuses to read locale files over 1 MiB.",
     "Split out or remove unused strings, then rebuild."),
    ("LOCALE_MESSAGES_ENCODING", LOCALES, r"messages\.json contains invalid UTF", "_locales/<default_locale>/messages.json",
     "messages.json is not valid UTF-8", "The file must be UTF-8 text to be parsed.",
     "Re-save the file as UTF-8."),
    ("LOCALE_MESSAGES_JSON", LOCALES, r"messages\.json contains malformed JSON", "_locales/<default_locale>/messages.json",
     "messages.json is not valid JSON", "A syntax error means none of its strings can be read.",
     "Fix the JSON syntax (a JSON validator helps) and rebuild."),
    ("LOCALE_MESSAGES_DUP_KEY", LOCALES, r"Duplicate key in messages\.json: '(?P<s>.*)'\.$", "messages.json: {s}",
     "Duplicate key in messages.json",
     "When a key is repeated, readers disagree about which value wins.",
     "Keep one definition of the key."),
    ("LOCALE_MESSAGES_NOT_OBJECT", LOCALES, r"messages\.json root must be", "_locales/<default_locale>/messages.json",
     "messages.json root is not an object", "Locale files must be a JSON object keyed by message name.",
     "Wrap the content in a top-level { } object."),
    ("LOCALE_ENTRY_INVALID", LOCALES, r"message entry '(?P<s>.*)' (?:is not an object|missing 'message' field|has non.string)", "messages.json: {s}",
     "Malformed locale message",
     "Each entry must be an object with a string \"message\" field.",
     "Use the form {\"key\": {\"message\": \"text\"}} for this entry."),

    ("MANIFEST_MISSING", MANIFEST, r"(?:Missing root-level manifest\.json|manifest\.json missing in ZIP archive)", "manifest.json",
     "manifest.json not found at the top level",
     "Chrome reads the manifest from the root of the package; without it nothing else can be checked.",
     "Zip the contents of the extension folder (not the folder itself) so manifest.json is at the top."),
    ("MANIFEST_AMBIGUOUS", MANIFEST, r"Ambiguous package: multiple root-level manifest\.json", "manifest.json",
     "More than one root manifest.json", "It is unclear which manifest is meant.",
     "Keep a single manifest.json at the top level."),
    ("MANIFEST_TOO_LARGE", MANIFEST, r"manifest\.json size", "manifest.json",
     "manifest.json is too large", "This tool refuses to read manifests over 1 MiB.",
     "Check that the file is really your manifest."),
    ("MANIFEST_READ_ERROR", MANIFEST, r"Unexpected error reading manifest\.json", "manifest.json",
     "manifest.json could not be read", "An unexpected read error stopped the manifest checks.",
     "Confirm the ZIP is intact and retry. The log file has technical details."),
    ("MANIFEST_EMPTY", MANIFEST, r"manifest\.json is empty", "manifest.json",
     "manifest.json is empty", "An empty file cannot describe the extension.", "Restore the manifest contents."),
    ("MANIFEST_ENCODING", MANIFEST, r"manifest\.json contains invalid UTF", "manifest.json",
     "manifest.json is not valid UTF-8", "The file must be UTF-8 text to be parsed.", "Re-save the file as UTF-8."),
    ("MANIFEST_JSON", MANIFEST, r"manifest\.json contains malformed JSON", "manifest.json",
     "manifest.json is not valid JSON", "A syntax error means no field can be read.",
     "Fix the JSON syntax (a JSON validator helps) and rebuild."),
    ("MANIFEST_NOT_OBJECT", MANIFEST, r"manifest\.json root must be", "manifest.json",
     "manifest.json root is not an object", "The manifest must be a JSON object.",
     "Wrap the content in a top-level { } object."),
    ("MANIFEST_DUP_KEY", MANIFEST, r"Duplicate key in manifest\.json: '(?P<s>.*)'\.$", "manifest.json: {s}",
     "Duplicate key in manifest.json", "When a key is repeated, readers disagree about which value wins.",
     "Keep one definition of the key."),
    ("MANIFEST_VERSION_UNSUPPORTED", MANIFEST, r"Unsupported manifest_version", "manifest.json: manifest_version",
     "Unsupported manifest_version", "This tool audits Manifest V3 packages and expects the integer 3.",
     "Set \"manifest_version\": 3. Moving from MV2 changes how background code and some APIs work, so test the extension."),
    ("MANIFEST_FIELD_MISSING", MANIFEST, r"Missing required field: (?P<s>\w+)\.", "manifest.json: {s}",
     "Required manifest field is missing", "The manifest must define manifest_version, name and version.",
     "Add the field to manifest.json."),
    ("MANIFEST_FIELD_INVALID", MANIFEST, r"Field '(?P<s>\w+)' must be", "manifest.json: {s}",
     "Manifest field has the wrong type", "This field must be a non-empty string.",
     "Replace the value with a non-empty string."),

    ("REF_UNSAFE_PATH", REFERENCES, r"(?P<f>\S+) contains unsafe path: (?P<p>.*)\.$", "{f} -> {p}",
     "Manifest references an unsafe path",
     "Paths in the manifest must stay inside the package: no absolute paths, drive letters or '..'.",
     "Change the reference to a relative path under the extension root."),
    ("REF_MISSING_FILE", REFERENCES, r"(?P<f>\S+) (?:references )?missing file: (?P<p>.*)\.$", "{f} -> {p}",
     "Referenced file is not in the package",
     "The manifest points at a file that is not in the ZIP, so the feature using it will fail.",
     "Add the file at that path, or correct the reference. A build step that skips the file is a common cause."),
    ("REF_DUPLICATE_FILE", REFERENCES, r"(?P<f>\S+) (?:references duplicate file|ambiguous duplicate|wildcard .* matches duplicate entry): (?P<p>.*)\.$", "{f} -> {p}",
     "Referenced path exists more than once", "The archive holds several entries for this path, so the target is ambiguous.",
     "Rebuild the ZIP so the path appears once."),
    ("REF_WILDCARD_EMPTY", REFERENCES, r"(?P<f>\S+) wildcard (?P<p>.*) matches no entries", "{f} -> {p}",
     "Wildcard matches no files", "The pattern exposes nothing, which usually means a typo or a missing build output.",
     "Check the pattern against the files in the package, or remove it if unused."),
    ("REF_MALFORMED_FIELD", REFERENCES, r"(?P<s>[\w.\[\]-]+) (?:is not an? |has unexpected type|contains non-string|missing path)", "{s}",
     "Manifest field has an unexpected shape", "Chrome may ignore the field, so its feature may not work as intended.",
     "Check the field against the Chrome manifest documentation for the expected type."),

    ("ICON_SVG", ICONS, r"SVG icons are not supported; found in (?P<s>.*)\.$", "{s}",
     "SVG used as an icon", "Chrome extension icons must be raster images; SVG is not supported there.",
     "Export the icon as PNG at the required sizes and update the manifest."),
    ("ICON_UNRECOGNIZED_EXT", ICONS, r"Unrecognized icon file extension '.*' for (?P<s>.*)\.$", "{s}",
     "Unrecognised icon file type", "This tool cannot confirm the file is a valid image.",
     "Use a PNG icon unless you know another format is intended."),
    ("ICON_NO_CHECKER", ICONS, r"No signature checker for extension '.*' in (?P<s>.*)\.$", "{s}",
     "Icon type not verified", "This tool has no validity check for this image type.",
     "Open the image in a viewer to confirm it is valid."),
    ("ICON_UNREADABLE", ICONS, r"Could not read (?P<s>.*?): ", "{s}",
     "Icon file could not be read", "The icon could not be loaded from the archive.",
     "Check the file is not damaged and rebuild."),
    ("ICON_INSPECTION_SKIPPED", ICONS, r"Icon (?P<s>.*) exceeds \d+ bytes; content inspection skipped", "{s}",
     "Icon not inspected (very large file)", "Its contents were not checked.",
     "Use a smaller icon; icons rarely need to be large files."),
    ("ICON_NON_SQUARE", ICONS, r"(?:PNG|JPEG|GIF|BMP|ICO) icon non.square dimensions \d+x\d+\. in (?P<s>.*)$", "{s}",
     "Icon is not square", "Extension icons are expected to be square; Chrome may scale or crop others.",
     "Provide a square image at the declared size."),
    ("ICON_INVALID_FILE", ICONS, r"(?:PNG|JPEG|GIF|BMP|ICO) icon (?:truncated|too small|missing|has zero).* in (?P<s>.*)$", "{s}",
     "Icon file looks damaged", "The file does not have the structure of the image type its extension claims.",
     "Re-export the image from its source and replace the file."),
]

_COMPILED = [(rid, chk, re.compile(r"^" + pat), where, title, why, act)
             for rid, chk, pat, where, title, why, act in _RULES]

RULE_IDS = tuple(r[0] for r in _RULES)


def _normalise(message: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"\d+", "#", message.lower())).strip()


def explain(severity: str, message: str) -> Guidance:
    """Guidance for one finding; never raises and always returns a stable ``id``."""
    level = LEVELS.get(severity, "review")
    for rid, check, rx, where, title, why, action in _COMPILED:
        m = rx.match(message)
        if not m:
            continue
        groups: Dict[str, str] = defaultdict(str, {k: v or "" for k, v in m.groupdict().items()})
        field = _NOIDX.sub("", groups["f"])
        path = groups["p"]
        subject = groups["s"] or ""
        if field or path:
            subject = f"{_NOIDX.sub('', field)}|{path}" if (field and path) else (field or path)
        shown = defaultdict(str, groups)
        return Guidance(rid, check, subject, where.format_map(shown), title, why, action, level)
    digest = hashlib.sha1(_normalise(message).encode("utf-8", "replace")).hexdigest()[:12]
    return Guidance(
        f"UNCLASSIFIED:{digest}", None, "", "",
        "Finding without specific guidance",
        "This tool has no specific advice for this message.",
        "Read the message, locate the named file or field in your package, and decide whether it needs a change.",
        level,
    )
