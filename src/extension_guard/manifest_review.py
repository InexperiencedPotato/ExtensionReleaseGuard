"""Static review of a package's manifest: permissions, host access, content scripts.

Reads only ``manifest.json`` from the ZIP (at most 1 MiB, never extracted, never executed) and
applies fixed rules. Everything reported is a *static observation* for the developer to confirm
against the extension's intended behaviour; a permission is not a defect. Only
``inconsistency`` items point at something that looks wrong in the manifest itself.
"""

from __future__ import annotations

import json
import zipfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

MAX_MANIFEST_SIZE = 1 * 1024 * 1024
MAX_LISTED = 50  # list entries kept per section, so a huge manifest cannot flood the UI or a report

# permission -> what it allows. Wording is deliberately neutral: many are routine.
SENSITIVE_PERMISSIONS: Dict[str, str] = {
    "tabs": "Reads the URL and title of every open tab.",
    "webNavigation": "Observes navigation events across tabs.",
    "webRequest": "Observes network requests the browser makes.",
    "declarativeNetRequest": "Blocks or redirects requests using rules.",
    "declarativeNetRequestFeedback": "Reports which request rules matched.",
    "cookies": "Reads and changes cookies for hosts it has access to.",
    "history": "Reads and edits the browsing history.",
    "bookmarks": "Reads and edits bookmarks.",
    "topSites": "Reads the most-visited sites.",
    "downloads": "Starts and manages downloads.",
    "management": "Lists and controls other installed extensions.",
    "debugger": "Attaches Chrome DevTools Protocol to tabs, which grants broad control of pages.",
    "nativeMessaging": "Exchanges messages with a native program installed on the computer.",
    "proxy": "Controls the browser's proxy settings.",
    "privacy": "Changes browser privacy settings.",
    "contentSettings": "Changes per-site content settings.",
    "clipboardRead": "Reads clipboard contents.",
    "clipboardWrite": "Writes to the clipboard.",
    "geolocation": "Requests the device location.",
    "identity": "Obtains account identity or OAuth tokens.",
    "desktopCapture": "Captures the screen or windows.",
    "tabCapture": "Captures tab audio and video.",
    "pageCapture": "Saves tabs as MHTML.",
    "scripting": "Injects scripts into pages on hosts it has access to.",
    "system.storage": "Reads attached storage device information.",
    "enterprise.platformKeys": "Accesses enterprise platform keys.",
    "vpnProvider": "Implements a VPN client.",
}

BROAD_HOSTS = ("<all_urls>", "*://*/*", "http://*/*", "https://*/*", "*://*/", "http://*/", "https://*/")


@dataclass
class ReviewItem:
    kind: str  # "observation" (static, for review) or "inconsistency" (looks wrong in the manifest)
    title: str
    detail: str
    entries: List[str] = field(default_factory=list)


@dataclass
class ManifestReview:
    available: bool = False
    reason: str = ""  # why it is unavailable
    manifest_version: str = ""
    name: str = ""
    version: str = ""
    permissions: List[str] = field(default_factory=list)
    optional_permissions: List[str] = field(default_factory=list)
    host_permissions: List[str] = field(default_factory=list)
    optional_host_permissions: List[str] = field(default_factory=list)
    content_script_matches: List[str] = field(default_factory=list)
    items: List[ReviewItem] = field(default_factory=list)
    declares_icons: bool = False
    declares_locale: bool = False
    declares_references: bool = False


def _shown(value: Any) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=True, default=str)
    return text if len(text) <= 120 else text[:117] + "..."


def _strings(value: Any) -> List[str]:
    """The string members of *value* (anything not a list of strings is ignored)."""
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def _is_host_pattern(value: str) -> bool:
    return value == "<all_urls>" or "://" in value


def _read_manifest(zip_path: str) -> Optional[Dict[str, Any]]:
    """The parsed root manifest, or ``None`` (unavailable); sets nothing on disk."""
    with zipfile.ZipFile(zip_path, "r", allowZip64=True) as zf:
        roots = [i for i in zf.infolist() if i.filename == "manifest.json"]
        if len(roots) != 1 or roots[0].file_size > MAX_MANIFEST_SIZE:
            return None
        with zf.open(roots[0]) as fp:
            raw = fp.read(MAX_MANIFEST_SIZE + 1)
    if len(raw) > MAX_MANIFEST_SIZE:
        return None
    obj = json.loads(raw.decode("utf-8"))
    return obj if isinstance(obj, dict) else None


def review_manifest(zip_path: str) -> ManifestReview:
    """Review ``manifest.json`` inside *zip_path*; never raises."""
    try:
        manifest = _read_manifest(zip_path)
    except (OSError, ValueError, zipfile.BadZipFile, RecursionError):
        manifest = None
    if manifest is None:
        return ManifestReview(reason="manifest.json is missing, too large or not a usable JSON object.")
    try:
        return build_review(manifest)
    except Exception as exc:  # noqa: BLE001 - a review must never break an audit
        return ManifestReview(reason=f"The manifest could not be reviewed ({type(exc).__name__}).")


def build_review(manifest: Dict[str, Any]) -> ManifestReview:
    """Apply the review rules to an already-parsed manifest."""
    perms_raw = manifest.get("permissions")
    opt_raw = manifest.get("optional_permissions")
    hosts_raw = manifest.get("host_permissions")
    opt_hosts_raw = manifest.get("optional_host_permissions")
    all_perms, opt_perms = _strings(perms_raw), _strings(opt_raw)
    api_perms = [p for p in all_perms if not _is_host_pattern(p)]
    stray_hosts = [p for p in all_perms if _is_host_pattern(p)]
    opt_api = [p for p in opt_perms if not _is_host_pattern(p)]
    hosts, opt_hosts = _strings(hosts_raw), _strings(opt_hosts_raw)

    scripts = manifest.get("content_scripts")
    matches: List[str] = []
    for entry in scripts if isinstance(scripts, list) else []:
        if isinstance(entry, dict):
            matches += _strings(entry.get("matches"))

    review = ManifestReview(
        available=True,
        manifest_version=_shown(manifest.get("manifest_version", "")),
        name=_shown(manifest.get("name", "")),
        version=_shown(manifest.get("version", "")),
        permissions=api_perms[:MAX_LISTED],
        optional_permissions=opt_perms[:MAX_LISTED],
        host_permissions=hosts[:MAX_LISTED],
        optional_host_permissions=opt_hosts[:MAX_LISTED],
        content_script_matches=sorted(set(matches))[:MAX_LISTED],
    )
    items = review.items

    # --- sensitive capabilities (observations) ---
    found = [p for p in api_perms if p in SENSITIVE_PERMISSIONS]
    if found:
        items.append(ReviewItem(
            "observation", "Permissions that warrant developer review",
            "These are legitimate for many extensions. Confirm each is needed, and be ready to explain it "
            "in your store listing.",
            [f"{p}: {SENSITIVE_PERMISSIONS[p]}" for p in found[:MAX_LISTED]],
        ))
    opt_found = [p for p in opt_api if p in SENSITIVE_PERMISSIONS]
    if opt_found:
        items.append(ReviewItem(
            "observation", "Optional permissions that warrant review",
            "Requested at runtime and only with the user's consent.",
            [f"{p}: {SENSITIVE_PERMISSIONS[p]}" for p in opt_found[:MAX_LISTED]],
        ))

    # --- host access ---
    broad_hosts = [h for h in hosts if h in BROAD_HOSTS]
    if broad_hosts:
        items.append(ReviewItem(
            "observation", "Access to all websites",
            "These host patterns let the extension act on every site. That is normal for some tools but is "
            "the broadest access a manifest can request; narrow it if the extension only works on specific sites.",
            broad_hosts,
        ))
    if any(h.startswith("file:") for h in hosts):
        items.append(ReviewItem(
            "observation", "Access to local files",
            "A file:// host pattern lets the extension read local files once the user enables file access for it.",
            [h for h in hosts if h.startswith("file:")][:MAX_LISTED],
        ))
    broad_matches = [m for m in review.content_script_matches if m in BROAD_HOSTS]
    if broad_matches:
        items.append(ReviewItem(
            "observation", "Content scripts run on all websites",
            "Content scripts matching every site run in each page the user visits. Confirm that is intended.",
            broad_matches,
        ))
    if isinstance(scripts, list) and any(isinstance(s, dict) and s.get("world") == "MAIN" for s in scripts):
        items.append(ReviewItem(
            "observation", "Content script in the page's own JavaScript world",
            "A script with \"world\": \"MAIN\" shares its environment with the page's scripts.",
        ))
    if "scripting" in api_perms and not hosts:
        items.append(ReviewItem(
            "observation", "scripting without host_permissions",
            "Script injection needs host access (host_permissions or activeTab) to take effect; "
            "check the extension injects where you expect.",
        ))

    war = manifest.get("web_accessible_resources")
    war_matches: List[str] = []
    for entry in war if isinstance(war, list) else []:
        if isinstance(entry, dict):
            war_matches += _strings(entry.get("matches"))
    if any(m in BROAD_HOSTS for m in war_matches):
        items.append(ReviewItem(
            "observation", "Packaged files exposed to all websites",
            "web_accessible_resources entries matching every site let any page load those files, "
            "which can make the extension detectable.",
            sorted({m for m in war_matches if m in BROAD_HOSTS}),
        ))

    # --- inconsistencies (point at the manifest itself) ---
    if stray_hosts:
        items.append(ReviewItem(
            "inconsistency", "Host patterns listed under permissions",
            "Manifest V3 expects host patterns in host_permissions. Chrome may not treat them as intended.",
            stray_hosts[:MAX_LISTED],
        ))
    both = sorted(set(api_perms) & set(opt_api))
    if both:
        items.append(ReviewItem(
            "inconsistency", "Permissions listed as both required and optional",
            "A permission should be either required or optional, not both.", both[:MAX_LISTED],
        ))
    for key, raw in (("permissions", perms_raw), ("optional_permissions", opt_raw),
                     ("host_permissions", hosts_raw), ("optional_host_permissions", opt_hosts_raw)):
        if raw is not None and (not isinstance(raw, list) or any(not isinstance(v, str) for v in raw)):
            items.append(ReviewItem(
                "inconsistency", f"{key} is not a list of strings",
                "Non-string entries were ignored in this review; Chrome may reject or ignore the field.",
            ))
    bad_hosts = [h for h in hosts + opt_hosts if not _is_host_pattern(h)]
    if bad_hosts:
        items.append(ReviewItem(
            "inconsistency", "Entries in host_permissions that are not host patterns",
            "Expected patterns such as https://example.com/* or <all_urls>.", bad_hosts[:MAX_LISTED],
        ))

    # --- what the manifest declares (used by readiness to judge which checks were meaningful) ---
    icons, action = manifest.get("icons"), manifest.get("action")
    review.declares_icons = bool(icons) or (isinstance(action, dict) and bool(action.get("default_icon")))
    review.declares_locale = manifest.get("default_locale") is not None
    ref_keys = ("background", "content_scripts", "options_page", "options_ui", "devtools_page", "side_panel",
                "chrome_url_overrides", "sandbox", "declarative_net_request", "web_accessible_resources")
    review.declares_references = (
        any(manifest.get(k) for k in ref_keys) or (isinstance(action, dict) and bool(action.get("default_popup")))
        or bool(icons)
    )
    return review
