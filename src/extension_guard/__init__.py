"""Extension Release Guard package.

This package contains the core audit logic for inspecting a Chrome
extension ZIP archive without extracting it.  The public API is
intentionally small so that future phases (manifest validation, GUI,
reporting, etc.) can depend on a stable foundation.
"""

__all__ = [
    "zip_inspector",
    "manifest_validator",
    "locale_validator",
    "reference_validator",
    "icon_validator",
    "audit",
]
