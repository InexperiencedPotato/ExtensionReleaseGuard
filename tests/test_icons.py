"""Unit tests for :mod:`extension_guard.icon_validator`.

The tests exercise a number of scenarios covering PNG, JPEG, GIF, BMP,
ICO, SVG, oversized icons and mismatched extensions.  They construct a
temporary ZIP archive for each test, mimicking a real Chrome
extension package.
"""

import os
import tempfile
import zipfile
import json
import unittest
from pathlib import Path

from src.extension_guard.icon_validator import validate_icons, MAX_INSPECTION_SIZE


# Helper to create a minimal icon binary for each type.
def _minimal_png(square: bool = True) -> bytes:
    # 1x1 PNG (or 1x2 if non-square)
    width = 1
    height = 1 if square else 2
    return (
        b"\x89PNG\r\n\x1a\n"  # PNG header
        b"\x00\x00\x00\x0d" + b"IHDR" +
        width.to_bytes(4, "big") + height.to_bytes(4, "big") +
        b"\x08\x02\x00\x00\x00" +  # 5 bytes of IHDR data
        b"\x00\x00\x00\x00"  # CRC placeholder
    )


def _minimal_jpeg() -> bytes:
    return (
        b"\xff\xd8"  # SOI
        b"\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00"  # minimal segment
        b"\xff\xd9"  # EOI
    )


def _minimal_gif() -> bytes:
    return b"GIF89a" + b"\x00\x00\x00\x00\x00\x00"


def _minimal_bmp() -> bytes:
    return b"BM" + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"


def _minimal_ico() -> bytes:
    return b"\x00\x00\x01\x00"


def _make_zip(entries: dict) -> str:
    """Create a temporary ZIP with *entries* mapping path -> bytes."""
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    with zipfile.ZipFile(tmp.name, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, content in entries.items():
            zf.writestr(path, content)
    return tmp.name


class TestIconValidator(unittest.TestCase):
    def _validate(self, entries):
        zip_path = _make_zip(entries)
        try:
            return validate_icons(zip_path)
        finally:
            os.unlink(zip_path)

    def test_valid_png(self):
        entries = {
            "manifest.json": json.dumps({
                "manifest_version": 3,
                "name": "Test",
                "version": "1.0",
                "icons": {"48": "icon.png"},
            }).encode("utf-8"),
            "icon.png": _minimal_png(),
        }
        res = self._validate(entries)
        self.assertFalse(res["errors"])
        self.assertFalse(res["warnings"])

    def test_invalid_png_missing_ihdr(self):
        # PNG header but missing IHDR chunk – provide enough bytes to
        # trigger the specific IHDR check.
        bad_png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
        entries = {
            "manifest.json": json.dumps({"icons": {"48": "bad.png"}}).encode("utf-8"),
            "bad.png": bad_png,
        }
        res = self._validate(entries)
        self.assertTrue(any("PNG icon missing IHDR" in e for e in res["errors"]))

    def test_valid_jpeg(self):
        entries = {
            "manifest.json": json.dumps({"icons": {"48": "icon.jpg"}}).encode("utf-8"),
            "icon.jpg": _minimal_jpeg(),
        }
        res = self._validate(entries)
        self.assertFalse(res["errors"])
        self.assertFalse(res["warnings"])

    def test_valid_gif(self):
        entries = {
            "manifest.json": json.dumps({"icons": {"48": "icon.gif"}}).encode("utf-8"),
            "icon.gif": _minimal_gif(),
        }
        res = self._validate(entries)
        self.assertFalse(res["errors"])
        self.assertFalse(res["warnings"])

    def test_valid_bmp(self):
        entries = {
            "manifest.json": json.dumps({"icons": {"48": "icon.bmp"}}).encode("utf-8"),
            "icon.bmp": _minimal_bmp(),
        }
        res = self._validate(entries)
        self.assertFalse(res["errors"])
        self.assertFalse(res["warnings"])

    def test_valid_ico(self):
        entries = {
            "manifest.json": json.dumps({"icons": {"48": "icon.ico"}}).encode("utf-8"),
            "icon.ico": _minimal_ico(),
        }
        res = self._validate(entries)
        self.assertFalse(res["errors"])
        self.assertFalse(res["warnings"])

    def test_svg_icon_error(self):
        entries = {
            "manifest.json": json.dumps({"icons": {"48": "icon.svg"}}).encode("utf-8"),
            "icon.svg": _minimal_png(),  # just any data
        }
        res = self._validate(entries)
        self.assertTrue(any("SVG icons are not supported" in e for e in res["errors"]))

    def test_extension_mismatch(self):
        entries = {
            "manifest.json": json.dumps({"icons": {"48": "icon.png"}}).encode("utf-8"),
            "icon.png": _minimal_jpeg(),  # JPEG data in .png file
        }
        res = self._validate(entries)
        self.assertTrue(any("PNG icon missing PNG signature" in e for e in res["errors"]))

    def test_oversized_icon(self):
        large = b"x" * (MAX_INSPECTION_SIZE + 1)
        entries = {
            "manifest.json": json.dumps({"icons": {"48": "big.png"}}).encode("utf-8"),
            "big.png": large,
        }
        res = self._validate(entries)
        self.assertTrue(any("exceeds" in w for w in res["warnings"]))
        self.assertFalse(res["errors"])

    def test_non_square_png_warning(self):
        entries = {
            "manifest.json": json.dumps({"icons": {"48": "icon.png"}}).encode("utf-8"),
            "icon.png": _minimal_png(square=False),
        }
        res = self._validate(entries)
        self.assertTrue(any("non‑square" in w for w in res["warnings"]))
        self.assertFalse(res["errors"])

    def test_multiple_icon_entries(self):
        entries = {
            "manifest.json": json.dumps(
                {
                    "icons": {"48": "icon1.png", "128": "icon2.jpg"},
                    "action": {"default_icon": {"48": "action_icon.ico", "128": "action_icon.png"}},
                }
            ).encode("utf-8"),
            "icon1.png": _minimal_png(),
            "icon2.jpg": _minimal_jpeg(),
            "action_icon.ico": _minimal_ico(),
            "action_icon.png": _minimal_png(),
        }
        res = self._validate(entries)
        self.assertFalse(res["errors"])
        self.assertFalse(res["warnings"])

    def test_no_icons(self):
        entries = {
            "manifest.json": json.dumps({"manifest_version": 3, "name": "Test", "version": "1.0"}).encode("utf-8"),
        }
        res = self._validate(entries)
        self.assertFalse(res["errors"])
        self.assertFalse(res["warnings"])
