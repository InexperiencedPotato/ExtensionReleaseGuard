"""Real-world check against a real extension ZIP.

Skipped (never faked) when the archive is not on disk.  Set REAL_EXTENSION_ZIP
to point at a different copy.  Findings are not asserted: only that the audit
completes without an application failure and returns well-formed results.
"""

import os
import unittest

from src.extension_guard.gui_core import flatten, result_state, run_audit_safe, summarize

ZIP = os.environ.get("REAL_EXTENSION_ZIP", "")


@unittest.skipUnless(ZIP and os.path.isfile(ZIP), f"Real extension ZIP not found: {ZIP}")
class TestRealExtension(unittest.TestCase):
    def test_audit_completes_without_crash(self):
        out = run_audit_safe(ZIP)
        self.assertIsNone(out.crash)
        counts = summarize(out.findings)
        self.assertEqual(len(flatten(out.findings)), sum(counts.values()))
        self.assertIn(result_state(out), ("clean", "findings"))


if __name__ == "__main__":
    unittest.main()
