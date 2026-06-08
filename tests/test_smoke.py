"""Smoke tests for BREACHWATCH. No network."""
import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from breachwatch import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    Identity,
    parse_stealer_log,
    redact,
    severity_for,
    triage,
)
from breachwatch.cli import main  # noqa: E402
from breachwatch.core import load_sources  # noqa: E402

DEMO = Path(__file__).resolve().parents[1] / "demos" / "01-basic"


class TestCore(unittest.TestCase):
    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "breachwatch")
        self.assertTrue(TOOL_VERSION)

    def test_redact_hides_value(self):
        r = redact("hunter2")
        self.assertNotIn("unter", r)
        self.assertIn("len=7", r)
        self.assertEqual(redact(""), "")

    def test_severity_thresholds(self):
        self.assertEqual(severity_for(0), "info")
        self.assertEqual(severity_for(100), "critical")
        self.assertEqual(severity_for(40), "medium")

    def test_stealer_log_parses_owned_only(self):
        ids = [Identity(email="chris@example.com", usernames=["archon"])]
        lines = [
            "https://mail.x/login:chris@example.com:Secret123!",
            "https://shop.x:archon:battery:horse",  # password contains ':'
            "user@unrelated.com:nope",              # not owned
            "# comment",
            "garbage",
        ]
        exps = parse_stealer_log(lines, ids)
        self.assertEqual(len(exps), 2)
        self.assertTrue(all(e.has_plaintext_password for e in exps))
        self.assertTrue(all(e.severity in ("high", "critical") for e in exps))
        self.assertIn("battery:horse", "".join(""))  # sanity placeholder

    def test_triage_dedupes_and_scores(self):
        ids, sources = load_sources(DEMO / "config.json")
        report = triage(ids, **sources)
        self.assertGreater(report.summary["total_exposures"], 0)
        self.assertGreaterEqual(report.summary["plaintext_passwords"], 1)
        # someone.else@example.org is not an owned identity -> excluded.
        self.assertNotIn(
            "someone.else@example.org",
            {e.identity for e in report.exposures},
        )
        # Highest-scoring exposure should be a plaintext stealer-log hit.
        top = report.exposures[0]
        self.assertEqual(top.severity, "critical")
        self.assertTrue(top.has_plaintext_password)
        # Report serializes to JSON cleanly.
        json.dumps(report.to_dict())


class TestCLI(unittest.TestCase):
    def test_json_output(self):
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["triage", str(DEMO / "config.json"), "--format", "json"])
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        self.assertIn("exposures", data)
        self.assertIn("summary", data)

    def test_fail_on_returns_nonzero(self):
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["triage", str(DEMO / "config.json"), "--fail-on", "high"])
        self.assertEqual(rc, 2)

    def test_missing_config_fails_cleanly(self):
        import io
        from contextlib import redirect_stderr

        buf = io.StringIO()
        with redirect_stderr(buf):
            rc = main(["triage", "does-not-exist.json"])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
