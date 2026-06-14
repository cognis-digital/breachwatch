"""Edge-case and error-path tests for breachwatch hardening."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from breachwatch.core import (
    Identity,
    load_sources,
    parse_dehashed,
    parse_hibp,
    triage,
)
from breachwatch.cli import main


class TestLoadSourcesValidation(unittest.TestCase):
    """load_sources should raise informative errors for bad configs."""

    def _write_config(self, d: dict, tmp: Path) -> Path:
        p = tmp / "config.json"
        p.write_text(json.dumps(d), encoding="utf-8")
        return p

    def test_missing_config_raises_filenotfounderror(self):
        with self.assertRaises(FileNotFoundError):
            load_sources("/nonexistent/path/config.json")

    def test_malformed_json_config_raises_valueerror(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad.json"
            p.write_text("{not valid json", encoding="utf-8")
            with self.assertRaises(ValueError, msg="expected ValueError for bad JSON"):
                load_sources(p)

    def test_config_not_a_dict_raises_valueerror(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "arr.json"
            p.write_text("[1, 2, 3]", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_sources(p)

    def test_empty_identities_raises_valueerror(self):
        with tempfile.TemporaryDirectory() as td:
            p = self._write_config({"identities": []}, Path(td))
            with self.assertRaises(ValueError):
                load_sources(p)

    def test_identity_with_invalid_email_raises_valueerror(self):
        with tempfile.TemporaryDirectory() as td:
            p = self._write_config(
                {"identities": [{"email": "not-an-email"}]}, Path(td)
            )
            with self.assertRaises(ValueError):
                load_sources(p)

    def test_missing_source_file_raises_filenotfounderror(self):
        with tempfile.TemporaryDirectory() as td:
            p = self._write_config(
                {
                    "identities": [{"email": "a@example.com"}],
                    "hibp_catalog": "nope.json",
                },
                Path(td),
            )
            with self.assertRaises(FileNotFoundError):
                load_sources(p)

    def test_malformed_source_json_raises_valueerror(self):
        with tempfile.TemporaryDirectory() as td:
            bad = Path(td) / "bad_catalog.json"
            bad.write_text("[{bad", encoding="utf-8")
            p = self._write_config(
                {
                    "identities": [{"email": "a@example.com"}],
                    "hibp_catalog": "bad_catalog.json",
                },
                Path(td),
            )
            with self.assertRaises(ValueError):
                load_sources(p)


class TestParseHibpGuards(unittest.TestCase):
    def test_non_list_catalog_raises_typeerror(self):
        with self.assertRaises(TypeError):
            parse_hibp({"Name": "Breach"}, {})  # type: ignore[arg-type]

    def test_empty_catalog_and_accounts_returns_empty(self):
        result = parse_hibp([], {})
        self.assertEqual(result, [])

    def test_non_dict_account_breaches_raises_typeerror(self):
        with self.assertRaises(TypeError):
            parse_hibp([], ["not", "a", "dict"])  # type: ignore[arg-type]

    def test_non_dict_entries_in_catalog_skipped(self):
        # Catalog list may contain garbage entries — they should be silently skipped.
        result = parse_hibp(["not-a-dict", None, 42], {"a@b.com": []})
        self.assertEqual(result, [])


class TestParseDehashedGuards(unittest.TestCase):
    def test_non_dict_dump_raises_typeerror(self):
        ids = [Identity(email="a@b.com")]
        with self.assertRaises(TypeError):
            parse_dehashed([], ids)  # type: ignore[arg-type]

    def test_non_list_entries_raises_typeerror(self):
        ids = [Identity(email="a@b.com")]
        with self.assertRaises(TypeError):
            parse_dehashed({"entries": "not-a-list"}, ids)

    def test_empty_entries_returns_empty(self):
        ids = [Identity(email="a@b.com")]
        result = parse_dehashed({"entries": []}, ids)
        self.assertEqual(result, [])

    def test_non_dict_entry_skipped(self):
        ids = [Identity(email="a@b.com")]
        result = parse_dehashed(
            {"entries": ["garbage", None, {"email": "a@b.com", "database_name": "DB"}]},
            ids,
        )
        self.assertEqual(len(result), 1)


class TestTriageGuards(unittest.TestCase):
    def test_empty_identities_raises_valueerror(self):
        with self.assertRaises(ValueError):
            triage([])

    def test_no_sources_returns_zero_exposures(self):
        ids = [Identity(email="a@b.com")]
        report = triage(ids)
        self.assertEqual(report.summary["total_exposures"], 0)
        self.assertEqual(len(report.actions), 1)  # "no urgent actions" message


class TestCLIErrorPaths(unittest.TestCase):
    """CLI must return non-zero exit codes and print to stderr on bad input."""

    def test_missing_config_exits_1(self):
        import io
        from contextlib import redirect_stderr

        buf = io.StringIO()
        with redirect_stderr(buf):
            rc = main(["triage", "/no/such/config.json"])
        self.assertEqual(rc, 1)
        self.assertIn("error", buf.getvalue().lower())

    def test_malformed_json_config_exits_1(self):
        import io
        from contextlib import redirect_stderr

        with tempfile.TemporaryDirectory() as td:
            bad = Path(td) / "bad.json"
            bad.write_text("{broken json", encoding="utf-8")
            buf = io.StringIO()
            with redirect_stderr(buf):
                rc = main(["triage", str(bad)])
        self.assertEqual(rc, 1)
        self.assertIn("error", buf.getvalue().lower())


if __name__ == "__main__":
    unittest.main()
