"""Unit tests for FindingWriter with structured input."""

import os
import tempfile
import unittest

from findings import FindingWriter, _canonical_endpoint, slugify
from tools import FindingFiled


def _make(title, endpoint="GET /x", severity="high"):
    return FindingFiled(
        title=title,
        severity=severity,
        endpoint=endpoint,
        description="d", reproduction_steps="rs",
        evidence="e", impact="i", verification_notes="v",
    )


class TestSlugify(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(slugify("Reflected XSS in /search"), "reflected-xss-in-search")
        self.assertEqual(slugify("  Spaces  &  Symbols  !"), "spaces-symbols")
        self.assertEqual(slugify(""), "")


class TestCanonicalEndpoint(unittest.TestCase):
    def test_strip_method_and_normalize(self):
        self.assertEqual(_canonical_endpoint("GET /Search/"), "/search")
        self.assertEqual(_canonical_endpoint("POST /api/users?id=1"), "/api/users")
        self.assertEqual(_canonical_endpoint("/api/Users"), "/api/users")
        self.assertEqual(_canonical_endpoint(""), "")


class TestFindingWriter(unittest.TestCase):
    def test_write_structured_produces_markdown(self):
        with tempfile.TemporaryDirectory() as td:
            w = FindingWriter(td)
            path = w.write(_make("Reflected XSS in search"))
            self.assertEqual(os.path.basename(path), "finding-01-reflected-xss-in-search.md")
            body = open(path).read()
            self.assertIn("# Reflected XSS in search", body)
            self.assertIn("**Severity**: high", body)
            self.assertIn("## Verification", body)

    def test_sequence_numbering(self):
        with tempfile.TemporaryDirectory() as td:
            w = FindingWriter(td)
            w.write(_make("A"))
            p2 = w.write(_make("B"))
            self.assertTrue(os.path.basename(p2).startswith("finding-02-"))

    def test_is_duplicate_by_slug(self):
        with tempfile.TemporaryDirectory() as td:
            w = FindingWriter(td)
            w.write(_make("Reflected XSS in /search"))
            self.assertTrue(
                w.is_duplicate(_make("reflected xss in /search", endpoint="POST /other"))
            )

    def test_is_duplicate_by_canonical_endpoint_with_similar_title(self):
        with tempfile.TemporaryDirectory() as td:
            w = FindingWriter(td)
            w.write(_make("Reflected XSS in search", endpoint="GET /search"))
            self.assertTrue(
                w.is_duplicate(_make("Reflected XSS in search results", endpoint="get /search/"))
            )

    def test_is_not_duplicate_for_different_finding(self):
        with tempfile.TemporaryDirectory() as td:
            w = FindingWriter(td)
            w.write(_make("Reflected XSS", endpoint="GET /search"))
            self.assertFalse(
                w.is_duplicate(_make("SQL injection in login", endpoint="POST /login"))
            )

    def test_summary_for_orchestrator(self):
        with tempfile.TemporaryDirectory() as td:
            w = FindingWriter(td)
            self.assertEqual(w.summary_for_orchestrator(), "No findings filed yet.")
            w.write(_make("XSS in X", endpoint="GET /x", severity="high"))
            w.write(_make("SQLi in Y", endpoint="POST /y", severity="critical"))
            out = w.summary_for_orchestrator()
            self.assertIn("1. [high] XSS in X — /x", out)
            self.assertIn("2. [critical] SQLi in Y — /y", out)


if __name__ == "__main__":
    unittest.main()
