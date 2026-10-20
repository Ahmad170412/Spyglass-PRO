"""Tests for email.py's tool runners (graceful degradation, no network)."""

import subprocess
import unittest
from unittest import mock

from helpers import imp

em = imp("email")


class RunnerGracefulTest(unittest.TestCase):
    def test_holehe_timeout_returns_empty(self):
        with mock.patch.object(em, "_check_tool", return_value=True), \
             mock.patch.object(em.utils, "_run_text",
                               side_effect=subprocess.TimeoutExpired("holehe", 120)):
            self.assertEqual(em._holehe("x@example.com"), set())

    def test_us_email_timeout_returns_empty(self):
        with mock.patch.object(em, "_check_tool", return_value=True), \
             mock.patch.object(em.utils, "_run_text",
                               side_effect=subprocess.TimeoutExpired("user-scanner", 120)):
            self.assertEqual(em._us_email("x@example.com"), {})

    def test_blackbird_email_timeout_returns_empty(self):
        with mock.patch.object(em, "_check_tool", return_value=True), \
             mock.patch.object(em.utils, "_run_text",
                               side_effect=subprocess.TimeoutExpired("blackbird", 120)):
            self.assertEqual(em._blackbird_email("x@example.com"), {})


class PayloadProvenanceTest(unittest.TestCase):
    def test_each_account_names_the_engines_that_found_it(self):
        """The UI column must be able to say *which* tools, not "2+"."""
        with mock.patch.object(em, "_holehe", return_value={"a.com", "b.com"}), \
             mock.patch.object(em, "_us_email", return_value={
                 "b.com": "https://b.com", "c.com": "https://c.com"}), \
             mock.patch.object(em, "_blackbird_email", return_value={
                 "b.com": "https://b.com", "d.com": "https://d.com"}), \
             mock.patch.object(em, "_breach_check", return_value={}), \
             mock.patch.object(em, "_verify", side_effect=lambda urls, **kw: set(urls)):
            out = em.email("x@example.com")

        by_domain = {}
        for bucket in ("both", "holehe_only", "user_scanner_only", "blackbird_only"):
            for row in out[bucket]:
                by_domain[row["domain"]] = (bucket, row["engines"])

        self.assertEqual(by_domain["a.com"], ("holehe_only", ["holehe"]))
        self.assertEqual(by_domain["b.com"],
                         ("both", ["holehe", "user-scanner", "blackbird"]))
        self.assertEqual(by_domain["c.com"],
                         ("user_scanner_only", ["user-scanner"]))
        self.assertEqual(by_domain["d.com"],
                         ("blackbird_only", ["blackbird"]))


if __name__ == "__main__":
    unittest.main()
