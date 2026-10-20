"""Tests for report.py: Markdown dossier rendering and writing."""

import os
import tempfile
import unittest
from unittest import mock

from helpers import imp

report = imp("report")


class RenderEmailTest(unittest.TestCase):
    def test_email_dossier(self):
        r = {
            "both": [{"domain": "example.com", "url": "https://example.com"}],
            "holehe_only": [{"domain": "foo.net"}],
            "user_scanner_only": [],
            "blackbird_only": [],
            "breach": {
                "found": 2,
                "sources": [{"name": "LeakDB", "date": "2021"}, {"name": "Other"}],
                "fields": ["email", "name"],
            },
        }
        md = report.render(r, "email", "user@example.com")
        self.assertIn("# Spyglass Report — email", md)
        self.assertIn("**Target:** `user@example.com`", md)
        self.assertIn("example.com", md)
        self.assertIn("foo.net", md)
        self.assertIn("**Breach found:** 2", md)
        self.assertIn("LeakDB (2021)", md)
        self.assertIn("**Exposed fields:** email, name", md)


class RenderIpTest(unittest.TestCase):
    def test_ip_dossier(self):
        r = {
            "ip": "1.2.3.4",
            "geo": {"country": "US", "city": "Testville", "isp": "Test ISP"},
            "shodan": {"ports": [22, 443], "hostnames": ["x.example.com"]},
        }
        md = report.render(r, "ip", "1.2.3.4")
        self.assertIn("### Geolocation", md)
        self.assertIn("**Country:** US", md)
        # Port data is Shodan's now; the nmap section is gone with the scan.
        self.assertIn("### Shodan", md)
        self.assertIn("22", md)
        self.assertNotIn("Open ports (nmap)", md)


class RenderErrorTest(unittest.TestCase):
    def test_error_result_rendered_as_quote(self):
        md = report.render({"error": "Could not resolve: nope.invalid"}, "ip", "nope.invalid")
        self.assertIn("Could not resolve: nope.invalid", md)


class RenderInvestigationTest(unittest.TestCase):
    def test_correlations_and_entities(self):
        r = {
            "inputs": {"email": "a@x.com"},
            "entities": {"domains": ["x.com"], "ips": ["1.2.3.4"]},
            "correlations": [
                {"type": "match", "desc": "Email domain matches website target", "detail": "x.com"}
            ],
            "results": {},
        }
        md = report.render(r, "investigation", "a@x.com")
        self.assertIn("### Known inputs", md)
        self.assertIn("### Entities found", md)
        self.assertIn("**Domains:** x.com", md)
        self.assertIn("### Correlations", md)
        self.assertIn("MATCH", md)

    def test_person_section_precedes_the_module_dossier(self):
        r = {
            "person": {
                "schema": "spyglass.person/1",
                "confidence": "high",
                "counts": {"anchors": 2, "accounts": 1, "confirmed_links": 1,
                           "possible_links": 1, "conflicts": 1, "breaches": 1},
                "names": [{"value": "Analyst", "source": "instagram", "confidence": "high"}],
                "emails": [{"value": "a@x.com", "source": "input", "confidence": "high"}],
                "accounts": [{"platform": "github.com", "url": "https://github.com/a",
                              "via": ["email", "username"],
                              "tools": ["holehe", "user-scanner"], "confidence": "high"}],
                "breaches": [{"name": "LeakDB", "date": "2021", "via": ["email"]}],
                "exposed_fields": ["email"],
                "links": [
                    {"kind": "whois-email", "desc": "Known email found in website WHOIS",
                     "detail": "a@x.com", "confidence": "high"},
                    {"kind": "handle-reuse", "desc": "Same handle, not proof",
                     "confidence": "possible"},
                ],
                "conflicts": [{"kind": "location", "desc": "Berlin differs from Russia"}],
                "context": {"website": "x.com", "emails": ["legal@x.com"]},
                "notes": ["WHOIS values describe the domain."],
            },
            "inputs": {"email": "a@x.com"},
            "entities": {"domains": ["x.com"]},
            "correlations": [],
            "results": {},
        }
        md = report.render(r, "investigation", "a@x.com")
        self.assertIn("## Person", md)
        self.assertIn("### Identity", md)
        self.assertIn("| Platform | URL | Linked by | Tools | Evidence |", md)
        self.assertIn("github.com", md)
        self.assertIn("holehe", md)
        self.assertIn("**POSSIBLE:**", md)
        self.assertIn("### Conflicts", md)
        self.assertIn("### Domain context", md)
        self.assertIn("not necessarily the person", md)
        self.assertLess(md.index("## Person"), md.index("### Known inputs"))


class RenderOpsecTest(unittest.TestCase):
    def test_recommendations_rendered(self):
        r = {
            "proxy_configured": True,
            "dns_leak": "unverified",
            "recommendations": ["DNS may leak — install torsocks to route DNS through Tor"],
        }
        md = report.render(r, "opsec", "")
        self.assertIn("### Recommendations", md)
        self.assertIn("DNS may leak", md)


class WriteReportTest(unittest.TestCase):
    def test_write_report_creates_sanitized_file(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(report._ui, "info"):
            path = report.write_report({"a": 1}, "ip", "1.2.3.4:80", tmp)
            self.assertTrue(os.path.isfile(path))
            self.assertTrue(os.path.basename(path).startswith("spyglass_report_ip_1.2.3.4_80_"))
            with open(path, encoding="utf-8") as f:
                self.assertIn("# Spyglass Report — ip", f.read())

    def test_render_reports_version(self):
        pkg = imp("")
        self.assertIn(f"- **Spyglass version:** {pkg.__version__}", report.render({}, "ip", "x"))


if __name__ == "__main__":
    unittest.main()
