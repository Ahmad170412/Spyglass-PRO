"""Tests for website.py's pure parsers (no network, no external tools)."""

import unittest
from unittest import mock

from helpers import imp

web = imp("website")


class ParseHeadersTest(unittest.TestCase):
    def test_final_block_wins(self):
        raw = (
            "HTTP/1.1 301 Moved Permanently\r\nLocation: https://x.com/\r\n\r\n"
            "HTTP/2 200 \r\nServer: nginx\r\nContent-Type: text/html\r\n"
        )
        headers = web._parse_headers_block(raw)
        self.assertEqual(headers["server"], "nginx")
        self.assertEqual(headers["content-type"], "text/html")
        self.assertNotIn("location", headers)


class SpfTest(unittest.TestCase):
    def test_all_mechanism(self):
        self.assertEqual(web._spf_all("v=spf1 include:_spf.google.com -all"), "strict")
        self.assertEqual(web._spf_all("v=spf1 mx ~all"), "softfail")
        self.assertEqual(web._spf_all("v=spf1 a"), "missing")

    def test_includes(self):
        inc = web._spf_includes("v=spf1 include:spf.protection.outlook.com include:_spf.google.com -all")
        self.assertIn("spf.protection.outlook.com", inc)
        self.assertIn("_spf.google.com", inc)


class CertSpotterTest(unittest.TestCase):
    def test_filters_to_target_domain(self):
        data = [{"dns_names": ["example.com", "www.example.com",
                               "example.edu", "*.cdn.example.com"]}]
        with mock.patch.object(web, "_http_json", return_value=data):
            subs = web._certspotter_subs("example.com")
        self.assertEqual(subs, {"example.com", "www.example.com", "cdn.example.com"})

    def test_non_json_response(self):
        with mock.patch.object(web, "_http_json", return_value=None):
            self.assertEqual(web._certspotter_subs("example.com"), set())

    def test_skips_non_dict_entries(self):
        data = [{"dns_names": ["www.example.com"]}, "garbage",
                {"dns_names": ["cdn.example.com"]}]
        with mock.patch.object(web, "_http_json", return_value=data):
            subs = web._certspotter_subs("example.com")
        self.assertEqual(subs, {"www.example.com", "cdn.example.com"})


class CrtSubsTest(unittest.TestCase):
    def test_multiline_name_value(self):
        data = [{"name_value": "example.com\n*.example.com\nwww.example.com\nother.org"}]
        with mock.patch.object(web, "_http_json", return_value=data):
            subs = web._crt_subs("example.com")
        self.assertEqual(subs, {"example.com", "www.example.com"})

    def test_skips_non_dict_entries(self):
        data = [{"name_value": "www.example.com"}, "garbage"]
        with mock.patch.object(web, "_http_json", return_value=data):
            self.assertEqual(web._crt_subs("example.com"), {"www.example.com"})


class ParseHeadersMultiCookieTest(unittest.TestCase):
    def test_multiple_set_cookie_preserved(self):
        raw = (
            "HTTP/2 200\r\n"
            "Set-Cookie: a=1; Path=/\r\n"
            "Set-Cookie: b=2; HttpOnly\r\n"
            "Content-Type: text/html\r\n"
        )
        headers = web._parse_headers_block(raw)
        self.assertEqual(headers["set-cookie"], "a=1; Path=/\nb=2; HttpOnly")
        self.assertEqual(headers["content-type"], "text/html")


class WaybackCdxTest(unittest.TestCase):
    def test_parses_rows_and_filters_hosts(self):
        data = [
            ["timestamp", "original", "statuscode"],
            ["20200101", "https://example.com/", "200"],
            ["20210101", "https://www.example.com/x", "200"],
            ["20220101", "https://other.com/", "200"],
        ]
        with mock.patch.object(web, "_http_json", return_value=data):
            out = web._wayback_cdx("example.com")
        self.assertEqual(out["first"], "20200101")
        self.assertEqual(out["last"], "20220101")
        self.assertEqual(out["count"], 3)
        self.assertIn("example.com", out["subs"])
        self.assertIn("www.example.com", out["subs"])
        self.assertNotIn("other.com", out["subs"])


class MemoizationTest(unittest.TestCase):
    def test_dig_short_cached_per_run(self):
        out = mock.Mock(returncode=0, stdout="1.2.3.4\n")
        with mock.patch.object(web, "_DIG", "/usr/bin/dig"), \
             mock.patch.object(web, "_sh", return_value=out) as sh:
            web._reset_caches()
            self.assertEqual(web._dig_short("x.com", "A"), "1.2.3.4")
            self.assertEqual(web._dig_short("x.com", "A"), "1.2.3.4")
            self.assertEqual(sh.call_count, 1)

    def test_dig_short_different_args_not_cached(self):
        with mock.patch.object(web, "_DIG", "/usr/bin/dig"), \
             mock.patch.object(web, "_sh",
                               return_value=mock.Mock(returncode=0, stdout="x\n")) as sh:
            web._reset_caches()
            web._dig_short("x.com", "A")
            web._dig_short("x.com", "AAAA")
            self.assertEqual(sh.call_count, 2)

    def test_http_body_cached_per_run(self):
        out = mock.Mock(returncode=0, stdout="<html>hi</html>")
        with mock.patch.object(web, "_CURL", "/usr/bin/curl"), \
             mock.patch.object(web, "_sh", return_value=out) as sh:
            web._reset_caches()
            self.assertEqual(web._http_body("https://x.com"), "<html>hi</html>")
            self.assertEqual(web._http_body("https://x.com"), "<html>hi</html>")
            self.assertEqual(sh.call_count, 1)


class PhaseWhoisTest(unittest.TestCase):
    def test_registered_follows_referral(self):
        thin = "refer: whois.verisign-grs.com\ndomain: COM\n"
        full = "Domain Name: GITHUB.COM\nRegistrar: MarkMonitor Inc.\n"
        with mock.patch.object(web, "_check_tool", return_value=True), \
             mock.patch.object(web, "_run", side_effect=[thin, full]):
            out = web._phase_whois("github.com")
        self.assertEqual(out["whois"]["Domain"], "GITHUB.COM")
        self.assertEqual(out["whois"]["Registrar"], "MarkMonitor Inc.")

    def test_unregistered_not_tld_data(self):
        thin = ("refer: whois.verisign-grs.com\n"
                "domain: COM\norganisation: VeriSign Global Registry Services\n")
        full = 'No match for domain "X.COM".\n'
        with mock.patch.object(web, "_check_tool", return_value=True), \
             mock.patch.object(web, "_run", side_effect=[thin, full]) as run:
            out = web._phase_whois("x.com")
        self.assertEqual(run.call_count, 2)
        self.assertEqual(out["whois"]["Status"], "unregistered (no registry record)")
        self.assertNotIn("Organization", out["whois"])
        self.assertNotIn("Domain", out["whois"])


class PhaseDnsTest(unittest.TestCase):
    def test_collects_ips_and_records(self):
        def fake_dig(*args, **kwargs):
            return {"A": "1.2.3.4", "AAAA": "", "MX": "10 mail.x.com."}.get(args[1], "")
        with mock.patch.object(web, "_DIG", "/usr/bin/dig"), \
             mock.patch.object(web, "_dig_short", side_effect=fake_dig), \
             mock.patch.object(web, "_dns_email_security", return_value=None), \
             mock.patch.object(web, "_is_wildcard", return_value=(False, "")):
            out = web._phase_dns("x.com")
        self.assertEqual(out["dns_records"]["A"], "1.2.3.4")
        self.assertEqual(out["_ips"], {"1.2.3.4"})


if __name__ == "__main__":
    unittest.main()
