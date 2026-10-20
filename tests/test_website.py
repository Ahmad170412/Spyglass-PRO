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

    def test_http_body_retries_a_transient_failure(self):
        """crt.sh and friends 429/5xx transiently; one attempt loses the source."""
        good = mock.Mock(returncode=0, stdout="<html>ok</html>")
        responses = [mock.Mock(returncode=22, stdout=""), good]
        with mock.patch.object(web, "_CURL", "/usr/bin/curl"), \
             mock.patch.object(web, "_sh", side_effect=responses) as sh, \
             mock.patch.object(web, "_urllib_get", return_value=None), \
             mock.patch.object(web.utils.time, "sleep"):
            web._reset_caches()
            self.assertEqual(web._http_body("https://crt.sh/?q=x"), "<html>ok</html>")
            self.assertEqual(sh.call_count, 2)

    def test_http_body_does_not_cache_a_failure(self):
        """An empty result must not be cached — it would poison the whole run."""
        with mock.patch.object(web, "_CURL", "/usr/bin/curl"), \
             mock.patch.object(web, "_sh",
                               return_value=mock.Mock(returncode=7, stdout="")), \
             mock.patch.object(web, "_urllib_get", return_value=None), \
             mock.patch.object(web.utils.time, "sleep"):
            web._reset_caches()
            self.assertEqual(web._http_body("https://crt.sh/?q=x"), "")
            self.assertNotIn(("https://crt.sh/?q=x", 1_000_000), web._BODY_CACHE)

    def test_http_body_gives_up_after_the_last_attempt(self):
        with mock.patch.object(web, "_CURL", "/usr/bin/curl"), \
             mock.patch.object(web, "_sh",
                               return_value=mock.Mock(returncode=7, stdout="")) as sh, \
             mock.patch.object(web, "_urllib_get", return_value=None), \
             mock.patch.object(web.utils.time, "sleep"):
            web._reset_caches()
            self.assertEqual(web._http_body("https://crt.sh/?q=x"), "")
            self.assertEqual(sh.call_count, 3)


class RetryCallTest(unittest.TestCase):
    """``utils.retry_call`` is what keeps a 429 from silently removing a
    passive source from the result."""

    def setUp(self):
        self.sleep = mock.patch.object(imp("utils").time, "sleep")
        self.sleep.start()
        self.addCleanup(self.sleep.stop)

    def test_returns_the_first_truthy_result(self):
        calls = []

        def flaky():
            calls.append(1)
            return "data" if len(calls) == 2 else None

        self.assertEqual(imp("utils").retry_call(flaky), "data")
        self.assertEqual(len(calls), 2)

    def test_a_first_attempt_success_is_not_retried(self):
        calls = []
        self.assertEqual(imp("utils").retry_call(lambda: calls.append(1) or "ok"), "ok")
        self.assertEqual(len(calls), 1)

    def test_exception_is_retried_then_gives_up_as_none(self):
        calls = []

        def boom():
            calls.append(1)
            raise RuntimeError("502 Bad Gateway")

        self.assertIsNone(imp("utils").retry_call(boom, attempts=3))
        self.assertEqual(len(calls), 3)

    def test_backoff_grows_and_is_capped(self):
        slept = []
        with mock.patch.object(imp("utils").time, "sleep", side_effect=slept.append):
            imp("utils").retry_call(lambda: None, attempts=5, base_delay=1.0, max_delay=8.0)
        self.assertEqual(slept, [1.0, 2.0, 4.0, 8.0])


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


class LightCollectTest(unittest.TestCase):
    """1.3 returns owner/WHOIS, basic DNS and CT — nothing heavier."""

    def test_collect_composes_only_light_keys(self):
        with mock.patch.object(web, "_reset_caches"), \
             mock.patch.object(
                 web, "_phase_dns",
                 return_value={"dns_records": {"A": "1.2.3.4"},
                               "wildcard_dns": {"detected": "no",
                                                "resolves_to": ""}}), \
             mock.patch.object(
                 web, "_phase_whois",
                 return_value={"whois": {"Registrar": "Example Registrar"}}), \
             mock.patch.object(
                 web, "_phase_ct",
                 return_value={"ct": ["www.example.com"]}):
            out = web._collect("example.com")
        self.assertEqual(set(out),
                         {"dns_records", "wildcard_dns", "whois", "ct"})
        for heavy in ("shodan", "subdomains", "subdomain_sources",
                      "wayback_subdomains", "history", "reverse_dns",
                      "crt_sh_subdomains"):
            self.assertNotIn(heavy, out)

    def test_ct_phase_renames_crt_names(self):
        with mock.patch.object(web, "_crt_subs",
                               return_value={"example.com", "www.example.com"}):
            out = web._phase_ct("example.com")
        self.assertEqual(out["ct"], ["example.com", "www.example.com"])


if __name__ == "__main__":
    unittest.main()
