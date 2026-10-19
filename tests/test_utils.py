"""Tests for utils.py: domain parsing, entity extraction, safe filenames."""

import sys
import unittest

from helpers import imp

utils = imp("utils")


class DomainTest(unittest.TestCase):
    def test_www_stripped(self):
        self.assertEqual(utils._domain("https://www.example.com/x"), "example.com")

    def test_bare_domain(self):
        self.assertEqual(utils._domain("example.com"), "example.com")

    def test_port_and_query(self):
        self.assertEqual(
            utils._domain("http://sub.example.com:8080/path?q=1"),
            "sub.example.com",
        )


class ExtractIpsTest(unittest.TestCase):
    def test_ips_extracted_deduplicated(self):
        self.assertEqual(
            utils._extract_ips("host 1.2.3.4 and 5.6.7.8 and 1.2.3.4"),
            ["1.2.3.4", "5.6.7.8"],
        )


class ExtractEmailsTest(unittest.TestCase):
    def test_emails_extracted(self):
        self.assertEqual(
            utils._extract_emails("mail a@b.com then c.d@e.co.uk now"),
            ["a@b.com", "c.d@e.co.uk"],
        )


class ExtractPhonesTest(unittest.TestCase):
    def test_phones_extracted(self):
        out = utils._extract_phones("call +1 (555) 123-4567 or 202-555-0199 or 2025550199")
        self.assertIn("+1 (555) 123-4567", out)
        self.assertIn("202-555-0199", out)
        self.assertIn("2025550199", out)

    def test_dates_and_ips_rejected(self):
        self.assertEqual(utils._extract_phones("2024-01-01 at 1.2.3.4"), [])

    def test_registry_ids_not_phones(self):
        text = (
            "Registry Domain ID: 1264983250_DOMAIN_COM-VRSN\n"
            "Registrar IANA ID: 292\n"
            "Registrar Abuse Contact Phone: +1.2086851750\n"
        )
        out = utils._extract_phones(text)
        self.assertEqual(out, ["+1.2086851750"])


class ExtractWhoisFieldsTest(unittest.TestCase):
    def test_fields_parsed(self):
        text = (
            "Registrant Name: John Doe\n"
            "Registrant Email: j@x.com\n"
            "Organization: Acme\n"
            "ignored: line\n"
        )
        out = utils._extract_whois_fields(text)
        self.assertEqual(out["Registrant Name"], "John Doe")
        self.assertEqual(out["Registrant Email"], "j@x.com")
        self.assertEqual(out["Organization"], "Acme")

    def test_iana_thin_format(self):
        text = (
            "domain:       EXAMPLE.COM\n"
            "organisation: Internet Assigned Numbers Authority\n"
            "created:      1992-01-01\n"
            "source:       IANA\n"
        )
        out = utils._extract_whois_fields(text)
        self.assertEqual(out["Domain"], "EXAMPLE.COM")
        self.assertEqual(out["Organization"], "Internet Assigned Numbers Authority")
        self.assertEqual(out["Creation Date"], "1992-01-01")
        self.assertEqual(out["Source"], "IANA")

    def test_verisign_full_format(self):
        text = (
            "   Domain Name: GITHUB.COM\n"
            "   Registrar: MarkMonitor Inc.\n"
            "   Creation Date: 2007-10-09T18:20:50Z\n"
            "   Registry Expiry Date: 2026-10-09T18:20:50Z\n"
            "   DNSSEC: unsigned\n"
            "   Name Server: DNS1.P08.NSONE.NET\n"
            "   Name Server: DNS2.P08.NSONE.NET\n"
        )
        out = utils._extract_whois_fields(text)
        self.assertEqual(out["Domain"], "GITHUB.COM")
        self.assertEqual(out["Registrar"], "MarkMonitor Inc.")
        self.assertEqual(out["Creation Date"], "2007-10-09T18:20:50Z")
        self.assertEqual(out["DNSSEC"], "unsigned")
        self.assertIn("DNS1.P08.NSONE.NET", out["Name Server"])
        self.assertIn("DNS2.P08.NSONE.NET", out["Name Server"])

    def test_repeatable_keys_joined(self):
        text = (
            "Domain Status: clientDeleteProhibited x\n"
            "Domain Status: clientTransferProhibited y\n"
        )
        out = utils._extract_whois_fields(text)
        self.assertIn("clientDeleteProhibited", out["Domain Status"])
        self.assertIn("clientTransferProhibited", out["Domain Status"])


class PickTest(unittest.TestCase):
    def test_first_dict_wins(self):
        pick = utils._pick({"a": 1}, {"a": 2, "b": 3})
        self.assertEqual(pick("a"), 1)
        self.assertEqual(pick("b"), 3)
        self.assertEqual(pick("z"), "z")


class SafeNameTest(unittest.TestCase):
    def test_sanitizes_hostile_characters(self):
        self.assertEqual(utils.safe_name("user@example.com/x:80"), "user_example.com_x_80")
        self.assertEqual(utils.safe_name("a b\tc"), "a_b_c")

    def test_empty_falls_back(self):
        self.assertEqual(utils.safe_name(""), "target")
        self.assertEqual(utils.safe_name("///"), "target")

    def test_windows_reserved_device_names_are_prefixed(self):
        """CON, NUL, COM1.. are reserved on Windows in any case and with any
        extension. open() fails there while succeeding on macOS/Linux, so the
        failure only shows up on the platform nobody tests on."""
        for name in ("con", "PRN", "aux", "NUL", "COM1", "com9", "LPT1", "lpt9"):
            got = utils.safe_name(name)
            self.assertTrue(got.startswith("_"), f"{name!r} -> {got!r} is still reserved")
        # With an extension too -- the reservation covers "nul.json".
        self.assertTrue(utils.safe_name("nul.json").startswith("_"))

    def test_names_that_merely_contain_a_reserved_word_are_kept(self):
        """Only an exact stem is reserved. Prefixing these would needlessly
        mangle legitimate usernames."""
        for name in ("congress", "console", "auxiliary", "comcast", "com-1", "null"):
            self.assertEqual(utils.safe_name(name), name)

    def test_case_folded_so_case_insensitive_volumes_do_not_collide(self):
        """macOS and Windows are case-insensitive by default, Linux is not.
        Without folding, EXAMPLE.COM and example.com are two files on Linux and
        one elsewhere -- so an export can overwrite its neighbour."""
        self.assertEqual(
            utils.safe_name("EXAMPLE.COM"), utils.safe_name("example.com")
        )


class ToolOutputDecodingTest(unittest.TestCase):
    """Tool output must decode as UTF-8, not the platform locale.

    text=True without an encoding decodes with the OS preferred codec: UTF-8 on
    Linux/macOS but cp1252 on a default Windows install. Verified failure mode --
    a tool emitting "café ✓" decodes as 'cafÃ© âœ"' under cp1252, and bytes cp1252
    cannot represent raise UnicodeDecodeError, turning a working scan into an
    empty one.
    """

    def test_run_text_pins_utf8_with_replacement(self):
        r = utils._run_text(
            [sys.executable, "-c",
             "import sys; sys.stdout.buffer.write('caf\\u00e9 \\u2713'.encode('utf-8'))"]
        )
        self.assertEqual(r.stdout, "café ✓")

    def test_invalid_bytes_do_not_raise(self):
        """errors='replace' keeps an undecodable byte from escalating into a
        failed lookup. For recon, a mangled character beats no result."""
        r = utils._run_text(
            [sys.executable, "-c",
             "import sys; sys.stdout.buffer.write(b'ok\\xff\\xfebad')"]
        )
        self.assertTrue(r.stdout.startswith("ok"))
        self.assertIn("bad", r.stdout)

    def test_unicode_round_trips_through_the_run_helper(self):
        out = utils._run(
            [sys.executable, "-c",
             "import sys; sys.stdout.buffer.write('\\u00e9\\u00e8'.encode('utf-8'))"]
        )
        self.assertEqual(out, "éè")


if __name__ == "__main__":
    unittest.main()
