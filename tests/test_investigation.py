"""Tests for investigation.py: entity collection, correlation, input parsing.

The heavy module functions (email, username, website, ...) shell out to
external tools, so only the pure logic is tested here with crafted results.
"""

import unittest
from unittest import mock

from helpers import imp

inv = imp("investigation")


def _entities():
    return {
        "emails": set(), "domains": set(), "ips": set(),
        "orgs": set(), "asns": set(), "phones": set(),
    }


class CollectEntitiesTest(unittest.TestCase):
    def test_website_whois_entities(self):
        results = {
            "website": {
                "dns_records": {"A": "1.2.3.4, 5.6.7.8"},
                "whois": {
                    "Organization": "Acme Inc",
                    "Registrant Email": "a@acme.com, b@acme.com",
                    "Phone": "+1 555 0100",
                },
            },
            "email": {},
        }
        entities = _entities()
        inv._collect_entities(results, entities)
        self.assertIn("1.2.3.4", entities["ips"])
        self.assertIn("5.6.7.8", entities["ips"])
        self.assertIn("Acme Inc", entities["orgs"])
        self.assertIn("a@acme.com", entities["emails"])
        self.assertIn("b@acme.com", entities["emails"])
        self.assertIn("acme.com", entities["domains"])
        self.assertIn("+1 555 0100", entities["phones"])

    def test_phone_region_collected(self):
        results = {"phone": {"phonenumbers": {"region": "Singapore"}}}
        entities = _entities()
        inv._collect_entities(results, entities)
        self.assertEqual(entities["regions"], {"Singapore"})


class CorrelateTest(unittest.TestCase):
    def test_email_domain_matches_website(self):
        inputs = {"email": "a@x.com", "website": "x.com"}
        corr = inv._correlate(inputs, {"email": {}, "website": {}}, {"domains": {"x.com"}})
        self.assertTrue(
            any(c["type"] == "match" and "matches website" in c["desc"] for c in corr)
        )

    def test_phone_region_matches_whois_country(self):
        # phonenumbers reports the ISO region code ("SG"), matching WHOIS country.
        inputs = {"phone": "+65 8526 0980"}
        results = {
            "phone": {"phonenumbers": {"region": "SG"}},
            "website": {"whois": {"Country": "SG"}},
        }
        corr = inv._correlate(inputs, results, _entities())
        self.assertTrue(
            any(c["type"] == "match" and "Phone region matches" in c["desc"] for c in corr)
        )

    def test_username_total_counted(self):
        inputs = {"username": "jdoe"}
        results = {"username": {"all_4": [{"domain": "a.com"}, {"domain": "b.com"}]}}
        corr = inv._correlate(inputs, results, _entities())
        self.assertTrue(any("Username found on 2 platforms" in c["desc"] for c in corr))


class CountryMatchTest(unittest.TestCase):
    """``_country_matches`` compares an ISO alpha-2 phone region against a
    free-text WHOIS country. It used to do that with substring containment,
    which matched unrelated countries; these pin the exact behaviour.
    """

    def test_codes_and_canonical_names_match(self):
        for code, country in (("GB", "United Kingdom"), ("US", "United States"),
                              ("DE", "Germany"), ("CA", "Canada"), ("SG", "Singapore"),
                              ("RU", "russia"), ("FR", "fr")):
            self.assertTrue(inv._country_matches(code, country), f"{code}/{country}")

    def test_registry_spellings_match(self):
        for code, country in (("KR", "Korea, Republic of"), ("CI", "Cote d'Ivoire"),
                              ("US", "USA"), ("GB", "Great Britain"), ("BO", "Bolivia")):
            self.assertTrue(inv._country_matches(code, country), f"{code}/{country}")

    def test_unrelated_countries_do_not_match(self):
        # Every one of these was a false positive under substring matching:
        # "us" in "russia", "ch" in "china", "in" in "indonesia", "uk" in
        # "ukraine", "us" in "austria", "de" in "denmark".
        for code, country in (("US", "russia"), ("CH", "china"), ("IN", "indonesia"),
                              ("GB", "Ukraine"), ("US", "Austria"), ("DE", "Denmark"),
                              ("GB", "US"), ("IN", "Iran")):
            self.assertFalse(inv._country_matches(code, country), f"{code}/{country}")

    def test_missing_or_malformed_input_is_not_a_match(self):
        for code, country in (("", "US"), ("USA", "US"), ("GB", ""), (None, None),
                              ("1", "US"), ("GB", "1")):
            self.assertFalse(inv._country_matches(code, country), f"{code!r}/{country!r}")

    def test_no_match_surfaces_as_a_correlation(self):
        """A US number against a Russian domain must not be reported as a match."""
        results = {"phone": {"phonenumbers": {"region": "US"}},
                   "website": {"whois": {"Country": "Russia"}}}
        corr = inv._correlate({"phone": "+1 202 555 0143"}, results, _entities())
        self.assertFalse(any("Phone region matches" in c["desc"] for c in corr))

    def test_real_match_still_surfaces(self):
        results = {"phone": {"phonenumbers": {"region": "GB"}},
                   "website": {"whois": {"Country": "United Kingdom"}}}
        corr = inv._correlate({"phone": "+44 7700 900123"}, results, _entities())
        self.assertTrue(any(c["type"] == "match" and "Phone region matches" in c["desc"]
                            for c in corr))


class InvestigateTest(unittest.TestCase):
    def test_runs_modules_and_collects_entities(self):
        email_mod = imp("email")
        username_mod = imp("username")
        phone_mod = imp("phone")
        website_mod = imp("website")
        with mock.patch.object(inv, "_quick_resolve", return_value=None), \
             mock.patch.object(email_mod, "email",
                               return_value={"both": [], "holehe_only": [],
                                             "user_scanner_only": [], "blackbird_only": [],
                                             "breach": {"found": 0}}) as em, \
             mock.patch.object(username_mod, "username",
                               return_value={"all_4": [{"domain": "gh.com"}],
                                             "breach": {"found": 0}}) as um, \
             mock.patch.object(phone_mod, "phone",
                               return_value={"phonenumbers": {"error": "no tools"}}) as pm, \
             mock.patch.object(website_mod, "website",
                               return_value={"dns_records": {"A": "1.2.3.4"},
                                             "whois": {"Organization": "Acme"}}) as wm:
            r = inv.investigate({"email": "a@x.com", "username": "jdoe",
                                 "phone": "+15550000", "website": "x.com"})

        em.assert_called_once_with("a@x.com")
        um.assert_called_once_with("jdoe")
        pm.assert_called_once_with("+15550000")
        wm.assert_called_once_with("x.com")
        self.assertIn("email", r["results"])
        self.assertIn("username", r["results"])
        self.assertIn("website", r["results"])
        # Input-derived entities survive even when the phone module errored.
        self.assertIn("x.com", r["entities"]["domains"])
        self.assertIn("a@x.com", r["entities"]["emails"])

    def test_missing_modules_are_skipped(self):
        email_mod = imp("email")
        username_mod = imp("username")
        with mock.patch.object(inv, "_quick_resolve", return_value=None), \
             mock.patch.object(email_mod, "email",
                               return_value={"both": [], "breach": {"found": 0}}), \
             mock.patch.object(username_mod, "username",
                               return_value={"all_4": [], "breach": {"found": 0}}):
            r = inv.investigate({"username": "onlyme"})
        self.assertNotIn("email", r["results"])
        self.assertIn("username", r["results"])


class RunnerInputTest(unittest.TestCase):
    """The dashboard replaced the CLI's ``_parse_investigation_input``
    helper with structured form fields, so the merged equivalent is
    ``runner.run_investigate``'s own input normalisation."""

    def test_blank_core_inputs_are_dropped(self):
        from spyglass_pro import runner
        with mock.patch.object(inv, "investigate",
                               return_value={"entities": {}, "correlations": []}) as m:
            runner.run_investigate({"email": "a@x.com", "username": "  "})
        m.assert_called_once_with({"email": "a@x.com"})

    def test_whitespace_only_payload_is_rejected(self):
        from spyglass_pro import runner
        r = runner.run_investigate({"email": "   ", "username": ""})
        self.assertIn("error", r)
        self.assertIn("at least one", r["error"])

    def test_optional_legs_run_when_supplied(self):
        from spyglass_pro import runner
        with mock.patch.object(inv, "investigate",
                               return_value={"entities": {}, "correlations": []}), \
             mock.patch.object(runner, "run_lens", return_value={"ok": "lens"}) as lens, \
             mock.patch.object(runner, "run_social", return_value={"ok": "insta"}) as social:
            r = runner.run_investigate({"website": "example.com",
                                        "ip": "8.8.8.8", "insta": "instagram"})
        lens.assert_called_once_with("8.8.8.8", {"passive": "1"})
        # The Instagram leg now shares the one social code path.
        self.assertEqual(social.call_args[0][:2], ("instagram", "instagram"))
        self.assertEqual(r["ip_recon"], {"ok": "lens"})
        self.assertEqual(r["social"], {"ok": "insta"})

    def test_optional_legs_absent_by_default(self):
        from spyglass_pro import runner
        with mock.patch.object(inv, "investigate",
                               return_value={"entities": {}, "correlations": []}):
            r = runner.run_investigate({"email": "a@x.com"})
        self.assertNotIn("ip_recon", r)
        self.assertNotIn("instacloak", r)


if __name__ == "__main__":
    unittest.main()
