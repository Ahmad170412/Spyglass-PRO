"""Tests for the person layer: provenance, links, context and conflicts.

The layer is pure — no tools run here. Every fixture is a finished
investigation payload, so these tests pin the honesty rules directly:
accounts carry the engines that found them, shared handles stay possible,
and unmatched WHOIS values stay in domain context.
"""

import unittest
from unittest import mock

from spyglass_pro import identity, runner


def _email_result():
    return {
        "both": [{"domain": "github.com", "url": "https://github.com/analyst",
                  "engines": ["holehe", "user-scanner"]}],
        "holehe_only": [], "user_scanner_only": [], "blackbird_only": [],
        "breach": {"found": 1, "sources": [{"name": "LeakDB", "date": "2021"}],
                   "fields": ["email", "password"]},
    }


def _username_result():
    return {
        "all_4": [{"domain": "github.com", "url": "https://github.com/analyst"},
                  {"domain": "mastodon.social", "url": "https://mastodon.social/@analyst"}],
        "breach": {"found": 1, "sources": [{"name": "LeakDB", "date": "2021"}]},
    }


def _research_result(**extra):
    result = {
        "results": {"email": _email_result(), "username": _username_result()},
        "entities": {},
        "correlations": [],
    }
    result.update(extra)
    return result


class AccountProvenanceTest(unittest.TestCase):
    def test_accounts_merge_email_and_username_with_engines(self):
        person = identity.resolve(
            {"email": "analyst@example.com", "username": "analyst"},
            _research_result())
        github = next(a for a in person["accounts"]
                      if a["platform"] == "github.com")
        self.assertEqual(github["via"], ["email", "username"])
        self.assertEqual(github["confidence"], "high")
        for tool in ("holehe", "user-scanner", "sherlock", "maigret", "blackbird"):
            self.assertIn(tool, github["tools"])
        self.assertEqual(person["counts"]["accounts"], 2)

    def test_shared_handle_is_possible_never_confirmed(self):
        person = identity.resolve(
            {"username": "analyst"},
            {"results": {"username": _username_result()},
             "entities": {}, "correlations": []})
        reuse = next(link for link in person["links"]
                     if link["kind"] == "handle-reuse")
        self.assertEqual(reuse["confidence"], "possible")
        self.assertIn("not proof of one person", reuse["desc"])
        self.assertNotEqual(person["confidence"], "high")

    def test_email_local_part_match_is_possible(self):
        person = identity.resolve(
            {"email": "analyst@example.com", "username": "analyst"},
            _research_result())
        link = next(item for item in person["links"]
                    if item["kind"] == "email-localpart")
        self.assertEqual(link["confidence"], "possible")


class SocialProfileTest(unittest.TestCase):
    def test_profile_fields_and_backlinks(self):
        social = {
            "platform": "instagram", "handle": "analyst", "found": True,
            "display_name": "Analyst", "location": "Berlin, Germany",
            "website": "https://example.com", "contact_email": "analyst@example.com",
            "url": "https://instagram.com/analyst",
            "bio": "reach me at analyst@example.com",
            "external_links": ["https://example.com/about"],
        }
        person = identity.resolve(
            {"email": "analyst@example.com", "username": "analyst",
             "website": "example.com"},
            _research_result(social=social))
        self.assertEqual(person["names"][0]["value"], "Analyst")
        self.assertIn("analyst@example.com",
                      [item["value"] for item in person["emails"]])
        self.assertIn("Berlin, Germany",
                      [item["value"] for item in person["locations"]])
        self.assertEqual(person["confidence"], "high")
        self.assertTrue(any(link["kind"] == "profile-email"
                            and link["confidence"] == "high"
                            for link in person["links"]))
        self.assertTrue(any(link["kind"] == "profile-bio"
                            and link["confidence"] == "high"
                            for link in person["links"]))
        instagram = next(a for a in person["accounts"]
                         if a["platform"] == "instagram.com")
        self.assertEqual(instagram["via"], ["social"])
        self.assertIn("instagram", instagram["tools"])

    def test_found_false_does_not_create_an_account(self):
        social = {"platform": "instagram", "handle": "analyst", "found": False,
                  "walls": {"followers": {"label": "Followers", "why": "login"}}}
        person = identity.resolve({"username": "analyst"},
                                  _research_result(social=social))
        self.assertFalse(any(a["platform"] == "instagram.com"
                             for a in person["accounts"]))
        self.assertTrue(any("not found" in note for note in person["notes"]))


class WebsiteContextTest(unittest.TestCase):
    def test_unmatched_whois_stays_in_context(self):
        website = {"whois": {
            "Organization": "Example Corp",
            "Registrant Email": "legal@example.com",
            "Phone": "+1 555 0100",
            "Country": "United States",
        }}
        person = identity.resolve(
            {"email": "a@example.com", "website": "example.com"},
            _research_result(results={"website": website}))
        values = [item["value"] for item in person["emails"]]
        self.assertEqual(values, ["a@example.com"])
        self.assertIn("legal@example.com", person["context"]["emails"])
        self.assertIn("Example Corp", person["context"]["organizations"])
        self.assertEqual(person["organizations"], [])
        self.assertEqual(person["confidence"], "unconfirmed")
        self.assertEqual(person["context"]["website"], "example.com")
        self.assertTrue(any("describe the domain" in note for note in person["notes"]))

    def test_matched_whois_attaches_but_keeps_provenance(self):
        website = {"whois": {
            "Organization": "Acme Ltd",
            "Registrant Email": "analyst@example.com",
            "Registrant Name": "Analyst",
            "Country": "Germany",
        }}
        social = {"platform": "instagram", "handle": "analyst", "found": True,
                  "display_name": "Analyst", "location": "Berlin, Germany",
                  "url": "https://instagram.com/analyst"}
        person = identity.resolve(
            {"email": "analyst@example.com", "website": "example.com"},
            _research_result(results={"website": website}, social=social))
        email = next(item for item in person["emails"]
                     if item["value"] == "analyst@example.com")
        self.assertIn("WHOIS", email["source"])
        self.assertEqual(person["organizations"][0]["value"], "Acme Ltd")
        self.assertTrue(any(link["kind"] == "whois-email"
                            and link["confidence"] == "high"
                            for link in person["links"]))
        self.assertTrue(any(link["kind"] == "whois-name"
                            and link["confidence"] == "high"
                            for link in person["links"]))
        self.assertEqual(person["conflicts"], [])

    def test_placeholders_are_not_identity_data(self):
        website = {"whois": {
            "Organization": "Domains By Proxy, LLC",
            "Registrant Name": "REDACTED FOR PRIVACY",
            "Country": "REDACTED FOR PRIVACY",
        }}
        person = identity.resolve(
            {"email": "a@example.com", "website": "example.com"},
            _research_result(results={"website": website}))
        self.assertEqual(person["names"], [])
        self.assertEqual(person["organizations"], [])
        self.assertNotIn("locations", person["context"])
        self.assertEqual(person["context"].get("organizations", []), [])


class ConflictTest(unittest.TestCase):
    def test_linked_whois_conflicts_are_surfaced(self):
        website = {"whois": {
            "Registrant Email": "a@example.com",
            "Registrant Name": "Ivan Petrov",
            "Country": "Russia",
            "Phone": "+1 (202) 555-0143",
        }}
        phone = {"phonenumbers": {"region": "US", "e164": "+12025550143"}}
        social = {"platform": "instagram", "handle": "a", "found": True,
                  "display_name": "Alice", "location": "Berlin, Germany",
                  "url": "https://instagram.com/a"}
        person = identity.resolve(
            {"email": "a@example.com", "phone": "+1 202 555 0143",
             "website": "example.com"},
            _research_result(results={"website": website, "phone": phone},
                             social=social))
        kinds = {conflict["kind"] for conflict in person["conflicts"]}
        self.assertEqual(kinds, {"location", "phone-region", "name"})
        self.assertTrue(any(link["kind"] == "whois-phone"
                            and link["confidence"] == "high"
                            for link in person["links"]))

    def test_unlinked_whois_country_does_not_conflict(self):
        website = {"whois": {"Country": "Russia"}}
        social = {"platform": "instagram", "handle": "a", "found": True,
                  "location": "Berlin, Germany", "url": "https://instagram.com/a"}
        person = identity.resolve(
            {"email": "a@example.com", "website": "example.com"},
            _research_result(results={"website": website}, social=social))
        self.assertEqual(person["conflicts"], [])
        self.assertEqual(person["context"]["locations"], ["Russia"])


class BreachMergeTest(unittest.TestCase):
    def test_same_source_across_legs_is_one_row(self):
        person = identity.resolve(
            {"email": "analyst@example.com", "username": "analyst"},
            _research_result())
        self.assertEqual(len(person["breaches"]), 1)
        self.assertEqual(person["breaches"][0]["via"], ["email", "username"])
        self.assertEqual(person["exposed_fields"], ["email", "password"])


class ListReadyTest(unittest.TestCase):
    def test_multiple_values_are_accepted_even_though_the_form_is_single(self):
        person = identity.resolve({"email": ["a@x.com", "b@y.com"]}, None)
        self.assertEqual(person["counts"]["anchors"], 2)
        self.assertEqual(len(person["emails"]), 2)
        self.assertEqual(person["confidence"], "unconfirmed")


class RunnerIntegrationTest(unittest.TestCase):
    def test_website_url_is_normalized_and_person_is_attached(self):
        from spyglass_osint import investigation

        def fake_investigate(inputs):
            return {"inputs": inputs, "results": {}, "entities": {},
                    "correlations": []}

        with mock.patch.object(investigation, "investigate",
                               side_effect=fake_investigate) as run:
            result = runner.run_investigate({
                "website": "https://Example.com/page",
                "email": "a@example.com",
            })
        run.assert_called_once_with({"email": "a@example.com",
                                     "website": "example.com"})
        self.assertEqual(result["person"]["schema"], identity.SCHEMA)
        self.assertEqual(result["person"]["context"]["website"], "example.com")
        fact_keys = [fact["key"] for fact in result["normalized"]["facts"]]
        self.assertIn("person_confidence", fact_keys)


if __name__ == "__main__":
    unittest.main()
