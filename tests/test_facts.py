"""Tests for the normalized fact layer (``spyglass_pro.facts``).

The block is derived data — the dashboard and the graph/timeline views
to come read it instead of learning every payload shape — so the rules
that matter are pinned here: it never appears on an errored run, it
never claims a field the engine did not report, and it reuses the case
store's entity extractor so both stay in step.
"""

import unittest
from unittest import mock

import helpers  # noqa: F401  — puts spyglass_pro/modules on sys.path

from spyglass_pro import facts, runner


def _fact(block, key):
    return next((f for f in block["facts"] if f["key"] == key), None)


def _entity_values(block, kind=None):
    return [e["value"] for e in block["entities"]
            if kind is None or e["kind"] == kind]


class SchemaContract(unittest.TestCase):
    def test_block_carries_schema_header(self):
        block = facts.normalize({"both": []}, "email", "a@x.com")
        self.assertEqual(block["schema"], facts.SCHEMA)
        self.assertEqual(block["qtype"], "email")
        self.assertEqual(block["target"], "a@x.com")
        self.assertEqual(block["engine"], "spyglass_osint")

    def test_engine_family_per_query_type(self):
        self.assertEqual(
            facts.normalize({"ports": []}, "lens", "1.2.3.4")["engine"],
            "lens_extender")
        self.assertEqual(
            facts.normalize({"entities": {}, "correlations": []},
                            "investigation", "a@x.com")["engine"],
            "correlated")
        self.assertEqual(
            facts.normalize({"platform": "instagram"}, "social", "handle")["engine"],
            "social_harness")

    def test_errored_run_yields_no_block(self):
        """Absence, not null filler, is what 'nothing was known' looks like."""
        self.assertIsNone(facts.normalize({"error": "boom"}, "email", "a@x.com"))
        self.assertIsNone(facts.normalize({"error": "boom"}, "email", ""))
        self.assertIsNone(facts.normalize(None, "email", "a@x.com"))
        self.assertIsNone(facts.normalize("text", "email", "a@x.com"))

    def test_every_fact_is_scalar(self):
        block = facts.normalize(
            {"both": [{"domain": "x.com"}], "geo": {"city": "Rome"}},
            "email", "a@x.com")
        for fact in block["facts"]:
            self.assertIsInstance(fact["value"], (str, int, float), fact)
            for key in ("key", "label", "source", "confidence"):
                self.assertIn(key, fact)

    def test_provenance_omits_absent_keys(self):
        block = facts.normalize({}, "email", "a@x.com")
        self.assertNotIn("summary", block["provenance"])
        self.assertNotIn("stored_run_id", block["provenance"])
        rich = facts.normalize({"summary": "done", "progress": ["a", "b"],
                                "stored_run_id": 7, "artifacts": [{}]},
                               "email", "a@x.com")
        self.assertEqual(rich["provenance"]["summary"], "done")
        self.assertEqual(rich["provenance"]["progress_lines"], 2)
        self.assertEqual(rich["provenance"]["stored_run_id"], 7)

    def test_response_keys_never_become_facts(self):
        block = facts.normalize(
            {"summary": "s", "progress": ["x"], "artifacts": [],
             "title": "Example"}, "email", "a@x.com")
        self.assertIsNone(_fact(block, "summary"))
        self.assertIsNone(_fact(block, "progress"))
        self.assertIsNone(_fact(block, "artifacts"))


class EntityExtractionTest(unittest.TestCase):
    def test_target_is_always_an_entity(self):
        for qtype, kind in (("email", "email"), ("username", "username"),
                           ("phone", "phone"), ("website", "domain"),
                           ("ip", "ip")):
            block = facts.normalize({}, qtype, "value-goes-here")
            self.assertIn(
                {"kind": kind, "value": "value-goes-here", "source": "target"},
                block["entities"], qtype)

    def test_opsec_and_metadata_targets_are_not_entities(self):
        block = facts.normalize({}, "opsec", "self")
        self.assertEqual(block["entities"], [])

    def test_darkweb_target_kind_is_guessed(self):
        for target, kind in (("a@b.com", "email"), ("example.com", "domain"),
                             ("+15550000111", "phone"),
                             ("1.2.3.4", "ip"), ("jdoe", "username")):
            block = facts.normalize({"ahmia": []}, "darkweb", target)
            self.assertIn(target, _entity_values(block, kind), target)

    def test_store_extractor_feeds_the_block(self):
        """The case store's extractor is the one true entity source —
        reusing it keeps graph and entity index agreeing."""
        block = facts.normalize(
            {"subdomains": ["a.example.com"], "dns_records": {"A": "1.2.3.4"},
             "whois": {"Organization": "Acme Ltd"}},
            "website", "example.com")
        self.assertIn("a.example.com", _entity_values(block, "domain"))
        self.assertIn("1.2.3.4", _entity_values(block, "ip"))
        self.assertIn("acme ltd", _entity_values(block, "org"))

    def test_investigation_entities_are_not_lowercased_targetless(self):
        block = facts.normalize(
            {"entities": {"emails": ["a@x.com"], "ips": ["1.2.3.4"]},
             "correlations": []}, "investigation", "a@x.com, jdoe")
        self.assertIn("a@x.com", _entity_values(block, "email"))
        self.assertIn("1.2.3.4", _entity_values(block, "ip"))

    def test_social_handle_becomes_a_username_entity(self):
        block = facts.normalize({"handle": "somebody"}, "social", "somebody")
        self.assertIn("somebody", _entity_values(block, "username"))
        # One entity, not two: target and collected handle are the same
        # value, and a graph node must not double up.
        self.assertEqual(_entity_values(block, "username").count("somebody"), 1)

    def test_lens_entities_come_from_resolved_ip(self):
        block = facts.normalize(
            {"resolved_ip": "9.9.9.9", "hostnames": ["x.example.com"],
             "target": "example.com"}, "lens", "example.com")
        self.assertIn("9.9.9.9", _entity_values(block, "ip"))
        self.assertIn("x.example.com", _entity_values(block, "domain"))


class FactExtractionTest(unittest.TestCase):
    def test_email_agreement_counts(self):
        block = facts.normalize(
            {"both": [{"domain": "x.com"}],
             "holehe_only": [{"domain": "y.com"}],
             "user_scanner_only": [], "blackbird_only": [],
             "breach": {"found": 0, "sources": []}},
            "email", "a@x.com")
        self.assertEqual(_fact(block, "accounts_total")["value"], 2)
        self.assertEqual(_fact(block, "accounts_agreed")["value"], 1)
        single = _fact(block, "accounts_single")
        self.assertEqual(single["value"], 1)
        self.assertEqual(single["confidence"], "medium")
        # A reported zero is a finding; it must not be dropped.
        self.assertEqual(_fact(block, "breach_records")["value"], 0)

    def test_absent_group_keys_claim_nothing(self):
        """A degraded run that returned no agreement groups must not be
        reported as '0 accounts found' — that would be an invention."""
        block = facts.normalize({"breach": {"found": 0}}, "email", "a@x.com")
        self.assertIsNone(_fact(block, "accounts_total"))
        self.assertEqual(_fact(block, "breach_records")["value"], 0)

    def test_username_engine_agreement(self):
        block = facts.normalize(
            {"all_4": [{"domain": "x.com"}], "us_only": [{"domain": "y.com"}]},
            "username", "jdoe")
        self.assertEqual(_fact(block, "accounts_agreed")["value"], 1)
        self.assertEqual(_fact(block, "accounts_4_of_4")["value"], 1)
        self.assertEqual(_fact(block, "accounts_single")["value"], 1)

    def test_opsec_false_stays_visible(self):
        """proxy_configured=False is the key OPSEC finding — a false bool
        that the engine really returned must surface as a fact."""
        block = facts.normalize(
            {"proxy_configured": False, "recommendations": ["use a proxy"]},
            "opsec", "self")
        fact = _fact(block, "proxy_configured")
        self.assertIsNotNone(fact)
        self.assertIs(fact["value"], False)
        self.assertEqual(_fact(block, "recommendations")["value"], 1)

    def test_investigation_legs_exclude_errored_legs(self):
        block = facts.normalize(
            {"entities": {"emails": ["a@x.com"], "domains": []},
             "correlations": [{"type": "match"}],
             "results": {"email": {"ok": 1}, "phone": {"error": "down"}},
             "ip_recon": {"error": "down"}},
            "investigation", "a@x.com")
        self.assertEqual(_fact(block, "legs")["value"], 1)
        self.assertEqual(_fact(block, "correlations_match")["value"], 1)
        self.assertEqual(_fact(block, "entities_email")["value"], 1)


class RunnerAttachmentTest(unittest.TestCase):
    """The runner attaches the block last, so provenance sees the final
    summary/progress/artifacts — and never on an errored run."""

    def test_finish_attaches_normalized_block(self):
        response = runner._finish(
            {"both": [], "holehe_only": [], "user_scanner_only": [],
             "blackbird_only": [], "breach": {"found": 0}},
            "email", "a@x.com", {}, runner.Progress())
        self.assertEqual(response["normalized"]["schema"], facts.SCHEMA)
        self.assertIn("summary", response["normalized"]["provenance"])

    def test_finish_error_has_no_normalized_block(self):
        response = runner._finish({"error": "engine blew up"}, "email",
                                  "a@x.com", {}, runner.Progress())
        self.assertNotIn("normalized", response)
        self.assertEqual(response["error"], "engine blew up")

    def test_derived_layer_failure_keeps_raw_payload(self):
        """A formatting bug must never cost the caller the run itself."""
        with mock.patch.object(facts, "normalize",
                               side_effect=ValueError("bad shape")):
            response = runner._finish({"both": []}, "email", "a@x.com", {},
                                      runner.Progress())
        self.assertNotIn("normalized", response)
        self.assertIn("facts_error", response)
        self.assertNotIn("\n", response["facts_error"])


if __name__ == "__main__":
    unittest.main()
