"""Pins the exposure boundary.

This build deleted the IP module, the heavy website phases and
Lens-Extender rather than leaving them dormant in-tree. This suite is the
guard on that promise:

* the product vocabulary is the whole vocabulary — the handler map is
  exactly the exposed set, so a new engine cannot become reachable
  without a scope decision;
* no dormant code survives anywhere in the tree (a regression that
  reintroduces it fails here, not just at review);
* the HTTP boundary refuses anything outside the scope list.

A test client is used because "not exposed" means the *operator* cannot
reach it over HTTP, which is where every request lands.
"""

import pathlib
import unittest
from unittest import mock

import helpers  # noqa: F401  — puts spyglass_pro/modules on sys.path

from spyglass_pro import runner, scope
from spyglass_pro.app import _TOOL_PROBES, _TOOLS_LEGS, app

_ROOT = pathlib.Path(__file__).resolve().parents[1]


class VocabularyTest(unittest.TestCase):
    def test_every_exposed_module_has_a_handler(self):
        missing = set(scope.EXPOSED_MODULES) - set(runner._SPYGLASS_HANDLERS)
        self.assertEqual(missing, set())

    def test_handler_map_is_exactly_the_exposed_set(self):
        """The scope list is the allowlist, not a comment.

        A handler that appears in the runner without a scope decision would
        otherwise be reachable over HTTP the moment it landed.
        """
        self.assertEqual(set(runner._SPYGLASS_HANDLERS), set(scope.EXPOSED_MODULES))

    def test_no_dormant_vocabulary_remains(self):
        """Nothing is "unexposed but present" any more — it is deleted."""
        self.assertFalse(hasattr(scope, "DORMANT_MODULES"))
        self.assertFalse(hasattr(scope, "DORMANT_ENGINES"))
        self.assertFalse(hasattr(scope, "dormant_error"))

    def test_website_light_is_declared(self):
        self.assertEqual(set(scope.WEBSITE_LIGHT),
                         {"registrant", "whois", "dns", "ct"})


class RemovedCodeTest(unittest.TestCase):
    """The buried IP/web OSINT code is gone from the tree, not just unrouted."""

    _REMOVED = (
        "spyglass_pro/modules/spyglass_osint/ip.py",
        "spyglass_pro/modules/lens_extender/osint.py",
        "spyglass_pro/modules/lens_extender/analyzer.py",
        "spyglass_pro/modules/lens_extender/app.py",
        "spyglass_pro/modules/lens_extender/cli.py",
        "spyglass_pro/modules/lens_extender/config.py",
        "spyglass_pro/modules/lens_extender/report.py",
    )

    def test_removed_files_are_absent(self):
        for rel in self._REMOVED:
            self.assertFalse((_ROOT / rel).exists(), f"{rel} is back in the tree")

    def test_ip_and_lens_engines_do_not_import(self):
        import importlib

        for name in ("spyglass_osint.ip", "lens_extender.osint",
                     "lens_extender.analyzer", "lens_extender.app"):
            with self.assertRaises(ModuleNotFoundError):
                importlib.import_module(name)

    def test_runner_has_no_ip_or_lens_dispatch(self):
        self.assertNotIn("ip", runner._SPYGLASS_HANDLERS)
        self.assertFalse(hasattr(runner, "run_lens"))
        self.assertFalse(hasattr(runner, "_sg_ip"))

    def test_web_module_has_no_heavy_phases(self):
        from spyglass_osint import website

        for name in ("_phase_shodan_ports", "_phase_passive_subs",
                     "_hackertarget_subs", "_certspotter_subs",
                     "_wayback_cdx", "_reverse_dns"):
            self.assertFalse(hasattr(website, name),
                             f"website.{name} survived the cleanup")

    def test_lens_case_store_is_the_only_survivor(self):
        """The store is data hygiene, not recon: it can list and delete
        legacy runs and nothing else."""
        import lens_extender.store as le_store

        self.assertTrue(callable(le_store._get_conn))
        self.assertFalse(hasattr(le_store, "gather"))
        self.assertFalse(hasattr(le_store, "store_scan"))


class StatusVocabularyTest(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_status_no_longer_reports_infra_legs(self):
        data = self.client.get("/api/status").get_json()
        self.assertNotIn("ip", data["degraded"])
        self.assertNotIn("ip", _TOOLS_LEGS)
        self.assertEqual(_TOOLS_LEGS["website"], ["dig", "whois"])
        self.assertNotIn("shodan", _TOOL_PROBES)
        self.assertNotIn("curl", _TOOL_PROBES)

    def test_lens_is_not_reported_as_an_engine(self):
        data = self.client.get("/api/status").get_json()
        self.assertNotIn("lens_extender", data["engines"])
        self.assertEqual(set(data["engines"]), {"spyglass", "social"})


class ApiBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_removed_ip_module_is_refused(self):
        resp = self.client.get("/api/spyglass/run?module=ip&target=8.8.8.8")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("unknown module", resp.get_json()["error"])

    def test_lens_endpoint_is_gone(self):
        resp = self.client.get("/api/lens/run?target=8.8.8.8")
        self.assertEqual(resp.status_code, 404)

    def test_unknown_module_is_refused(self):
        resp = self.client.get("/api/spyglass/run?module=evil&target=x")
        self.assertIn("unknown module", resp.get_json()["error"])

    def test_handler_without_a_scope_decision_is_refused(self):
        """A new engine is unreachable until the scope list names it."""
        with mock.patch.dict(runner._SPYGLASS_HANDLERS,
                             {"ghost": lambda t, f, p: {"ran": True}}):
            resp = self.client.get("/api/spyglass/run?module=ghost&target=x")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("unknown module", resp.get_json()["error"])


if __name__ == "__main__":
    unittest.main()
