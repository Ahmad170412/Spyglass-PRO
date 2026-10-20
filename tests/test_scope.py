"""Pins the 1.3 exposure boundary.

1.3 unexposes the IP module, the heavy website phases and Lens-Extender
without deleting them. This suite is the guard on that promise:

* the product vocabulary and the dormant set cannot overlap;
* every exposed module still has a dispatch handler;
* the dormant code still imports (the sibling tool depends on it);
* the HTTP boundary refuses dormant work with honest, named errors.

A test client is used because "unexposed" means the *operator* cannot
reach it, not that the library lost the function.
"""

import unittest

import helpers  # noqa: F401  — puts spyglass_pro/modules on sys.path

from spyglass_pro import runner, scope
from spyglass_pro.app import _TOOL_PROBES, _TOOLS_LEGS, app


class VocabularyTest(unittest.TestCase):
    def test_exposed_and_dormant_do_not_overlap(self):
        self.assertEqual(set(scope.EXPOSED_MODULES) & set(scope.DORMANT_MODULES), set())

    def test_every_exposed_module_has_a_handler(self):
        missing = set(scope.EXPOSED_MODULES) - set(runner._SPYGLASS_HANDLERS)
        self.assertEqual(missing, set())

    def test_dormant_modules_are_still_in_the_handler_map(self):
        """Unexposed is not deleted: the vendored engine stays callable."""
        for module in scope.DORMANT_MODULES:
            self.assertIn(module, runner._SPYGLASS_HANDLERS)

    def test_dormant_code_still_imports(self):
        import importlib
        for module in scope.DORMANT_MODULES:
            importlib.import_module(f"spyglass_osint.{module}")
        importlib.import_module("lens_extender")

    def test_website_light_is_declared(self):
        self.assertEqual(set(scope.WEBSITE_LIGHT),
                         {"registrant", "whois", "dns", "ct"})


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

    def test_lens_is_reported_dormant(self):
        data = self.client.get("/api/status").get_json()
        self.assertTrue(data["engines"]["lens_extender"].get("dormant"))


class ApiBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_dormant_module_is_refused(self):
        resp = self.client.get("/api/spyglass/run?module=ip&target=8.8.8.8")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("dormant", resp.get_json()["error"])

    def test_lens_endpoint_is_refused(self):
        resp = self.client.get("/api/lens/run?target=8.8.8.8")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("dormant", resp.get_json()["error"])

    def test_unknown_module_is_not_mislabelled_dormant(self):
        resp = self.client.get("/api/spyglass/run?module=evil&target=x")
        self.assertIn("unknown module", resp.get_json()["error"])


if __name__ == "__main__":
    unittest.main()
