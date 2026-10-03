"""Version metadata.

The standalone Spyglass-OSINT CLI's ``--version`` flag is gone — the
dashboard replaced that UI — so these tests cover the version strings the
merged product actually reports: the dashboard's own version and the
vendored engine's.
"""

import unittest

from helpers import imp

import spyglass_pro

pkg = imp("")


class VersionTest(unittest.TestCase):
    def test_package_version(self):
        self.assertEqual(spyglass_pro.__version__, "1.0.0-pro")

    def test_version_module_is_single_source(self):
        from spyglass_pro import version
        self.assertEqual(version.__version__, spyglass_pro.__version__)

    def test_engine_version(self):
        self.assertEqual(pkg.__version__, "1.1.1")

    def test_status_endpoint_reports_version(self):
        from spyglass_pro.app import app
        client = app.test_client()
        data = client.get("/api/status").get_json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["version"], spyglass_pro.__version__)

    def test_modules_dir_is_importable(self):
        """The engines must import the same way runner.py loads them."""
        import instacloak  # noqa: F401
        import lens_extender  # noqa: F401
        import spyglass_osint  # noqa: F401


if __name__ == "__main__":
    unittest.main()