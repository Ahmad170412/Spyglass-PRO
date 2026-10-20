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
        self.assertEqual(spyglass_pro.__version__, "1.5.0")

    def test_package_version_matches_distribution(self):
        """pyproject and the app must agree — two version strings that
        can drift (1.0.0 vs 1.0.0-pro once did) break every version check
        a user or script performs. 1.0.0-pro is not even PEP 440-valid,
        so PyPI would reject an upload carrying it. Parsed by regex so
        this holds on 3.10 too (no tomllib there)."""
        import re
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        text = (root / "pyproject.toml").read_text(encoding="utf-8")
        match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
        self.assertIsNotNone(match, "no version in pyproject.toml")
        self.assertEqual(match.group(1), spyglass_pro.__version__)

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

    def test_dashboard_shows_version_and_key_count(self):
        """The HTML shell renders its version chip and the initial
        API-key fraction from the server — hardcoding either in the
        template is how a 1.0 release displays a stale "0/9" forever."""
        from spyglass_pro import app as app_module
        html = app_module.app.test_client().get("/").data.decode()
        self.assertIn(f"v{spyglass_pro.__version__}</span>", html)
        self.assertIn(f"0/{len(app_module._SETTINGS_SPEC)}</span>", html)

    def test_modules_dir_is_importable(self):
        """The engines must import the same way runner.py loads them."""
        import instacloak  # noqa: F401
        import lens_extender  # noqa: F401
        import spyglass_osint  # noqa: F401


if __name__ == "__main__":
    unittest.main()
