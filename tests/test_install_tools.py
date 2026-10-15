"""Tests for scripts/install_tools.py — the optional-engine installer.

Two contracts matter here. First, detection must mirror the application:
"present" in --check has to mean the same thing it means to the engines,
or the script and the dashboard disagree about what's installed. Second,
every tool the dashboard can detect must be installable through this
script (or carry an honest manual pointer) — a "install what's missing"
script with gaps strands a fresh clone on a degraded install.
"""

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

_ROOT = Path(__file__).resolve().parents[1]
for _p in (str(_ROOT / "scripts"), str(_ROOT),
           str(_ROOT / "spyglass_pro" / "modules")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import install_tools


class DetectionMirrorTest(unittest.TestCase):
    def test_fallbacks_cover_every_utils_location(self):
        """utils.py scans six blackbird locations; the script must too."""
        import re

        utils = (Path(__file__).resolve().parents[1] / "spyglass_pro"
                 / "modules" / "spyglass_osint" / "utils.py").read_text()
        block = utils.split("_BLACKBIRD_PATHS = (", 1)[1].split(")", 1)[0]
        home = os.path.expanduser("~")

        locations = set(re.findall(r'"(/[^"]+)"', block))
        for join in re.findall(
                r'os\.path\.join\(_home((?:,\s*"[^"]*")*)\)', block):
            parts = re.findall(r'"([^"]*)"', join)
            locations.add(os.path.join(home, *parts))
        self.assertTrue(locations, "could not parse utils.py fallbacks")

        mirrored = set()
        for directory in install_tools._BLACKBIRD_FALLBACKS:
            directory = directory.replace("~", home)
            if directory.endswith(".py"):
                mirrored.add(directory)
            else:
                mirrored.add(os.path.join(directory, "blackbird.py"))
        for location in locations:
            self.assertIn(location, mirrored,
                          f"utils location uncovered: {location}")

    def test_pipx_message_names_a_real_installer(self):
        """'Install pipx with pipx' sends the user in a circle."""
        with mock.patch.object(install_tools.shutil, "which", return_value=None):
            ok, detail = install_tools._pipx_install("sherlock")
        self.assertFalse(ok)
        self.assertNotIn("pipx install pipx", detail)
        self.assertIn("pip install pipx", detail)

    def test_partial_blackbird_clone_is_not_an_install(self):
        """A failed clone leaves ~/blackbird behind without blackbird.py —
        the old check saw the directory and reported success."""
        with mock.patch.object(install_tools, "_run",
                               return_value=(False, "clone failed")), \
             mock.patch.object(install_tools.os.path, "isfile",
                               return_value=False) as isfile:
            ok, _ = install_tools.install_blackbird()
        self.assertFalse(ok)
        self.assertTrue(isfile.called)

    def test_existing_clone_skips_git(self):
        with mock.patch.object(install_tools, "_run") as run, \
             mock.patch.object(install_tools.os.path, "isfile",
                               return_value=True):
            ok, _ = install_tools.install_blackbird()
        self.assertTrue(ok)
        run.assert_not_called()

    def test_phoneinfoga_without_brew_stays_manual(self):
        """No third-party apt repos are added silently."""
        with mock.patch.object(install_tools.shutil, "which", return_value=None):
            ok, detail = install_tools.install_phoneinfoga()
        self.assertFalse(ok)
        self.assertIn("phoneinfoga", detail)


class CoverageTest(unittest.TestCase):
    def test_every_status_probe_is_installable(self):
        """Each tool /api/status can report must have a script entry —
        otherwise --check can name a gap it cannot close."""
        from spyglass_pro.app import _TOOL_PROBES

        covered_by = {
            "holehe": "holehe",
            "user-scanner": "user-scanner",
            "sherlock": "sherlock",
            "maigret": "maigret",
            "blackbird": "blackbird",
            "ignorant": "ignorant",
            "phoneinfoga": "phoneinfoga",
            "dig": "sysutils",
            "whois": "sysutils",
            "shodan": "shodan",
            "exiftool": "exiftool",
            "curl": "sysutils",
        }
        self.assertEqual(set(_TOOL_PROBES), set(covered_by))
        for key in covered_by.values():
            self.assertIn(key, install_tools.TOOLS)

    def test_check_mode_installs_nothing(self):
        with mock.patch("shutil.which", return_value="/bin/true"):
            self.assertEqual(install_tools.main(["--check"]), 0)

    def test_check_reports_missing_without_touching_the_system(self):
        with mock.patch("shutil.which", return_value=None), \
             mock.patch.object(install_tools, "_run") as run:
            code = install_tools.main(["--check", "--only", "sherlock"])
        self.assertEqual(code, 1)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
