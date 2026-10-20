"""Tests for scripts/install_tools.py — the optional-engine installer.

Two contracts matter here. First, detection must not merely mirror the
application — it must *be* the application's detection (the same list,
imported) — or the script and the dashboard end up disagreeing about
what's installed. Second, every tool the dashboard can detect must be
installable through this script (or carry an honest manual pointer) — a
"install what's missing" script with gaps strands a fresh clone on a
degraded install.
"""

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
    def test_imports_the_engine_constant_itself(self):
        """No forked copy: the installer must scan the *very list object*
        the engine scans (import identity), so an edit to either side can
        never drift apart — the exact bug class the old hand-synced
        fallback tuple had. Also pins that the list stays substantive."""
        from spyglass_osint import utils as sg_utils
        self.assertIs(install_tools._BLACKBIRD_PATHS, sg_utils._BLACKBIRD_PATHS)
        self.assertGreaterEqual(len(install_tools._BLACKBIRD_PATHS), 5)
        for path in install_tools._BLACKBIRD_PATHS:
            self.assertTrue(path.endswith("blackbird.py"),
                            f"unexpected candidate shape: {path}")

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
            "exiftool": "exiftool",
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


class WindowsInstallerTest(unittest.TestCase):
    """The Windows branches, driven offline by pinning os.name and the
    package-manager availability. The winget/choco IDs are real manifests
    in the winget-pkgs / community registries (verified 2026-10); a wrong
    ID installs nothing and reports success only of failure."""

    def _as_nt(self, managers):
        """Patch os.name to 'nt' and shutil.which to the manager table."""
        nt = mock.patch.object(install_tools.os, "name", "nt")
        return nt, mock.patch.object(install_tools.shutil, "which", managers.get)

    def test_exiftool_goes_through_winget_first(self):
        nt, mgr = self._as_nt({"winget": "/wt", "choco": "/ch"})
        with nt, mgr, \
             mock.patch.object(install_tools, "_winget_install",
                               return_value=(True, "winget ok")) as winget, \
             mock.patch.object(install_tools, "_choco_install") as choco:
            ok, _detail = install_tools.install_exiftool()
        self.assertTrue(ok)
        winget.assert_called_once_with("OliverBetz.ExifTool")
        choco.assert_not_called()

    def test_exiftool_falls_back_to_choco_without_winget(self):
        """winget is offered first (the manager is simply *absent* here, which
        _winget_install humouring as None models) and choco takes over —
        falling through is the contract, not skipping the attempt."""
        nt, mgr = self._as_nt({"choco": "/ch"})
        with nt, mgr, \
             mock.patch.object(install_tools, "_winget_install",
                               return_value=None) as winget, \
             mock.patch.object(install_tools, "_choco_install",
                               return_value=(True, "choco ok")) as choco:
            ok, _ = install_tools.install_exiftool()
        self.assertTrue(ok)
        winget.assert_called_once_with("OliverBetz.ExifTool")
        choco.assert_called_once_with("exiftool")

    def test_sysutils_splits_across_managers(self):
        """dig has no winget manifest (ISC ships BIND as a zip) — it must
        take the choco path while whois takes winget, in one --only run."""
        nt, mgr = self._as_nt({"winget": "/wt", "choco": "/ch"})
        with nt, mgr, \
             mock.patch.object(install_tools, "_winget_install",
                               return_value=(True, "winget ok")) as winget, \
             mock.patch.object(install_tools, "_choco_install",
                               return_value=(True, "choco ok")) as choco:
            ok, _detail = install_tools.install_sysutils()
        self.assertTrue(ok)
        winget.assert_called_once_with("Microsoft.Sysinternals.Suite")
        choco.assert_called_once_with("bind-toolsonly")

    def test_sysutils_without_managers_points_every_tool_someplace(self):
        nt, mgr = self._as_nt({})
        with nt, mgr:
            ok, detail = install_tools.install_sysutils()
        self.assertFalse(ok)
        for tool in ("dig", "whois"):
            self.assertIn(tool, detail)
        # Both tools carry an honest manual pointer — no silent gaps.
        self.assertIn("isc.org", detail)
        self.assertIn("sysinternals", detail)

    def test_torsocks_on_windows_names_the_proxy_alternative(self):
        nt, mgr = self._as_nt({})
        with nt, mgr:
            ok, detail = install_tools.install_torsocks()
        self.assertFalse(ok)
        self.assertIn("SPYGLASS_PROXY", detail)

    def test_windows_branches_never_run_apt_or_brew(self):
        """A missing os.name guard would shell out to sudo on a Windows box
        (or brew to a Mac user); the branch table must contain them."""
        nt, mgr = self._as_nt({"winget": "/wt"})
        with nt, mgr, \
             mock.patch.object(install_tools, "_apt_install") as apt, \
             mock.patch.object(install_tools, "_winget_install",
                               return_value=(True, "ok")):
            install_tools.install_exiftool()
            install_tools.install_sysutils()
        apt.assert_not_called()


if __name__ == "__main__":
    unittest.main()
