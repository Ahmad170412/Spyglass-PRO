"""The entry point's PATH engineering.

``run.py`` exists so the server finds its CLI engines even when it is not
started from an interactive login shell — a cron job, a launch agent, a
Windows service. The candidate list below is the contract: every location
an engine can be installed into must appear, per platform, or a module
silently degrades to breach-only with nothing on the dashboard to explain
why. The per-platform branches run under their own CI jobs, so the
Windows branch here is exercised on the Windows runner, not just parsed.
"""

import os
import sys
import sysconfig
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
for _p in (str(_ROOT),):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Import for its helpers; importing run.py also enacts the PATH fix, which
# is harmless here (it only adds existing dirs to os.environ["PATH"]).
import run


class PathCandidatesTest(unittest.TestCase):
    def setUp(self):
        self.candidates = [c for c in run._path_candidates() if c]
        self.home = os.path.expanduser("~")

    def _assert_any(self, substring, msg=""):
        self.assertTrue(any(substring in c for c in self.candidates),
                        f"missing {substring} from PATH candidates: {msg}")

    def test_venv_scripts_dir_is_first(self):
        """Engines installed inside the running venv resolve before anything
        else — a pipx install of the same tool must not shadow it."""
        self.assertEqual(self.candidates[0],
                         os.path.dirname(os.path.abspath(sys.executable)))

    def test_user_scheme_scripts_dir(self):
        """pip install --user must be visible on every platform. The dir comes
        from sysconfig's <os>_user scheme — POSIX: ~/.local/bin; Windows:
        %APPDATA%\\Python\\<ver>\\Scripts, which a hardcoded userbase/bin
        guess never found."""
        self._assert_any(sysconfig.get_path("scripts", f"{os.name}_user"))

    def test_pipx_dirs_for_this_platform(self):
        if os.name == "nt":
            self._assert_any(os.path.join(self.home, ".local", "bin"),
                             "pipx default on Windows")
            self._assert_any(os.path.join(self.home, ".pyx", "bin"),
                             "pipx alternate layout on Windows")
        else:
            self._assert_any(os.path.join(self.home, ".local", "bin"),
                             "pipx default on POSIX")
            # The Windows-only .pyx dir is meaningless on POSIX, and its
            # absence here is what keeps the list predictable.
            self.assertFalse(any(".pyx" in c for c in self.candidates),
                             "Windows-only pipx dir leaked into a POSIX build")

    def test_pipx_env_var_honoured(self):
        saved = os.environ.get("PIPX_BIN_DIR")
        try:
            os.environ["PIPX_BIN_DIR"] = os.path.join("custom", "pipxbin")
            self.assertTrue(any("custom/pipxbin" in c.replace(os.sep, "/")
                                for c in run._path_candidates()),
                            "PIPX_BIN_DIR must override the default layout")
        finally:
            if saved is None:
                os.environ.pop("PIPX_BIN_DIR", None)
            else:
                os.environ["PIPX_BIN_DIR"] = saved

    def test_blackbird_clone_parent(self):
        """blackbird is a git clone, never a console script — its parent dir
        has to be on PATH or `which('blackbird')` is always false."""
        expected = os.path.join(self.home, ".local", "bin", "blackbird")
        self.assertIn(expected, self.candidates)


if __name__ == "__main__":
    unittest.main()
