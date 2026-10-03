"""Shared import helper for the Spyglass-Pro test suite.

The three engines are vendored as top-level packages under
``spyglass_pro/modules/`` (``spyglass_osint``, ``instacloak``,
``lens_extender``) because that is where ``spyglass_pro/runner.py`` puts
them on ``sys.path`` at runtime. The tests import them exactly the same
way, so a passing test means the dashboard's own import path works.

We also scrub ``sys.path``. ``spyglass_osint/email.py`` and
``spyglass_osint/metadata.py`` shadow stdlib modules of the same name, so
the *engine* directory must never land on ``sys.path`` — only its parent.

The ``spyglass_osint`` suites are inherited from the standalone
Spyglass-OSINT repository and reach their modules through ``imp()``.
"""

import importlib
import os
import sys

# Repository root — the directory that contains the ``spyglass_pro`` package.
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
# The vendored engines' parent directory.
_MODULES_DIR = os.path.join(_ROOT, "spyglass_pro", "modules")
# The engine directory itself (never import from here — it shadows stdlib).
_PKG_DIR = os.path.join(_MODULES_DIR, "spyglass_osint")

for _path in (_ROOT, _MODULES_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

sys.path[:] = [p for p in sys.path if p and os.path.abspath(p) != _PKG_DIR]


def imp(name: str = ""):
    """Import a module inside the vendored spyglass_osint package."""
    return importlib.import_module("spyglass_osint" if not name else f"spyglass_osint.{name}")