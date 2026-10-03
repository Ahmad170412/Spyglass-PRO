#!/usr/bin/env python3
"""Run the whole Spyglass-Pro suite.

Three suites with three different shapes, one command:

* ``test_*.py``       — unittest modules (engine suites + the merge layer)
* ``test_instacloak.py`` — plain test functions, upstream style
* ``lens_smoke_test.py`` — a script with PASS/FAIL counters

Run:  .venv/bin/python tests/run_tests.py
"""

import sys
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS_DIR))
sys.path.insert(0, str(TESTS_DIR.parents[0] / "spyglass_pro" / "modules"))

import helpers  # noqa: F401  — sets up sys.path for the vendored engines


def run_unittest_modules():
    loader = unittest.TestLoader()
    suite = loader.discover(str(TESTS_DIR), pattern="test_*.py", top_level_dir=str(TESTS_DIR))
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    return result.testsRun, len(result.failures) + len(result.errors)


def run_instacloak():
    """InstaCloak's suite is a list of module-level test functions."""
    import test_instacloak

    fns = [(name, fn) for name, fn in sorted(vars(test_instacloak).items())
           if name.startswith("test_") and callable(fn)]
    print(f"\n== instacloak ({len(fns)} offline tests) ==")
    failed = []
    for name, fn in fns:
        try:
            fn()
            print(f"  [PASS] {name}")
        except Exception as exc:
            print(f"  [FAIL] {name}: {exc}")
            failed.append(name)
    return len(fns), len(failed)


def run_lens_smoke():
    """Lens-Extender ships a script that exits non-zero on failure.

    Importing it executes every check and leaves PASS/FAIL behind; only
    the final ``SystemExit`` is guarded by ``__main__``.
    """
    print("\n== lens-extender smoke ==")
    import lens_smoke_test

    return lens_smoke_test.PASS + lens_smoke_test.FAIL, lens_smoke_test.FAIL


def run_cases_ui():
    """The Cases panel's render functions, checked under node.

    Skipped when node is unavailable — the Python suites still cover the
    API side of the same panel.
    """
    import shutil
    import subprocess

    if not shutil.which("node"):
        print("\n== cases UI ==\n  [SKIP] node not installed")
        return 0, 0
    print("\n== cases UI ==")
    script = TESTS_DIR / "test_frontend.js"
    proc = subprocess.run([shutil.which("node"), str(script)],
                          capture_output=True, text=True)
    sys.stdout.write(proc.stdout)
    if proc.returncode:
        sys.stdout.write(proc.stderr)
    passed = sum(1 for line in proc.stdout.splitlines() if "[PASS]" in line)
    failed = sum(1 for line in proc.stdout.splitlines() if "[FAIL]" in line)
    return passed + failed, failed


def main():
    total, failed = 0, 0

    if "--no-lens" in sys.argv:
        print("== lens-extender smoke skipped ==")
    else:
        lens_total, lens_failed = run_lens_smoke()
        total += lens_total
        failed += lens_failed

    ic_total, ic_failed = run_instacloak()
    total += ic_total
    failed += ic_failed

    ui_total, ui_failed = run_cases_ui()
    total += ui_total
    failed += ui_failed

    ut_total, ut_failed = run_unittest_modules()
    total += ut_total
    failed += ut_failed

    print(f"\n{'=' * 40}\n{total} checks, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
