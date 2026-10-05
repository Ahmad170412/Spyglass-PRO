#!/usr/bin/env python3
"""Spyglass-Pro — Flask GUI entry point."""

import os
import site
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _augment_path() -> None:
    """Put the CLI-engine install locations on PATH.

    Two separate sets of tools feed the identity modules:

    * venv-installed engines (``holehe``, ``user-scanner``, ``ignorant``) land
      beside ``sys.executable``;
    * pipx-installed engines (``sherlock``, ``maigret``) land in pipx's own
      bin dir — ``~/.local/bin`` on POSIX, ``%USERPROFILE%\\.local\\bin`` or
      ``%USERPROFILE%\\.pyx\\bin`` on Windows — which is only on PATH in an
      interactive login shell. A server started from a process without a
      login shell (a launch agent, cron, Docker CMD) silently loses them and
      the email/username modules degrade to breach-only.

    Tool paths are resolved once at import here, so this has to run before
    ``spyglass_pro.utils`` is imported by anything.
    """
    candidates = [os.path.dirname(os.path.abspath(sys.executable))]

    # pipx honours PIPX_BIN_DIR; fall back to its documented defaults.
    candidates.append(os.environ.get("PIPX_BIN_DIR", ""))
    home = os.path.expanduser("~")
    if os.name == "nt":
        candidates += [os.path.join(home, ".local", "bin"),
                       os.path.join(home, ".pyx", "bin")]
    else:
        candidates.append(os.path.join(home, ".local", "bin"))

    # Blackbird is a git clone rather than a console script; utils.py looks for
    # it under a handful of fixed locations, so put its parent on PATH too.
    candidates.append(os.path.join(home, ".local", "bin", "blackbird"))

    try:
        user_base = site.getuserbase()
        candidates.append(os.path.join(user_base, "bin"))
    except Exception:
        pass

    current = os.environ.get("PATH", "").split(os.pathsep)
    for candidate in candidates:
        if candidate and os.path.isdir(candidate) and candidate not in current:
            current.insert(0, candidate)
    os.environ["PATH"] = os.pathsep.join(current)


_augment_path()

from spyglass_pro.app import run  # noqa: E402 - PATH fix above must run first

if __name__ == "__main__":
    host = os.environ.get("SPYGLASS_PRO_HOST", "127.0.0.1")
    port = os.environ.get("SPYGLASS_PRO_PORT", "5000")
    if not os.environ.get("SPYGLASS_PRO_TOKEN") and host.lower() not in ("127.0.0.1", "localhost", "::1"):
        print("WARNING: binding to %s without SPYGLASS_PRO_TOKEN — "
              "the dashboard is unauthenticated. Set a token first." % host)
    print("Spyglass-Pro starting on http://%s:%s" % (host, port))
    run()
