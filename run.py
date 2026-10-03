#!/usr/bin/env python3
"""Spyglass-Pro — Flask GUI entry point."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Make venv-installed CLI engines (sherlock, maigret, holehe, user-scanner,
# ignorant, ...) discoverable via shutil.which even when the server is
# launched without activating the venv first.
_venv_bin = os.path.dirname(os.path.abspath(sys.executable))
if _venv_bin not in os.environ.get("PATH", "").split(os.pathsep):
    os.environ["PATH"] = _venv_bin + os.pathsep + os.environ.get("PATH", "")

from spyglass_pro.app import run  # noqa: E402 - PATH fix above must run first

if __name__ == "__main__":
    host = os.environ.get("SPYGLASS_PRO_HOST", "127.0.0.1")
    port = os.environ.get("SPYGLASS_PRO_PORT", "5000")
    if not os.environ.get("SPYGLASS_PRO_TOKEN") and host.lower() not in ("127.0.0.1", "localhost", "::1"):
        print("WARNING: binding to %s without SPYGLASS_PRO_TOKEN — "
              "the dashboard is unauthenticated. Set a token first." % host)
    print("Spyglass-Pro starting on http://%s:%s" % (host, port))
    run()
