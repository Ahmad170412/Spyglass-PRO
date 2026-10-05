#!/usr/bin/env python3
"""Install the optional CLI engines that Spyglass-Pro's identity modules shell out to.

The email, username and phone modules are thin orchestrators: they resolve six
external tools on ``PATH`` (see ``spyglass_pro/modules/spyglass_osint/utils.py``)
and skip themselves with a message when one is absent. Nothing in this
repository installs those tools, so a fresh clone reports three near-empty
modules. This script closes that gap.

Detection mirrors ``utils.py`` exactly, including blackbird's fallback path
scan, so "present" here means the same thing it means to the application.

    python scripts/install_tools.py            # install what's missing
    python scripts/install_tools.py --check    # report only, change nothing
    python scripts/install_tools.py --only sherlock maigret

Every tool is installed independently; one failure never aborts the rest. The
script exits 0 when every requested tool ends up present, 1 otherwise.

Legal note: ``holehe`` and ``ignorant`` enumerate which platforms an email or
phone number is registered on. That is active account enumeration against
third-party services and it sits against Spyglass-Pro's passive-only posture
(see AUDIT-2026-10.md). They are installed here because they materially change
what the email and phone modules return, but using them may breach those
platforms' terms. Use identifiers you own or have permission to test.
"""

import argparse
import os
import shutil
import subprocess
import sys

# ── detection (kept in sync with spyglass_osint/utils.py) ────────────────────

# Blackbird is a git clone rather than a console script, so `which` misses it
# and utils.py falls back to scanning these locations. Mirror that exactly.
_BLACKBIRD_FALLBACKS = (
    "/opt/blackbird",
    os.path.expanduser("~/.local/bin/blackbird"),
    "/opt/homebrew/bin/blackbird.py",
    "/usr/local/bin/blackbird.py",
    os.path.expanduser("~/blackbird"),
)


def _which(name):
    return shutil.which(name)


def _blackbird_path():
    for candidate in (shutil.which("blackbird"), shutil.which("blackbird.py")):
        if candidate:
            return candidate
    for directory in _BLACKBIRD_FALLBACKS:
        path = candidate_file(directory)
        if path:
            return path
    return None


def candidate_file(directory):
    """Return <directory>/blackbird.py when it exists, else None."""
    path = os.path.join(directory, "blackbird.py") if os.path.isdir(directory) else directory
    return path if os.path.isfile(path) else None


# ── installers ──────────────────────────────────────────────────────────────
# Each returns (ok, detail). pipx is preferred over pip for the Python CLIs:
# these tools pin old dependencies (aiohttp, requests) that conflict with each
# other and with the project venv, and pipx gives each its own venv.


def _run(cmd):
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode == 0, (proc.stderr or proc.stdout).strip()


def _pipx_install(package):
    if not shutil.which("pipx"):
        return False, "pipx not found — install it with: pipx install pipx"
    return _run(["pipx", "install", package])


def install_sherlock():
    return _pipx_install("sherlock-project")


def install_maigret():
    return _pipx_install("maigret")


def install_holehe():
    return _pipx_install("holehe")


def install_ignorant():
    return _pipx_install("ignorant")


def install_blackbird():
    ok, detail = _run(["git", "clone", "--depth", "1",
                       "https://github.com/p1ngul1n0/blackbird.git",
                       os.path.expanduser("~/blackbird")])
    if ok:
        return True, "cloned to ~/blackbird"
    if os.path.isdir(os.path.expanduser("~/blackbird")):
        return True, "already cloned at ~/blackbird"
    return False, detail.splitlines()[-1] if detail else "git clone failed"


def install_torsocks():
    """Tor SOCKS proxy — used to route dig/whois over Tor for .onion lookups."""
    if shutil.which("brew"):
        return _run(["brew", "install", "torsocks"])
    if shutil.which("apt-get"):
        return _run(["sudo", "apt-get", "install", "-y", "torsocks"])
    return False, "no supported package manager found (need brew or apt-get)"


TOOLS = {
    "sherlock": (lambda: _which("sherlock"), install_sherlock,
                 "Username sweep across hundreds of sites"),
    "maigret": (lambda: _which("maigret"), install_maigret,
                "Username sweep, wider site list than sherlock"),
    "holehe": (lambda: _which("holehe"), install_holehe,
               "Checks which sites an email is registered on (enumeration)"),
    "ignorant": (lambda: _which("ignorant"), install_ignorant,
                 "Checks which sites a phone number is registered on (enumeration)"),
    "blackbird": (_blackbird_path, install_blackbird,
                  "Email/username/phone sweep; git clone, no console script"),
    "torsocks": (lambda: _which("torsocks"), install_torsocks,
                 "Routes dig/whois over Tor for .onion — optional"),
}


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="install_tools.py",
        description="Install Spyglass-Pro's optional CLI engines.",
    )
    parser.add_argument("--check", action="store_true",
                        help="report what is missing, install nothing")
    parser.add_argument("--only", nargs="+", metavar="TOOL", choices=sorted(TOOLS),
                        help="limit to these tools")
    args = parser.parse_args(argv)

    names = args.only or sorted(TOOLS)

    print("Spyglass-Pro — optional CLI engines\n")
    missing = []
    for name in names:
        detect, _, purpose = TOOLS[name]
        if detect():
            print(f"  [ok]      {name} — already present")
        else:
            missing.append(name)
            print(f"  [missing] {name} — {purpose}")

    if not missing:
        print("\nEverything requested is already installed.")
        return 0

    if args.check:
        print(f"\n{len(missing)} missing: {', '.join(missing)}")
        print("Re-run without --check to install.")
        return 1

    print()
    if {"holehe", "ignorant"} & set(missing):
        print("Note: holehe/ignorant perform account enumeration against third-party")
        print("services. See the legal note in this script.\n")

    failed = []
    for name in missing:
        _, installer, _ = TOOLS[name]
        print(f"  installing {name}...", flush=True)
        try:
            ok, detail = installer()
        except Exception as exc:  # one bad tool must not abort the rest
            ok, detail = False, str(exc)
        if ok:
            print(f"  [ok]      {name}")
        else:
            print(f"  [FAILED]  {name} — {detail}")
            failed.append(name)

    print()
    still_missing = [n for n in names if not TOOLS[n][0]()]
    if still_missing:
        print(f"Still missing: {', '.join(still_missing)}")
        if any(n in failed for n in still_missing):
            print("Spyglass-Pro reads these on PATH at import time — restart the")
            print("server after installing so the new tools are picked up.")
    else:
        print("All requested tools are now present.")
        print("Restart Spyglass-Pro if it is already running — tool paths are")
        print("resolved once at import, not per scan.")
    return 1 if still_missing else 0


if __name__ == "__main__":
    sys.exit(main())
