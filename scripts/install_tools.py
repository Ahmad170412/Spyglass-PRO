#!/usr/bin/env python3
"""Install the optional CLI engines that Spyglass-Pro's recon legs shell out to.

The email, username, phone, website, dark-web and metadata modules resolve
their tools on ``PATH`` (see ``spyglass_pro/app.py::_TOOL_PROBES`` and
``spyglass_osint/utils.py``) and skip themselves with a message when one is
absent. Nothing in this repository installs those tools, so a fresh clone
reports near-empty modules. This script closes that gap — every tool the
dashboard can detect has an installer or an honest manual pointer here.

Detection uses the application's own constants: blackbird's clone-location
fallback list is *imported* from ``spyglass_osint.utils`` rather than kept
as a here-maintained mirror, so the installer can agree with the engine
exactly — if a resolver drifts, the installer drifts with it or fails
loudly at import, never silently. Installs go through the package manager
each platform actually ships with — brew on macOS, apt on Debian/Ubuntu,
and winget (with a choco fallback) on Windows.

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
from pathlib import Path

# ── detection (imported from the application, not mirrored) ─────────────────
#
# Blackbird is a git clone rather than a console script, so `which` misses it
# and the engine falls back to fixed clone layouts. Import that list instead
# of keeping a second copy here: two hand-synced lists are one known drift
# bug (see AUDIT-2026-10.md's acceptance find) plus the one the installer
# itself shipped with. Import fails closed — loud SystemExit, not a quiet
# false negative — and this script only ever runs from a repository checkout
# (it is not packaged), so the path is always the vendored engine.

_MODULES_DIR = str(Path(__file__).resolve().parents[1] / "spyglass_pro" / "modules")
if os.path.isdir(_MODULES_DIR) and _MODULES_DIR not in sys.path:
    sys.path.insert(0, _MODULES_DIR)

try:
    from spyglass_osint.utils import _BLACKBIRD_PATHS
except ImportError as _exc:
    raise SystemExit(
        f"install_tools.py: cannot resolve the engine's own detection "
        f"({_exc}). Run this script from a Spyglass-Pro repository "
        f"checkout — it is not packaged with the wheel."
    ) from None


def _which(name):
    return shutil.which(name)


def _blackbird_path():
    for candidate in (shutil.which("blackbird"), shutil.which("blackbird.py")):
        if candidate:
            return candidate
    for path in _BLACKBIRD_PATHS:
        if os.path.isfile(path):
            return path
    return None


# ── installers ──────────────────────────────────────────────────────────────
# Each returns (ok, detail). pipx is preferred over pip for the Python CLIs:
# these tools pin old dependencies (aiohttp, requests) that conflict with each
# other and with the project venv, and pipx gives each its own venv.


def _run(cmd):
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode == 0, (proc.stderr or proc.stdout).strip()


def _pipx_install(package):
    if not shutil.which("pipx"):
        return False, ("pipx not found — install it first: "
                       "brew install pipx (macOS) or python3 -m pip install pipx")
    return _run(["pipx", "install", package])


def _apt_install(*packages):
    """apt-get branch shared by the system-package installers."""
    if not shutil.which("apt-get"):
        return None
    return _run(["sudo", "apt-get", "install", "-y", *packages])


def _winget_install(package_id):
    """winget branch for Windows. None = unavailable (so the caller can fall
    through to the next manager or the manual pointer). The silent/agreement
    flags keep this unattended-safe; a success still needs a *terminal*
    restart for the tool to land on PATH, which the returned detail notes."""
    winget = shutil.which("winget")
    if not winget:
        return None
    proc = subprocess.run(
        [winget, "install", "--id", package_id, "--exact", "--silent",
         "--accept-package-agreements", "--accept-source-agreements"],
        capture_output=True, text=True)
    if proc.returncode == 0:
        return True, (f"installed via winget ({package_id}) — open a new "
                      "terminal so PATH picks it up, then restart the server")
    # winget writes progress to stdout and reasons to stderr; surface the
    # last line of whichever spoke, plus the exit code it died with.
    output = (proc.stderr or proc.stdout or "").strip()
    tail = output.splitlines()[-1] if output else "no output"
    return False, (f"winget install of {package_id} failed "
                   f"(exit {proc.returncode}): {tail}")


def _choco_install(*packages):
    """choco fallback when winget is absent or an ID has no winget package.
    3010 is chocolatey's 'reboot required' — the files exist either way."""
    choco = shutil.which("choco")
    if not choco:
        return None
    proc = subprocess.run([choco, "install", "-y", "--no-progress",
                           *packages], capture_output=True, text=True)
    names = ", ".join(packages)
    if proc.returncode in (0, 3010):
        return True, (f"installed via choco ({names}) — restart the server "
                      "so the new tool is found")
    output = (proc.stderr or proc.stdout or "").strip()
    tail = output.splitlines()[-1] if output else "no output"
    return False, (f"choco install of {names} failed "
                   f"(exit {proc.returncode}): {tail}")


def install_sherlock():
    return _pipx_install("sherlock-project")


def install_maigret():
    return _pipx_install("maigret")


def install_holehe():
    return _pipx_install("holehe")


def install_ignorant():
    return _pipx_install("ignorant")


def install_blackbird():
    home = os.path.expanduser("~/blackbird")
    script = os.path.join(home, "blackbird.py")
    if os.path.isfile(script):
        return True, "already cloned at ~/blackbird"
    ok, detail = _run(["git", "clone", "--depth", "1",
                       "https://github.com/p1ngul1n0/blackbird.git", home])
    # A failed clone leaves the directory behind — a directory without the
    # script is not an install, so verify the file, not the folder.
    if os.path.isfile(script):
        return True, "already cloned at ~/blackbird" if not ok else "cloned to ~/blackbird"
    return False, detail.splitlines()[-1] if detail else "git clone failed"


def install_user_scanner():
    return _pipx_install("user-scanner")


def install_exiftool():
    """brew / winget+choco / apt / manual, in that order per platform."""
    if shutil.which("brew"):
        return _run(["brew", "install", "exiftool"])
    winget = _winget_install("OliverBetz.ExifTool")
    if winget is not None:
        return winget
    choco = _choco_install("exiftool")
    if choco is not None:
        return choco
    apt = _apt_install("libimage-exiftool-perl")
    if apt is not None:
        return apt
    return False, "install exiftool with: brew install exiftool"


def install_phoneinfoga():
    if shutil.which("brew"):
        return _run(["brew", "install", "phoneinfoga"])
    # No silent third-party apt repos: on Linux without brew this is manual.
    return False, ("no brew found — on Debian/Ubuntu add the phoneinfoga apt "
                   "repository (see github.com/sundowndev/phoneinfoga), then "
                   "apt-get install phoneinfoga")


def _have_sysutils():
    return all(shutil.which(tool) for tool in ("dig", "whois", "curl"))


# Package IDs for dig/whois/curl on Windows, where no single package
# manager carries all three. Verified against the live winget-pkgs and
# chocolatey registries (2026-10); a None winget id means "no winget
# manifest exists" — ISC ships BIND as a zip, so choco's bind-toolsonly
# is the closest packaged equivalent.
_WINDOWS_SYSUTILS = {
    "dig":   (None, ("bind-toolsonly",),
              "download BIND tools from isc.org/downloads — dig.exe is "
              "standalone, no BIND server needed"),
    "whois": ("Microsoft.Sysinternals.Suite", ("sysinternals",),
              "Sysinternals Whois from learn.microsoft.com/sysinternals/downloads/whois"),
}


def install_sysutils():
    """dig + whois + curl, per platform.

    curl ships with Windows 10+, so the Windows branch concerns dig (BIND
    tools) and whois (Sysinternals). POSIX keeps the one-shot package
    manager call.
    """
    if os.name == "nt":
        outcomes = []
        for name, spec in _WINDOWS_SYSUTILS.items():
            ok, detail = _install_windows_tool(name, *spec)
            outcomes.append((ok, name, detail))
        failed = [(name, detail) for ok, name, detail in outcomes if not ok]
        if not failed:
            return True, "installed via winget/choco: " + ", ".join(
                name for _, name, _ in outcomes)
        return False, "; ".join(f"{name} — {detail}" for name, detail in failed)
    if shutil.which("brew"):
        return _run(["brew", "install", "bind", "whois", "curl"])
    apt = _apt_install("dnsutils", "whois", "curl")
    if apt is not None:
        return apt
    return False, "install dig, whois and curl with your package manager"


def _install_windows_tool(name, winget_id, choco_ids, manual):
    """One Windows tool through winget, then choco, then an honest pointer."""
    if winget_id:
        result = _winget_install(winget_id)
        if result is not None:
            return result
    for package in choco_ids:
        result = _choco_install(package)
        if result is not None:
            return result
    return False, (f"no winget or choco found — install {name} manually: {manual}")


def install_torsocks():
    """Tor SOCKS proxy — used to route dig/whois over Tor for .onion lookups."""
    if os.name == "nt":
        # There is no torsocks port for Windows; the honest Windows-native
        # alternative is pointing SPYGLASS_PROXY at a Tor SOCKS endpoint.
        return False, ("no torsocks for Windows — .onion DNS routing is a "
                       "POSIX feature here; use SPYGLASS_PROXY=socks5://127.0.0.1:9050 "
                       "(a Tor SOCKS endpoint) instead")
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
    "user-scanner": (lambda: _which("user-scanner"), install_user_scanner,
                     "Email/username account sweeps"),
    "phoneinfoga": (lambda: _which("phoneinfoga"), install_phoneinfoga,
                    "Phone footprinting"),
    "exiftool": (lambda: _which("exiftool"), install_exiftool,
                 "Metadata extraction"),
    "sysutils": (_have_sysutils, install_sysutils,
                 "dig + whois + curl (DNS/WHOIS/HTTP legs)"),
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
