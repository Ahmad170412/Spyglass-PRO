#!/usr/bin/env python3
import concurrent.futures
import json
import os
import re
import shutil
import subprocess
import time
from urllib.parse import urlparse

# ─── proxy ─────────────────────────────────────────────────

_PROXY = None


def set_proxy(url):
    global _PROXY
    _PROXY = url


def _proxy_env():
    if not _PROXY:
        return None
    env = os.environ.copy()
    env["ALL_PROXY"] = _PROXY
    env["HTTP_PROXY"] = _PROXY
    env["HTTPS_PROXY"] = _PROXY
    return env


def _proxy_args():
    return ["--proxy", _PROXY] if _PROXY else []


def _proxy_prefix(cmd):
    if not _PROXY or not cmd:
        return cmd
    base = os.path.basename(cmd[0])
    if base in {"dig", "whois"} and _TORSOCKS:
        return [_TORSOCKS, *cmd]
    return cmd


# ─── tool output decoding ─────────────────────────────────

# Every external CLI writes UTF-8 (or, for the DNS/WHOIS tools, whatever the
# registry replied with). Passing text=True without an explicit encoding makes
# Python decode with the *platform's* preferred codec, which is UTF-8 on
# Linux/macOS but cp1252 on a default Windows install. That silently mangles
# every non-ASCII character a tool returns -- an accented registrant name, a
# non-Latin IDN label, an em dash in a description -- and on bytes cp1252
# cannot represent at all it raises UnicodeDecodeError, turning a working scan
# into an empty one. errors="replace" keeps a mangled byte from escalating into
# a failed lookup, which is the right trade for recon: a slightly wrong
# character beats no result.
_TEXT = {"text": True, "encoding": "utf-8", "errors": "replace"}


def _run_text(cmd, **kwargs):
    """subprocess.run with the decoding policy above applied.

    Centralised so a new call site cannot reintroduce the locale dependency
    by copying an older one.
    """
    kwargs = {**_TEXT, **kwargs}
    return subprocess.run(cmd, capture_output=True, **kwargs)


# ─── tool paths ───────────────────────────────────────────

_TORSOCKS = shutil.which("torsocks")
_HOLEHE  = shutil.which("holehe")
_US      = shutil.which("user-scanner")
_SH      = shutil.which("sherlock")
_MG      = shutil.which("maigret")
_BB      = shutil.which("blackbird") or shutil.which("blackbird.py")
_BB_DIR  = os.path.dirname(_BB) if _BB else None
_PHONEINFOGA = shutil.which("phoneinfoga")
_IGNORANT = shutil.which("ignorant")

# Blackbird is a git clone, not a console script, so it is never on PATH
# even when installed -- these are the layouts its own installer uses.
# The POSIX-only paths are kept (they are the common case on Linux/macOS)
# but the Windows locations are now probed too: pipx on Windows installs
# into %USERPROFILE%\.local\bin or %USERPROFILE%\.pyx\bin, and a manual
# clone lands wherever the user put it. Without these, blackbird is
# unreachable on Windows no matter how it was installed.
#
# Kept as a constant (not inline) so the dashboard's /api/status probe
# and scripts/install_tools.py mirror this list instead of each
# maintaining a forked copy that drifts.
_BB_HOME = os.path.expanduser("~")
_BLACKBIRD_PATHS = (
    "/opt/blackbird/blackbird.py",                              # Linux (git clone)
    os.path.join(_BB_HOME, ".local", "bin", "blackbird", "blackbird.py"),  # pipx-style
    "/opt/homebrew/bin/blackbird.py",                           # macOS (Apple Silicon)
    "/usr/local/bin/blackbird.py",                              # macOS (Intel)
    os.path.join(_BB_HOME, "blackbird", "blackbird.py"),         # manual clone
    os.path.join(_BB_HOME, ".pyx", "bin", "blackbird", "blackbird.py"),  # Windows pipx
)

if not _BB:
    for _p in _BLACKBIRD_PATHS:
        if os.path.isfile(_p):
            _BB = _p
            _BB_DIR = os.path.dirname(_p)
            break

_DIG = shutil.which("dig")
_WHOIS = shutil.which("whois")
_CURL = shutil.which("curl")
_SHODAN = shutil.which("shodan")
_EXIFTOOL = shutil.which("exiftool")


# ─── network helpers ──────────────────────────────────────

def retry_call(fn, attempts=3, base_delay=1.0, max_delay=8.0):
    """Call ``fn`` until it returns something truthy, backing off between tries.

    Every passive source this engine uses is a free third-party endpoint:
    crt.sh, CertSpotter, HackerTarget, Wayback CDX, ip-api, RDAP, RIPEstat.
    They rate-limit hard, and several 5xx under load. With a single attempt
    one 429 or one blip silently removes that source from the result — the
    scan still "succeeds", just with less in it, which is the worst way to
    lose data. `lens_extender/osint.py::_get` already retries the same
    endpoints with backoff; this keeps the two engines degrading alike.

    Only for idempotent GETs against third-party APIs — never for anything
    that touches the target's own network. Returns the first truthy result,
    or None if every attempt came back empty.
    """
    for attempt in range(attempts):
        try:
            out = fn()
            if out:
                return out
        except Exception:
            pass
        if attempt < attempts - 1:
            time.sleep(min(max_delay, base_delay * (2 ** attempt)))
    return None


def _curl_json(url, timeout=15):
    if not _CURL:
        return None

    def _once():
        cmd = [_CURL, "-sS", "-L", "--max-time", str(timeout), url]
        if _PROXY:
            cmd = cmd[:1] + _proxy_args() + cmd[1:]
        try:
            r = _run_text(cmd, timeout=timeout)
            if r.returncode == 0 and r.stdout.strip():
                return json.loads(r.stdout.strip())
        except Exception:
            pass
        return None

    return retry_call(_once)


def _check_tool(name, path):
    if not path:
        from . import display as _ui
        _ui.err(f"{name} not found. Install it and ensure it's in your PATH.")
        return False
    return True


# ─── text / URL helpers ───────────────────────────────────

def safe_name(value) -> str:
    """Make an arbitrary target string safe for use as a filename on any OS.

    Two platform rules bite beyond the character whitelist:

    * Windows reserves a set of device names -- CON, PRN, AUX, NUL, COM1-9,
      LPT1-9 -- in *any* case and *with or without an extension*. They pass
      the whitelist untouched, so "con" survives, and every later open()
      against that path fails on Windows while working fine on macOS and Linux.
      A stem that matches is suffixed instead.
    * macOS and Windows filesystems are case-insensitive by default, so
      "EXAMPLE.COM" and "example.com" name the same file there but two
      different files on Linux. Folding case keeps an export written on
      Windows from overwriting the one next to it.
    """
    s = re.sub(r"[^A-Za-z0-9._+-]+", "_", str(value)).strip("_.")
    s = s or "target"
    # Reserved names are checked on the stem, so "nul.json" is caught too.
    if re.match(r"(?i)^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$", s):
        s = "_" + s
    return s.lower()


def _domain(url):
    p = urlparse(url)
    d = (p.netloc or p.path).lower()
    if ":" in d:
        d = d.split(":")[0]  # strip the port, keep the hostname
    return d[4:] if d.startswith("www.") else d


def _pick(*dicts):
    def _fn(d):
        for dd in dicts:
            if d in dd:
                return dd[d]
        return d
    return _fn


def _run(cmd, timeout=15, stdin="", proxy=True):
    kwargs = dict(capture_output=True, timeout=timeout, input=stdin, **_TEXT)
    cmd = list(cmd)
    if proxy and _PROXY:
        base = os.path.basename(cmd[0]) if cmd else ""
        if base == "curl":
            cmd = cmd[:1] + _proxy_args() + cmd[1:]
        else:
            cmd = _proxy_prefix(cmd)
            kwargs["env"] = _proxy_env()
    try:
        r = subprocess.run(cmd, **kwargs)
        return r.stdout.strip() or r.stderr.strip()
    except Exception as e:
        return str(e)


def _verify(urls, max_workers=30, timeout=10, silent=False):
    if not urls:
        return set()
    if not silent:
        print(f"  [*] Verifying {len(urls)} URLs with curl...", end=" ", flush=True)

    def _check(u):
        try:
            cmd = ["curl", "-s", "-o", os.devnull, "-w", "%{http_code}", u]
            if _PROXY:
                cmd = cmd[:1] + _proxy_args() + cmd[1:]
            r = _run_text(cmd, timeout=timeout)
            code = r.stdout.strip()
            return code.isdigit() and 200 <= int(code) < 400
        except Exception:
            return False

    valid = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        fm = {pool.submit(_check, u): u for u in urls}
        for f in concurrent.futures.as_completed(fm):
            if f.result():
                valid.add(fm[f])
    if not silent:
        print(f"({len(valid)} alive)")
    return valid


# ─── extraction helpers ───────────────────────────────────

def _extract_ips(text):
    return sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)))


def _extract_emails(text):
    return sorted(set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)))


def _extract_phones(text):
    # The lookahead rejects digit runs glued to letters/underscores — e.g. a
    # registry domain ID like "1264983250_DOMAIN_COM-VRSN" is not a phone.
    pats = re.findall(r"\+?\d[\d\s().-]{7,20}(?![\w])", text)
    out = set()
    for p in pats:
        s = p.strip()
        if len(s) < 7:
            continue
        if re.search(r"\d{4}[-/]\d{2}[-/]\d{2}", s):
            continue
        if re.search(r"\d{1,3}(?:\.\d{1,3}){3}", s):
            continue
        digits = re.sub(r"\D", "", s)
        has_plus = s.startswith("+")
        has_sep = bool(re.search(r"[-()]", s))
        if not has_plus and not has_sep and len(digits) < 10:
            continue
        if len(digits) > 15:
            continue
        out.add(s)
    return sorted(out)


def _extract_whois_fields(text):
    """Extract fields from registry (ARIN/RIPE) and domain (IANA/VeriSign) whois.

    Domain registries spell keys differently (``Domain Name``, ``Registrar``,
    ``Creation Date``, ``Name Server``, ``created``, ``organisation``, ...) than
    ARIN/RIPE do. Everything is matched case-insensitively and normalized to a
    canonical display name; repeatable keys (Name Server, Domain Status) are
    joined with commas.
    """
    keys = [
        # registry / IP-whois (ARIN/RIPE)
        "Name", "Organization", "Organisation", "Address", "City", "State",
        "PostalCode", "Country", "Phone", "Fax", "Email", "E-Mail", "Fax No",
        "Tech Email", "Admin Email",
        "Registrant Name", "Registrant Organization", "Registrant Email",
        "Admin Name", "Admin Organization", "Admin Email",
        "Tech Name", "Tech Organization", "Tech Email",
        # domain-whois (IANA thin + VeriSign/PIR full)
        "Domain", "Domain Name", "Registry Domain ID", "Registrar",
        "Registrar IANA ID", "Registrar URL", "Registrar WHOIS Server",
        "Sponsoring Registrar", "Whois Server", "Creation Date", "Updated Date",
        "Registry Expiry Date", "Expiry Date", "Domain Status", "Status",
        "Name Server", "DNSSEC", "Created", "Updated", "Source", "Refer",
    ]
    canon = {
        "Domain Name": "Domain",
        "Organisation": "Organization",
        "E-Mail": "Email",
        "Fax No": "Fax",
        "Created": "Creation Date",
        "Updated": "Updated Date",
        "Expiry Date": "Registry Expiry Date",
    }
    repeat = {"Name Server", "Domain Status"}
    out = {}
    for line in text.split("\n"):
        for k in keys:
            m = re.match(rf"^\s*{re.escape(k)}\s*:\s*(.+)", line, re.IGNORECASE)
            if not m:
                continue
            val = m.group(1).strip()
            key = canon.get(k, k)
            if key in repeat and key in out:
                out[key] = f"{out[key]}, {val}"
            else:
                out[key] = val
            break
    return out
