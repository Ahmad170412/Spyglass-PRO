#!/usr/bin/env python3
import concurrent.futures
import re
import sys

from . import utils
from .breach import check as _breach_check
from .utils import _BB, _BB_DIR, _HOLEHE, _US, _check_tool, _domain, _pick, _proxy_args, _proxy_env, _verify

# ─── tool runners ─────────────────────────────────────────

def _holehe(email):
    if not _check_tool("holehe", _HOLEHE):
        return set()
    try:
        r = utils._run_text(
            [_HOLEHE, email, "--only-used"],
            timeout=120,
            env=_proxy_env(),
        )
    except Exception:
        return set()
    out = set()
    for line in r.stdout.split("\n"):
        line = line.strip()
        if line.startswith("[+] "):
            d = line[4:].strip()
            if d and "." in d and " " not in d:
                out.add(d.lower())
    return out


def _us_email(email):
    if not _check_tool("user-scanner", _US):
        return {}
    try:
        r = utils._run_text(
            [_US, "-e", email, "-v", "--only-found"],
            timeout=120, input="n\n",
            env=_proxy_env(),
        )
    except Exception:
        return {}
    out = {}
    for line in r.stdout.split("\n"):
        m = re.search(r"\[(https?://[^\]]+)\]", line)
        if m:
            u = m.group(1)
            out[_domain(u)] = u
    return out


def _blackbird_email(email):
    if not _check_tool("blackbird", _BB):
        return {}
    bb_cmd = [sys.executable, _BB, "-e", email, "--no-update", "--no-nsfw"]
    if utils._PROXY:
        bb_cmd += _proxy_args()
    try:
        r = utils._run_text(
            bb_cmd,
            timeout=120, cwd=_BB_DIR,
            env=_proxy_env(),
        )
    except Exception:
        return {}
    out = {}
    for i, line in enumerate(r.stdout.split("\n")):
        m = re.search(r"✔️\s+\[([^\]]+)\]\s*(https?://\S+)?", line)
        if m:
            url = m.group(2)
            if not url and i + 1 < len(r.stdout.split("\n")):
                nxt = re.search(r"(https?://\S+)", r.stdout.split("\n")[i + 1])
                if nxt:
                    url = nxt.group(1)
            if url:
                out[_domain(url)] = url
    return out


# ─── public API ───────────────────────────────────────────

def email(target):
    """Run holehe + user-scanner + blackbird on an email in parallel.

    Returns:
        both           - sites confirmed by >=2 tools
        holehe_only    - only holehe flagged it
        user_scanner_only
        blackbird_only
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        h_fut  = pool.submit(_holehe, target)
        u_fut  = pool.submit(_us_email, target)
        bb_fut = pool.submit(_blackbird_email, target)
        br_fut = pool.submit(_breach_check, target, "email")
        h  = h_fut.result()
        u  = u_fut.result()
        bb = bb_fut.result()
        br = br_fut.result()

    if u:
        alive = _verify(set(u.values()), silent=True)
        u = {d: url for d, url in u.items() if url in alive}
    if bb:
        alive = _verify(set(bb.values()), silent=True)
        bb = {d: url for d, url in bb.items() if url in alive}

    uk  = set(u)
    bsk = set(bb)
    get = _pick(u, bb)

    both = (h & uk) | (h & bsk) | (uk & bsk)

    # Per-row provenance: which engines actually matched this domain. The
    # bucket alone only says "one" or "2+", which cannot be shown as a tool
    # name in the UI. Listing the exact set keeps the display honest without
    # changing the bucket contract older runs and exports already use.
    def engines(domain):
        return [name for name, members in (
            ("holehe", h), ("user-scanner", uk), ("blackbird", bsk),
        ) if domain in members]

    return {
        "both":             [{"domain": d, "url": get(d), "engines": engines(d)}
                             for d in sorted(both)],
        "holehe_only":      [{"domain": d, "engines": engines(d)}
                             for d in sorted(h - uk - bsk)],
        "user_scanner_only":[{"domain": d, "url": u[d], "engines": engines(d)}
                             for d in sorted(uk - h - bsk)],
        "blackbird_only":   [{"domain": d, "url": bb[d], "engines": engines(d)}
                             for d in sorted(bsk - h - uk)],
        "breach":           br,
    }
