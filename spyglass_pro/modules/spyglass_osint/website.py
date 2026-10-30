"""Website reconnaissance for Spyglass — light, PASSIVE ONLY.

This module never opens a connection to the target. It resolves basic DNS
records, reads Certificate Transparency logs and queries WHOIS registries,
and stops there. It does not fetch the target's pages, probe its ports,
brute-force paths, or enumerate subdomains by dictionary.

Scope: owner/registrant + WHOIS, basic DNS, and certificate
transparency only. Shodan, the aggregated subdomain sweep and Wayback
history were deleted outright in the 2026-10 cleanup rather than left
dormant in-tree — ``_collect`` below is the whole module.

Active collection lives in a separate project. Everything that used to run
here was removed rather than switched off, so none of it can be re-enabled
by configuration: nmap service detection, gobuster directory and DNS brute
force, httpx probing of discovered hosts, the homepage fetch behind the
fingerprint and content phases, exposure-path checks, the adjacent-host PTR
sweep, and DNS zone-transfer (AXFR) attempts.

Where the line sits: ordinary DNS record lookups (A, MX, NS, TXT, SPF,
DMARC, CNAME) are still made, because no useful host recon exists without
them and every OSINT tool treats them as passive. A zone transfer is a
deliberate attempt to dump a whole zone, so it is not, and it is gone.

What this costs you, stated plainly: no HTTP headers, no TLS certificate or
cipher details, no server/technology fingerprinting, no robots.txt or
sitemap, no page content, no favicon hash, no exposure-path findings and no
zone transfer. All of those require touching the target.

Design principles
-----------------
* No paid APIs and no API keys. The light surface reads crt.sh for
  certificate transparency and the local ``whois``/``dig`` tools.
* OPSEC-aware: HTTP goes through curl (which honors --proxy) to third-party
  hosts only; DNS through ``dig`` is routed via torsocks when a proxy is
  active; in-process DNS resolution is only used when no proxy is set, so the
  operator's resolver is never leaked through Tor.
* dig, curl and whois are auto-detected and skipped cleanly when absent.
"""


from __future__ import annotations

import concurrent.futures
import json
import os
import re
import socket
import urllib.request
from typing import Any

from . import utils
from .utils import (
    _CURL,
    _DIG,
    _WHOIS,
    _check_tool,
    _extract_emails,
    _extract_phones,
    _extract_whois_fields,
    _run,
)

# Generic browser UA so probe traffic blends in with normal clients.
UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

# ─── per-run memoization ───────────────────────────────────
# Cleared at the start of every _collect() so one target's answers never leak
# into the next. Dig/HTTP lookups are cheap to repeat but the same query often
# runs several times in one pass (e.g. host "A" for both the IP set and the
# DNS table), so cache them for the duration of the run.
_DIG_CACHE: dict[str, Any] = {}
_BODY_CACHE: dict[str, Any] = {}


def _reset_caches():
    _DIG_CACHE.clear()
    _BODY_CACHE.clear()


# ─── HTTP layer ───────────────────────────────────────────

def _sh(args, timeout=15, stdin=""):
    """Run a subprocess, honoring the proxy for curl and torsocks for dig."""
    cmd = list(args)
    env = None
    if utils._PROXY:
        base = os.path.basename(cmd[0])
        if base == "curl":
            cmd = cmd[:1] + utils._proxy_args() + cmd[1:]
        else:
            cmd = utils._proxy_prefix(cmd)
            env = utils._proxy_env()
    return utils._run_text(cmd, timeout=timeout, input=stdin, env=env)


def _urllib_get(url, timeout=15, want="body", limit=1_000_000):
    """Native fallback for curl-free machines; honors the configured proxy."""
    try:
        handlers = []
        if utils._PROXY:
            handlers.append(urllib.request.ProxyHandler(
                {"http": utils._PROXY, "https": utils._PROXY}))
        opener = urllib.request.build_opener(*handlers)
        req = urllib.request.Request(url, headers={"User-Agent": UA})  # noqa: S310 - recon target is user-supplied
        with opener.open(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.getheaders()}
            body = resp.read(limit) if want in ("body", "all") else b""
            status = resp.status
        return headers, body.decode("utf-8", "replace"), status
    except Exception:
        return None


def _http_body(url, timeout=15, limit=1_000_000):
    key = (url, limit)
    if key in _BODY_CACHE:
        return _BODY_CACHE[key]

    def _once():
        body = ""
        if _CURL:
            try:
                r = _sh([_CURL, "-sS", "-L", "-A", UA, "--max-time", str(timeout), url])
                if r.returncode == 0 and r.stdout:
                    body = r.stdout[:limit]
            except Exception:
                pass
        if not body:
            got = _urllib_get(url, timeout=timeout, want="body", limit=limit)
            body = got[1] if got else ""
        return body

    # Retry: these are free third-party endpoints (crt.sh, CertSpotter,
    # HackerTarget, Wayback) that rate-limit and 5xx transiently. Without
    # this a single 429 drops the source from the report silently.
    body = utils.retry_call(_once, attempts=3)
    # Only cache a success. Caching the empty string would make one
    # transient failure permanent for the rest of the process, which is
    # strictly worse than not caching at all.
    if body:
        _BODY_CACHE[key] = body
    return body or ""


def _http_json(url, timeout=15):
    body = _http_body(url, timeout=timeout)
    if not body:
        return None
    try:
        return json.loads(body)
    except (ValueError, json.JSONDecodeError):
        return None


# ─── DNS layer (proxy-aware) ──────────────────────────────

def _dig_short(*args, timeout=10):
    """Run ``dig <args> +short`` and return stdout only on success.

    Unlike ``utils._run``, a timeout or a nonzero exit yields ``""`` — dig
    error text must never be mistaken for data (e.g. "dnssec: yes"). Results
    are memoized per run (see _DIG_CACHE).
    """
    if not _DIG:
        return ""
    key = args
    if key in _DIG_CACHE:
        return _DIG_CACHE[key]
    try:
        r = _sh(["dig", *args, "+short"], timeout=timeout)
        val = r.stdout.strip() if r.returncode == 0 else ""
    except Exception:
        val = ""
    _DIG_CACHE[key] = val
    return val


def _resolve_a(host):
    """Resolve A record via dig (proxy/torsocks) or native resolver."""
    if _DIG:
        raw = _dig_short(host, "A")
        for line in raw.split("\n"):
            line = line.strip()
            if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", line):
                return line
    if not utils._PROXY:
        try:
            for res in socket.getaddrinfo(host, None, socket.AF_INET):
                return res[4][0]
        except Exception:
            pass
    return None


def _is_wildcard(host):
    """Detect wildcard DNS by resolving a random subdomain."""
    probe = f"{os.urandom(4).hex()}.{host}"
    ip = _resolve_a(probe)
    return (ip is not None, ip)


def _future_result(fut, default):
    """Safely unwrap a future — a malformed API response must not kill recon."""
    try:
        return fut.result()
    except Exception:
        return default


# ─── certificate transparency ────────────────────────────

def _crt_subs(host):
    subs = set()
    data = _http_json(f"https://crt.sh/?q=%.{host}&output=json&limit=500", timeout=30)
    if isinstance(data, list):
        for entry in data:
            if not isinstance(entry, dict):
                continue
            for name in str(entry.get("name_value", "")).split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name and (name.endswith(f".{host}") or name == host):
                    subs.add(name)
    return subs


def _dns_email_security(host):
    out = {}
    if not _DIG:
        return out
    tx = _dig_short(host, "TXT")
    spf = ""
    for chunk in re.findall(r'"([^"]*)"', tx):
        if chunk.startswith("v=spf1"):
            spf = chunk
            break
    if spf:
        out["spf"] = spf
        out["spf_all"] = _spf_all(spf)
        inc = _spf_includes(spf)
        if inc:
            out["spf_includes"] = ", ".join(inc)
    dmarc_raw = _dig_short(f"_dmarc.{host}", "TXT")
    dmarc = ""
    for chunk in re.findall(r'"([^"]*)"', dmarc_raw):
        if chunk.startswith("v=DMARC1"):
            dmarc = chunk
            break
    if dmarc:
        out["dmarc"] = dmarc
        p = re.search(r"p=(\w+)", dmarc)
        if p:
            out["dmarc_policy"] = p.group(1)
    caa = _dig_short(host, "CAA")
    caa_vals = [ln.strip() for ln in caa.split("\n") if ln.strip()]
    if caa_vals:
        out["caa"] = ", ".join(caa_vals)
    dnskey = _dig_short(host, "DNSKEY")
    out["dnssec"] = "yes" if dnskey.strip() else "no"
    return out


def _spf_all(spf):
    m = re.search(r"([+~?-])all\b", spf)
    if not m:
        return "missing"
    return {"+": "permissive", "~": "softfail", "-": "strict", "?": "neutral"}.get(m.group(1), m.group(1))


def _spf_includes(spf):
    # Underscores are common in SPF targets (_spf.google.com, _smtp._tls).
    return re.findall(r"(?:include|redirect|a|mx):([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})", spf)


# ─── orchestrator ─────────────────────────────────────────

def website(target, display=None):
    out = _collect(target)
    if display:
        display(out)
    return out


def _phase_dns(host):
    """A/AAAA/... records, email security, wildcard DNS."""
    result = {}
    dns = {}
    if _DIG:
        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "CAA", "SOA"):
            raw = _dig_short(host, rtype)
            vals = [ln.strip() for ln in raw.split("\n") if ln.strip()]
            if vals:
                dns[rtype] = ", ".join(vals)
    if dns:
        result["dns_records"] = dns
    try:
        es = _dns_email_security(host)
        if es:
            result["dns_email_security"] = es
    except Exception:
        pass
    try:
        wild, wild_ip = _is_wildcard(host)
        result["wildcard_dns"] = {"detected": "yes" if wild else "no",
                                  "resolves_to": wild_ip or ""}
    except Exception:
        pass
    return result


def _phase_ct(host):
    """Certificate transparency names (crt.sh) — CT, not enumeration.

    Only the certificate-transparency source is read. The aggregated
    subdomain sweep (HackerTarget / CertSpotter / Wayback) was deleted
    with the rest of the infra work rather than left dormant in-tree.
    """
    result = {}
    try:
        names = _crt_subs(host)
    except Exception:
        names = set()
    if names:
        result["ct"] = sorted(names)
    return result


def _phase_whois(host):
    """WHOIS. Follow the IANA thin referral to the registry when present."""
    result = {}
    if _check_tool("whois", _WHOIS):
        wh = _run(["whois", host], timeout=30)
        fields = _extract_whois_fields(wh)
        refer = re.search(r"(?m)^refer:\s*(\S+)", wh)
        if refer:
            # The IANA thin referral describes the TLD (e.g. "Domain: COM"),
            # not the queried domain. Only present it if the registry follow-up
            # fails to return anything about the domain itself.
            full = _run(["whois", "-h", refer.group(1), host], timeout=30)
            full_fields = _extract_whois_fields(full)
            if full_fields:
                wh, fields = full, full_fields
            elif re.search(r"no match", full, re.I):
                wh, fields = "", {"Status": "unregistered (no registry record)"}
            else:
                wh, fields = "", {"Status": "whois unavailable"}
        who_emails = _extract_emails(wh)
        who_phones = _extract_phones(wh)
        whois_data = dict(fields)
        extra_emails = [e for e in who_emails if e not in whois_data.values()]
        if extra_emails:
            whois_data["Extra Emails"] = ", ".join(extra_emails)
        extra_phones = [p for p in who_phones if p not in whois_data.values()]
        if extra_phones:
            whois_data["Extra Phones"] = ", ".join(extra_phones)
        if whois_data:
            result["whois"] = whois_data
    return result


def _collect(target):
    host = utils._domain(target)
    _reset_caches()
    result = {}

    # Light website only: owner/registrant (WHOIS), basic DNS, and
    # certificate transparency. Everything heavier — Shodan, the aggregated
    # subdomain sweep, Wayback history — was deleted rather than disabled.
    # No phase here opens a connection to the target: no page fetch, no
    # port scan, no brute force. See the module docstring.
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        dns_f = pool.submit(_phase_dns, host)
        whois_f = pool.submit(_phase_whois, host)
        ct_f = pool.submit(_phase_ct, host)
        dns = _future_result(dns_f, {})
        whois = _future_result(whois_f, {})
        ct = _future_result(ct_f, {})

    for phase in (dns, whois, ct):
        for key, value in phase.items():
            if not key.startswith("_"):
                result[key] = value

    return result

