"""Website reconnaissance for Spyglass — PASSIVE ONLY.

This module never opens a connection to the target. It resolves DNS,
Certificate Transparency logs, WHOIS registries, the Wayback Machine and
Shodan, and stops there. It does not fetch the target's pages, probe its
ports, brute-force paths, or enumerate subdomains by dictionary.

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
* No paid APIs and no API keys. Passive sources are crt.sh, CertSpotter,
  HackerTarget and the Wayback Machine CDX index.
* OPSEC-aware: HTTP goes through curl (which honors --proxy) to third-party
  hosts only; DNS through ``dig`` is routed via torsocks when a proxy is
  active; in-process DNS resolution is only used when no proxy is set, so the
  operator's resolver is never leaked through Tor.
* dig, curl, whois and shodan are auto-detected and skipped cleanly when
  absent.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import re
import socket
import subprocess
import urllib.parse
import urllib.request

from . import utils
from .utils import (
    _CURL,
    _DIG,
    _SHODAN,
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
_DIG_CACHE = {}
_BODY_CACHE = {}


def _reset_caches():
    _DIG_CACHE.clear()
    _BODY_CACHE.clear()

# A larger bundled subdomain list than the original ~100 names. A SecLists
# checkout on disk wins when present; otherwise this stays the fallback.
_SUB_LIST = [
    "www", "mail", "email", "smtp", "imap", "pop", "pop3", "webmail",
    "mx", "mx1", "mx2", "mx3", "ns", "ns1", "ns2", "ns3", "ns4",
    "dns", "dns1", "dns2", "dns3", "dns4", "ftp", "sftp", "ssh",
    "git", "gitlab", "github", "svn", "cvs", "vpn", "vpn1", "vpn2",
    "remote", "secure", "login", "sso", "id", "oauth", "auth", "signin",
    "signup", "register", "account", "accounts", "admin", "administrator",
    "adm", "panel", "control", "manage", "management", "dashboard",
    "cpanel", "webmail2", "mail2", "smtp2", "relay", "gateway", "portal",
    "my", "apps", "app", "api", "api1", "api2", "api3", "dev",
    "developer", "developers", "dev1", "dev2", "stage", "staging", "test",
    "test1", "test2", "testing", "qa", "uat", "beta", "alpha", "demo",
    "sandbox", "preview", "review", "canary", "prod", "production", "www1",
    "www2", "www3", "www4", "web", "web1", "web2", "web3", "static",
    "static1", "static2", "assets", "assets1", "cdn", "cdn1", "cdn2",
    "cdn3", "img", "images", "image", "media", "video", "videos", "audio",
    "download", "downloads", "dl", "files", "file", "upload", "uploads",
    "docs", "documentation", "doc", "support", "help", "helpdesk", "status",
    "health", "check", "monitor", "monitoring", "metrics", "grafana",
    "kibana", "logs", "log", "analytics", "stats", "statistics", "report",
    "reports", "data", "db", "database", "sql", "mysql", "postgres",
    "redis", "mongo", "cache", "memcached", "elastic", "search", "solr",
    "es", "backup", "backups", "snapshot", "archive", "archived", "old",
    "legacy", "blog", "news", "articles", "forum", "forums", "community",
    "wiki", "knowledge", "base", "kb", "docs1", "shop", "store", "shopify",
    "cart", "checkout", "pay", "payment", "payments", "billing", "invoice",
    "invoices", "billing2", "accounting", "finance", "jobs", "job", "career",
    "careers", "hr", "human", "resources", "recruiting", "talent", "about",
    "contact", "team", "press", "media2", "investor", "investors", "partners",
    "partner", "affiliate", "marketing", "advertise", "ads", "advertising",
    "legal", "privacy", "terms", "security", "trust", "policies", "policy",
    "compliance", "audit", "certifications", "cert", "certificate", "licenses",
    "license", "brand", "events", "calendar", "maps", "map", "locations",
    "location", "store2", "stores", "locator",
]





# (name, {header: regex}, [body regex]) — lightweight Wappalyzer-style sniffing.


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
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          input=stdin, env=env)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _urllib_get(url, timeout=15, want="body", limit=1_000_000, follow=True):
    """Native fallback for curl-free machines; honors the configured proxy."""
    try:
        handlers = []
        if utils._PROXY:
            handlers.append(urllib.request.ProxyHandler(
                {"http": utils._PROXY, "https": utils._PROXY}))
        if not follow:
            handlers.append(_NoRedirect())
        opener = urllib.request.build_opener(*handlers)
        req = urllib.request.Request(url, headers={"User-Agent": UA})  # noqa: S310 - recon target is user-supplied
        with opener.open(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.getheaders()}
            body = resp.read(limit) if want in ("body", "all") else b""
            status = resp.status
        return headers, body.decode("utf-8", "replace"), status
    except Exception:
        return None


def _parse_headers_block(text):
    """Parse the final header block from curl -D output.

    ``Set-Cookie`` is the one header that legitimately repeats; it is joined
    with newlines so every cookie survives instead of the last one winning.
    """
    headers = {}
    blocks = re.split(r"\r?\n\r?\n", text.strip())
    if not blocks:
        return headers
    for line in blocks[-1].splitlines():
        if ":" not in line or line.startswith(("HTTP/", "curl:")):
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        if key == "set-cookie":
            headers[key] = (headers.get(key, "") + "\n" + value.strip()).strip("\n")
        else:
            headers[key] = value.strip()
    return headers


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


def _http_status(url, timeout=15, follow=True):
    if _CURL:
        try:
            args = [_CURL, "-sS", "-o", os.devnull, "-w", "%{http_code}",
                    "-A", UA, "--max-time", str(timeout)]
            if follow:
                args.append("-L")
            args.append(url)
            r = _sh(args)
            if r.returncode == 0 and r.stdout.strip().isdigit():
                return int(r.stdout.strip())
        except Exception:
            pass
    got = _urllib_get(url, timeout=timeout, want="headers", follow=follow)
    return got[2] if got else 0


def _http_bytes(url, timeout=10, limit=512 * 1024):
    """Fetch raw bytes (for favicons); curl-only, best-effort."""
    if not _CURL:
        return None
    try:
        cmd = [_CURL, "-sS", "-L", "-A", UA, "--max-time", str(timeout), url]
        if utils._PROXY:
            cmd = cmd[:1] + utils._proxy_args() + cmd[1:]
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        if r.returncode == 0 and r.stdout:
            return r.stdout[:limit]
    except Exception:
        pass
    return None


def _http_json(url, timeout=15):
    body = _http_body(url, timeout=timeout)
    if not body:
        return None
    try:
        return json.loads(body)
    except (ValueError, json.JSONDecodeError):
        return None


# ─── DNS layer (proxy-aware) ──────────────────────────────

def _is_ipv4(s):
    try:
        socket.inet_pton(socket.AF_INET, s)
        return True
    except (OSError, ValueError):
        return False


def _is_ipv6(s):
    try:
        socket.inet_pton(socket.AF_INET6, s)
        return True
    except (OSError, ValueError):
        return False


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


def _reverse_dns(ip):
    """PTR lookup via dig (proxy) or native resolver."""
    if _DIG:
        raw = _dig_short("-x", ip)
        val = raw.split("\n")[0].strip().rstrip(".")
        if val and val != ".":
            return val
    if not utils._PROXY:
        try:
            return socket.gethostbyaddr(ip)[0]
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


# ─── subdomain sources ────────────────────────────────────

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


def _certspotter_subs(host):
    """Certificate Transparency via CertSpotter — free, no key."""
    subs = set()
    data = _http_json(
        f"https://api.certspotter.com/v1/issuances?domain={host}"
        f"&include_subdomains=true&expand=dns_names"
    )
    if isinstance(data, list):
        for entry in data:
            if not isinstance(entry, dict):
                continue
            for name in entry.get("dns_names", []):
                name = str(name).strip().lower().lstrip("*.")
                if name and (name.endswith(f".{host}") or name == host):
                    subs.add(name)
    return subs


def _hackertarget_subs(host):
    """Returns (subs, ips). Free, no key, rate-limited per source IP."""
    subs, ips = set(), set()
    body = _http_body(f"https://api.hackertarget.com/hostsearch/?q={host}")
    if not body or "error" in body.lower() or "api count" in body.lower():
        return subs, ips
    for line in body.splitlines():
        line = line.strip()
        if "," not in line:
            continue
        sub, ip = line.split(",", 1)
        sub = sub.strip().lower().lstrip("*.")
        if sub and (sub.endswith(f".{host}") or sub == host):
            subs.add(sub)
            if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ip.strip()):
                ips.add(ip.strip())
    return subs, ips


def _wayback_cdx(host):
    """One CDX query with matchType=domain: subdomains + snapshot history."""
    out = {"subs": set(), "first": "", "last": "", "count": 0}
    url = (
        f"https://web.archive.org/cdx/search/cdx?url={host}&matchType=domain"
        f"&output=json&fl=timestamp,original,statuscode"
        f"&filter=statuscode:200&collapse=urlkey&limit=3000"
    )
    data = _http_json(url, timeout=30)
    if not isinstance(data, list) or len(data) < 2:
        return out
    stamps = []
    for row in data[1:]:
        if not isinstance(row, list) or len(row) < 2:
            continue
        stamps.append(row[0])
        original = str(row[1])
        parsed = urllib.parse.urlparse(original if "://" in original else f"//{original}")
        h = (parsed.hostname or "").lower()
        if h and (h.endswith(f".{host}") or h == host):
            out["subs"].add(h)
    if stamps:
        out["first"] = min(stamps)
        out["last"] = max(stamps)
        out["count"] = len(stamps)
    return out


# ─── fingerprinting ───────────────────────────────────────

# ─── content discovery ────────────────────────────────────


# ─── DNS email security ───────────────────────────────────

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
    """A/AAAA/... records, email security, wildcard DNS, zone transfer."""
    result = {}
    ips = set()
    dns = {}
    if _DIG:
        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "CAA", "SOA"):
            raw = _dig_short(host, rtype)
            vals = [ln.strip() for ln in raw.split("\n") if ln.strip()]
            if vals:
                dns[rtype] = ", ".join(vals)
            if rtype in ("A", "AAAA"):
                for line in vals:
                    # `dig +short` can emit a CNAME target alongside the A
                    # record; only keep addresses so PTR/sweep/scans stay valid.
                    line = line.rstrip(".")
                    if _is_ipv4(line) or _is_ipv6(line):
                        ips.add(line)
    if dns:
        result["dns_records"] = dns
    try:
        es = _dns_email_security(host)
        if es:
            result["dns_email_security"] = es
    except Exception:
        pass
    wild, wild_ip = False, ""
    try:
        wild, wild_ip = _is_wildcard(host)
        result["wildcard_dns"] = {"detected": "yes" if wild else "no",
                                  "resolves_to": wild_ip or ""}
    except Exception:
        pass
    result["_ips"] = ips
    result["_wild"] = wild
    result["_wild_ip"] = wild_ip
    return result


def _phase_passive_subs(host):
    """Passive subdomain sources (crt.sh, HackerTarget, CertSpotter, Wayback)."""
    result = {}
    passive_subs, passive_ips = set(), set()
    sources = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        crt_f = pool.submit(_crt_subs, host)
        ht_f = pool.submit(_hackertarget_subs, host)
        cs_f = pool.submit(_certspotter_subs, host)
        wb_f = pool.submit(_wayback_cdx, host)
        crt = _future_result(crt_f, set())
        ht_subs, ht_ips = _future_result(ht_f, (set(), set()))
        cs = _future_result(cs_f, set())
        wb = _future_result(wb_f, {"subs": set(), "first": "", "last": "", "count": 0})
    passive_subs |= crt | ht_subs | cs | wb.get("subs", set())
    passive_ips |= ht_ips
    sources["crt_sh"] = len(crt)
    sources["hackertarget"] = len(ht_subs)
    sources["certspotter"] = len(cs)
    sources["wayback"] = len(wb.get("subs", set()))
    result["_passive_subs"] = passive_subs
    result["_passive_ips"] = passive_ips
    result["_sources"] = sources
    result["_crt"] = crt
    result["_wb"] = wb
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


def _phase_shodan_ports(ips):
    """Shodan host data + reverse DNS. Both read third-party sources."""
    result = {}
    if ips and _check_tool("shodan", _SHODAN):
        shodan_data = []
        for ip in ips[:3]:
            try:
                r = subprocess.run(["shodan", "host", ip], capture_output=True,  # noqa: S607 - PATH-checked tool
                                   text=True, timeout=20, env=utils._proxy_env())
            except Exception as exc:
                shodan_data.append(f"{ip}: {exc}")
                continue
            data, err = r.stdout.strip(), r.stderr.strip()
            if data:
                org = isp = country = ports = ""
                for line in data.split("\n"):
                    low = line.lower()
                    if "organization" in low or low.startswith("org:"):
                        org = line.split(":", 1)[1].strip() if ":" in line else ""
                    elif "isp" in low:
                        isp = line.split(":", 1)[1].strip() if ":" in line else ""
                    elif "country" in low:
                        country = line.split(":", 1)[1].strip() if ":" in line else ""
                    elif "ports" in low:
                        ports = line.split(":", 1)[1].strip() if ":" in line else ""
                parts = [p for p in (f"Org: {org}" if org else "",
                                     f"ISP: {isp}" if isp else "",
                                     f"Country: {country}" if country else "",
                                     f"Ports: {ports}" if ports else "") if p]
                shodan_data.append(f"{ip}: {' | '.join(parts)}" if parts else f"{ip}: No Shodan data")
            elif "403" in err:
                shodan_data.append(f"{ip}: Free tier limit")
            elif "init" in err.lower():
                shodan_data.append(f"{ip}: Shodan not configured")
            elif err:
                shodan_data.append(f"{ip}: {err.splitlines()[-1]}")
            else:
                shodan_data.append(f"{ip}: No Shodan data")
        result["shodan"] = shodan_data

    if ips:
        try:
            rdns = []
            for ip in ips[:8]:
                name = _reverse_dns(ip)
                if name:
                    rdns.append(f"{ip} -> {name}")
            if rdns:
                result["reverse_dns"] = rdns
        except Exception:
            pass
    return result


def _collect(target):
    host = utils._domain(target)
    _reset_caches()
    result = {}

    # Every phase here reads third-party sources (DNS, Certificate Transparency,
    # WHOIS registries, Shodan). Nothing in this module opens a connection to
    # the target: no page fetch, no port scan, no brute force. See the
    # "Passive-only" note in the module docstring.
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        dns_f = pool.submit(_phase_dns, host)
        subs_f = pool.submit(_phase_passive_subs, host)
        whois_f = pool.submit(_phase_whois, host)
        dns = _future_result(dns_f, {})
        subs = _future_result(subs_f, {})
        whois = _future_result(whois_f, {})

    for phase in (dns, subs, whois):
        for key, value in phase.items():
            if not key.startswith("_"):
                result[key] = value

    # State the dependent phase needs.
    ips = sorted(set(dns.get("_ips", set())) | set(subs.get("_passive_ips", set())))

    scan = _phase_shodan_ports(ips)
    for key, value in scan.items():
        result[key] = value

    # Subdomain assembly — passive sources only.
    passive_subs = subs.get("_passive_subs", set())
    sources = dict(subs.get("_sources", {}))
    all_subs = sorted(passive_subs)
    if all_subs:
        result["subdomains"] = all_subs
        result["subdomain_sources"] = sources
    crt = subs.get("_crt", set())
    if crt:
        result["crt_sh_subdomains"] = sorted(crt)
    wb = subs.get("_wb", {})
    if wb.get("subs"):
        result["wayback_subdomains"] = sorted(wb["subs"])

    # Wayback history (from the CDX call in stage 1).
    if wb.get("first"):
        result["history"] = {
            "first_snapshot": wb["first"],
            "last_snapshot": wb["last"],
            "snapshot_count": wb["count"],
        }

    return result

