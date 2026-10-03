"""Passive OSINT lookups. None of these connect to the target directly."""

import ipaddress
import logging
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from urllib.parse import quote

import httpx

logger = logging.getLogger("lens_extender.osint")

_USER_AGENTS = [
    # User-agent strings must stay on one line (sent verbatim).
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",  # noqa: E501
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
]

_SECRET_PATTERN = re.compile(
    r"(api[_-]?key|password|passwd|secret|token|key)\s*=\s*[^&\s\"']+|Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*",
    re.IGNORECASE,
)


def _sanitize(text: str) -> str:
    def _repl(m):
        g = m.group(0)
        if g.lower().startswith("bearer"):
            return "Bearer [REDACTED]"
        eq = g.find("=")
        if eq != -1:
            return g[: eq + 1] + "[REDACTED]"
        colon = g.find(":")
        if colon != -1:
            return g[: colon + 1] + " [REDACTED]"
        return "[REDACTED]"

    return _SECRET_PATTERN.sub(_repl, str(text))


def _clean(text) -> str:
    return _sanitize(str(text)).replace("[", "\\[")


@dataclass
class OsintResult:
    target: str
    input_type: str = "ip"  # "ip" or "domain"
    resolved_ip: str = ""
    domain: str = ""
    geo: dict = field(default_factory=dict)
    rdap: dict = field(default_factory=dict)
    reverse_dns: str = ""
    fcrdns: str = ""
    shodan: dict | None = None
    internetdb: dict | None = None
    certs: list = field(default_factory=list)
    vulns: list = field(default_factory=list)
    ripestat: dict = field(default_factory=dict)
    greynoise: dict = field(default_factory=dict)
    dnsbl: list = field(default_factory=list)
    dns_records: dict = field(default_factory=dict)
    cohosted: list = field(default_factory=list)
    abuseipdb: dict = field(default_factory=dict)
    virustotal: dict = field(default_factory=dict)
    whois_domain: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)


def _get_client(config: dict) -> httpx.Client:
    """Create an httpx client with proxy, User-Agent, and retry settings."""
    proxy = config.get("proxy", "") or config.get("socks_proxy", "")
    import random

    ua = random.choice(_USER_AGENTS)
    transport_kwargs = {"follow_redirects": True}
    if proxy:
        transport_kwargs["proxy"] = proxy
    client = httpx.Client(
        follow_redirects=True,
        headers={"User-Agent": ua},
        timeout=20,
        **({"proxy": proxy} if proxy else {}),
    )
    return client


def _get(client: httpx.Client, url: str, params: dict | None = None, retries: int = 3) -> dict:
    last_exc: BaseException | None = None
    for attempt in range(retries):
        try:
            response = client.get(url, params=params, timeout=20)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as exc:
            last_exc = exc
            status = exc.response.status_code
            if status == 429:
                wait = min(30, 2 ** (attempt + 1))
                logger.warning("Rate limited on %s, waiting %ds", url, wait)
                time.sleep(wait)
                continue
            if status >= 500 and attempt < retries - 1:
                time.sleep(1 * (attempt + 1))
                continue
            raise
        except (httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout) as exc:
            last_exc = exc
            if attempt < retries - 1:
                time.sleep(1 * (attempt + 1))
                continue
            raise
    raise last_exc  # type: ignore[misc]


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_nvd_interval = [6.5]
_last_nvd_request = [0.0]


def _nvd_get(client: httpx.Client, params: dict, nvd_api_key: str = "") -> dict:
    interval = 0.6 if nvd_api_key else _nvd_interval[0]
    wait = interval - (time.monotonic() - _last_nvd_request[0])
    if wait > 0:
        time.sleep(wait)
    _last_nvd_request[0] = time.monotonic()
    headers = {}
    if nvd_api_key:
        headers["apiKey"] = nvd_api_key
    try:
        response = client.get(NVD_URL, params=params, headers=headers, timeout=20)
        response.raise_for_status()
        return response.json()
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code not in (429, 403):
            raise
        time.sleep(interval * 2)
        _last_nvd_request[0] = time.monotonic()
        response = client.get(NVD_URL, params=params, headers=headers, timeout=20)
        response.raise_for_status()
        return response.json()


def reverse_dns(ip: str, timeout: float = 5.0) -> str:
    try:
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(socket.gethostbyaddr, ip)
            return future.result(timeout=timeout)[0]
    except (concurrent.futures.TimeoutError, socket.herror, socket.gaierror, OSError):
        return ""


def resolve_domain(domain: str) -> str:
    """Resolve a domain to its A record IP address."""
    try:
        with httpx.Client(follow_redirects=True, timeout=10) as client:
            data = _get(
                client,
                "https://dns.google/resolve",
                {"name": domain, "type": "A"},
            )
            answers = data.get("Answer", [])
            for a in answers:
                if a.get("type") == 1:
                    return a.get("data", "")
    except Exception:
        pass
    try:
        return socket.gethostbyname(domain)
    except (socket.gaierror, OSError):
        return ""


def geo_lookup(client: httpx.Client, ip: str) -> dict:
    fields = "status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query"  # noqa: E501
    data = _get(client, f"http://ip-api.com/json/{ip}", {"fields": fields})
    if data.get("status") != "success":
        raise ValueError(f"GeoIP: {data.get('message', 'lookup failed')} ({data.get('status')})")
    return data


def rdap_lookup(client: httpx.Client, ip: str) -> dict:
    data = _get(client, f"https://rdap.org/ip/{ip}")
    emails = []
    registrant = ""
    for entity in data.get("entities", []):
        vcard = entity.get("vcardArray", [])
        if len(vcard) > 1:
            for item in vcard[1]:
                if item[0] == "email":
                    emails.append(item[3])
                if item[0] == "fn" and not registrant:
                    registrant = item[3]
        for sub in entity.get("entities", []):
            svcard = sub.get("vcardArray", [])
            if len(svcard) > 1:
                for item in svcard[1]:
                    if item[0] == "email":
                        emails.append(item[3])
    abuse = [e for e in emails if "abuse" in e.lower()]
    chosen = list(dict.fromkeys(abuse or emails))
    created = updated = ""
    for event in data.get("events", []):
        action = event.get("eventAction", "").lower()
        date = event.get("eventDate", "")[:10]
        if action == "registration" and not created:
            created = date
        elif action in ("last changed", "last update", "last modification") and not updated:
            updated = date
    return {
        "handle": data.get("handle", ""),
        "name": data.get("name", ""),
        "range": data.get("startAddress", "") + " - " + data.get("endAddress", ""),
        "abuse_contact": ", ".join(chosen[:3]),
        "registrant": registrant,
        "type": data.get("type", ""),
        "country": data.get("country", ""),
        "parent_handle": data.get("parentHandle", {}).get("handle", "")
        if isinstance(data.get("parentHandle"), dict)
        else str(data.get("parentHandle", "")),
        "status": ", ".join(data.get("status", []) or []),
        "created": created,
        "updated": updated,
    }


def domain_whois_lookup(client: httpx.Client, domain: str) -> dict:
    """Look up domain WHOIS via RDAP."""
    try:
        data = _get(client, f"https://rdap.org/domain/{domain}")
    except Exception:
        return {}
    registrant = ""
    emails = []
    for entity in data.get("entities", []):
        vcard = entity.get("vcardArray", [])
        if len(vcard) > 1:
            for item in vcard[1]:
                if item[0] == "fn" and not registrant:
                    registrant = item[3]
                if item[0] == "email":
                    emails.append(item[3])
    statuses = data.get("status", []) or []
    events = {}
    for event in data.get("events", []):
        action = event.get("eventAction", "").lower()
        date = event.get("eventDate", "")[:10]
        if action not in events:
            events[action] = date
    nameservers = [ns.get("ldhName", "") for ns in data.get("nameservers", [])]
    return {
        "name": data.get("ldhName", domain),
        "registrant": registrant,
        "emails": emails[:5],
        "status": statuses,
        "created": events.get("registration", ""),
        "expires": events.get("expiration", ""),
        "updated": events.get("last changed", "") or events.get("last update of RDAP database", ""),
        "nameservers": nameservers[:10],
    }


def shodan_lookup(client: httpx.Client, ip: str, api_key: str) -> dict:
    return _get(client, f"https://api.shodan.io/shodan/host/{ip}", {"key": api_key})


def internetdb_lookup(client: httpx.Client, ip: str) -> dict | None:
    response = client.get(f"https://internetdb.shodan.io/{ip}", timeout=15)
    if response.status_code == 404:
        return None
    response.raise_for_status()
    return response.json()


def crtsh_lookup(client: httpx.Client, domain: str) -> list:
    domain = quote(domain, safe=".")
    data: list[dict] = []
    for attempt in range(3):
        try:
            raw = _get(client, "https://crt.sh/", {"q": domain, "output": "json"})
            data = raw if isinstance(raw, list) else []  # crt.sh returns a JSON array
            break
        except httpx.HTTPStatusError:
            if attempt == 2:
                raise
            time.sleep(1)
    seen, certs = set(), []
    for entry in data:
        name = entry.get("name_value", "").replace("\n", ", ")
        key = (name, entry.get("issuer_name", ""))
        if key in seen:
            continue
        seen.add(key)
        certs.append(
            {
                "names": name,
                "issuer": entry.get("issuer_name", ""),
                "not_before": entry.get("not_before", "")[:10],
                "not_after": entry.get("not_after", "")[:10],
            }
        )
    return certs


def _parse_cve(cve: dict) -> dict:
    metrics = cve.get("metrics", {})
    score, severity = None, "UNKNOWN"
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            cvss = metrics[key][0]["cvssData"]
            score = cvss.get("baseScore")
            severity = cvss.get("baseSeverity", severity)
            break
    return {
        "id": cve.get("id", ""),
        "severity": severity,
        "score": score,
        "description": next(
            (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
            "",
        )[:500],
    }


def nvd_by_id(client: httpx.Client, cve_id: str, nvd_api_key: str = "") -> dict | None:
    data = _nvd_get(client, {"cveId": cve_id}, nvd_api_key)
    items = data.get("vulnerabilities", [])
    return _parse_cve(items[0]["cve"]) if items else None


def ripestat_lookup(client: httpx.Client, ip: str) -> dict:
    data = _get(client, "https://stat.ripe.net/data/prefix-overview/data.json", {"resource": ip})
    d = data.get("data", {})
    asns = [f"AS{a.get('asn', '?')} {a.get('holder', '')}".strip() for a in d.get("asns", [])]
    result = {
        "prefix": d.get("prefix", ""),
        "asns": asns,
        "holder": d.get("holder", ""),
        "announced": d.get("announced", None),
        "type": d.get("type", ""),
        "block": d.get("block", {}),
        "neighbours": [],
    }
    primary_asn = None
    for entry in d.get("asns", []):
        asn = entry.get("asn")
        if asn:
            primary_asn = asn
            break
    if primary_asn:
        try:
            nb_data = _get(
                client,
                "https://stat.ripe.net/data/asn-neighbors/data.json",
                {"resource": primary_asn},
            )
            neighbours = nb_data.get("data", {}).get("neighbors", []) or nb_data.get("data", {}).get("neighbours", [])
            result["neighbours"] = [f"AS{n.get('asn', '?')} ({n.get('type', 'peer')})" for n in neighbours[:10]]
        except Exception as exc:
            logger.debug("RIPEstat neighbour lookup failed: %s", exc)
        if not result["neighbours"]:
            try:
                rs_data = _get(
                    client,
                    "https://stat.ripe.net/data/routing-status/data.json",
                    {"resource": ip},
                )
                vis = rs_data.get("data", {}).get("visibility", "")
                if vis:
                    result["visibility"] = vis
            except Exception as exc:
                logger.debug("RIPEstat routing-status lookup failed: %s", exc)
    return result


def greynoise_lookup(client: httpx.Client, ip: str) -> dict:
    response = client.get(f"https://api.greynoise.io/v3/community/{ip}", timeout=15)
    if response.status_code == 404:
        return {}
    response.raise_for_status()
    data = response.json()
    if "message" in data and "classification" not in data:
        return {}
    return {
        "ip": data.get("ip", ip),
        "noise": data.get("noise", False),
        "riot": data.get("riot", False),
        "classification": data.get("classification", "unknown"),
        "name": data.get("name", ""),
        "link": data.get("link", ""),
        "last_seen": data.get("last_seen", ""),
        "message": data.get("message", ""),
    }


def abuseipdb_lookup(client: httpx.Client, ip: str, api_key: str) -> dict:
    if not api_key:
        return {}
    data = _get(
        client,
        "https://api.abuseipdb.com/api/v2/check",
        {
            "ipAddress": ip,
            "maxAgeInDays": "90",
        },
        retries=2,
    )
    return data.get("data", {})


def virustotal_lookup(client: httpx.Client, ip: str, api_key: str) -> dict:
    if not api_key:
        return {}
    try:
        response = client.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": api_key},
            timeout=20,
        )
        response.raise_for_status()
        data = response.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "harmless": stats.get("harmless", 0),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attrs.get("reputation", 0),
            "tags": attrs.get("tags", []),
        }
    except Exception as exc:
        logger.debug("VirusTotal lookup failed: %s", exc)
        return {}


DNSBL_ZONES = (
    ("zen.spamhaus.org", "Spamhaus"),
    ("b.barracudacentral.org", "Barracuda"),
    ("bl.spamcop.net", "SpamCop"),
    ("dnsbl.sorbs.net", "SORBS"),
    ("spam.dnsbl.sorbs.net", "SORBS-Spam"),
    ("bl.spamrats.com", "SpamRats"),
    ("noptr.spamrats.com", "SpamRats-NoPtr"),
    ("spamrbl.ipstorm.com", "IPStorm"),
    ("dyna.spamrats.com", "SpamRats-Dyn"),
    ("dnsbl.dronebl.org", "DroneBL"),
)


def is_ipv4(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).version == 4
    except ValueError:
        return False


_SPAMHAUS_DETAILS = {
    "127.0.0.2": "SBL (spam source)",
    "127.0.0.3": "CSS (snowshoe spam)",
    "127.0.0.4": "XBL (exploited host)",
    "127.0.0.5": "SBL+CSS",
    "127.0.0.6": "SBL+XBL",
    "127.0.0.7": "SBL+CSS+XBL",
    "127.0.0.9": "SBL+CSS",
    "127.0.0.10": "PBL (policy blocklist)",
    "127.0.0.11": "PBL+SBL",
}


def dnsbl_check(ip: str) -> list:
    if not is_ipv4(ip):
        return []
    reversed_ip = ".".join(reversed(ip.split(".")))
    listed = []

    def _check_zone(zone, name):
        try:
            answer = socket.gethostbyname(f"{reversed_ip}.{zone}")
            if answer.startswith("127.255."):
                return None
            if answer.startswith("127.0.0."):
                if zone == "zen.spamhaus.org" and answer in _SPAMHAUS_DETAILS:
                    return f"{name} [{_SPAMHAUS_DETAILS[answer]}]"
                else:
                    return f"{name} ({answer})" if answer != "127.0.0.2" else name
        except (socket.gaierror, OSError):
            pass
        return None

    with ThreadPoolExecutor(max_workers=len(DNSBL_ZONES)) as pool:
        futures = {pool.submit(_check_zone, z, n): n for z, n in DNSBL_ZONES}
        for future in as_completed(futures):
            result = future.result()
            if result:
                listed.append(result)
    return listed


def dns_records(client: httpx.Client, domain: str) -> dict:
    records = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
        try:
            data = _get(client, "https://dns.google/resolve", {"name": domain, "type": rtype})
            answers = [a.get("data", "") for a in data.get("Answer", [])]
            if answers:
                records[rtype] = answers[:5]
        except Exception as exc:
            logger.debug("DoH lookup for %s %s failed: %s", domain, rtype, exc)
    return records


def cohosted_lookup(client: httpx.Client, ip: str) -> list:
    response = client.get("https://api.hackertarget.com/reverseiplookup/", params={"q": ip}, timeout=15)
    response.raise_for_status()
    text = response.text
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    lower = text.strip().lower()
    if len(lines) <= 2 and (
        lower.startswith(("error ", "error:"))
        or lower == "error"
        or "api count exceeded" in lower
        or "no records found" in lower
        or "api limit exceeded" in lower
    ):
        return []
    valid = []
    seen = set()
    for line in lines:
        lower_line = line.lower()
        if lower_line in seen:
            continue
        if _is_ip(line):
            continue
        if "." not in line or " " in line or "/" in line:
            continue
        if not re.match(r"^[a-z0-9][a-z0-9\.\-]*\.[a-z]{2,}$", lower_line):
            continue
        seen.add(lower_line)
        valid.append(line)
    valid.sort(key=str.lower)
    return valid[:50]


def _cve_matches_product(cve: dict, product: str, version: str) -> bool:
    prod = product.lower()
    ver = version.lower()
    for cfg in cve.get("configurations", []) or []:
        for node in cfg.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or node.get("cpe_match", []) or []:
                criteria = str(match.get("criteria", "")).lower()
                if prod in criteria and (not ver or ver in criteria):
                    return True
            for child in node.get("children", []) or []:
                for match in child.get("cpeMatch", []) or []:
                    criteria = str(match.get("criteria", "")).lower()
                    if prod in criteria and (not ver or ver in criteria):
                        return True
    desc = " ".join(d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en").lower()
    if prod not in desc:
        return False
    return not (ver and ver not in desc)


def nvd_lookup(client: httpx.Client, product: str, version: str, nvd_api_key: str = "") -> list:
    query = f"{product} {version}".strip()
    if not query:
        return []
    cpe_name = f"cpe:2.3:a:*:{product}:{version}:*:*:*:*:*:*:*" if version else ""
    if cpe_name:
        try:
            data = _nvd_get(client, {"cpeName": cpe_name, "resultsPerPage": 10}, nvd_api_key)
            results = [_parse_cve(item["cve"]) for item in data.get("vulnerabilities", [])]
            if results:
                return results
        except Exception as exc:
            logger.debug("NVD CPE search failed for %s %s: %s", product, version, exc)
    data = _nvd_get(
        client,
        {"keywordSearch": query, "keywordExactMatch": "", "resultsPerPage": 10},
        nvd_api_key,
    )
    filtered = []
    for item in data.get("vulnerabilities", []) or []:
        cve = item.get("cve", {})
        if _cve_matches_product(cve, product, version):
            filtered.append(_parse_cve(cve))
    return filtered


_INTERNAL_HOST_RE = re.compile(
    r"(internal|local|compute|\.cloudapp\.|\.azure|google\.internal|\.amazonaws\.com)",
    re.IGNORECASE,
)
_IP_HOST_RE = re.compile(r"^ip-\d+-\d+-\d+-\d+", re.IGNORECASE)
_TWO_LABEL_TLDS = frozenset(
    {
        "co.uk",
        "co.jp",
        "com.au",
        "co.nz",
        "co.za",
        "com.br",
        "co.in",
        "co.kr",
        "ne.jp",
        "or.jp",
    }
)


def _extract_domain(hostname: str) -> str:
    if not hostname or _is_ip(hostname) or hostname.lower().endswith(".arpa"):
        return ""
    h = hostname.strip().lower().rstrip(".")
    if "." not in h:
        return ""
    if _INTERNAL_HOST_RE.search(h):
        return ""
    if _IP_HOST_RE.match(h):
        return ""
    labels = h.split(".")
    if len(labels) < 2 or len(labels[-1]) < 2:
        return ""
    if len(labels) >= 3 and ".".join(labels[-2:]) in _TWO_LABEL_TLDS:
        return ".".join(labels[-3:])
    if len(labels) > 2:
        return ".".join(labels[-2:])
    return h


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def _resolve_target(target: str, config: dict, log) -> tuple[str, str, str]:
    """Resolve target to (ip, domain, input_type)."""
    target = target.strip()
    if _is_ip(target):
        ip = str(ipaddress.ip_address(target))
        rdns = reverse_dns(ip)
        domain = _extract_domain(rdns)
        return ip, domain, "ip"
    else:
        domain = target.lower().rstrip(".")
        ip = resolve_domain(domain)
        if not ip:
            raise ValueError(f"Could not resolve domain {domain} to an IP address")
        return ip, domain, "domain"


def gather(target: str, config: dict, log) -> OsintResult:
    ip, domain, input_type = _resolve_target(target, config, log)
    result = OsintResult(target=target, input_type=input_type, resolved_ip=ip, domain=domain)

    if input_type == "ip":
        result.reverse_dns = reverse_dns(ip)
        if not domain:
            domain = _extract_domain(result.reverse_dns)
            result.domain = domain

    nvd_api_key = config.get("nvd_api_key", "")

    with _get_client(config) as client:

        parallel_lookups = [
            ("geo", "GeoIP", lambda: geo_lookup(client, ip)),
            ("rdap", "RDAP", lambda: rdap_lookup(client, ip)),
        ]
        with ThreadPoolExecutor(max_workers=len(parallel_lookups)) as pool:
            futures = {pool.submit(fn): (attr, label) for attr, label, fn in parallel_lookups}
            for future in as_completed(futures):
                attr, label = futures[future]
                try:
                    setattr(result, attr, future.result())
                    log(f"[green]{label}[/green] lookup OK")
                except Exception as exc:
                    result.errors.append(_sanitize(f"{label}: {exc}"))
                    log(f"[red]{label}[/red] failed: {_clean(exc)}")
                    logger.debug("%s lookup failed: %s", label, exc)

        try:
            result.internetdb = internetdb_lookup(client, ip)
            if result.internetdb:
                log("[green]InternetDB[/green] lookup OK (free Shodan mirror)")
            else:
                log("[dim]InternetDB[/dim]: no data for this IP")
        except Exception as exc:
            result.errors.append(_sanitize(f"InternetDB: {exc}"))
            log(f"[red]InternetDB[/red] failed: {_clean(exc)}")

        try:
            result.greynoise = greynoise_lookup(client, ip)
            if result.greynoise:
                cls = result.greynoise.get("classification", "unknown")
                log(f"[green]GreyNoise[/green] lookup OK (classification: {cls})")
            else:
                log("[dim]GreyNoise[/dim]: no observations for this IP")
        except Exception as exc:
            result.errors.append(_sanitize(f"GreyNoise: {exc}"))
            log(f"[red]GreyNoise[/red] failed: {_clean(exc)}")

        abuseipdb_key = config.get("abuseipdb_api_key", "")
        if abuseipdb_key:
            try:
                result.abuseipdb = abuseipdb_lookup(client, ip, abuseipdb_key)
                score = result.abuseipdb.get("abuseConfidenceScore", 0)
                log(f"[green]AbuseIPDB[/green] lookup OK (abuse score: {score}%)")
            except Exception as exc:
                result.errors.append(_sanitize(f"AbuseIPDB: {exc}"))
                log(f"[red]AbuseIPDB[/red] failed: {_clean(exc)}")
        else:
            log("[dim]AbuseIPDB[/dim] skipped (no API key)")

        vt_key = config.get("virustotal_api_key", "")
        if vt_key:
            try:
                result.virustotal = virustotal_lookup(client, ip, vt_key)
                mal = result.virustotal.get("malicious", 0)
                log(f"[green]VirusTotal[/green] lookup OK (malicious: {mal})")
            except Exception as exc:
                result.errors.append(_sanitize(f"VirusTotal: {exc}"))
                log(f"[red]VirusTotal[/red] failed: {_clean(exc)}")
        else:
            log("[dim]VirusTotal[/dim] skipped (no API key)")

        api_key = config.get("shodan_api_key", "")
        if api_key:
            try:
                result.shodan = shodan_lookup(client, ip, api_key)
                log("[green]Shodan[/green] lookup OK")
            except Exception as exc:
                result.errors.append(_sanitize(f"Shodan: {exc}"))
                log(f"[red]Shodan[/red] failed: {_clean(exc)}")
        else:
            log("[yellow]Shodan[/yellow] skipped (no API key in ~/.lens-extender/config.json)")

        if result.shodan:
            seen_products = set()
            for banner in result.shodan.get("data", []):
                product = banner.get("product") or banner.get("_shodan", {}).get("module", "")
                version = banner.get("version", "")
                key = (product, version)
                if not product or key in seen_products:
                    continue
                seen_products.add(key)
                try:
                    found = nvd_lookup(client, product, version, nvd_api_key)
                    result.vulns.extend(found)
                    log(f"[green]NVD[/green] checked {product} {version}")
                except Exception as exc:
                    result.errors.append(_sanitize(f"NVD ({product}): {exc}"))

        if domain:
            try:
                result.certs = crtsh_lookup(client, domain)
                log(f"[green]crt.sh[/green] found {len(result.certs)} certs for {domain}")
            except Exception as exc:
                result.errors.append(_sanitize(f"crt.sh: {exc}"))
                log(f"[red]crt.sh[/red] failed: {_clean(exc)}")

            try:
                result.whois_domain = domain_whois_lookup(client, domain)
                if result.whois_domain:
                    log(f"[green]Domain WHOIS[/green] lookup OK for {domain}")
            except Exception as exc:
                result.errors.append(_sanitize(f"Domain WHOIS: {exc}"))
                log(f"[dim]Domain WHOIS[/dim] failed: {_clean(exc)}")

        all_raw = list((result.internetdb or {}).get("vulns") or [])
        already_seen = {v["id"] for v in result.vulns}
        deduped = [c for c in all_raw if c not in already_seen]
        cve_ids = list(dict.fromkeys(deduped))
        total = len(cve_ids)
        if total > 30:
            result.errors.append(f"InternetDB returned {total} CVEs — enriching first 30 to respect NVD rate limits")
            log(f"[yellow]InternetDB has {total} CVEs — enriching first 30[/yellow]")
            cve_ids = cve_ids[:30]
        for cve_id in cve_ids:
            try:
                if detail := nvd_by_id(client, cve_id, nvd_api_key):
                    result.vulns.append(detail)
            except Exception as exc:
                result.errors.append(_sanitize(f"NVD ({cve_id}): {exc}"))
        if cve_ids:
            log(
                f"[green]NVD[/green] enriched {len(cve_ids)} CVEs from InternetDB "
                f"({len(result.vulns)} total after dedup)"
            )

        seen_ids: set[str] = set()
        deduped_vulns: list[dict] = []
        for v in result.vulns:
            if v["id"] not in seen_ids:
                seen_ids.add(v["id"])
                deduped_vulns.append(v)
        result.vulns = deduped_vulns

        if is_ipv4(ip):
            ipv4_lookups = [
                ("ripestat", "RIPEstat", lambda: ripestat_lookup(client, ip)),
                ("dnsbl", "DNSBL", lambda: dnsbl_check(ip)),
                ("cohosted", "Reverse-IP", lambda: cohosted_lookup(client, ip)),
            ]
            with ThreadPoolExecutor(max_workers=len(ipv4_lookups)) as pool:
                futures = {pool.submit(fn): (attr, label) for attr, label, fn in ipv4_lookups}  # type: ignore[arg-type]
                for future in as_completed(futures):
                    attr, label = futures[future]
                    try:
                        setattr(result, attr, future.result())
                        log(f"[green]{label}[/green] lookup OK")
                    except Exception as exc:
                        result.errors.append(_sanitize(f"{label}: {exc}"))
                        log(f"[red]{label}[/red] failed: {_clean(exc)}")
                        logger.debug("%s lookup failed: %s", label, exc)
        else:
            log("[dim]DNSBL + Reverse-IP[/dim] skipped (IPv6 not supported by these sources)")

        if domain:
            try:
                result.dns_records = dns_records(client, domain)
                log(f"[green]DoH[/green] records for {domain}")
            except Exception as exc:
                result.errors.append(_sanitize(f"DoH: {exc}"))
                log(f"[red]DoH[/dim] failed: {_clean(exc)}")

        rdns = result.reverse_dns
        if not rdns or rdns.lower().endswith(".arpa") or _is_ip(rdns):
            result.fcrdns = "no rDNS"
        else:
            try:
                a_data = _get(client, "https://dns.google/resolve", {"name": rdns, "type": "A"})
                aaaa_data = _get(client, "https://dns.google/resolve", {"name": rdns, "type": "AAAA"})
                answers = []
                for d in (a_data, aaaa_data):
                    answers.extend([a.get("data", "") for a in d.get("Answer", [])])
                if not answers:
                    result.fcrdns = "unverified (no A/AAAA for rDNS host)"
                else:
                    import ipaddress as _ip2

                    try:
                        target_norm = str(_ip2.ip_address(ip))
                    except ValueError:
                        target_norm = ip
                    norm_answers = []
                    for rec in answers:
                        try:
                            norm_answers.append(str(_ip2.ip_address(rec.strip())))
                        except ValueError:
                            norm_answers.append(rec.strip())
                    if target_norm in norm_answers:
                        result.fcrdns = "confirmed"
                        log(f"[green]FCRDNS[/green] confirmed ({rdns} -> {target_norm})")
                    else:
                        result.fcrdns = f"mismatch ({rdns} -> {', '.join(answers[:3])})"
                        log(f"[yellow]FCRDNS[/yellow] mismatch ({rdns} resolves elsewhere)")
            except Exception as exc:
                result.fcrdns = "unverified"
                log(f"[dim]FCRDNS[/dim] check failed: {_clean(exc)}")

    return result
