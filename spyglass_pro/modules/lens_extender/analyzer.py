"""Correlate passive and active results into one report structure."""

import datetime
import socket
from typing import Any

from lens_extender.osint import _sanitize


def _service_name(port: str, protocol: str = "tcp") -> str:
    try:
        return socket.getservbyport(int(port), protocol)
    except (OSError, ValueError):
        return ""


def _parse_cpes(cpes: list) -> list:
    parsed = []
    type_names = {"a": "application", "o": "os", "h": "hardware"}
    for cpe in cpes:
        if cpe.startswith("cpe:2.3:"):
            parts = cpe.split(":")
            if len(parts) < 6:
                continue
            ptype, vendor, product, version = parts[2], parts[3], parts[4], parts[5]
        elif cpe.startswith("cpe:/"):
            parts = cpe[5:].split(":")
            if len(parts) < 3:
                continue
            ptype = parts[0]
            vendor = parts[1]
            product = parts[2]
            version = parts[3] if len(parts) > 3 else ""
        else:
            continue
        parsed.append(
            {
                "type": type_names.get(ptype, ptype),
                "vendor": vendor,
                "product": product,
                "version": version,
            }
        )
    return parsed


def _age_days(timestamp: str) -> int | None:
    try:
        parsed = datetime.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=datetime.timezone.utc)
        return max(0, (datetime.datetime.now(datetime.timezone.utc) - parsed).days)
    except ValueError:
        return None


def build_report(target: str, osint_result, scan_result=None) -> dict:
    shodan = osint_result.shodan or {}
    internetdb = osint_result.internetdb or {}
    ports = []

    seen = set()
    for banner in shodan.get("data", []):
        port = banner.get("port")
        key = (port, banner.get("transport", "tcp"))
        if port and key not in seen:
            seen.add(key)
            ports.append(
                {
                    "port": str(port),
                    "protocol": banner.get("transport", "tcp"),
                    "service": banner.get("product") or banner.get("_shodan", {}).get("module", ""),
                    "version": banner.get("version", ""),
                }
            )

    for port in internetdb.get("ports") or []:
        if str(port) not in {p["port"] for p in ports}:
            name = _service_name(str(port))
            ports.append({"port": str(port), "protocol": "tcp", "service": name, "version": ""})

    software = _parse_cpes(internetdb.get("cpes") or [])
    for entry in shodan.get("data", []):
        if entry.get("product"):
            software.append(
                {
                    "type": "application",
                    "vendor": "",
                    "product": entry["product"],
                    "version": entry.get("version", ""),
                }
            )
        elif entry.get("service") and not any(s["product"] == entry["service"] for s in software):
            software.append(
                {
                    "type": "application",
                    "vendor": "",
                    "product": entry["service"],
                    "version": "",
                }
            )

    if scan_result:
        existing = {(p["port"], p["protocol"]): p for p in ports}
        for entry in scan_result.ports:
            key = (entry["port"], entry["protocol"])
            if key in existing:
                # Merge richer nmap fields without clobbering passive data unnecessarily
                target_entry = existing[key]
                for k, v in entry.items():
                    if not v:
                        continue
                    if isinstance(v, dict):
                        if isinstance(target_entry.get(k), dict):
                            target_entry[k].update(v)
                        else:
                            target_entry[k] = dict(v)
                    elif isinstance(v, list):
                        if v:
                            target_entry[k] = v
                    else:
                        # Prefer nmap's product/version/extrainfo when more specific
                        if k in (
                            "product",
                            "version",
                            "extrainfo",
                            "hostname",
                            "ostype",
                            "cpe",
                            "cpes",
                            "method",
                            "conf",
                        ) or not target_entry.get(k):
                            target_entry[k] = v
            else:
                ports.append(entry)
                existing[key] = entry
        # Enrich software from nmap CPEs (worth the active contact)
        for entry in scan_result.ports:
            cpes = entry.get("cpes") or ([entry.get("cpe")] if entry.get("cpe") else [])
            for cpe in cpes:
                if cpe:
                    software.extend(_parse_cpes([cpe]))

    os_guesses = scan_result.os_guess if scan_result else []
    if not os_guesses and shodan.get("os"):
        os_guesses = [shodan["os"]]
    for sw in software:
        if sw["type"] == "os":
            guess = f"{sw['vendor']} {sw['product']} {sw['version']}".strip()
            if guess and guess not in os_guesses:
                os_guesses.append(f"{guess} (CPE hint)")

    seen_sw: set[tuple[Any, ...]] = set()
    deduped: list[dict] = []
    for s in software:
        sw_key: tuple[Any, ...] = (s["type"], s["vendor"], s["product"], s["version"])
        if sw_key not in seen_sw:
            seen_sw.add(sw_key)
            deduped.append(s)
    software = deduped

    # ---- Shodan meta (org, hostnames, HTTP/TLS) — already fetched, just surface ----
    shodan_org = shodan.get("org", "") if isinstance(shodan.get("org"), str) else ""
    shodan_hostnames = shodan.get("hostnames", []) if isinstance(shodan.get("hostnames"), list) else []
    shodan_isp = shodan.get("isp", "") if isinstance(shodan.get("isp"), str) else ""
    http_profiles: list[dict] = []
    tls_profiles: list[dict] = []
    for banner in shodan.get("data", []) or []:
        port = str(banner.get("port", ""))
        # HTTP details (Shodan extracts when banner is HTTP)
        http = banner.get("http") or {}
        if http:
            http_profiles.append(
                {
                    "port": port,
                    "server": (http.get("server") or banner.get("product") or "")[:80],
                    "title": (http.get("title") or "")[:80],
                    "host": http.get("host", "")[:80],
                    "status": str(http.get("status", ""))[:20],
                }
            )
        # TLS details
        ssl_info = banner.get("ssl") or {}
        if ssl_info:
            cert = ssl_info.get("cert") or {}
            subject = cert.get("subject") or {}
            tls_profiles.append(
                {
                    "port": port,
                    "cipher": str(ssl_info.get("cipher", ""))[:60]
                    if not isinstance(ssl_info.get("cipher"), dict)
                    else str(ssl_info.get("cipher", {}).get("name", ""))[:60],
                    "versions": ", ".join(ssl_info.get("versions", []) or []),
                    "cert_subject": str(
                        subject.get("CN", "")[:80] or cert.get("subject", "")[:80]
                        if isinstance(cert.get("subject"), str)
                        else subject.get("CN", "")[:80]
                    ),
                    "cert_issuer": (cert.get("issuer") or {}).get("CN", "")[:80]
                    if isinstance(cert.get("issuer"), dict)
                    else str(cert.get("issuer", ""))[:80],
                }
            )
    fcrdns = getattr(osint_result, "fcrdns", "") or ""

    greynoise = osint_result.greynoise or {}
    freshness = []
    for source, ts in (
        ("Shodan", shodan.get("last_update") or ""),
        ("GreyNoise", greynoise.get("last_seen") or ""),
    ):
        if ts:
            age = _age_days(ts)
            freshness.append({"source": source, "last_seen": str(ts)[:10], "age_days": age})
    # InternetDB has no explicit timestamp but is a live mirror — mark as
    # current when data is present so staleness logic isn't blind to it.
    if internetdb:
        today = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
        freshness.append({"source": "InternetDB", "last_seen": today, "age_days": 0})
    # crt.sh: use the most recent certificate's not_before as freshness.
    if osint_result.certs:
        dates = [c.get("not_before", "") for c in osint_result.certs if c.get("not_before")]
        if dates:
            latest = max(dates)
            freshness.append(
                {
                    "source": "crt.sh",
                    "last_seen": latest[:10],
                    "age_days": _age_days(latest),
                }
            )

    hostnames = internetdb.get("hostnames") or []
    host_scripts = getattr(scan_result, "scripts", []) if scan_result else []
    return {
        "target": target,
        "input_type": getattr(osint_result, "input_type", "ip"),
        "resolved_ip": getattr(osint_result, "resolved_ip", ""),
        "reverse_dns": osint_result.reverse_dns or ", ".join(hostnames),
        "hostnames": hostnames,
        "shodan_org": shodan_org,
        "shodan_isp": shodan_isp,
        "shodan_hostnames": shodan_hostnames,
        "http_profiles": http_profiles,
        "tls_profiles": tls_profiles,
        "fcrdns": fcrdns,
        "geo": osint_result.geo,
        "rdap": osint_result.rdap,
        "ports": sorted(ports, key=lambda p: int(p["port"]) if str(p["port"]).isdigit() else 0),
        "host_scripts": host_scripts,
        "os_guesses": os_guesses,
        "software": software,
        "tags": internetdb.get("tags") or [],
        "cpes": internetdb.get("cpes") or [],
        "certs": osint_result.certs,
        "vulns": osint_result.vulns,
        "ripestat": osint_result.ripestat,
        "greynoise": greynoise,
        "freshness": freshness,
        "dnsbl": osint_result.dnsbl,
        "dns_records": osint_result.dns_records,
        "cohosted": osint_result.cohosted,
        "abuseipdb": getattr(osint_result, "abuseipdb", {}),
        "virustotal": getattr(osint_result, "virustotal", {}),
        "whois_domain": getattr(osint_result, "whois_domain", {}),
        "errors": osint_result.errors
        + ([_sanitize(scan_result.raw_error)] if scan_result and scan_result.raw_error else []),
    }
