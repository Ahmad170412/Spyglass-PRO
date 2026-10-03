"""Report export — Markdown, JSON, and CSV."""

import csv
import io
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


def _kv(pairs: dict) -> list[str]:
    return [f"- **{k}:** {v}" for k, v in pairs.items() if v]


def _cell(value) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", "")


def render(report: dict) -> str:
    lines = [
        f"# Recon Report: {report['target']}",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
    ]

    geo = report.get("geo", {})
    rdap = report.get("rdap", {})
    if geo or rdap or report.get("reverse_dns") or report.get("hostnames") or report.get("shodan_org"):
        hostnames = report.get("hostnames") or []
        alt = ", ".join(h for h in hostnames if h != report.get("reverse_dns"))
        shodan_hosts = ", ".join(report.get("shodan_hostnames") or [])
        lines += [
            "## Network Identity",
            *_kv(
                {
                    "Hostname (rDNS)": report.get("reverse_dns"),
                    "FCRDNS": report.get("fcrdns"),
                    "Alt hostnames (InternetDB)": alt,
                    "Shodan hostnames": shodan_hosts,
                    "Org / ISP": report.get("shodan_org") or geo.get("org") or geo.get("isp"),
                    "Shodan ISP": report.get("shodan_isp"),
                    "ASN": geo.get("as"),
                    "Network name (RDAP)": rdap.get("name"),
                    "IP range": rdap.get("range"),
                    "RDAP handle": rdap.get("handle"),
                    "Registrant": rdap.get("registrant"),
                    "Country (RDAP)": rdap.get("country"),
                    "Type / Status": ", ".join(filter(None, [rdap.get("type"), rdap.get("status")])),
                    "Parent handle": rdap.get("parent_handle"),
                    "Created": rdap.get("created"),
                    "Updated": rdap.get("updated"),
                    "Abuse contact": rdap.get("abuse_contact"),
                }
            ),
            "",
        ]

    whois = report.get("whois_domain") or {}
    if whois:
        lines += [
            "## Domain WHOIS",
            *_kv(
                {
                    "Domain": whois.get("name"),
                    "Registrant": whois.get("registrant"),
                    "Emails": ", ".join(whois.get("emails", [])),
                    "Status": ", ".join(whois.get("status", [])),
                    "Created": whois.get("created"),
                    "Expires": whois.get("expires"),
                    "Updated": whois.get("updated"),
                    "Nameservers": ", ".join(whois.get("nameservers", [])),
                }
            ),
            "",
        ]

    if geo:
        proxy_flags = []
        if geo.get("proxy"):
            proxy_flags.append("proxy")
        if geo.get("hosting"):
            proxy_flags.append("hosting")
        if geo.get("mobile"):
            proxy_flags.append("mobile")
        lines += [
            "## Geo",
            *_kv(
                {
                    "Country": f"{geo.get('country', '')} ({geo.get('countryCode', '')})",
                    "Region": geo.get("regionName"),
                    "City": geo.get("city"),
                    "Coordinates": f"{geo.get('lat')}, {geo.get('lon')}" if geo.get("lat") is not None else "",
                    "Timezone": geo.get("timezone"),
                    "Flags": ", ".join(proxy_flags),
                }
            ),
            "",
        ]

    ripe = report.get("ripestat") or {}
    if ripe.get("prefix"):
        lines += [
            "## BGP / RIPEstat",
            *_kv(
                {
                    "Prefix": ripe.get("prefix"),
                    "Holder": ripe.get("holder"),
                    "ASNs": ", ".join(ripe.get("asns") or []),
                    "Announced": str(ripe.get("announced")) if ripe.get("announced") is not None else "",
                    "Type": ripe.get("type"),
                    "Neighbours": ", ".join(ripe.get("neighbours") or []),
                    "Visibility": str(ripe.get("visibility")) if ripe.get("visibility") is not None else "",
                }
            ),
            "",
        ]
        if ripe.get("block"):
            block = ripe["block"]
            if isinstance(block, dict):
                lines += [
                    "**Block:**",
                    *[f"- {k}: {v}" for k, v in block.items() if v],
                    "",
                ]

    if report.get("os_guesses"):
        lines += ["## OS Fingerprint", *[f"- {g}" for g in report["os_guesses"]], ""]

    gn = report.get("greynoise") or {}
    if gn:
        lines += [
            "## Internet Noise (GreyNoise)",
            *_kv(
                {
                    "Classification": gn.get("classification"),
                    "Identity": gn.get("name"),
                    "RIOT": "yes — known benign service" if gn.get("riot") else "",
                    "Noise": "yes — observed scanning" if gn.get("noise") else "",
                    "Last seen": str(gn.get("last_seen", ""))[:10],
                    "Link": gn.get("link", ""),
                }
            ),
            "",
        ]

    abuse = report.get("abuseipdb") or {}
    if abuse:
        lines += [
            "## AbuseIPDB",
            *_kv(
                {
                    "Abuse Score": f"{abuse.get('abuseConfidenceScore', 0)}%",
                    "Country": abuse.get("countryCode"),
                    "ISP": abuse.get("isp"),
                    "Usage Type": abuse.get("usageType"),
                    "Total Reports": str(abuse.get("totalReports", 0)),
                    "Reports (90d)": str(abuse.get("numReports", 0)),
                    "Last Reported": (abuse.get("lastReportedAt") or "")[:10],
                }
            ),
            "",
        ]

    vt = report.get("virustotal") or {}
    if vt:
        lines += [
            "## VirusTotal",
            *_kv(
                {
                    "Malicious": str(vt.get("malicious", 0)),
                    "Suspicious": str(vt.get("suspicious", 0)),
                    "Harmless": str(vt.get("harmless", 0)),
                    "Undetected": str(vt.get("undetected", 0)),
                    "Reputation": str(vt.get("reputation", 0)),
                    "Tags": ", ".join(vt.get("tags", [])),
                }
            ),
            "",
        ]

    freshness = report.get("freshness") or []
    if freshness:
        entries = [
            f"- **{e['source']}:** {e['last_seen']} ({e['age_days']} days ago)"
            if e.get("age_days") is not None
            else f"- **{e['source']}:** {e['last_seen']}"
            for e in freshness
        ]
        lines += ["## Data Freshness", *entries, ""]

    software = report.get("software", [])
    if software:
        lines += [
            "## Identified Software",
            "",
            "| Type | Vendor | Product | Version |",
            "|------|--------|---------|---------|",
        ]
        for s in software:
            lines.append(
                f"| {_cell(s['type'])} | {_cell(s['vendor'] or '—')} | "
                f"{_cell(s['product'])} | {_cell(s['version'] or '—')} |"
            )
        lines.append("")

    tags, cpes = report.get("tags", []), report.get("cpes", [])
    if tags or cpes:
        lines += [
            "## Exposure (Shodan InternetDB)",
            *_kv({"Tags": ", ".join(tags)}),
            "",
        ]
        if cpes:
            lines += ["**CPEs:**", *[f"- `{c}`" for c in cpes], ""]

    http_profiles = report.get("http_profiles") or []
    if http_profiles:
        lines += [
            "## HTTP Stack (Shodan)",
            "",
            "| Port | Server | Title | Host |",
            "|------|--------|-------|------|",
        ]
        for p in http_profiles[:10]:
            lines.append(
                f"| {_cell(p.get('port', ''))} | {_cell(p.get('server', '') or '—')} | "
                f"{_cell(p.get('title', '') or '—')} | {_cell(p.get('host', '') or '—')} |"
            )
        lines.append("")

    tls_profiles = report.get("tls_profiles") or []
    if tls_profiles:
        lines += [
            "## TLS / Certificates (Shodan)",
            "",
            "| Port | Cipher | TLS Versions | Cert CN |",
            "|------|--------|--------------|---------|",
        ]
        for p in tls_profiles[:10]:
            lines.append(
                f"| {_cell(p.get('port', ''))} | {_cell(p.get('cipher', '') or '—')} | "
                f"{_cell(p.get('versions', '') or '—')} | {_cell(p.get('cert_subject', '') or '—')} |"
            )
        lines.append("")

    certs = report.get("certs", [])
    if certs:
        lines += [
            "## Certificates (crt.sh)",
            "",
            "| SAN / CN | Issuer | Since | Expires |",
            "|----------|--------|-------|---------|",
        ]
        for c in certs[:30]:
            lines.append(
                f"| {_cell(c['names'])} | {_cell(c['issuer'])} | "
                f"{_cell(c['not_before'])} | {_cell(c.get('not_after', ''))} |"
            )
        lines.append("")

    ports = report.get("ports", [])
    if ports:
        has_extra = any(p.get("extrainfo") or p.get("hostname") or p.get("scripts") for p in ports)
        if has_extra:
            lines += [
                "## Open Ports (live + passive)",
                "",
                "| Port | Service | Product | Version | ExtraInfo | Scripts |",
                "|------|---------|---------|---------|-----------|---------|",
            ]
            for p in ports:
                scripts = ", ".join(p.get("scripts", {}).keys()) if isinstance(p.get("scripts"), dict) else ""
                extra = p.get("extrainfo") or p.get("hostname") or ""
                lines.append(
                    f"| {_cell(p['port'])}/{_cell(p['protocol'])} | {_cell(p.get('service', ''))} | "
                    f"{_cell(p.get('product', ''))} | {_cell(p.get('version', ''))} | "
                    f"{_cell(extra)} | {_cell(scripts)} |"
                )
        else:
            lines += [
                "## Open Ports",
                "",
                "| Port | Service | Product | Version |",
                "|------|---------|---------|---------|",
            ]
            for p in ports:
                lines.append(
                    f"| {_cell(p['port'])}/{_cell(p['protocol'])} | {_cell(p.get('service', ''))} | "
                    f"{_cell(p.get('product', ''))} | {_cell(p.get('version', ''))} |"
                )
        lines.append("")
        has_scripts = any(isinstance(p.get("scripts"), dict) and p["scripts"] for p in ports)
        has_host_scripts = bool(report.get("host_scripts"))
        if has_scripts or has_host_scripts:
            lines += ["## NSE Script Findings", ""]
            for p in ports:
                port_scripts: dict[str, str] = p.get("scripts") if isinstance(p.get("scripts"), dict) else {}  # type: ignore[assignment]
                for sid, out in port_scripts.items():
                    first_line = out.splitlines()[0][:300] if out else ""
                    lines.append(f"- **{p['port']}/{p['protocol']} {sid}:** `{_cell(first_line)}`")
            for hs in report.get("host_scripts") or []:
                lines.append(f"- **host {hs.get('id', '')}:** `{_cell(str(hs.get('output', '')[:300]))}`")
            lines.append("")

    dns_records = report.get("dns_records") or {}
    if dns_records:
        lines += ["## DNS Records (Google DoH)", ""]
        for rtype in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"):
            if rtype in dns_records:
                lines += [
                    f"**{rtype}:**",
                    *[f"- `{_cell(v)}`" for v in dns_records[rtype]],
                    "",
                ]

    cohosted = report.get("cohosted") or []
    if cohosted:
        lines += [
            "## Co-hosted Domains (Reverse-IP)",
            "",
            f"Found {len(cohosted)} domains on this IP:",
            *[f"- `{_cell(d)}`" for d in cohosted[:50]],
            "",
        ]
        if len(cohosted) > 50:
            lines.append(f"- *...and {len(cohosted) - 50} more*")
            lines.append("")

    dnsbl = report.get("dnsbl") or []
    if dnsbl:
        lines += [
            "## DNSBL (Blacklist) Hits",
            *[f"- **{_cell(e)}**" for e in dnsbl],
            "",
        ]

    vulns = report.get("vulns", [])
    if vulns:
        lines += [
            "## Vulnerabilities (NVD)",
            "",
            "| CVE | Severity | Score | Description |",
            "|-----|----------|-------|-------------|",
        ]
        for v in vulns[:25]:
            lines.append(
                f"| {_cell(v['id'])} | {_cell(v['severity'])} | {v['score'] or 'n/a'} | {_cell(v['description'])} |"
            )
        lines.append("")

    errors = report.get("errors", [])
    if errors:
        lines += ["## Warnings / Errors", *[f"- {e}" for e in errors], ""]

    return "\n".join(lines)


def render_json(report: dict) -> str:
    """Render report as JSON."""
    return json.dumps(report, indent=2, default=str, ensure_ascii=False)


def render_csv(report: dict) -> str:
    """Render report as CSV (flattened key-value pairs for top-level data)."""
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["Section", "Key", "Value"])
    target = report.get("target", "")
    writer.writerow(["Target", "target", target])

    for section in (
        "geo",
        "rdap",
        "greynoise",
        "abuseipdb",
        "virustotal",
        "whois_domain",
        "ripestat",
    ):
        data = report.get(section) or {}
        if data:
            for k, v in data.items():
                if isinstance(v, (list, dict)):
                    v = json.dumps(v, default=str)
                writer.writerow([section, k, v])

    for cert in report.get("certs", [])[:20]:
        writer.writerow(
            [
                "cert",
                cert.get("names", ""),
                f"{cert.get('issuer', '')} | {cert.get('not_before', '')} - {cert.get('not_after', '')}",
            ]
        )

    for port in report.get("ports", []):
        writer.writerow(
            [
                "port",
                f"{port.get('port')}/{port.get('protocol')}",
                f"{port.get('service', '')} {port.get('product', '')} {port.get('version', '')}",
            ]
        )

    for vuln in report.get("vulns", [])[:25]:
        writer.writerow(
            [
                "vuln",
                vuln.get("id", ""),
                f"{vuln.get('severity', '')} {vuln.get('score', '')}",
            ]
        )

    for domain in report.get("cohosted", [])[:50]:
        writer.writerow(["cohosted", domain, ""])

    for bl in report.get("dnsbl", []):
        writer.writerow(["dnsbl", bl, "listed"])

    return output.getvalue()


def _prepare_path(path: str) -> str:
    p = Path(path).expanduser()
    if p.parent and str(p.parent) not in (".", ""):
        p.parent.mkdir(parents=True, exist_ok=True)
    resolved = str(p)
    if sys.platform == "win32" and not resolved.startswith("\\\\?\\"):
        try:
            abs_path = str(p.resolve())
        except OSError:
            abs_path = os.path.abspath(resolved)
        if len(abs_path) >= 240:
            prefix = "\\\\?\\UNC\\" if abs_path.startswith("\\\\") else "\\\\?\\"
            resolved = prefix + (abs_path[2:] if prefix.endswith("UNC\\") else abs_path)
    return resolved


def write(report: dict, path: str) -> str:
    content = render(report)
    safe_path = _prepare_path(path)
    with open(safe_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)
    return safe_path


def write_json(report: dict, path: str) -> str:
    content = render_json(report)
    safe_path = _prepare_path(path)
    with open(safe_path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return safe_path


def write_csv(report: dict, path: str) -> str:
    content = render_csv(report)
    safe_path = _prepare_path(path)
    with open(safe_path, "w", encoding="utf-8", newline="") as fh:
        fh.write(content)
    return safe_path
