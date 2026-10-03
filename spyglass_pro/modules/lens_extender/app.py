"""Rich TUI dashboard rendering and orchestration."""

import datetime
import ipaddress

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from lens_extender import analyzer, osint
from lens_extender import report as report_mod

console = Console()

BANNER = r"""[bold green]
██       ███████ ███    ██ ███████     ███████ ██   ██ ████████ ███████ ███    ██ ██████  ███████ ██████
██       ██      ████   ██ ██          ██       ██ ██     ██    ██      ████   ██ ██   ██ ██      ██   ██
██       █████   ██ ██  ██ ███████     █████     ███      ██    █████   ██ ██  ██ ██   ██ █████   ██████
██       ██      ██  ██ ██      ██     ██       ██ ██     ██    ██      ██  ██ ██ ██   ██ ██      ██   ██
████████ ███████ ██   ████ ███████     ███████ ██   ██    ██    ███████ ██   ████ ██████  ███████ ██   ██

[/bold green][dim green]Long-range IP/domain reconnaissance — passive-first, OPSEC-aware[/dim green]"""

THEME = "green"
THEME_BRIGHT = "bright_green"
THEME_DIM = "dark_green"

SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
    "UNKNOWN": "dim",
}


def validate_target(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        console.print("[bold red]Empty target.[/]")
        raise SystemExit(1)
    # If it looks like an IP (all numeric labels with dots), validate strictly
    parts = raw.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        try:
            addr = ipaddress.ip_address(raw)
        except ValueError:
            console.print(f"[bold red]Invalid IP address:[/] {escape(raw)}")
            raise SystemExit(1)
        if addr.is_unspecified or addr.is_multicast or str(addr) == "255.255.255.255":
            console.print(f"[bold red]Refusing target:[/] {addr} (unspecified, multicast, or broadcast)")
            raise SystemExit(1)
        return str(addr)
    # IPv6
    try:
        addr = ipaddress.ip_address(raw)
        return str(addr)
    except ValueError:
        pass
    # Domain
    if "." in raw and " " not in raw and "/" not in raw:
        return raw.lower().rstrip(".")
    console.print(f"[bold red]Invalid target:[/] {escape(raw)} (must be an IP address or domain)")
    raise SystemExit(1)


def log_line(message: str) -> None:
    console.print(f"  [{THEME_DIM}]>[/] {message}")


def identity_panel(report: dict) -> Panel:
    geo = report.get("geo", {})
    rdap = report.get("rdap", {})
    hostnames = report.get("hostnames") or []
    alt_hosts = ", ".join(h for h in hostnames if h != report.get("reverse_dns"))
    shodan_hosts = ", ".join(report.get("shodan_hostnames") or [])
    org = report.get("shodan_org") or geo.get("org") or geo.get("isp")
    fcrdns = report.get("fcrdns", "")
    fcrdns_style = {"confirmed": "green", "mismatch": "yellow"}.get(fcrdns.split()[0], "dim") if fcrdns else "dim"
    rows = [
        ("Target", report.get("target")),
        (
            "Resolved IP",
            report.get("resolved_ip") if report.get("input_type") == "domain" else "",
        ),
        ("Hostname (rDNS)", report.get("reverse_dns")),
        (
            "FCRDNS",
            f"[{fcrdns_style}]{escape(fcrdns)}[/]" if fcrdns and fcrdns != "no rDNS" else "",
        ),
        ("Alt hostnames (InternetDB)", alt_hosts or ""),
        ("Shodan hostnames", shodan_hosts or ""),
        ("Org / ISP", org),
        ("Shodan ISP", report.get("shodan_isp") or ""),
        ("ASN", geo.get("as")),
        ("Network (RDAP)", rdap.get("name")),
        ("IP range", rdap.get("range")),
        ("RDAP handle", rdap.get("handle")),
        ("Registrant", rdap.get("registrant")),
        ("Country (RDAP)", rdap.get("country")),
        (
            "Type / Status",
            ", ".join(filter(None, [rdap.get("type"), rdap.get("status")])),
        ),
        ("Parent handle", rdap.get("parent_handle")),
        ("Created", rdap.get("created")),
        ("Updated", rdap.get("updated")),
        ("Abuse contact", rdap.get("abuse_contact")),
    ]
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold")
    table.add_column()
    for key, value in rows:
        if value:
            table.add_row(key, escape(str(value)))
    return Panel(table, title="Network Identity", box=box.ROUNDED, border_style=THEME)


def whois_panel(report: dict) -> Panel | None:
    whois = report.get("whois_domain") or {}
    if not whois:
        return None
    rows = [
        ("Domain", whois.get("name")),
        ("Registrant", whois.get("registrant")),
        ("Emails", ", ".join(whois.get("emails", []))),
        ("Status", ", ".join(whois.get("status", []))),
        ("Created", whois.get("created")),
        ("Expires", whois.get("expires")),
        ("Updated", whois.get("updated")),
        ("Nameservers", ", ".join(whois.get("nameservers", []))),
    ]
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold")
    table.add_column()
    for key, value in rows:
        if value:
            table.add_row(key, escape(str(value)))
    return Panel(table, title="Domain WHOIS", box=box.ROUNDED, border_style=THEME)


def geo_panel(report: dict) -> Panel:
    geo = report.get("geo", {})
    flags = [
        name
        for name, flag in (
            ("proxy", "proxy"),
            ("hosting", "hosting"),
            ("mobile", "mobile"),
        )
        if geo.get(flag)
    ]
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold")
    table.add_column()
    for key, value in [
        (
            "Location",
            f"{geo.get('city', '')}, {geo.get('regionName', '')}, {geo.get('country', '')}",
        ),
        (
            "Coordinates",
            f"{geo.get('lat')}, {geo.get('lon')}" if geo.get("lat") is not None else "",
        ),
        ("Timezone", geo.get("timezone") or ""),
        ("Flags", ", ".join(flags)),
    ]:
        if value and str(value).strip(", "):
            table.add_row(key, escape(str(value)))
    return Panel(table, title="GeoIP", box=box.ROUNDED, border_style=THEME)


def ports_table(report: dict) -> Table:
    has_extra = any(p.get("extrainfo") or p.get("hostname") or p.get("scripts") for p in report.get("ports", []))
    table = Table(title="Open Ports (live nmap + passive)", box=box.ROUNDED, border_style=THEME)
    table.add_column("Port")
    table.add_column("Service")
    table.add_column("Product")
    table.add_column("Version")
    if has_extra:
        table.add_column("ExtraInfo")
        table.add_column("Scripts", overflow="fold")
    for p in report.get("ports", []):
        scripts = ", ".join(p.get("scripts", {}).keys()) if isinstance(p.get("scripts"), dict) else ""
        if has_extra:
            table.add_row(
                f"{p['port']}/{p['protocol']}",
                escape(p.get("service", "")),
                escape(p.get("product", "")),
                escape(p.get("version", "")),
                escape(p.get("extrainfo", "") or p.get("hostname", "") or ""),
                escape(scripts or "-") if scripts else "[dim]-[/dim]",
            )
        else:
            table.add_row(
                f"{p['port']}/{p['protocol']}",
                escape(p.get("service", "")),
                escape(p.get("product", "")),
                escape(p.get("version", "")),
            )
    return table


def nse_scripts_panel(report: dict) -> Panel | None:
    rows = []
    for p in report.get("ports", []):
        scripts = p.get("scripts") if isinstance(p.get("scripts"), dict) else {}
        for sid, out in scripts.items():
            preview = out.splitlines()[0][:120] if out else ""
            rows.append((f"{p['port']}/{p['protocol']} {sid}", preview))
    for hs in report.get("host_scripts", []) or []:
        rows.append((f"host {hs.get('id', '')}", hs.get("output", "")[:120]))
    if not rows:
        return None
    table = Table(box=box.ROUNDED, border_style=THEME, title="NSE Script Findings")
    table.add_column("Source", style="bold")
    table.add_column("Output", overflow="fold")
    for src, out in rows[:15]:
        table.add_row(escape(src), escape(out or "-"))
    grid = Table.grid(padding=(0, 0))
    grid.add_row(table)
    if len(rows) > 15:
        grid.add_row(f"[dim]...and {len(rows) - 15} more scripts[/dim]")
    return Panel(grid, box=box.ROUNDED, border_style=THEME)


def os_panel(report: dict) -> Panel | None:
    guesses = report.get("os_guesses", [])
    if not guesses:
        return None
    body = "\n".join(escape(g) for g in guesses)
    return Panel(body, title="OS Fingerprint", box=box.ROUNDED, border_style=THEME)


def software_table(report: dict) -> Table | None:
    software = report.get("software", [])
    if not software:
        return None
    table = Table(title="Identified Software (CPE / banners)", box=box.ROUNDED, border_style=THEME)
    table.add_column("Type")
    table.add_column("Vendor")
    table.add_column("Product")
    table.add_column("Version")
    for s in software:
        table.add_row(
            s["type"],
            escape(s["vendor"] or "-"),
            escape(s["product"]),
            escape(s["version"] or "-"),
        )
    return table


def exposure_table(report: dict) -> Table | None:
    tags, cpes = report.get("tags", []), report.get("cpes", [])
    if not tags and not cpes:
        return None
    table = Table(title="Exposure (Shodan InternetDB)", box=box.ROUNDED, border_style=THEME)
    table.add_column("Tags")
    table.add_column("CPEs", overflow="fold")
    table.add_row(escape(", ".join(tags)) or "-", escape("\n".join(cpes)) or "-")
    return table


def certs_table(report: dict) -> Table | None:
    certs = report.get("certs", [])
    if not certs:
        return None
    table = Table(title="Certificates (crt.sh)", box=box.ROUNDED, border_style=THEME)
    table.add_column("SAN / CN", overflow="fold")
    table.add_column("Issuer")
    table.add_column("Since")
    table.add_column("Expires")
    for c in certs:
        table.add_row(
            escape(c["names"]),
            escape(c["issuer"]),
            escape(c["not_before"]),
            escape(c.get("not_after", "")),
        )
    return table


def http_profiles_table(report: dict) -> Table | None:
    profiles = report.get("http_profiles") or []
    if not profiles:
        return None
    table = Table(title="HTTP Stack (Shodan)", box=box.ROUNDED, border_style=THEME)
    table.add_column("Port")
    table.add_column("Server", overflow="fold")
    table.add_column("Title", overflow="fold")
    table.add_column("Host")
    for p in profiles[:10]:
        table.add_row(
            escape(p.get("port", "")),
            escape(p.get("server", "") or "-"),
            escape(p.get("title", "") or "-"),
            escape(p.get("host", "") or "-"),
        )
    return table


def tls_profiles_table(report: dict) -> Table | None:
    profiles = report.get("tls_profiles") or []
    if not profiles:
        return None
    table = Table(title="TLS / Certificates (Shodan)", box=box.ROUNDED, border_style=THEME)
    table.add_column("Port")
    table.add_column("Cipher", overflow="fold")
    table.add_column("TLS Versions")
    table.add_column("Cert CN", overflow="fold")
    for p in profiles[:10]:
        table.add_row(
            escape(p.get("port", "")),
            escape(p.get("cipher", "") or "-"),
            escape(p.get("versions", "") or "-"),
            escape(p.get("cert_subject", "") or "-"),
        )
    return table


def greynoise_panel(report: dict) -> Panel | None:
    gn = report.get("greynoise") or {}
    if not gn:
        return None
    classification = gn.get("classification", "unknown")
    style = {"malicious": "bold red", "benign": "green"}.get(classification, "yellow")
    riot_note = " (RIOT - benign service)" if gn.get("riot") else ""
    noise_note = " (Internet scanner)" if gn.get("noise") else ""
    rows = [
        (
            "Classification",
            f"[{style}]{escape(classification)}[/]{riot_note}{noise_note}",
        ),
        ("Identity", gn.get("name") or ""),
        ("RIOT", "yes - known benign service" if gn.get("riot") else ""),
        ("Noise", "yes - observed scanning" if gn.get("noise") else ""),
        ("Last seen", str(gn.get("last_seen", ""))[:10]),
    ]
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold")
    table.add_column()
    for key, value in rows:
        if value and value.strip():
            table.add_row(key, str(value))
    return Panel(table, title="Internet Noise (GreyNoise)", box=box.ROUNDED, border_style=THEME)


def abuseipdb_panel(report: dict) -> Panel | None:
    abuse = report.get("abuseipdb") or {}
    if not abuse:
        return None
    score = abuse.get("abuseConfidenceScore", 0)
    style = "bold red" if score >= 50 else "yellow" if score > 0 else "green"
    rows = [
        ("Abuse Score", f"[{style}]{score}%[/]"),
        ("Country", abuse.get("countryCode") or ""),
        ("ISP", abuse.get("isp") or ""),
        ("Usage Type", abuse.get("usageType") or ""),
        ("Total Reports", str(abuse.get("totalReports", 0))),
        ("Last Reported", (abuse.get("lastReportedAt") or "")[:10]),
    ]
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold")
    table.add_column()
    for key, value in rows:
        if value:
            table.add_row(key, escape(str(value)))
    return Panel(table, title="AbuseIPDB", box=box.ROUNDED, border_style=THEME)


def virustotal_panel(report: dict) -> Panel | None:
    vt = report.get("virustotal") or {}
    if not vt:
        return None
    mal = vt.get("malicious", 0)
    style = "bold red" if mal > 0 else "green"
    rows = [
        ("Malicious", f"[{style}]{mal}[/]"),
        ("Suspicious", str(vt.get("suspicious", 0))),
        ("Harmless", str(vt.get("harmless", 0))),
        ("Reputation", str(vt.get("reputation", 0))),
        ("Tags", ", ".join(vt.get("tags", []))),
    ]
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold")
    table.add_column()
    for key, value in rows:
        if value:
            table.add_row(key, escape(str(value)))
    return Panel(table, title="VirusTotal", box=box.ROUNDED, border_style=THEME)


def dns_panel(report: dict) -> Panel | None:
    records = report.get("dns_records") or {}
    if not records:
        return None
    table = Table(title="DNS Records (Google DoH)", box=box.ROUNDED, border_style=THEME)
    table.add_column("Type", style="bold")
    table.add_column("Values", overflow="fold")
    for rtype in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"):
        if rtype in records:
            table.add_row(rtype, escape("\n".join(records[rtype])))
    if table.row_count == 0:
        return None
    return Panel(table, title="DNS Records (Google DoH)", box=box.ROUNDED, border_style=THEME)


def cohosted_panel(report: dict) -> Panel | None:
    cohosted = report.get("cohosted") or []
    if not cohosted:
        return None
    body = "\n".join(escape(d) for d in cohosted[:30])
    if len(cohosted) > 30:
        body += f"\n[dim]...and {len(cohosted) - 30} more[/dim]"
    return Panel(
        body,
        title=f"Co-hosted Domains ({len(cohosted)})",
        box=box.ROUNDED,
        border_style=THEME,
    )


def bgp_panel(report: dict) -> Panel | None:
    ripe = report.get("ripestat") or {}
    if not ripe or not ripe.get("prefix"):
        return None
    rows = [
        ("Prefix", ripe.get("prefix")),
        ("Holder", ripe.get("holder")),
        ("ASNs", ", ".join(ripe.get("asns") or [])),
        (
            "Announced",
            str(ripe.get("announced")) if ripe.get("announced") is not None else "",
        ),
        ("Type", ripe.get("type")),
        ("Neighbours", ", ".join(ripe.get("neighbours") or [])[:160]),
        (
            "Visibility",
            str(ripe.get("visibility")) if ripe.get("visibility") is not None else "",
        ),
    ]
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold")
    table.add_column()
    for key, value in rows:
        if value and str(value).strip():
            table.add_row(key, escape(str(value)))
    return Panel(table, title="BGP / RIPEstat", box=box.ROUNDED, border_style=THEME)


def dnsbl_panel(report: dict) -> Panel | None:
    dnsbl = report.get("dnsbl") or []
    if not dnsbl:
        return None
    body = "\n".join(f"[red]{escape(e)}[/]" for e in dnsbl)
    return Panel(body, title="DNSBL (Blacklist) Hits", box=box.ROUNDED, border_style="red")


def freshness_line(report: dict) -> str | None:
    freshness = report.get("freshness") or []
    parts = []
    for entry in freshness:
        age = entry.get("age_days")
        shown = f"{age}d ago" if age is not None else entry["last_seen"]
        parts.append(f"{entry['source']}: {shown}")
    return ", ".join(parts) or None


def vulns_table(report: dict) -> Table | None:
    vulns = report.get("vulns", [])
    if not vulns:
        return None
    table = Table(title="Vulnerabilities (NVD)", box=box.ROUNDED, border_style=THEME)
    table.add_column("CVE")
    table.add_column("Severity")
    table.add_column("Score", justify="right")
    table.add_column("Description", overflow="fold")
    for v in vulns[:25]:
        severity = v["severity"].upper()
        table.add_row(
            escape(v["id"]),
            f"[{SEVERITY_STYLE.get(severity, 'white')}]{severity}[/]",
            str(v["score"] or "n/a"),
            escape(v["description"]),
        )
    return table


def show_banner() -> None:
    Console(width=max(console.width, 108)).print(BANNER)
    console.print()


def render_dashboard(target: str, options: dict | None = None) -> dict:
    options = options or {}
    console.print()

    from lens_extender import config as cfg

    config = cfg.load()
    if options.get("proxy"):
        config["proxy"] = options["proxy"]

    console.print("[bold]Passive recon[/] ([dim]no direct connection to target[/])")
    with console.status(f"[{THEME_BRIGHT}]Running passive recon...[/]", spinner="dots"):
        osint_result = osint.gather(target, config, log_line)
    scan_result = None

    # Active scanning was removed from this package. nmap opened a direct
    # connection to the target; the port data below now comes only from
    # Shodan and InternetDB.
    scan_result = None

    data = analyzer.build_report(target, osint_result, scan_result)
    console.print()
    console.print(identity_panel(data))

    if panel := whois_panel(data):
        console.print()
        console.print(panel)

    console.print(geo_panel(data))

    if panel := bgp_panel(data):
        console.print()
        console.print(panel)

    if data.get("ports"):
        console.print()
        console.print(ports_table(data))
        if panel := nse_scripts_panel(data):
            console.print()
            console.print(panel)
    else:
        console.print("\n[dim]No port data available — Shodan returned none for this host.[/]")

    if table := software_table(data):
        console.print()
        console.print(table)

    if table := exposure_table(data):
        console.print()
        console.print(table)

    if table := http_profiles_table(data):
        console.print()
        console.print(table)

    if table := tls_profiles_table(data):
        console.print()
        console.print(table)

    if table := certs_table(data):
        console.print()
        console.print(table)

    if panel := greynoise_panel(data):
        console.print()
        console.print(panel)

    if panel := abuseipdb_panel(data):
        console.print()
        console.print(panel)

    if panel := virustotal_panel(data):
        console.print()
        console.print(panel)

    if panel := dns_panel(data):
        console.print()
        console.print(panel)

    if panel := cohosted_panel(data):
        console.print()
        console.print(panel)

    if panel := dnsbl_panel(data):
        console.print()
        console.print(panel)

    if freshness := freshness_line(data):
        console.print(f"\n[dim]Passive data freshness — {freshness}[/dim]")
        stale = any(e.get("age_days") is None or e.get("age_days", 0) > 30 for e in data["freshness"])
        if stale:
            console.print("[dim]Passive data is stale — consider an active scan for current state.[/dim]")

    if panel := os_panel(data):
        console.print(panel)

    if table := vulns_table(data):
        console.print()
        console.print(table)

    if errors := data.get("errors"):
        console.print()
        warn = Table(box=box.ROUNDED, border_style=THEME, title="Warnings", show_header=False)
        warn.add_column()
        for e in errors:
            warn.add_row(f"[yellow]{escape(str(e))}[/]")
        console.print(warn)

    export_paths = []
    auto_export = options.get("no_interactive", False)
    json_output = options.get("json_output", False)
    csv_output = options.get("csv_output", False)

    if json_output:
        filename = f"report-{target}-{datetime.datetime.now():%Y%m%d-%H%M%S}.json"
        try:
            path = report_mod.write_json(data, filename)
            export_paths.append(path)
        except OSError as exc:
            console.print(f"[red]JSON export failed:[/] {exc}")

    if csv_output:
        filename = f"report-{target}-{datetime.datetime.now():%Y%m%d-%H%M%S}.csv"
        try:
            path = report_mod.write_csv(data, filename)
            export_paths.append(path)
        except OSError as exc:
            console.print(f"[red]CSV export failed:[/] {exc}")

    if not export_paths:
        if auto_export:
            filename = f"report-{target}-{datetime.datetime.now():%Y%m%d-%H%M%S}.md"
            try:
                path = report_mod.write(data, filename)
                export_paths.append(path)
            except OSError as exc:
                console.print(f"[red]Export failed:[/] {exc}")
                data.setdefault("errors", []).append(f"Markdown export failed: {exc}")
        elif Confirm.ask("\n[bold]Export report to Markdown?[/]", default=True):
            filename = Prompt.ask(
                "Filename",
                default=f"report-{target}-{datetime.datetime.now():%Y%m%d-%H%M%S}.md",
            )
            try:
                path = report_mod.write(data, filename)
                export_paths.append(path)
            except OSError as exc:
                console.print(f"[red]Export failed:[/] {exc}")
                data.setdefault("errors", []).append(f"Markdown export failed: {exc}")

    if options.get("store"):
        from lens_extender import store

        if store.store_scan(target, data):
            console.print("[green]Scan stored to case database.[/]")
        else:
            console.print("[yellow]Failed to store scan.[/]")

    console.print()
    for p in export_paths:
        console.print(f"[green bold]Report saved:[/] {p}")
    console.print("[dim]Done.[/]")
    return data


def _run_single(target: str, options: dict) -> dict:
    return render_dashboard(target, options)


def _run_batch(batch_file: str, options: dict) -> None:
    try:
        with open(batch_file, "r") as fh:
            targets = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
    except OSError as exc:
        console.print(f"[red]Failed to read batch file:[/] {exc}")
        raise SystemExit(1)

    if not targets:
        console.print("[yellow]No targets found in batch file.[/]")
        return

    console.print(f"[bold]Batch mode:[/] {len(targets)} targets from {batch_file}")
    results = []
    for i, target in enumerate(targets, 1):
        console.print(f"\n[bold]--- Target {i}/{len(targets)}: {target} ---[/]")
        try:
            validated = validate_target(target)
            data = _run_single(validated, options)
            results.append(data)
        except SystemExit:
            continue
        except KeyboardInterrupt:
            console.print("\n[yellow]Batch interrupted.[/]")
            break

    if results:
        console.print(f"\n[bold green]Batch complete:[/] {len(results)}/{len(targets)} targets scanned")


def run(args) -> None:
    show_banner()

    options = {
        "proxy": getattr(args, "proxy", None),
        "json_output": getattr(args, "json_output", False),
        "csv_output": getattr(args, "csv", False),
        "no_interactive": getattr(args, "no_interactive", False),
        "store": getattr(args, "store", False),
    }

    batch_file = getattr(args, "batch", None)
    if batch_file:
        _run_batch(batch_file, options)
        return

    targets = getattr(args, "target", [])
    if not targets:
        raw = Prompt.ask(f"[bold {THEME_BRIGHT}]Target IP or domain[/]")
        targets = [raw]

    for target in targets:
        try:
            target = validate_target(target)
        except SystemExit:
            continue
        try:
            _run_single(target, options)
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted[/] — partial results were not exported.")
            raise SystemExit(130)
