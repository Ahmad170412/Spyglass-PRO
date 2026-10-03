"""Lens-Extender — long-range IP reconnaissance TUI.

Passive-first OSINT across 15+ keyless sources, optional stealth-scanned
nmap (decoys / Tor), Rich TUI dashboard, markdown/json/csv export,
SQLite case store for history.
"""

import argparse

from lens_extender import __version__, app


def cli() -> None:
    parser = argparse.ArgumentParser(
        prog="lens-extender",
        description="Long-range IP/domain reconnaissance with a Rich TUI dashboard. Passive-first, OPSEC-aware.",
    )
    parser.add_argument("target", nargs="*", help="Target IP address or domain (prompted if omitted)")
    parser.add_argument("--version", action="version", version=f"lens-extender {__version__}")
    parser.add_argument(
        "--decoys",
        type=int,
        default=0,
        metavar="N",
        help="Active scans only: hide your IP among N random decoy IPs (nmap -D RND:N,ME)",
    )
    parser.add_argument(
        "--tor",
        action="store_true",
        help="Active scans only: route nmap through Tor SOCKS proxy on 127.0.0.1:9050",
    )
    parser.add_argument(
        "--ports",
        type=str,
        default=None,
        metavar="SPEC",
        help="Active scans only: nmap port spec (e.g. '1-65535', '1-1000,8080', 'top2000'). Default: top 1000",
    )
    parser.add_argument(
        "--udp",
        action="store_true",
        help="Active scans only: add UDP top 100 ports (slower, extra coverage)",
    )
    parser.add_argument(
        "--scripts",
        type=str,
        default="default,http-title,http-server-header,ssl-cert,ssl-enum-ciphers,banner",
        metavar="LIST",
        help="Active scans only: comma-separated NSE scripts. Use '' to disable",
    )
    parser.add_argument(
        "--intensity",
        type=int,
        default=5,
        choices=range(10),
        metavar="0-9",
        help="Active scans only: version detection intensity 0-9 (default 5)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Export results as JSON instead of Markdown",
    )
    parser.add_argument(
        "--csv",
        action="store_true",
        help="Export results as CSV alongside Markdown/JSON",
    )
    parser.add_argument(
        "--proxy",
        type=str,
        default=None,
        metavar="URL",
        help="HTTP/SOCKS5 proxy for all passive lookups (e.g. socks5://127.0.0.1:9050)",
    )
    parser.add_argument(
        "--batch",
        type=str,
        default=None,
        metavar="FILE",
        help="Read targets from file (one IP/domain per line) and scan each",
    )
    parser.add_argument(
        "--no-interactive",
        action="store_true",
        help="Skip interactive prompts (auto-confirm active scan, auto-export)",
    )
    parser.add_argument(
        "--store",
        action="store_true",
        help="Persist scan results to local SQLite case store",
    )
    parser.add_argument(
        "--store-list",
        action="store_true",
        help="List all stored targets",
    )
    parser.add_argument(
        "--store-diff",
        type=str,
        default=None,
        metavar="TARGET",
        help="Compare the two most recent scans for a target",
    )
    parser.add_argument(
        "--store-timeline",
        type=str,
        default=None,
        metavar="TARGET",
        help="Show scan history for a target",
    )

    args = parser.parse_args()

    if args.store_list:
        _handle_store_list()
        return
    if args.store_diff:
        _handle_store_diff(args.store_diff)
        return
    if args.store_timeline:
        _handle_store_timeline(args.store_timeline)
        return

    app.run(args)


def _handle_store_list() -> None:
    from rich.console import Console
    from rich.table import Table

    from lens_extender import store

    console = Console()
    targets = store.list_targets()
    if not targets:
        console.print("[dim]No scans stored yet.[/]")
        return
    table = Table(title="Stored Targets")
    table.add_column("Target")
    table.add_column("Scans", justify="right")
    table.add_column("Last Scan")
    for t in targets:
        table.add_row(t["target"], str(t["scan_count"]), t["last_scan"][:19])
    console.print(table)


def _handle_store_diff(target: str) -> None:
    from rich.console import Console

    from lens_extender import store

    console = Console()
    changes = store.diff_scans(target)
    if changes is None:
        console.print(f"[yellow]Need at least 2 scans of {target} to diff.[/]")
        return
    console.print(f"[bold]Diff for {target}:[/]")
    if "message" in changes:
        console.print(f"  {changes['message']}")
    else:
        for section, delta in changes.items():
            console.print(f"  [bold]{section}:[/]")
            for k, v in delta.items():
                console.print(f"    {k}: {v}")


def _handle_store_timeline(target: str) -> None:
    from rich.console import Console
    from rich.table import Table

    from lens_extender import store

    console = Console()
    timeline = store.get_timeline(target)
    if not timeline:
        console.print(f"[yellow]No scans found for {target}.[/]")
        return
    table = Table(title=f"Timeline: {target}")
    table.add_column("Scan #", justify="right")
    table.add_column("Timestamp")
    table.add_column("Type")
    for i, entry in enumerate(timeline, 1):
        table.add_row(str(i), entry["timestamp"][:19], entry["scan_type"])
    console.print(table)
