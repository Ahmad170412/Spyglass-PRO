"""Lens-Extender — long-range IP reconnaissance TUI. PASSIVE ONLY.

Recon from 15+ keyless sources: Shodan, InternetDB, RDAP, RIPEstat,
GreyNoise, reverse DNS and DNSBL. Nothing here connects to the target. The
optional active nmap scan (with decoys, Tor routing, UDP, NSE scripts and
port specs) was removed rather than switched off.

Still includes the Rich TUI dashboard and a SQLite case store for history.
"""

import argparse

from lens_extender import __version__, app


def cli() -> None:
    parser = argparse.ArgumentParser(
        prog="lens-extender",
        description="Long-range IP/domain reconnaissance with a Rich TUI dashboard. Passive-only, OPSEC-aware.",
    )
    parser.add_argument("target", nargs="*", help="Target IP address or domain (prompted if omitted)")
    parser.add_argument("--version", action="version", version=f"lens-extender {__version__}")
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
