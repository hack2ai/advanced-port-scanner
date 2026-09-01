#!/usr/bin/env python3
"""Command-line interface for authorized network service discovery."""
from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import datetime, timezone

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from scanner.config import settings
from scanner.profiles import get_profile, list_profiles
from scanner.scanner import scan_target
from scanner.utils import parse_port_range, resolve_target, save_csv, save_json, save_txt, setup_logging
from scanner.version import VERSION
from scanner.vuln_hints import RISK_COLORS

console = Console()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aps",
        description="Professional network service discovery for authorized security testing.",
    )
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {VERSION}")
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="Run an authorized network discovery scan")
    scan.add_argument("targets", help="Comma-separated IP addresses or hostnames")
    scan.add_argument("-p", "--ports", default=None, help="Port or inclusive range; overrides --profile")
    scan.add_argument("--profile", choices=tuple(list_profiles_item["name"] for list_profiles_item in list_profiles()), default="standard", help="Reusable scan profile")
    scan.add_argument("--scan-type", choices=("tcp", "syn"), default="tcp", help="TCP connect or optional SYN lab mode")
    scan.add_argument("--no-banner", action="store_true", help="Disable small service-banner probes")
    scan.add_argument("--save-json", action="store_true", help="Write a JSON report")
    scan.add_argument("--save-csv", action="store_true", help="Write a CSV report")
    scan.add_argument("--save-txt", action="store_true", help="Write a text report")
    scan.add_argument("--output-dir", default="reports", help="Report directory (default: reports)")

    subparsers.add_parser("profiles", help="List available scan profiles")
    return parser


def print_results(target: str, data: dict) -> None:
    open_ports = data.get("open_ports", [])
    console.print(f"\n[bold cyan]{target}[/bold cyan]  {data.get('ip', 'unresolved')}  •  {len(open_ports)} open")
    if not open_ports:
        console.print("  [dim]No open ports found in the selected range.[/dim]")
        return
    table = Table(show_header=True, header_style="bold cyan", expand=True)
    for name in ("Port", "Service", "Risk", "Banner", "Assessment"):
        table.add_column(name)
    for item in open_ports:
        risk = item.get("risk", "INFO")
        color = RISK_COLORS.get(risk, "white")
        table.add_row(str(item["port"]), item.get("service", "unknown"), f"[{color}]{risk}[/{color}]", (item.get("banner") or "")[:70], item.get("vuln_hint", ""))
    console.print(table)


def run_scan(args: argparse.Namespace) -> int:
    profile = get_profile(args.profile)
    ports_text = args.ports or (profile.port_range if profile else "1-1024")
    ports = parse_port_range(ports_text)
    if not ports:
        console.print(f"[bold red]Invalid port range:[/bold red] {ports_text}")
        return 2
    start_port, end_port = ports
    requested_ports = end_port - start_port + 1
    if requested_ports > settings.max_ports:
        console.print(
            f"[bold red]Port range exceeds configured limit:[/bold red] "
            f"{requested_ports} ports requested, MAX_PORTS={settings.max_ports}. "
            "Raise MAX_PORTS explicitly to enable a larger authorized scan."
        )
        return 2

    logger = setup_logging()
    raw_targets = list(dict.fromkeys(t.strip() for t in args.targets.split(",") if t.strip()))
    if len(raw_targets) > settings.max_targets:
        console.print(
            f"[bold red]Too many targets:[/bold red] {len(raw_targets)} targets requested, "
            f"MAX_TARGETS={settings.max_targets}. Reduce the target list or raise MAX_TARGETS explicitly."
        )
        return 2

    resolved: dict[str, str] = {}
    for target in raw_targets:
        ip = resolve_target(target, logger)
        if ip:
            resolved[target] = ip
        else:
            console.print(f"[yellow]Skipping unresolved target:[/yellow] {target}")
    if not resolved:
        console.print("[bold red]No resolvable targets.[/bold red]")
        return 2

    profile_label = args.profile if args.ports is None else "custom"
    console.print(Panel.fit(
        f"[bold cyan]ADVANCED PORT SCANNER[/bold cyan]  v{VERSION}\n"
        f"Targets: {len(resolved)}  •  Profile: {profile_label}  •  Ports: {start_port}-{end_port}  •  Mode: {args.scan_type.upper()}\n"
        "[yellow]Authorized systems only.[/yellow]",
        border_style="cyan",
    ))

    started = time.monotonic()
    target_data: dict[str, dict] = {}
    for target, ip in resolved.items():
        target_data[target] = scan_target(ip, start_port, end_port, args.scan_type, not args.no_banner, logger)
        print_results(target, target_data[target])

    duration = round(time.monotonic() - started, 2)
    total_open = sum(len(data.get("open_ports", [])) for data in target_data.values())
    results = {
        "schema_version": "1.0",
        "scanner_version": VERSION,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "duration": f"{duration}s",
        "scan_type": args.scan_type.upper(),
        "profile": profile_label,
        "port_range": f"{start_port}-{end_port}",
        "total_open": total_open,
        "targets": target_data,
    }

    saved: list[str] = []
    os.makedirs(args.output_dir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    if args.save_json:
        path = os.path.join(args.output_dir, f"scan_{stamp}.json"); save_json(results, path); saved.append(path)
    if args.save_csv:
        path = os.path.join(args.output_dir, f"scan_{stamp}.csv"); save_csv(results, path); saved.append(path)
    if args.save_txt:
        path = os.path.join(args.output_dir, f"scan_{stamp}.txt"); save_txt(results, path); saved.append(path)

    message = f"[bold green]Scan complete[/bold green]  •  {len(resolved)} targets  •  {total_open} open ports  •  {duration}s"
    if saved:
        message += "\nReports: " + ", ".join(saved)
    console.print(Panel(message, border_style="green"))
    return 0


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "profiles":
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Profile")
        table.add_column("Ports")
        table.add_column("Description")
        for profile in list_profiles():
            table.add_row(profile["name"], profile["ports"], str(profile["description"]))
        console.print(table)
        return 0
    if args.command == "scan":
        return run_scan(args)
    console.print("[yellow]Choose a command. Try:[/yellow] aps scan --help")
    return 2


if __name__ == "__main__":
    sys.exit(main())
