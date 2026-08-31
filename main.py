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

from scanner.scanner import scan_target
from scanner.utils import parse_port_range, resolve_target, save_csv, save_json, save_txt, setup_logging
from scanner.vuln_hints import RISK_COLORS

VERSION = "3.0.0"
console = Console()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portscanner",
        description="Professional TCP service discovery for authorized security testing.",
    )
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("-t", "--targets", required=True, help="Comma-separated IP addresses or hostnames")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port or inclusive range (default: 1-1024)")
    parser.add_argument("--scan-type", choices=("tcp", "syn"), default="tcp", help="TCP connect or optional SYN lab mode")
    parser.add_argument("--no-banner", action="store_true", help="Disable small service-banner probes")
    parser.add_argument("--save-json", action="store_true", help="Write a JSON report")
    parser.add_argument("--save-csv", action="store_true", help="Write a CSV report")
    parser.add_argument("--save-txt", action="store_true", help="Write a text report")
    parser.add_argument("--output-dir", default="reports", help="Report directory (default: reports)")
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


def main() -> int:
    args = build_parser().parse_args()
    ports = parse_port_range(args.ports)
    if not ports:
        console.print(f"[bold red]Invalid port range:[/bold red] {args.ports}")
        return 2

    logger = setup_logging()
    raw_targets = list(dict.fromkeys(t.strip() for t in args.targets.split(",") if t.strip()))
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

    start_port, end_port = ports
    console.print(Panel.fit(
        f"[bold cyan]ADVANCED PORT SCANNER[/bold cyan]  v{VERSION}\n"
        f"Targets: {len(resolved)}  •  Ports: {start_port}-{end_port}  •  Mode: {args.scan_type.upper()}\n"
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
        "port_range": f"{start_port}-{end_port}",
        "total_open": total_open,
        "targets": target_data,
    }

    saved: list[str] = []
    os.makedirs(args.output_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
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


if __name__ == "__main__":
    sys.exit(main())
