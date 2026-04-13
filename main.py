#!/usr/bin/env python3
"""
main.py — CLI entry point for the Advanced Network Port Scanner.

Usage examples:
  python main.py -t 192.168.1.1
  python main.py -t 192.168.1.1 -p 1-65535 --scan-type tcp --save-json --save-csv
  python main.py -t scanme.nmap.org,192.168.1.1 -p 20-1000 --no-banner --save-txt
  python main.py -t 10.0.0.1 -p 1-65535 --scan-type syn   # root required for SYN
"""

import argparse
import os
import sys
import time
from datetime import datetime

from rich                import box
from rich.console        import Console
from rich.panel          import Panel
from rich.table          import Table
from rich.text           import Text
from rich.rule           import Rule

# Add project root to path so `scanner` package is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.scanner    import scan_target
from scanner.utils      import (
    setup_logging, resolve_target, parse_port_range,
    save_json, save_csv, save_txt,
)
from scanner.vuln_hints import RISK_COLORS


console = Console()


# ─────────────────────────────────────────────────────────────────────────────
#  UI helpers
# ─────────────────────────────────────────────────────────────────────────────

def print_banner() -> None:
    """Display the tool banner."""
    art = Text(justify="center")
    art.append("\n  ███████╗ ██████╗  █████╗ ███╗  ██╗\n", style="bold cyan")
    art.append("  ██╔════╝██╔════╝██╔══██╗████╗ ██║\n", style="bold cyan")
    art.append("  ███████╗██║     ███████║██╔██╗██║\n", style="bold cyan")
    art.append("  ╚════██║██║     ██╔══██║██║╚████║\n", style="bold cyan")
    art.append("  ███████║╚██████╗██║  ██║██║ ╚███║\n", style="bold cyan")
    art.append("  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝\n", style="bold cyan")
    art.append("\n  Advanced Network Port Scanner  v2.0\n", style="bold white")
    art.append("  ⚠  For authorised testing only!\n", style="bold red")

    console.print(Panel(art, border_style="cyan", padding=(0, 2)))


def print_results(target: str, data: dict) -> None:
    """Render per-target results as a rich table."""
    open_ports = data.get("open_ports", [])

    console.print(Rule(style="cyan"))
    console.print(
        f"  [bold cyan]Target  :[/bold cyan] {target}   "
        f"[bold cyan]IP      :[/bold cyan] {data.get('ip', target)}"
    )
    console.print(
        f"  [bold cyan]OS Guess:[/bold cyan] {data.get('os_guess', 'Unknown')}   "
        f"[bold cyan]TTL     :[/bold cyan] {data.get('ttl', 'N/A')}"
    )
    console.print(
        f"  [bold green]Open Ports: {len(open_ports)}[/bold green]\n"
    )

    if not open_ports:
        console.print("  [yellow]  No open ports found in scanned range.[/yellow]\n")
        return

    table = Table(
        title=f"Results — {target}",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold bright_cyan",
        show_lines=True,
        expand=False,
    )
    table.add_column("PORT",    style="bold white",        width=7,  justify="right")
    table.add_column("SERVICE", style="bold yellow",       width=14)
    table.add_column("RISK",    style="bold",              width=10)
    table.add_column("BANNER",  style="dim white",         width=38)
    table.add_column("VULNERABILITY HINT", style="italic", width=48)

    for p in open_ports:
        risk       = p.get("risk", "INFO")
        risk_color = RISK_COLORS.get(risk, "white")
        table.add_row(
            str(p["port"]),
            p.get("service", ""),
            f"[{risk_color}]{risk}[/{risk_color}]",
            (p.get("banner") or "")[:38],
            p.get("vuln_hint", ""),
        )

    console.print(table)


def print_summary(
    n_targets: int,
    total_open: int,
    duration: float,
    saved_files: list[str],
) -> None:
    """Print the final scan summary panel."""
    lines = (
        f"[bold green]✔  Scan complete![/bold green]\n\n"
        f"  Targets scanned : [bold]{n_targets}[/bold]\n"
        f"  Total open ports: [bold green]{total_open}[/bold green]\n"
        f"  Time elapsed    : [bold cyan]{duration:.2f}s[/bold cyan]"
    )
    if saved_files:
        lines += "\n\n  [bold]Reports saved:[/bold]"
        for f in saved_files:
            lines += f"\n    [dim]→[/dim] {f}"

    console.print(Panel(lines, title="Summary", border_style="green", padding=(1, 2)))


# ─────────────────────────────────────────────────────────────────────────────
#  Argument parsing
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portscanner",
        description="Advanced Network Port Scanner — fast, threaded, professional.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py -t 192.168.1.1\n"
            "  python main.py -t 192.168.1.1 -p 1-1024 --save-json --save-csv\n"
            "  python main.py -t scanme.nmap.org -p 1-65535 --scan-type tcp\n"
            "  python main.py -t 10.0.0.1,10.0.0.2 -p 22,80,443 --no-banner\n"
        ),
    )

    parser.add_argument(
        "-t", "--targets", required=True,
        help="Target IP(s) or hostname(s), comma-separated.\n"
             "Example: 192.168.1.1  or  192.168.1.1,scanme.nmap.org",
    )
    parser.add_argument(
        "-p", "--ports", default="1-1024",
        help="Port range or single port.\n"
             "Examples:  80  |  20-1000  |  1-65535\n"
             "Default: 1-1024",
    )
    parser.add_argument(
        "--scan-type", choices=["tcp", "syn"], default="tcp",
        help="Scan method:\n"
             "  tcp — TCP connect scan (no root needed) [default]\n"
             "  syn — SYN stealth scan (requires root/Administrator)",
    )
    parser.add_argument(
        "--no-banner", action="store_true",
        help="Skip banner grabbing (faster scan)",
    )
    parser.add_argument("--save-json", action="store_true", help="Export results as JSON")
    parser.add_argument("--save-csv",  action="store_true", help="Export results as CSV")
    parser.add_argument("--save-txt",  action="store_true", help="Export results as TXT report")
    parser.add_argument(
        "--output-dir", default="reports",
        help="Directory to save reports (default: reports/)",
    )
    return parser


# ─────────────────────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    print_banner()

    args   = build_parser().parse_args()
    logger = setup_logging()

    # ── Validate port range ───────────────────────────────────
    port_range = parse_port_range(args.ports)
    if not port_range:
        console.print(f"[bold red][!] Invalid port range: '{args.ports}'[/bold red]")
        sys.exit(1)
    start_port, end_port = port_range
    port_count = end_port - start_port + 1

    # ── Resolve targets ───────────────────────────────────────
    raw_targets = [t.strip() for t in args.targets.split(",") if t.strip()]
    resolved: dict[str, str] = {}

    console.print(Rule("[cyan]Target Resolution[/cyan]", style="cyan"))
    for t in raw_targets:
        ip = resolve_target(t, logger)
        if ip:
            console.print(f"  [green]✔[/green] {t} → {ip}")
            resolved[t] = ip
        else:
            console.print(f"  [red]✘[/red] {t} — cannot resolve, skipping")

    if not resolved:
        console.print("\n[bold red]No valid targets. Exiting.[/bold red]")
        sys.exit(1)

    # ── Scan info ─────────────────────────────────────────────
    console.print(Rule("[cyan]Scan Configuration[/cyan]", style="cyan"))
    console.print(
        f"  Scan type  : [bold]{args.scan_type.upper()}[/bold]\n"
        f"  Port range : [bold]{start_port}–{end_port}[/bold]  ({port_count:,} ports)\n"
        f"  Banner grab: [bold]{'No' if args.no_banner else 'Yes'}[/bold]"
    )

    if args.scan_type == "syn":
        console.print(
            "  [yellow]⚠  SYN scan selected — requires root/Administrator.[/yellow]\n"
            "  [yellow]   Falls back to TCP connect if Scapy is unavailable.[/yellow]"
        )

    console.print()

    # ── Run scans ─────────────────────────────────────────────
    target_data: dict[str, dict] = {}
    start_time = time.time()

    for raw_t, ip in resolved.items():
        data = scan_target(
            ip=ip,
            start_port=start_port,
            end_port=end_port,
            scan_type=args.scan_type,
            grab_banners=not args.no_banner,
            logger=logger,
        )
        target_data[raw_t] = data
        print_results(raw_t, data)

    duration   = time.time() - start_time
    total_open = sum(len(d.get("open_ports", [])) for d in target_data.values())

    # ── Build results object ──────────────────────────────────
    results = {
        "scan_time":  datetime.now().isoformat(),
        "duration":   f"{duration:.2f}s",
        "scan_type":  args.scan_type.upper(),
        "port_range": f"{start_port}-{end_port}",
        "total_open": total_open,
        "targets":    target_data,
    }

    # ── Save reports ──────────────────────────────────────────
    os.makedirs(args.output_dir, exist_ok=True)
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    saved_files: list[str] = []

    if args.save_json:
        path = os.path.join(args.output_dir, f"scan_{timestamp}.json")
        save_json(results, path)
        saved_files.append(path)

    if args.save_csv:
        path = os.path.join(args.output_dir, f"scan_{timestamp}.csv")
        save_csv(results, path)
        saved_files.append(path)

    if args.save_txt:
        path = os.path.join(args.output_dir, f"scan_{timestamp}.txt")
        save_txt(results, path)
        saved_files.append(path)

    print_summary(len(resolved), total_open, duration, saved_files)


if __name__ == "__main__":
    main()
