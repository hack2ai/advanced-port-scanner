"""
scanner — Core scanning package for the Advanced Port Scanner.

Exports:
  scan_target      — Scan a single resolved IP over a port range.
  resolve_target   — Resolve hostname / validate IP.
  parse_port_range — Parse "80" or "20-1000" into (start, end).
  setup_logging    — Configure file + console logging.
  save_json        — Export results to JSON.
  save_csv         — Export results to CSV.
  save_txt         — Export results to plain text report.
"""

from scanner.scanner   import scan_target
from scanner.utils     import (
    setup_logging,
    resolve_target,
    parse_port_range,
    save_json,
    save_csv,
    save_txt,
)

__all__ = [
    "scan_target",
    "setup_logging",
    "resolve_target",
    "parse_port_range",
    "save_json",
    "save_csv",
    "save_txt",
]
