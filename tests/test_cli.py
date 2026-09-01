from argparse import Namespace
from dataclasses import replace

import main


def test_cli_rejects_range_above_configured_limit(monkeypatch):
    monkeypatch.setattr(main, "settings", replace(main.settings, max_ports=4))
    called = False

    def fake_scan(*args, **kwargs):
        nonlocal called
        called = True
        return {}

    monkeypatch.setattr(main, "scan_target", fake_scan)
    args = Namespace(
        targets="127.0.0.1",
        ports="1-5",
        profile="standard",
        scan_type="tcp",
        no_banner=True,
        save_json=False,
        save_csv=False,
        save_txt=False,
        output_dir="reports",
    )

    assert main.run_scan(args) == 2
    assert called is False


def test_cli_rejects_more_targets_than_configured_limit(monkeypatch):
    monkeypatch.setattr(main, "settings", replace(main.settings, max_targets=2))
    resolved = []

    def fake_resolve(target, logger):
        resolved.append(target)
        return "127.0.0.1"

    monkeypatch.setattr(main, "resolve_target", fake_resolve)
    args = Namespace(
        targets="127.0.0.1,127.0.0.2,127.0.0.3",
        ports="1-2",
        profile="standard",
        scan_type="tcp",
        no_banner=True,
        save_json=False,
        save_csv=False,
        save_txt=False,
        output_dir="reports",
    )

    assert main.run_scan(args) == 2
    assert resolved == []
