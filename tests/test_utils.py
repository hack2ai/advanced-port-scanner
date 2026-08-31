from scanner.utils import detect_os, parse_port_range, resolve_target


def test_parse_single_port():
    assert parse_port_range("443") == (443, 443)


def test_parse_range_with_spaces():
    assert parse_port_range(" 20 - 80 ") == (20, 80)


def test_reject_invalid_ports():
    assert parse_port_range("0") is None
    assert parse_port_range("65536") is None
    assert parse_port_range("100-10") is None
    assert parse_port_range("abc") is None


def test_os_guess_is_heuristic():
    assert "Linux" in detect_os(64)
    assert "Windows" in detect_os(128)


def test_literal_ip_resolution():
    assert resolve_target("127.0.0.1") == "127.0.0.1"


def test_reject_malformed_target():
    assert resolve_target("bad target!") is None
