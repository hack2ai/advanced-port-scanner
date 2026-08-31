import socket
import threading

from scanner.scanner import get_service_name, scan_target, tcp_connect_scan


def test_common_service_name():
    assert get_service_name(443) == "HTTPS"


def test_tcp_connect_scan_against_local_listener():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        assert tcp_connect_scan("127.0.0.1", port) == (port, True)
    finally:
        server.close()


def test_tcp_connect_scan_closed_port():
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    assert tcp_connect_scan("127.0.0.1", port) == (port, False)


def test_scan_target_reports_progress(monkeypatch):
    monkeypatch.setattr("scanner.scanner.get_ttl", lambda _ip: None)
    seen = []

    def fake_probe(_ip, port):
        return port, port % 2 == 0

    monkeypatch.setattr("scanner.scanner.tcp_connect_scan", fake_probe)
    result = scan_target("127.0.0.1", 1, 4, progress_callback=lambda done, total: seen.append((done, total)))

    assert [p["port"] for p in result["open_ports"]] == [2, 4]
    assert seen[-1] == (4, 4)


def test_scan_target_can_be_cancelled(monkeypatch):
    monkeypatch.setattr("scanner.scanner.get_ttl", lambda _ip: None)
    monkeypatch.setattr("scanner.scanner.tcp_connect_scan", lambda _ip, port: (port, False))
    cancel = threading.Event()
    calls = []

    def progress(done, total):
        calls.append(done)
        if done >= 1:
            cancel.set()

    try:
        scan_target("127.0.0.1", 1, 8, progress_callback=progress, cancel_event=cancel)
        assert False, "expected cancellation"
    except InterruptedError:
        pass

    assert calls
