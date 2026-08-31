import socket

from scanner.scanner import get_service_name, tcp_connect_scan


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
