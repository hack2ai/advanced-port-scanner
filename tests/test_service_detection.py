from scanner.service_detection import identify_from_banner


def test_identifies_openssh_and_version():
    result = identify_from_banner("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13")
    assert result.service == "ssh"
    assert result.product == "OpenSSH"
    assert result.version == "9.6p1"
    assert result.confidence >= 0.9


def test_identifies_http_server_product():
    result = identify_from_banner("HTTP/1.1 200 OK\r\nServer: nginx/1.27.0\r\nContent-Length: 0")
    assert result.service == "http"
    assert result.product == "nginx"
    assert result.version == "1.27.0"


def test_port_fallback_is_conservative():
    result = identify_from_banner("", 443)
    assert result.service == "https"
    assert 0.0 < result.confidence < 1.0


def test_unknown_response_is_safe():
    result = identify_from_banner("not a known protocol")
    assert result.service == "unknown"
    assert result.confidence == 0.0
