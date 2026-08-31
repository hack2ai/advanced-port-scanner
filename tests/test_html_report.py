from pathlib import Path

from scanner.html_report import generate_html_report


def test_html_report_escapes_untrusted_fields(tmp_path: Path):
    output = tmp_path / "report.html"
    generate_html_report(
        {
            "schema_version": "1.0",
            "scan_time": "2026-08-31T00:00:00+00:00",
            "duration": "1.2s",
            "total_open": 1,
            "report_title": "Report <x>",
            "targets": {
                "127.0.0.1"><script>": {
                    "ip": "127.0.0.1",
                    "open_ports": [
                        {
                            "port": 80,
                            "service": "HTTP",
                            "risk": "LOW",
                            "banner": "<script>alert(1)</script>",
                            "confidence": 0.9,
                        }
                    ],
                }
            },
        },
        str(output),
    )
    content = output.read_text(encoding="utf-8")
    assert output.exists()
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in content
    assert "<script>alert(1)</script>" not in content
    assert "Report &lt;x&gt;" in content
