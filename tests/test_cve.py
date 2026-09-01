from scanner.cve import enrich, lookup_offline


def test_offline_lookup_matches_product_and_version():
    feed = [
        {"product": "OpenSSH", "version": "9.8", "cve_id": "CVE-TEST-1", "severity": "high", "score": 8.1}
    ]
    matches = lookup_offline("OpenSSH", "9.8", feed)
    assert len(matches) == 1
    assert matches[0].cve_id == "CVE-TEST-1"
    assert matches[0].severity == "HIGH"
    assert matches[0].score == 8.1


def test_offline_lookup_requires_matching_version():
    feed = [{"product": "OpenSSH", "version": "9.8", "cve_id": "CVE-TEST-1"}]
    assert lookup_offline("OpenSSH", "9.7", feed) == []


def test_enrichment_off_mode_never_uses_network():
    result = enrich("OpenSSH", "9.8", mode="off")
    assert result["mode"] == "off"
    assert result["matches"] == []
