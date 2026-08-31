from scanner.profiles import get_profile, list_profiles


def test_profiles_include_expected_presets():
    profiles = list_profiles()
    assert [item["name"] for item in profiles] == ["quick", "standard", "extended", "full"]
    assert profiles[0]["ports"] == "1-100"
    assert profiles[-1]["ports"] == "1-65535"


def test_profile_lookup_is_case_insensitive():
    profile = get_profile(" Standard ")
    assert profile is not None
    assert profile.port_range == "1-1024"


def test_unknown_profile_returns_none():
    assert get_profile("unknown") is None
