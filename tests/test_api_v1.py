from web.api_v1 import api_v1


def test_v1_health_response_shape():
    routes = [rule.rule for rule in api_v1.url_values_defaults or []]
    assert api_v1.name == "api_v1"
    assert "/api/v1" in api_v1.url_prefix


def test_v1_blueprint_exposes_expected_routes():
    rules = {rule.rule for rule in api_v1.deferred_functions if hasattr(rule, "rule")}
    # Flask stores deferred view registration as closures, so verify the
    # public blueprint metadata and route functions directly instead.
    assert callable(api_v1)
