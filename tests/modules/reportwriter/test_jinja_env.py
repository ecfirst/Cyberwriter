"""Tests for reportwriter Jinja environment helpers."""

from ghostwriter.modules.reportwriter import prepare_jinja2_env


def test_defined_test_accepts_extra_arguments_and_records_undefined():
    env, undefined_vars = prepare_jinja2_env(debug=True)

    template = env.from_string("{{ value is defined('ignored') }}")

    assert template.render({"value": "present"}) == "True"
    assert template.render({}) == "False"
    assert "value" in undefined_vars
