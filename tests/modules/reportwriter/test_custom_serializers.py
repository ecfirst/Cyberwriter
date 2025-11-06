"""Tests for custom serializers workbook data helpers."""

from ghostwriter.modules.custom_serializers import ProjectSerializer


def test_collect_ad_responses_handles_none_domains():
    workbook_data = {"ad": {"domains": None}}

    result = ProjectSerializer._collect_ad_responses({}, workbook_data)

    assert result == {}


def test_collect_endpoint_responses_handles_none_domains():
    workbook_data = {"endpoint": {"domains": None}}

    result = ProjectSerializer._collect_endpoint_responses({}, workbook_data)

    assert result == {}
