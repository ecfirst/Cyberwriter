import os

import importlib.util
import django
import pytest


if importlib.util.find_spec("channels") is None:
    pytest.skip("Django dependencies not installed", allow_module_level=True)

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.test")
os.environ.setdefault("DATABASE_URL", "sqlite:///memory")
django.setup()

from ghostwriter.modules.reportwriter.base.html_rich_text import LazilyRenderedTemplate
from ghostwriter.modules.reportwriter.project.base import ExportProjectBase


class DummyExporter:
    def create_lazy_template(self, location, text, context):
        return {"location": location, "text": text, "context": context}


def test_render_risk_rich_text_fields_recurses_nested_structures():
    context = {"sentinel": True}
    lazy_template = LazilyRenderedTemplate.__new__(LazilyRenderedTemplate)

    container = {
        "grade_rt": "<p>A</p>",
        "unchanged": "plain",
        "nested": [
            {"risk_rt": "<p>High</p>", "other": "x"},
            {"deep": {"score_rt": "<p>Low</p>", "already": lazy_template}},
        ],
    }

    ExportProjectBase._render_risk_rich_text_fields(
        DummyExporter(), container, "root", context
    )

    assert isinstance(container["grade_rt"], dict)
    assert container["grade_rt"]["text"] == "<p>A</p>"
    assert container["nested"][0]["risk_rt"]["text"] == "<p>High</p>"
    assert container["nested"][1]["deep"]["score_rt"]["text"] == "<p>Low</p>"
    # Existing lazy templates should be preserved
    assert container["nested"][1]["deep"]["already"] is lazy_template
    # Non-rt fields should be untouched
    assert container["nested"][0]["other"] == "x"
