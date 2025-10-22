"""Forms that power the streamlined reporting workflow."""

# Standard Libraries
import json
from typing import Any, Dict, Iterable, List, Optional

# Django Imports
from django import forms
from django.forms.utils import flatatt
from django.utils.translation import gettext_lazy as _

# Ghostwriter Libraries
from ghostwriter.rolodex.models import ProjectDataFile


class MultipleTextInput(forms.Widget):
    """Render one or more text inputs that can be dynamically extended in the UI."""

    template_name = "rolodex/widgets/multiple_text_input.html"

    def get_context(self, name: str, value: Any, attrs: Dict[str, Any]):  # type: ignore[override]
        context = super().get_context(name, value, attrs)
        attrs = context["widget"].get("attrs", {})
        attrs.pop("id", None)
        existing_class = attrs.get("class", "")
        if "form-control" not in existing_class.split():
            attrs["class"] = (existing_class + " form-control").strip()
        context["widget"]["flat_attrs"] = flatatt(attrs)

        values: List[str]
        if value is None or value == "":
            values = [""]
        elif isinstance(value, (list, tuple)):
            values = [str(item) for item in value if str(item).strip()]
            if not values:
                values = [""]
        else:
            text = str(value)
            values = [text] if text else [""]
        context["widget"]["value_list"] = values
        return context

    def value_from_datadict(self, data: Any, files: Dict[str, Any], name: str):  # type: ignore[override]
        if hasattr(data, "getlist"):
            values = data.getlist(name)
        else:  # pragma: no cover - fallback for unexpected data types
            raw_value = data.get(name)
            if isinstance(raw_value, (list, tuple)):
                values = list(raw_value)
            elif raw_value is None:
                values = []
            else:
                values = [raw_value]
        return [str(item).strip() for item in values if str(item).strip()]


class MultiValueField(forms.Field):
    """Capture one or more string responses as a list."""

    widget = MultipleTextInput

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("required", False)
        super().__init__(*args, **kwargs)

    def to_python(self, value: Any) -> List[str]:  # type: ignore[override]
        if value in (None, ""):
            return []
        if isinstance(value, (list, tuple)):
            return [str(item).strip() for item in value if str(item).strip()]
        text = str(value).strip()
        return [text] if text else []

    def validate(self, value: Iterable[str]):  # type: ignore[override]
        if self.required and not value:
            raise forms.ValidationError(self.error_messages["required"], code="required")


class ProjectWorkbookForm(forms.Form):
    """Upload and validate a workbook JSON file."""

    workbook_file = forms.FileField(
        label=_("Workbook JSON"),
        widget=forms.FileInput(attrs={"class": "form-control-file"}),
    )

    def clean_workbook_file(self):  # type: ignore[override]
        workbook_file = self.cleaned_data.get("workbook_file")
        if not workbook_file:
            raise forms.ValidationError(_("Please provide a workbook file."))
        filename = workbook_file.name or ""
        if not filename.lower().endswith(".json"):
            raise forms.ValidationError(_("The workbook must be a JSON file."))
        try:
            raw_data = workbook_file.read()
            if isinstance(raw_data, bytes):
                raw_data = raw_data.decode("utf-8")
        except UnicodeDecodeError as exc:
            workbook_file.seek(0)
            raise forms.ValidationError(_("Unable to decode the uploaded file as UTF-8.")) from exc
        try:
            parsed = json.loads(raw_data)
        except json.JSONDecodeError as exc:
            workbook_file.seek(0)
            raise forms.ValidationError(_("The uploaded workbook is not valid JSON.")) from exc
        workbook_file.seek(0)
        self.cleaned_data["parsed_workbook"] = parsed
        return workbook_file


class ProjectDataFileForm(forms.ModelForm):
    """Upload additional artefacts that support reporting."""

    class Meta:
        model = ProjectDataFile
        fields = ["file", "description"]
        labels = {
            "file": _("Supporting Data File"),
            "description": _("Description"),
        }
        help_texts = {
            "file": _("Upload CSV, JSON, or other artefacts referenced in the report."),
            "description": _("Optional note to help identify this file."),
        }
        widgets = {
            "file": forms.ClearableFileInput(attrs={"class": "form-control-file"}),
            "description": forms.TextInput(attrs={"placeholder": _("Optional description")}),
        }


class ProjectDataResponsesForm(forms.Form):
    """Dynamically render questions driven by the workbook contents."""

    def __init__(self, *args, question_definitions: Optional[List[Dict[str, Any]]] = None, **kwargs):
        self.question_definitions = question_definitions or []
        super().__init__(*args, **kwargs)
        initial_values = self.initial.copy()
        for definition in self.question_definitions:
            field_kwargs = definition.get("field_kwargs", {}).copy()
            key = definition["key"]
            field_class = definition["field_class"]
            if key in initial_values:
                field_kwargs.setdefault("initial", initial_values[key])
            self.fields[key] = field_class(**field_kwargs)

    @property
    def ordered_questions(self) -> List[Dict[str, Any]]:
        """Expose the ordered question definitions for template rendering."""

        return self.question_definitions
