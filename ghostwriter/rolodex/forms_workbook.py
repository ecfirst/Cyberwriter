"""Forms that power the streamlined reporting workflow."""

# Standard Libraries
import json
from typing import Any, Dict, Iterable, List, Optional

# Django Imports
from django import forms
from django.forms.utils import flatatt
from django.utils.translation import gettext_lazy as _

# Ghostwriter Libraries
from ghostwriter.rolodex.ip_artifacts import (
    IP_ARTIFACT_DEFINITIONS,
    IP_ARTIFACT_TYPE_EXTERNAL,
    IP_ARTIFACT_TYPE_INTERNAL,
    normalize_ip_entries,
    parse_ip_text,
)
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
        widget=forms.FileInput(
            attrs={
                "class": "form-control-file",
                "accept": "application/json,.json",
            }
        ),
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

        if not isinstance(parsed, dict):
            workbook_file.seek(0)
            raise forms.ValidationError(_("The workbook JSON must contain an object at the top level."))
        workbook_file.seek(0)
        self.cleaned_data["parsed_workbook"] = parsed
        return workbook_file


class ProjectDataFileForm(forms.ModelForm):
    """Upload additional artifacts that support reporting."""

    class Meta:
        model = ProjectDataFile
        fields = ["file", "description"]
        labels = {
            "file": _("Supporting Data File"),
            "description": _("Description"),
        }
        help_texts = {
            "file": _("Upload CSV, JSON, or other artifacts referenced in the report."),
            "description": _("Optional note to help identify this file."),
        }
        widgets = {
            "file": forms.ClearableFileInput(attrs={"class": "form-control-file"}),
            "description": forms.TextInput(attrs={"placeholder": _("Optional description")}),
        }


class ProjectIPArtifactForm(forms.Form):
    """Capture supplemental IP list content for a project."""

    ip_type = forms.ChoiceField(
        choices=(
            (IP_ARTIFACT_TYPE_EXTERNAL, IP_ARTIFACT_DEFINITIONS[IP_ARTIFACT_TYPE_EXTERNAL].label),
            (IP_ARTIFACT_TYPE_INTERNAL, IP_ARTIFACT_DEFINITIONS[IP_ARTIFACT_TYPE_INTERNAL].label),
        ),
        widget=forms.HiddenInput(),
    )
    ip_text = forms.CharField(
        required=False,
        widget=forms.Textarea(
            attrs={
                "class": "form-control no-auto-tinymce",
                "rows": 5,
                "placeholder": _("One IP address per line"),
            }
        ),
        label=_("IP Addresses"),
    )
    ip_file = forms.FileField(
        required=False,
        widget=forms.ClearableFileInput(
            attrs={
                "class": "form-control-file",
                "accept": ".txt,text/plain",
            }
        ),
        label=_("Upload Plain Text"),
        help_text=_("Upload a text file containing one IP address per line."),
    )

    def clean(self):
        cleaned_data = super().clean()
        ip_type = cleaned_data.get("ip_type")
        if ip_type not in IP_ARTIFACT_DEFINITIONS:
            raise forms.ValidationError("Unsupported IP list type submitted.")

        text_content = cleaned_data.get("ip_text") or ""
        uploaded_file = cleaned_data.get("ip_file")
        if not text_content and not uploaded_file:
            raise forms.ValidationError("Provide IP addresses by pasting them or uploading a file.")

        parsed_values = []
        if text_content:
            parsed_values.extend(parse_ip_text(text_content))
        if uploaded_file:
            file_content = uploaded_file.read()
            if isinstance(file_content, bytes):
                file_content = file_content.decode("utf-8", "ignore")
            parsed_values.extend(parse_ip_text(file_content))
            uploaded_file.seek(0)

        normalized_values = normalize_ip_entries(parsed_values)
        if not normalized_values:
            raise forms.ValidationError("No IP addresses were found in the submitted data.")

        cleaned_data["parsed_ips"] = normalized_values
        return cleaned_data


def _format_summary_with_conjunction(parts: List[str]) -> str:
    if not parts:
        return ""
    if len(parts) == 1:
        return parts[0]
    if len(parts) == 2:
        return f"{parts[0]} and {parts[1]}"
    leading = ", ".join(parts[:-1])
    return f"{leading} and {parts[-1]}"


def _build_entry_slug_lookup(question_definitions: Optional[List[Dict[str, Any]]]) -> Dict[str, Dict[str, str]]:
    """Create a lookup map from section/subheading pairs to entry slugs."""

    lookup: Dict[str, Dict[str, str]] = {}
    if not question_definitions:
        return lookup

    for definition in question_definitions:
        section_key = str(definition.get("section_key") or "").strip()
        subheading = str(definition.get("subheading") or "").strip()
        entry_slug = definition.get("entry_slug")

        if not section_key or not subheading or not entry_slug:
            continue

        section_lookup = lookup.setdefault(section_key.lower(), {})
        section_lookup.setdefault(subheading, entry_slug)
        section_lookup.setdefault(subheading.lower(), entry_slug)

    return lookup


def _flatten_grouped_initial(
    initial: Dict[str, Any], question_definitions: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """Return a copy of ``initial`` with grouped sections expanded for form fields."""

    source = dict(initial or {})
    flattened: Dict[str, Any] = {}

    slug_lookup = _build_entry_slug_lookup(question_definitions)

    wireless_values = source.pop("wireless", None)
    if isinstance(wireless_values, dict):
        for key, value in wireless_values.items():
            flattened[f"wireless_{key}"] = value

    for section_key, section_value in source.items():
        if not isinstance(section_value, dict):
            flattened[section_key] = section_value
            continue

        normalized_section_key = str(section_key or "").strip().lower()
        section_slug_lookup = slug_lookup.get(normalized_section_key, {})
        entries = section_value.get("entries")
        if isinstance(entries, list):
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                slug_value = entry.get("_slug") or entry.get("slug")
                identifier = entry.get("domain") or entry.get("name")
                if not slug_value and identifier:
                    identifier_text = str(identifier).strip()
                    slug_value = section_slug_lookup.get(identifier_text) or section_slug_lookup.get(
                        identifier_text.lower()
                    )
                for field_key, field_value in entry.items():
                    if field_key in {"domain", "name", "_slug", "slug"}:
                        continue
                    if slug_value:
                        flattened[f"{slug_value}_{field_key}"] = field_value
                    elif identifier:
                        flattened[f"{section_key}_{field_key}"] = field_value

        for field_key, field_value in section_value.items():
            if field_key == "entries":
                continue
            flattened_key = field_key
            if section_key == "overall_risk" and field_key == "major_issues":
                flattened_key = "overall_risk_major_issues"
            flattened[flattened_key] = field_value

    return flattened


class SummaryMultipleChoiceField(forms.MultipleChoiceField):
    """Return a natural language summary string for the selected options."""

    def __init__(self, *args, summary_map: Optional[Dict[str, str]] = None, **kwargs):
        self.summary_map = summary_map or {}
        super().__init__(*args, **kwargs)

    def clean(self, value: Any):  # type: ignore[override]
        selected_values = super().clean(value)
        if not selected_values:
            return ""
        parts: List[str] = []
        for option in selected_values:
            summary_text = self.summary_map.get(option)
            if summary_text is None:
                summary_text = self._lookup_label(option)
            parts.append(summary_text)
        return _format_summary_with_conjunction(parts)

    def prepare_value(self, value):  # type: ignore[override]
        if isinstance(value, str):
            return self._parse_summary(value)
        return super().prepare_value(value)

    def _lookup_label(self, option_value: str) -> str:
        for candidate_value, candidate_label in self.choices:
            if isinstance(candidate_label, (list, tuple)):
                for nested_value, nested_label in candidate_label:
                    if nested_value == option_value:
                        return str(nested_label)
            elif candidate_value == option_value:
                return str(candidate_label)
        return str(option_value)

    def _parse_summary(self, summary: str) -> List[str]:
        summary = summary.strip()
        if not summary:
            return []
        parts: List[str]
        if " and " in summary:
            leading, last = summary.rsplit(" and ", 1)
            leading_parts = [segment.strip() for segment in leading.split(",") if segment.strip()]
            parts = leading_parts + [last.strip()]
        else:
            parts = [summary]

        reverse_map = {text: key for key, text in self.summary_map.items()}
        resolved: List[str] = []
        for part in parts:
            value = reverse_map.get(part)
            if value is None:
                value = self._find_value_by_label(part)
            if value is not None:
                resolved.append(value)
        return resolved

    def _find_value_by_label(self, label: str) -> Optional[str]:
        for candidate_value, candidate_label in self.choices:
            if isinstance(candidate_label, (list, tuple)):
                for nested_value, nested_label in candidate_label:
                    if str(nested_label) == label:
                        return nested_value
            elif str(candidate_label) == label:
                return candidate_value
        return None


class ProjectDataResponsesForm(forms.Form):
    """Dynamically render questions driven by the workbook contents."""

    def __init__(self, *args, question_definitions: Optional[List[Dict[str, Any]]] = None, **kwargs):
        self.question_definitions = question_definitions or []
        super().__init__(*args, **kwargs)
        initial_values = _flatten_grouped_initial(self.initial, self.question_definitions)
        for definition in self.question_definitions:
            field_kwargs = definition.get("field_kwargs", {}).copy()
            key = definition["key"]
            field_class = definition["field_class"]
            if key in initial_values:
                field_kwargs["initial"] = initial_values[key]
            self.fields[key] = field_class(**field_kwargs)

    def clean(self):  # type: ignore[override]
        cleaned_data = super().clean()
        if not isinstance(cleaned_data, dict):
            return cleaned_data

        wireless_prefix = "wireless_"
        wireless_values = cleaned_data.get("wireless")
        if isinstance(wireless_values, dict):
            grouped = dict(wireless_values)
        else:
            grouped = {}

        for key in list(cleaned_data.keys()):
            if isinstance(key, str) and key.startswith(wireless_prefix):
                value = cleaned_data.pop(key)
                grouped_key = key[len(wireless_prefix) :]
                grouped[grouped_key] = value

        if grouped:
            cleaned_data["wireless"] = grouped
        else:
            cleaned_data.pop("wireless", None)

        return cleaned_data

    @property
    def ordered_questions(self) -> List[Dict[str, Any]]:
        """Expose the ordered question definitions for template rendering."""

        return self.question_definitions
