"""Forms for managing vulnerability and web issue matrices."""

from django import forms

from ghostwriter.rolodex.matrix_text import normalize_matrix_text
from ghostwriter.rolodex.models import VulnerabilityMatrixEntry, WebIssueMatrixEntry


def _no_tinymce_textarea(rows=3):
    """Return a Textarea widget that opts out of the global TinyMCE hookup.

    Matrix fields are always consumed as plain strings, never as rich text,
    so a WYSIWYG editor would silently save HTML (e.g. "<p>...</p>") into
    them. The "no-auto-tinymce" class is the pattern already used elsewhere
    in the codebase (see rolodex/forms_workbook.py, commandcenter/models.py)
    to exclude a textarea from static/js/tinymce/config.js's selector.
    """

    return forms.Textarea(attrs={"class": "form-control no-auto-tinymce", "rows": rows})


class BaseMatrixEntryForm(forms.ModelForm):
    """Shared configuration for matrix entry forms."""

    def clean(self):
        cleaned_data = super().clean()
        # Normalize all string fields to plain text. This trims whitespace
        # (to avoid duplicate entries) and also strips/unwraps any HTML that
        # may still arrive from a WYSIWYG editor, so already-corrupted rows
        # self-heal the next time they're saved.
        for field_name, value in cleaned_data.items():
            if isinstance(value, str):
                cleaned_data[field_name] = normalize_matrix_text(value)
        return cleaned_data


class VulnerabilityMatrixEntryForm(BaseMatrixEntryForm):
    class Meta:
        model = VulnerabilityMatrixEntry
        fields = (
            "vulnerability",
            "action_required",
            "remediation_impact",
            "vulnerability_threat",
            "category",
        )
        widgets = {
            "vulnerability": _no_tinymce_textarea(rows=2),
            "action_required": _no_tinymce_textarea(),
            "remediation_impact": _no_tinymce_textarea(),
            "vulnerability_threat": _no_tinymce_textarea(),
        }

    def clean_vulnerability_threat(self):
        # Normalize here (rather than relying solely on the shared clean())
        # since field-level clean_<field> methods run before Form.clean(),
        # and the <EC> check needs to see the plain-text value.
        value = normalize_matrix_text(self.cleaned_data.get("vulnerability_threat", ""))
        if value and "<EC>" not in value:
            raise forms.ValidationError("Vulnerability threat must include the '<EC>' placeholder.")
        return value


class WebIssueMatrixEntryForm(BaseMatrixEntryForm):
    class Meta:
        model = WebIssueMatrixEntry
        fields = (
            "title",
            "impact",
            "fix",
        )
        widgets = {
            "title": _no_tinymce_textarea(rows=2),
            "impact": _no_tinymce_textarea(),
            "fix": _no_tinymce_textarea(),
        }


class MatrixUploadForm(forms.Form):
    """Form for CSV uploads."""

    csv_file = forms.FileField(
        label="CSV file",
        help_text="Upload a UTF-8 encoded CSV file containing the matrix entries.",
    )

    def clean_csv_file(self):
        csv_file = self.cleaned_data["csv_file"]
        if csv_file.size == 0:
            raise forms.ValidationError("The uploaded file is empty.")
        return csv_file
