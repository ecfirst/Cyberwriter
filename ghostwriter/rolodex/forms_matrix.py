"""Forms for managing vulnerability and web issue matrices."""

from django import forms

from ghostwriter.rolodex.models import VulnerabilityMatrixEntry, WebIssueMatrixEntry


class BaseMatrixEntryForm(forms.ModelForm):
    """Shared configuration for matrix entry forms."""

    def clean(self):
        cleaned_data = super().clean()
        # Trim whitespace from all string fields to avoid duplicate entries.
        for field_name, value in cleaned_data.items():
            if isinstance(value, str):
                cleaned_data[field_name] = value.strip()
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
            "action_required": forms.Textarea(attrs={"rows": 3}),
            "remediation_impact": forms.Textarea(attrs={"rows": 3}),
        }


class WebIssueMatrixEntryForm(BaseMatrixEntryForm):
    class Meta:
        model = WebIssueMatrixEntry
        fields = (
            "title",
            "impact",
            "fix",
        )
        widgets = {
            "impact": forms.Textarea(attrs={"rows": 3}),
            "fix": forms.Textarea(attrs={"rows": 3}),
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
