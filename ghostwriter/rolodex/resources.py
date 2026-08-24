"""Import/export resources for the Rolodex application."""

from import_export import resources

from ghostwriter.rolodex.matrix_text import normalize_matrix_text
from ghostwriter.rolodex.models import VulnerabilityMatrixEntry, WebIssueMatrixEntry


class VulnerabilityMatrixEntryResource(resources.ModelResource):
    """Import/export configuration for :model:`rolodex.VulnerabilityMatrixEntry`."""

    class Meta:
        model = VulnerabilityMatrixEntry
        skip_unchanged = False
        fields = (
            "id",
            "vulnerability",
            "action_required",
            "remediation_impact",
            "vulnerability_threat",
            "category",
        )
        export_order = fields

    def before_import_row(self, row, **kwargs):
        # Defensive normalization: a CSV exported from a database with
        # already-corrupted (HTML-wrapped) matrix entries should not
        # round-trip that HTML straight back in on re-import.
        for field_name in ("vulnerability", "action_required", "remediation_impact", "vulnerability_threat"):
            if field_name in row:
                row[field_name] = normalize_matrix_text(row[field_name])


class WebIssueMatrixEntryResource(resources.ModelResource):
    """Import/export configuration for :model:`rolodex.WebIssueMatrixEntry`."""

    class Meta:
        model = WebIssueMatrixEntry
        skip_unchanged = False
        fields = (
            "id",
            "title",
            "impact",
            "fix",
        )
        export_order = fields

    def before_import_row(self, row, **kwargs):
        for field_name in ("title", "impact", "fix"):
            if field_name in row:
                row[field_name] = normalize_matrix_text(row[field_name])
