"""Import/export resources for the Rolodex application."""

from import_export import resources

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
