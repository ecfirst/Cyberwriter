import logging

from django.core.management.base import BaseCommand, CommandError

from ghostwriter.rolodex.data_parsers import NEXPOSE_METRICS_KEY_MAP
from ghostwriter.rolodex.models import Project

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = (
        "Regenerate on-disk Nexpose XLSX workbooks (ProjectArtifactFile) for projects "
        "still serving an old base64-embedded workbook from before "
        "NEXPOSE_AGGREGATE_SCHEMA_VERSION 2. The 0103_aggregate_nexpose_findings "
        "migration deliberately leaves those old workbooks in place rather than "
        "regenerating them itself (a migration shouldn't write to file storage, "
        "possibly S3, for a potentially large number of projects with unbounded "
        "runtime) -- this command does that work instead, run deliberately and "
        "outside the request/response cycle."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--project-id",
            type=int,
            default=None,
            help="Only rebuild this one project (by pk), instead of every project with a stale workbook.",
        )
        parser.add_argument(
            "--force",
            action="store_true",
            help="Rebuild even projects that already have an on-disk workbook for every populated metrics key.",
        )

    def handle(self, *args, **options):
        project_id = options.get("project_id")
        force = options.get("force")

        if project_id is not None:
            queryset = Project.objects.filter(pk=project_id)
            if not queryset.exists():
                raise CommandError(f"No project with ID={project_id} exists.")
        else:
            queryset = Project.objects.all()

        rebuilt = 0
        skipped = 0
        errored = 0

        for project in queryset.only("id", "data_artifacts").iterator(chunk_size=25):
            artifacts = project.data_artifacts if isinstance(project.data_artifacts, dict) else {}
            if not force and not self._has_stale_workbook(artifacts):
                skipped += 1
                continue

            try:
                project.rebuild_data_artifacts()
            except Exception:
                errored += 1
                logger.exception("Failed to rebuild Nexpose workbooks for project ID=%s", project.pk)
                continue

            rebuilt += 1
            self.stdout.write(f"Rebuilt project ID={project.pk}")

        self.stdout.write(
            self.style.SUCCESS(
                f"Done. Rebuilt: {rebuilt}, skipped (already current): {skipped}, errored: {errored}."
            )
        )

    @staticmethod
    def _has_stale_workbook(artifacts) -> bool:
        """True if any populated Nexpose metrics key still needs a real on-disk workbook.

        "Stale" means: the metrics key exists and has findings (a non-empty
        ``summary.total``), but no ``xlsx`` reference (either never
        generated, or still on the old base64-embedded form from before
        NEXPOSE_AGGREGATE_SCHEMA_VERSION 2).
        """
        for metrics_key in NEXPOSE_METRICS_KEY_MAP.values():
            payload = artifacts.get(metrics_key)
            if not isinstance(payload, dict):
                continue
            summary = payload.get("summary")
            total = summary.get("total") if isinstance(summary, dict) else 0
            if not total:
                continue
            if not isinstance(payload.get("xlsx"), dict):
                return True
        return False
