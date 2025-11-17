from decimal import Decimal

from django.core.validators import MinValueValidator
from django.db import migrations, models


DEFAULT_RISK_SCORE_MAP = (
    ("Low", Decimal("1.0"), Decimal("1.9")),
    ("Low-->Medium", Decimal("2.0"), Decimal("2.4")),
    ("Medium-->Low", Decimal("2.5"), Decimal("2.9")),
    ("Medium", Decimal("3.0"), Decimal("3.9")),
    ("Medium-->High", Decimal("4.0"), Decimal("4.4")),
    ("High-->Medium", Decimal("4.5"), Decimal("4.9")),
    ("High", Decimal("5.0"), Decimal("6.0")),
)


def seed_risk_score_ranges(apps, schema_editor):
    mapping_model = apps.get_model("reporting", "RiskScoreRangeMapping")
    for risk, min_score, max_score in DEFAULT_RISK_SCORE_MAP:
        mapping_model.objects.update_or_create(
            risk=risk,
            defaults={"min_score": min_score, "max_score": max_score},
        )


class Migration(migrations.Migration):

    dependencies = [
        ("reporting", "0061_passwordcompliancemapping"),
    ]

    operations = [
        migrations.CreateModel(
            name="RiskScoreRangeMapping",
            fields=[
                (
                    "id",
                    models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID"),
                ),
                (
                    "risk",
                    models.CharField(
                        help_text="Risk bucket label (e.g., Low or Medium-->High)",
                        max_length=32,
                        unique=True,
                        verbose_name="Risk label",
                    ),
                ),
                (
                    "min_score",
                    models.DecimalField(
                        decimal_places=1,
                        help_text="Lowest inclusive score for this risk bucket.",
                        max_digits=4,
                        validators=[MinValueValidator(Decimal("0.0"))],
                        verbose_name="Minimum score",
                    ),
                ),
                (
                    "max_score",
                    models.DecimalField(
                        decimal_places=1,
                        help_text="Highest inclusive score for this risk bucket.",
                        max_digits=4,
                        validators=[MinValueValidator(Decimal("0.0"))],
                        verbose_name="Maximum score",
                    ),
                ),
            ],
            options={
                "ordering": ["min_score", "risk"],
                "verbose_name": "Risk to score range mapping",
                "verbose_name_plural": "Risk to score range mappings",
            },
        ),
        migrations.RunPython(seed_risk_score_ranges, migrations.RunPython.noop),
    ]
