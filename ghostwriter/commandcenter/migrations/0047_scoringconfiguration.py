from decimal import Decimal

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("commandcenter", "0046_rename_openaiconfiguration_prompt_id"),
    ]

    operations = [
        migrations.CreateModel(
            name="ScoringConfiguration",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "area_score_exponent",
                    models.DecimalField(
                        decimal_places=2,
                        default=Decimal("3.00"),
                        help_text="Power-mean exponent used to roll sub-area scores up into an area total. 1 = plain weighted average; higher values let high scores dominate and low scores drag less.",
                        max_digits=4,
                        validators=[django.core.validators.MinValueValidator(Decimal("1.00"))],
                        verbose_name="Area Score Exponent",
                    ),
                ),
                (
                    "overall_score_exponent",
                    models.DecimalField(
                        decimal_places=2,
                        default=Decimal("2.00"),
                        help_text="Power-mean exponent used to roll area totals up into the overall grade. 1 = plain average; higher values let high-risk areas dominate.",
                        max_digits=4,
                        validators=[django.core.validators.MinValueValidator(Decimal("1.00"))],
                        verbose_name="Overall Score Exponent",
                    ),
                ),
                (
                    "wireless_overall_weight",
                    models.DecimalField(
                        decimal_places=2,
                        default=Decimal("0.90"),
                        help_text="Share of an equal area weight that Wireless carries in the overall grade (wireless exploitation requires physical proximity). The remainder is spread across the other in-scope areas.",
                        max_digits=3,
                        validators=[
                            django.core.validators.MinValueValidator(Decimal("0.00")),
                            django.core.validators.MaxValueValidator(Decimal("1.00")),
                        ],
                        verbose_name="Wireless Overall Weight",
                    ),
                ),
            ],
            options={
                "verbose_name": "Scoring Settings",
            },
        ),
    ]
