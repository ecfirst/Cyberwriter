from decimal import Decimal

from django.db import migrations
from django.db.models import Max


def rebalance_iam_weights(apps, schema_editor):  # pragma: no cover - data migration
    Category = apps.get_model("reporting", "ScopingWeightCategory")
    Option = apps.get_model("reporting", "ScopingWeightOption")

    try:
        category = Category.objects.get(key="iam")
    except Category.DoesNotExist:
        return

    Option.objects.filter(category=category, key="ad").update(weight=Decimal("0.375"))
    Option.objects.filter(category=category, key="password").update(weight=Decimal("0.25"))

    max_position = category.options.aggregate(max_position=Max("position")).get("max_position") or 0
    Option.objects.update_or_create(
        category=category,
        key="ad_attack_paths",
        defaults={
            "label": "AD Attack Paths",
            "weight": Decimal("0.375"),
            "position": max_position + 1,
        },
    )


class Migration(migrations.Migration):
    dependencies = [
        ("reporting", "0067_merge_20251217_1610"),
    ]

    operations = [
        migrations.RunPython(rebalance_iam_weights, migrations.RunPython.noop),
    ]
