from decimal import Decimal

from django.db import migrations
from django.db.models import Max


def add_cloud_system_configuration_weight(apps, schema_editor):  # pragma: no cover - data migration
    Category = apps.get_model("reporting", "ScopingWeightCategory")
    Option = apps.get_model("reporting", "ScopingWeightOption")

    category, _ = Category.objects.get_or_create(
        key="cloud",
        defaults={"label": "Cloud", "position": 0},
    )

    max_position = category.options.aggregate(max_position=Max("position")).get("max_position") or 0
    Option.objects.update_or_create(
        category=category,
        key="system_configuration",
        defaults={
            "label": "System Configuration",
            "weight": Decimal("0.5"),
            "position": max_position + 1,
        },
    )


class Migration(migrations.Migration):
    dependencies = [
        ("reporting", "0063_scopingweightcategory_alter_reporttemplate_document_and_more"),
    ]

    operations = [
        migrations.RunPython(add_cloud_system_configuration_weight, migrations.RunPython.noop),
    ]
