from decimal import Decimal

from django.db import migrations


def adjust_cloud_weights(apps, schema_editor):  # pragma: no cover - data migration
    Category = apps.get_model("reporting", "ScopingWeightCategory")
    Option = apps.get_model("reporting", "ScopingWeightOption")

    try:
        category = Category.objects.get(key="cloud")
    except Category.DoesNotExist:
        return

    target_weights = {
        "iam_management": Decimal("0.4"),
        "cloud_management": Decimal("0.4"),
        "system_configuration": Decimal("0.2"),
    }

    for option_key, weight in target_weights.items():
        Option.objects.filter(category=category, key=option_key).update(weight=weight)


class Migration(migrations.Migration):
    dependencies = [
        ("reporting", "0064_add_cloud_system_configuration_weight"),
    ]

    operations = [
        migrations.RunPython(adjust_cloud_weights, migrations.RunPython.noop),
    ]
