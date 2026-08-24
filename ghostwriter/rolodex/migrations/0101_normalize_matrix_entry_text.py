import logging

from django.db import migrations

from ghostwriter.rolodex.matrix_text import normalize_matrix_text

logger = logging.getLogger(__name__)


def _key(value):
    return " ".join(str(value).strip().lower().split())


def _normalize_model(model, unique_field, text_fields):
    """Strip editor-generated HTML from ``text_fields`` on every row of ``model``.

    ``unique_field`` is normalized like everywhere else via
    ``_normalize_matrix_key`` in data_parsers.py (lowercased, whitespace
    collapsed), so a row's unique field is only updated if doing so won't
    collide with another row's normalized key -- including another row that
    would land on the same key as part of this same pass, and including a
    row whose unique field doesn't need any changes of its own. Colliding
    rows are left untouched and logged, since a migration must not raise
    IntegrityError on a customer database.

    The collision check is unconditional (it does not compare the row's old
    and new ``_key()`` first): ``_key()`` collapses whitespace and case, so
    two literal values can differ (e.g. a trailing space) while producing
    the same ``_key()`` on both sides. Gating the check on "did the key
    change" would then skip it entirely for a row whose literal value is
    changing into something byte-for-byte identical to another row that was
    already in the table -- exactly the collision this function exists to
    catch.
    """

    entries = list(model.objects.all())

    # First pass: compute the normalized field values for every row without
    # mutating anything yet, so we can detect collisions across the whole
    # batch (not just against rows that already existed before this ran).
    plans = []
    final_keys = {}
    for entry in entries:
        normalized_values = {field_name: normalize_matrix_text(getattr(entry, field_name)) for field_name in text_fields}
        new_key = _key(normalized_values[unique_field])
        plans.append((entry, normalized_values, new_key))
        final_keys.setdefault(new_key, []).append(entry.pk)

    to_update = []
    skipped = []
    missing_ec = []

    for entry, normalized_values, new_key in plans:
        changed_fields = {
            field_name: value
            for field_name, value in normalized_values.items()
            if value != getattr(entry, field_name)
        }
        if not changed_fields:
            continue

        # Only the unique field itself can trigger a uniqueness collision.
        # If it's not among this row's changes, there's nothing to guard
        # against here, regardless of what _key() bucket it happens to
        # share with another row (e.g. a case-only variant).
        if unique_field in changed_fields and len(final_keys[new_key]) > 1:
            skipped.append((entry.pk, getattr(entry, unique_field)))
            continue

        for field_name, value in changed_fields.items():
            setattr(entry, field_name, value)
        to_update.append(entry)

        if "vulnerability_threat" in text_fields:
            threat = getattr(entry, "vulnerability_threat", "")
            if threat and "<EC>" not in threat:
                missing_ec.append((entry.pk, getattr(entry, unique_field)))

    if to_update:
        model.objects.bulk_update(to_update, text_fields)

    if skipped:
        logger.warning(
            "%s: skipped normalizing %d row(s) that would collide with an existing "
            "unique key after stripping HTML: %s",
            model.__name__,
            len(skipped),
            skipped,
        )

    if missing_ec:
        logger.warning(
            "%s: %d row(s) have a non-empty vulnerability_threat with no '<EC>' "
            "placeholder after normalization (it was likely already stripped by "
            "the WYSIWYG editor before this migration ran). These rows require "
            "manual review or re-import: %s",
            model.__name__,
            len(missing_ec),
            missing_ec,
        )


def normalize_matrix_entries(apps, schema_editor):
    vulnerability_model = apps.get_model("rolodex", "VulnerabilityMatrixEntry")
    _normalize_model(
        vulnerability_model,
        "vulnerability",
        ["vulnerability", "action_required", "remediation_impact", "vulnerability_threat"],
    )

    web_issue_model = apps.get_model("rolodex", "WebIssueMatrixEntry")
    _normalize_model(
        web_issue_model,
        "title",
        ["title", "impact", "fix"],
    )


class Migration(migrations.Migration):

    dependencies = [
        ("rolodex", "0100_add_ad_attack_paths_general_cap_map"),
    ]

    operations = [
        migrations.RunPython(normalize_matrix_entries, migrations.RunPython.noop),
    ]
