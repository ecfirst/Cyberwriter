# Standard Libraries
import logging
import zoneinfo

# Django Imports
from django.test import TestCase

# Ghostwriter Libraries
from ghostwriter.factories import (
    BannerConfigurationFactory,
    CloudServicesConfigurationFactory,
    CompanyInformationFactory,
    GeneralConfigurationFactory,
    NamecheapConfigurationFactory,
    OpenAIConfigurationFactory,
    ReportConfigurationFactory,
    SlackConfigurationFactory,
    VirusTotalConfigurationFactory,
)

logging.disable(logging.CRITICAL)


class NamecheapConfigurationTests(TestCase):
    """Collection of tests for :model:`commandcenter.NamecheapConfiguration`."""

    @classmethod
    def setUpTestData(cls):
        cls.NamecheapConfiguration = NamecheapConfigurationFactory._meta.model

    def test_crud_finding(self):
        # Create
        entry = NamecheapConfigurationFactory(enable=False)

        # Read
        self.assertEqual(entry.enable, False)
        self.assertEqual(entry.pk, 1)

        # Update
        entry.enable = True
        entry.save()
        entry.refresh_from_db()
        self.assertEqual(entry.enable, True)

        # Delete
        entry.delete()
        self.assertFalse(self.NamecheapConfiguration.objects.all().exists())

    def test_get_solo_method(self):
        try:
            entry = self.NamecheapConfiguration.get_solo()
            self.assertEqual(entry.pk, 1)
        except Exception:
            self.fail("NamecheapConfiguration model `get_solo` method failed unexpectedly!")

    def test_sanitized_api_key_property(self):
        entry = self.NamecheapConfiguration.get_solo()
        length = len(entry.api_key)
        replacement = "\u2717" * (length - 8)
        sanitized = entry.sanitized_api_key
        self.assertNotEqual(entry.api_key, sanitized)
        self.assertIn(replacement, sanitized)


class ReportConfigurationTests(TestCase):
    """Collection of tests for :model:`commandcenter.ReportConfiguration`."""

    @classmethod
    def setUpTestData(cls):
        cls.ReportConfiguration = ReportConfigurationFactory._meta.model

    def test_crud_finding(self):
        # Create
        entry = ReportConfigurationFactory(enable_borders=False)

        # Read
        self.assertEqual(entry.enable_borders, False)
        self.assertEqual(entry.pk, 1)

        # Update
        entry.enable_borders = True
        entry.save()
        entry.refresh_from_db()
        self.assertEqual(entry.enable_borders, True)

        # Delete
        entry.delete()
        self.assertFalse(self.ReportConfiguration.objects.all().exists())

    def test_get_solo_method(self):
        try:
            entry = self.ReportConfiguration.get_solo()
            self.assertEqual(entry.pk, 1)
        except Exception:
            self.fail("ReportConfiguration model `get_solo` method failed unexpectedly!")


class SlackConfigurationTests(TestCase):
    """Collection of tests for :model:`commandcenter.SlackConfiguration`."""

    @classmethod
    def setUpTestData(cls):
        cls.SlackConfiguration = SlackConfigurationFactory._meta.model

    def test_crud_finding(self):
        # Create
        entry = SlackConfigurationFactory(enable=False)

        # Read
        self.assertEqual(entry.enable, False)
        self.assertEqual(entry.pk, 1)

        # Update
        entry.enable = True
        entry.save()
        entry.refresh_from_db()
        self.assertEqual(entry.enable, True)

        # Delete
        entry.delete()
        self.assertFalse(self.SlackConfiguration.objects.all().exists())

    def test_get_solo_method(self):
        try:
            entry = self.SlackConfiguration.get_solo()
            self.assertEqual(entry.pk, 1)
        except Exception:
            self.fail("SlackConfiguration model `get_solo` method failed unexpectedly!")

    def test_sanitized_webhook_property(self):
        entry = self.SlackConfiguration.get_solo()
        length = len(entry.webhook_url.split("/")[-1])
        replacement = "\u2717" * (length - 8)
        sanitized = entry.sanitized_webhook
        self.assertNotEqual(entry.webhook_url, sanitized)
        self.assertIn(replacement, sanitized)


class CompanyInformationTests(TestCase):
    """Collection of tests for :model:`commandcenter.CompanyInformation`."""

    @classmethod
    def setUpTestData(cls):
        cls.CompanyInformation = CompanyInformationFactory._meta.model

    def test_crud_finding(self):
        # Create
        entry = CompanyInformationFactory(company_name="SpecterOps")

        # Read
        self.assertEqual(entry.company_name, "SpecterOps")
        self.assertEqual(entry.pk, 1)

        # Update
        entry.company_name = "SpecterOps, Inc."
        entry.save()
        entry.refresh_from_db()
        self.assertEqual(entry.company_name, "SpecterOps, Inc.")

        # Delete
        entry.delete()
        self.assertFalse(self.CompanyInformation.objects.all().exists())

    def test_get_solo_method(self):
        try:
            entry = self.CompanyInformation.get_solo()
            self.assertEqual(entry.pk, 1)
        except Exception:
            self.fail("CompanyInformation model `get_solo` method failed unexpectedly!")


class CloudServicesConfigurationTests(TestCase):
    """Collection of tests for :model:`commandcenter.CloudServicesConfiguration`."""

    @classmethod
    def setUpTestData(cls):
        cls.CloudServicesConfiguration = CloudServicesConfigurationFactory._meta.model

    def test_crud_finding(self):
        # Create
        entry = CloudServicesConfigurationFactory(enable=False)

        # Read
        self.assertEqual(entry.enable, False)
        self.assertEqual(entry.pk, 1)

        # Update
        entry.enable = True
        entry.save()
        entry.refresh_from_db()
        self.assertEqual(entry.enable, True)

        # Delete
        entry.delete()
        self.assertFalse(self.CloudServicesConfiguration.objects.all().exists())

    def test_get_solo_method(self):
        try:
            entry = self.CloudServicesConfiguration.get_solo()
            self.assertEqual(entry.pk, 1)
        except Exception:
            self.fail("CloudServicesConfiguration model `get_solo` method failed unexpectedly!")

    def test_sanitized_aws_key_property(self):
        entry = self.CloudServicesConfiguration.get_solo()
        length = len(entry.aws_key)
        replacement = "\u2717" * (length - 8)
        sanitized = entry.sanitized_aws_key
        self.assertNotEqual(entry.aws_key, sanitized)
        self.assertIn(replacement, sanitized)

    def test_sanitized_aws_secret_property(self):
        entry = self.CloudServicesConfiguration.get_solo()
        length = len(entry.aws_secret)
        replacement = "\u2717" * (length - 8)
        sanitized = entry.sanitized_aws_secret
        self.assertNotEqual(entry.aws_secret, sanitized)
        self.assertIn(replacement, sanitized)

    def test_sanitized_do_api_key_property(self):
        entry = self.CloudServicesConfiguration.get_solo()
        length = len(entry.do_api_key)
        replacement = "\u2717" * (length - 8)
        sanitized = entry.sanitized_do_api_key
        self.assertNotEqual(entry.do_api_key, sanitized)
        self.assertIn(replacement, sanitized)


class VirusTotalConfigurationTests(TestCase):
    """Collection of tests for :model:`commandcenter.VirusTotalConfiguration`."""

    @classmethod
    def setUpTestData(cls):
        cls.VirusTotalConfiguration = VirusTotalConfigurationFactory._meta.model

    def test_crud_finding(self):
        # Create
        entry = VirusTotalConfigurationFactory(enable=False)

        # Read
        self.assertEqual(entry.enable, False)
        self.assertEqual(entry.pk, 1)

        # Update
        entry.enable = True
        entry.save()
        entry.refresh_from_db()
        self.assertEqual(entry.enable, True)

        # Delete
        entry.delete()
        self.assertFalse(self.VirusTotalConfiguration.objects.all().exists())

    def test_get_solo_method(self):
        try:
            entry = self.VirusTotalConfiguration.get_solo()
            self.assertEqual(entry.pk, 1)
        except Exception:
            self.fail("VirusTotalConfiguration model `get_solo` method failed unexpectedly!")

    def test_sanitized_api_key_property(self):
        entry = self.VirusTotalConfiguration.get_solo()
        length = len(entry.api_key)
        replacement = "\u2717" * (length - 8)
        sanitized = entry.sanitized_api_key
        self.assertNotEqual(entry.api_key, sanitized)
        self.assertIn(replacement, sanitized)


class OpenAIConfigurationTests(TestCase):
    """Collection of tests for :model:`commandcenter.OpenAIConfiguration`."""

    @classmethod
    def setUpTestData(cls):
        cls.OpenAIConfiguration = OpenAIConfigurationFactory._meta.model

    def test_crud_finding(self):
        entry = OpenAIConfigurationFactory(enable=False)
        self.assertEqual(entry.enable, False)
        self.assertEqual(entry.pk, 1)

        entry.enable = True
        entry.prompt_id = "prompt_test"
        entry.api_key = "sk-test"
        entry.save()
        entry.refresh_from_db()

        self.assertEqual(entry.enable, True)
        self.assertEqual(entry.prompt_id, "prompt_test")
        self.assertEqual(entry.api_key, "sk-test")

        entry.delete()
        self.assertFalse(self.OpenAIConfiguration.objects.all().exists())

    def test_get_solo_method(self):
        try:
            entry = self.OpenAIConfiguration.get_solo()
            self.assertEqual(entry.pk, 1)
        except Exception:
            self.fail("OpenAIConfiguration model `get_solo` method failed unexpectedly!")

    def test_sanitized_api_key_property(self):
        entry = self.OpenAIConfiguration.get_solo()
        entry.api_key = "sk-test-value-123456"
        entry.save(update_fields=["api_key"])
        sanitized = entry.sanitized_api_key
        self.assertNotEqual(entry.api_key, sanitized)
        self.assertIn("\u2717", sanitized)


class GeneralConfigurationTests(TestCase):
    """Collection of tests for :model:`commandcenter.GeneralConfiguration`."""

    @classmethod
    def setUpTestData(cls):
        cls.GeneralConfiguration = GeneralConfigurationFactory._meta.model

    def test_crud_finding(self):
        # Create
        entry = GeneralConfigurationFactory(default_timezone="UTC")

        # Read
        self.assertEqual(entry.default_timezone, zoneinfo.ZoneInfo("UTC"))
        self.assertEqual(entry.pk, 1)

        # Update
        entry.default_timezone = "US/Pacific"
        entry.save()
        entry.refresh_from_db()
        self.assertEqual(entry.default_timezone, zoneinfo.ZoneInfo("US/Pacific"))

        # Delete
        entry.delete()
        self.assertFalse(self.GeneralConfiguration.objects.all().exists())

    def test_get_solo_method(self):
        try:
            entry = self.GeneralConfiguration.get_solo()
            self.assertEqual(entry.pk, 1)
        except Exception:
            self.fail("GeneralConfiguration model `get_solo` method failed unexpectedly!")


class BannerConfigurationTests(TestCase):
    """Collection of tests for :model:`commandcenter.BannerConfiguration`."""

    @classmethod
    def setUpTestData(cls):
        cls.BannerConfiguration = BannerConfigurationFactory._meta.model

    def test_crud_finding(self):
        # Create
        entry = BannerConfigurationFactory(enable_banner=False)

        # Read
        self.assertEqual(entry.enable_banner, False)
        self.assertEqual(entry.pk, 1)

        # Update
        entry.enable_banner = True
        entry.save()
        entry.refresh_from_db()
        self.assertEqual(entry.enable_banner, True)

        # Delete
        entry.delete()
        self.assertFalse(self.BannerConfiguration.objects.all().exists())

    def test_get_solo_method(self):
        try:
            entry = self.BannerConfiguration.get_solo()
            self.assertEqual(entry.pk, 1)
        except Exception:
            self.fail("BannerConfiguration model `get_solo` method failed unexpectedly!")


class ScoringConfigurationTests(TestCase):
    """Collection of tests for :model:`commandcenter.ScoringConfiguration`."""

    def test_get_values_returns_defaults_without_edits(self):
        from decimal import Decimal

        from ghostwriter.commandcenter.models import ScoringConfiguration

        values = ScoringConfiguration.get_values()
        self.assertEqual(values.area_score_exponent, Decimal("3.00"))
        self.assertEqual(values.overall_score_exponent, Decimal("2.00"))
        self.assertEqual(values.wireless_overall_weight, Decimal("0.90"))

    def test_get_values_reflects_saved_settings(self):
        from decimal import Decimal

        from ghostwriter.commandcenter.models import ScoringConfiguration

        config = ScoringConfiguration.get_solo()
        config.area_score_exponent = Decimal("1.00")
        config.wireless_overall_weight = Decimal("0.75")
        config.save()

        values = ScoringConfiguration.get_values()
        self.assertEqual(values.area_score_exponent, Decimal("1.00"))
        self.assertEqual(values.overall_score_exponent, Decimal("2.00"))
        self.assertEqual(values.wireless_overall_weight, Decimal("0.75"))


class AIReviewPromptTemplateTests(TestCase):
    """Collection of tests for :model:`commandcenter.AIReviewPromptTemplate`."""

    @classmethod
    def setUpTestData(cls):
        from importlib import import_module

        from django.apps import apps

        # Re-run the data migration seed so the test DB has one row per area
        # even when migrations are skipped.
        migration = import_module("ghostwriter.commandcenter.migrations.0048_aireviewprompttemplate")
        migration.seed_default_prompts(apps, None)

    def test_seed_creates_one_row_per_area_with_default_text(self):
        from ghostwriter.commandcenter.models import AIReviewPromptTemplate
        from ghostwriter.rolodex.ai_review_prompts import AI_REVIEW_PROMPT_DEFAULTS

        rows = {row.section_key: row for row in AIReviewPromptTemplate.objects.all()}
        self.assertEqual(set(rows), set(AI_REVIEW_PROMPT_DEFAULTS))
        self.assertEqual(len(rows), 17)
        for key, entry in AI_REVIEW_PROMPT_DEFAULTS.items():
            self.assertEqual(rows[key].instruction, entry["instruction"])
            self.assertEqual(rows[key].footer, entry["footer"])
            self.assertEqual(str(rows[key]), entry["label"])

    def test_get_prompt_texts_matches_defaults_without_edits(self):
        from ghostwriter.commandcenter.models import AIReviewPromptTemplate
        from ghostwriter.rolodex.ai_review_prompts import AI_REVIEW_PROMPT_DEFAULTS

        texts = AIReviewPromptTemplate.get_prompt_texts()
        for key, entry in AI_REVIEW_PROMPT_DEFAULTS.items():
            self.assertEqual(texts[key]["instruction"], entry["instruction"])
            self.assertEqual(texts[key]["footer"], entry["footer"])

        internal = AIReviewPromptTemplate.get_prompt_text("internal_nexpose")
        self.assertIn("Vulnerability scanning results for internal systems", internal["instruction"])
        self.assertTrue(internal["footer"].startswith("End the paragraph with this risk statement:"))
        self.assertIn("{risk}", internal["footer"])

    def test_get_prompt_texts_reflects_edits_and_blank_footer(self):
        from ghostwriter.commandcenter.models import AIReviewPromptTemplate
        from ghostwriter.rolodex.ai_review_prompts import AI_REVIEW_PROMPT_DEFAULTS

        row = AIReviewPromptTemplate.objects.get(section_key="snmp_rt")
        row.instruction = "Summarize the SNMP review in two sentences."
        row.footer = ""
        row.save()

        texts = AIReviewPromptTemplate.get_prompt_texts()
        self.assertEqual(texts["snmp_rt"]["instruction"], "Summarize the SNMP review in two sentences.")
        self.assertEqual(texts["snmp_rt"]["footer"], "")
        # Other areas are untouched.
        self.assertEqual(texts["sql_rt"], {
            "instruction": AI_REVIEW_PROMPT_DEFAULTS["sql_rt"]["instruction"],
            "footer": AI_REVIEW_PROMPT_DEFAULTS["sql_rt"]["footer"],
        })

    def test_missing_row_and_unknown_key_fall_back_to_defaults(self):
        from ghostwriter.commandcenter.models import AIReviewPromptTemplate
        from ghostwriter.rolodex.ai_review_prompts import AI_REVIEW_PROMPT_DEFAULTS, GENERIC_INSTRUCTION

        AIReviewPromptTemplate.objects.filter(section_key="dns_rt").delete()
        texts = AIReviewPromptTemplate.get_prompt_texts()
        self.assertEqual(texts["dns_rt"]["instruction"], AI_REVIEW_PROMPT_DEFAULTS["dns_rt"]["instruction"])

        self.assertEqual(
            AIReviewPromptTemplate.get_prompt_text("not_a_section"),
            {"instruction": GENERIC_INSTRUCTION, "footer": ""},
        )

    def test_reset_to_default_restores_both_fields(self):
        from ghostwriter.commandcenter.models import AIReviewPromptTemplate
        from ghostwriter.rolodex.ai_review_prompts import AI_REVIEW_PROMPT_DEFAULTS

        row = AIReviewPromptTemplate.objects.get(section_key="wireless_rt")
        row.instruction = "custom"
        row.footer = "custom footer"
        row.save()

        row.reset_to_default()
        row.refresh_from_db()
        self.assertEqual(row.instruction, AI_REVIEW_PROMPT_DEFAULTS["wireless_rt"]["instruction"])
        self.assertEqual(row.footer, AI_REVIEW_PROMPT_DEFAULTS["wireless_rt"]["footer"])

