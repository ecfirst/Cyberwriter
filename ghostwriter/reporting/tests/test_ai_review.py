# Standard Libraries
import json
import logging
import shutil
import tempfile
from unittest import mock

# Django Imports
from django.contrib.messages import get_messages
from django.test import Client, SimpleTestCase, TestCase, override_settings
from django.urls import reverse

# Ghostwriter Libraries
from ghostwriter.factories import (
    FindingTypeFactory,
    OpenAIConfigurationFactory,
    ProjectAssignmentFactory,
    ReportFactory,
    ReportFindingLinkFactory,
    SeverityFactory,
    UserFactory,
)
from ghostwriter.modules.linting_utils import LINTER_CONTEXT
from ghostwriter.modules.reportwriter.report.json import ExportReportJson
from ghostwriter.reporting.ai_review_prompts import (
    AI_REVIEW_PROMPT_DEFAULTS,
    AI_REVIEW_SECTION_KEYS,
    AI_REVIEW_SECTION_LABELS,
    AI_REVIEW_SECTIONS,
    GENERIC_INSTRUCTION,
    get_default_prompt_text,
    normalize_section_key,
    render_prompt_text,
)
from ghostwriter.reporting.models import ReportSupplementalFile
from ghostwriter.reporting.tests.supplemental_fixtures import nexpose_workbook, uploaded, web_workbook
from ghostwriter.reporting.views2 import ai_review

logging.disable(logging.CRITICAL)

PASSWORD = "SuperNaturalReporting!"
MEDIA_ROOT = tempfile.mkdtemp(prefix="gw-ai-review-")
GENERATE_TARGET = "ghostwriter.reporting.views2.ai_review.submit_prompt_to_assistant"


def tearDownModule():
    shutil.rmtree(MEDIA_ROOT, ignore_errors=True)


def messages_for(response):
    return [str(message) for message in get_messages(response.wsgi_request)]


def supplemental(report, kind, entries):
    """Create a :model:`reporting.ReportSupplementalFile` holding ``entries`` as its parsed cache."""
    data = nexpose_workbook() if kind == "nexpose" else web_workbook()
    return ReportSupplementalFile.objects.create(
        report=report,
        kind=kind,
        document=uploaded(f"{kind}.xlsx", data),
        original_filename=f"{kind}.xlsx",
        cap_entries=entries,
        row_count=len(entries),
    )


class PromptModuleTests(SimpleTestCase):
    """Tests for :mod:`reporting.ai_review_prompts`."""

    def test_sections_are_the_owasp_2025_top_ten(self):
        self.assertEqual(len(AI_REVIEW_SECTIONS), 10)
        self.assertEqual(AI_REVIEW_SECTION_KEYS, [f"a{n:02d}_rt" for n in range(1, 11)])
        self.assertEqual(AI_REVIEW_SECTION_LABELS["a01_rt"], "A01:2025 Broken Access Control")
        self.assertEqual(AI_REVIEW_SECTION_LABELS["a10_rt"], "A10:2025 Mishandling of Exceptional Conditions")
        self.assertEqual(list(AI_REVIEW_PROMPT_DEFAULTS), AI_REVIEW_SECTION_KEYS)

    def test_defaults_carry_label_placeholder_and_category_description(self):
        for key, label, description in AI_REVIEW_SECTIONS:
            entry = AI_REVIEW_PROMPT_DEFAULTS[key]
            self.assertEqual(entry["label"], label)
            self.assertIn("{label}", entry["instruction"])
            self.assertIn(description, entry["instruction"])
            self.assertEqual(entry["footer"], "")

    def test_helpers(self):
        self.assertEqual(normalize_section_key("a01"), "a01_rt")
        self.assertEqual(normalize_section_key("a01_rt"), "a01_rt")
        self.assertEqual(normalize_section_key(""), "")
        self.assertEqual(get_default_prompt_text("a05")["instruction"], AI_REVIEW_PROMPT_DEFAULTS["a05_rt"]["instruction"])
        self.assertEqual(get_default_prompt_text("nope"), {"instruction": GENERIC_INSTRUCTION, "footer": ""})
        self.assertEqual(render_prompt_text("Summarize {label}.", "A05:2025 Injection"), "Summarize A05:2025 Injection.")
        self.assertEqual(render_prompt_text("Summarize {label}.", None), "Summarize the category.")
        self.assertEqual(render_prompt_text("   ", "x"), "")


class HelperTests(SimpleTestCase):
    """Tests for the pure helpers in :mod:`reporting.views2.ai_review`."""

    def test_plain_text_strips_html_and_truncates(self):
        self.assertEqual(ai_review.plain_text(None), "")
        self.assertEqual(ai_review.plain_text("  plain  "), "plain")
        self.assertEqual(ai_review.plain_text("<p>Hello <b>world</b></p>"), "Hello world")
        long_text = "x" * 50
        truncated = ai_review.plain_text(long_text, limit=10)
        self.assertEqual(len(truncated), 10)
        self.assertTrue(truncated.endswith("…"))

    def test_normalize_ai_response(self):
        self.assertEqual(ai_review.normalize_ai_response(None), "")
        self.assertEqual(ai_review.normalize_ai_response("   "), "")
        self.assertEqual(
            ai_review.normalize_ai_response("One <b>two</b>\n\nThree\nFour"),
            "<p>One &lt;b&gt;two&lt;/b&gt;</p><p>Three<br />Four</p>",
        )

    def test_build_ai_review_sections(self):
        sections = ai_review.build_ai_review_sections({"a03_rt": "<p>Supply chain</p>", "junk": "x"})
        self.assertEqual([section["key"] for section in sections], AI_REVIEW_SECTION_KEYS)
        self.assertEqual(sections[2]["content"], "<p>Supply chain</p>")
        self.assertEqual(sections[2]["label"], "A03:2025 Software Supply Chain Failures")
        self.assertEqual(sections[0]["content"], "")
        self.assertEqual(len(ai_review.build_ai_review_sections(None)), 10)
        self.assertEqual(len(ai_review.build_ai_review_sections("bad")), 10)

    def test_normalize_ai_review_payload(self):
        self.assertEqual(ai_review.normalize_ai_review_payload(None), {})
        self.assertEqual(ai_review.normalize_ai_review_payload(["x"]), {})
        self.assertEqual(ai_review.normalize_ai_review_payload({"a01_rt": "<p>x</p>"}), {"a01_rt": "<p>x</p>"})

    def test_build_ai_review_prompt_uses_texts_and_label(self):
        texts = {
            "a05_rt": {"instruction": "Describe {label} issues.", "footer": "Close with the {label} risk."},
            "a06_rt": {"instruction": "Design only.", "footer": ""},
        }
        prompt = ai_review.build_ai_review_prompt("a05", '{"findings": []}', prompt_texts=texts)
        self.assertEqual(
            prompt,
            'Describe A05:2025 Injection issues.\n\n{"findings": []}\n\nClose with the A05:2025 Injection risk.',
        )
        self.assertEqual(ai_review.build_ai_review_prompt("a06_rt", "{}", prompt_texts=texts), "Design only.\n\n{}")


@override_settings(MEDIA_ROOT=MEDIA_ROOT)
class PayloadTests(TestCase):
    """Tests for :func:`reporting.views2.ai_review.build_ai_review_payload`."""

    @classmethod
    def setUpTestData(cls):
        cls.report = ReportFactory()
        high = SeverityFactory(severity="High", weight=1)
        low = SeverityFactory(severity="Low", weight=3)
        web_type = FindingTypeFactory(finding_type="Web")
        cls.low_finding = ReportFindingLinkFactory(
            report=cls.report,
            title="Verbose Errors",
            severity=low,
            finding_type=web_type,
            cvss_score=None,
            cvss_vector="",
            description="<p>Stack traces</p>",
            impact="",
        )
        cls.high_finding = ReportFindingLinkFactory(
            report=cls.report,
            title="SQL Injection",
            severity=high,
            finding_type=web_type,
            cvss_score=9.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            description="<p>The <b>search</b> parameter is injectable.</p><p>Second paragraph.</p>",
            impact="<ul><li>Data theft</li></ul>",
        )
        cls.high_finding.tags.add("owasp", "injection")
        supplemental(
            cls.report,
            "nexpose",
            [
                {
                    "source": "nexpose",
                    "issue": "Outdated OpenSSL",
                    "systems": "10.0.0.1",
                    "action": "Upgrade",
                    "risk": "High",
                    "score": None,
                    "impact": "<p>Remote code execution</p>",
                    "evidence": ["OpenSSL/1.0.1", ""],
                },
                {"source": "nexpose", "issue": "Legacy entry without details", "risk": None},
                {"source": "nexpose", "issue": "", "impact": "skipped"},
                "junk",
            ],
        )
        supplemental(
            cls.report,
            "web",
            [{"source": "web", "issue": "Reflected XSS", "risk": "Medium", "impact": "Script execution", "evidence": "not a list"}],
        )

    def test_payload_shape(self):
        payload = ai_review.build_ai_review_payload(self.report)

        self.assertEqual(payload["report"]["title"], self.report.title)
        self.assertEqual(payload["report"]["client"], str(self.report.project.client))
        self.assertEqual(payload["report"]["project"], str(self.report.project))

        self.assertEqual([f["title"] for f in payload["findings"]], ["SQL Injection", "Verbose Errors"])
        sqli = payload["findings"][0]
        self.assertEqual(sqli["tags"], ["injection", "owasp"])
        self.assertEqual(sqli["finding_type"], "Web")
        self.assertEqual(sqli["severity"], "High")
        self.assertEqual(sqli["cvss_score"], 9.1)
        self.assertEqual(sqli["cvss_vector"], "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")
        self.assertNotIn("<", sqli["description"])
        self.assertIn("search parameter is injectable", sqli["description"])
        self.assertIn("Second paragraph", sqli["description"])
        self.assertEqual(sqli["impact"], "Data theft")
        verbose = payload["findings"][1]
        self.assertIsNone(verbose["cvss_score"])
        self.assertEqual(verbose["impact"], "")
        self.assertEqual(set(sqli), {"title", "tags", "finding_type", "severity", "cvss_score", "cvss_vector", "description", "impact"})

        issues = payload["supplemental_issues"]
        self.assertEqual([i["issue"] for i in issues], ["Reflected XSS", "Outdated OpenSSL", "Legacy entry without details"])
        self.assertEqual(issues[0]["source"], "Web (Burp)")
        self.assertEqual(issues[0]["evidence"], [], "Non-list evidence is ignored")
        self.assertEqual(issues[1]["source"], "Nexpose")
        self.assertEqual(issues[1]["risk"], "High")
        self.assertEqual(issues[1]["impact"], "Remote code execution")
        self.assertEqual(issues[1]["evidence"], ["OpenSSL/1.0.1"])
        self.assertEqual(issues[2]["impact"], "")
        self.assertEqual(issues[2]["evidence"], [])
        self.assertEqual(issues[2]["risk"], "")

        # The payload must be JSON serializable as sent to OpenAI
        json.dumps(payload)

    def test_payload_without_findings_or_supplementals(self):
        report = ReportFactory()
        payload = ai_review.build_ai_review_payload(report)
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["supplemental_issues"], [])


class AiReviewViewTestsBase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.report = ReportFactory()
        cls.user = UserFactory(password=PASSWORD)
        cls.mgr_user = UserFactory(password=PASSWORD, role="manager")
        cls.detail_uri = reverse("reporting:report_detail", kwargs={"pk": cls.report.pk})
        cls.generate_uri = reverse("reporting:ajax_generate_report_ai_review", kwargs={"pk": cls.report.pk})
        cls.save_uri = reverse("reporting:report_ai_review_update", kwargs={"pk": cls.report.pk})

    def setUp(self):
        self.client = Client()
        self.client_auth = Client()
        self.client_mgr = Client()
        self.assertTrue(self.client_auth.login(username=self.user.username, password=PASSWORD))
        self.assertTrue(self.client_mgr.login(username=self.mgr_user.username, password=PASSWORD))


@override_settings(MEDIA_ROOT=MEDIA_ROOT)
class ReportAiReviewGenerateTests(AiReviewViewTestsBase):
    """Collection of tests for :view:`reporting.ReportAiReviewGenerate`."""

    def enable_openai(self):
        return OpenAIConfigurationFactory(enable=True, api_key="sk-test", model="gpt-test")

    def test_view_requires_login_and_permissions(self):
        self.enable_openai()
        with mock.patch(GENERATE_TARGET, return_value="Text") as submit:
            response = self.client.post(self.generate_uri)
            self.assertEqual(response.status_code, 302)

            response = self.client_auth.post(self.generate_uri)
            self.assertEqual(response.status_code, 403)
            self.assertEqual(response.json()["result"], "error")
            submit.assert_not_called()

            ProjectAssignmentFactory(project=self.report.project, operator=self.user)
            response = self.client_auth.post(self.generate_uri, {"section": "a01_rt"})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["result"], "success")

    def test_get_is_not_allowed(self):
        response = self.client_mgr.get(self.generate_uri)
        self.assertEqual(response.status_code, 405)

    def test_warning_when_openai_is_not_enabled(self):
        OpenAIConfigurationFactory(enable=False, api_key="sk-test")
        with mock.patch(GENERATE_TARGET) as submit:
            response = self.client_mgr.post(self.generate_uri)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["result"], "warning")
        self.assertIn("not enabled", data["message"])
        self.assertEqual(data["data"], {})
        submit.assert_not_called()
        self.report.refresh_from_db()
        self.assertEqual(self.report.ai_review, {})

    def test_generate_all_saves_every_category(self):
        self.enable_openai()
        self.report.ai_review = {"a01_rt": "<p>old</p>", "custom": "<p>kept</p>"}
        self.report.save()

        def fake_submit(prompt):
            for key, label, _description in AI_REVIEW_SECTIONS:
                if label in prompt:
                    return f"Summary for {label}\n\nSecond paragraph"
            raise AssertionError("prompt did not name a category")

        with mock.patch(GENERATE_TARGET, side_effect=fake_submit) as submit:
            response = self.client_mgr.post(self.generate_uri)

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["result"], "success")
        self.assertEqual(data["message"], "AI review generation complete.")
        self.assertEqual(data["failed"], [])
        self.assertEqual(set(data["data"]), set(AI_REVIEW_SECTION_KEYS))
        self.assertEqual(
            data["data"]["a01_rt"],
            "<p>Summary for A01:2025 Broken Access Control</p><p>Second paragraph</p>",
        )
        self.assertEqual(submit.call_count, 10)

        # Every prompt carries the report data JSON after the instruction
        prompt = submit.call_args_list[0].args[0]
        self.assertIn('"findings": []', prompt)
        self.assertIn('"supplemental_issues": []', prompt)
        self.assertIn(self.report.title, prompt)

        self.report.refresh_from_db()
        self.assertEqual(self.report.ai_review["a01_rt"], data["data"]["a01_rt"])
        self.assertEqual(self.report.ai_review["custom"], "<p>kept</p>", "Unknown keys are preserved")

    def test_generate_single_section_touches_only_that_key(self):
        self.enable_openai()
        self.report.ai_review = {"a01_rt": "<p>old</p>"}
        self.report.save()

        with mock.patch(GENERATE_TARGET, return_value="Supply chain text") as submit:
            response = self.client_mgr.post(self.generate_uri, {"section": "a03"})

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["result"], "success")
        self.assertEqual(data["data"], {"a03_rt": "<p>Supply chain text</p>"})
        self.assertEqual(submit.call_count, 1)
        self.assertIn("A03:2025 Software Supply Chain Failures", submit.call_args.args[0])

        self.report.refresh_from_db()
        self.assertEqual(self.report.ai_review, {"a01_rt": "<p>old</p>", "a03_rt": "<p>Supply chain text</p>"})

    def test_unknown_section_returns_404(self):
        self.enable_openai()
        with mock.patch(GENERATE_TARGET) as submit:
            response = self.client_mgr.post(self.generate_uri, {"section": "a99"})
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["result"], "warning")
        submit.assert_not_called()

    def test_partial_failure_reports_failed_categories(self):
        self.enable_openai()

        def fake_submit(prompt):
            if "A05:2025 Injection" in prompt or "A09:2025" in prompt:
                return None
            return "ok"

        with mock.patch(GENERATE_TARGET, side_effect=fake_submit):
            response = self.client_mgr.post(self.generate_uri)

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["result"], "success")
        self.assertEqual(data["message"], "Some categories could not be generated.")
        self.assertEqual(data["failed"], ["a05_rt", "a09_rt"])
        self.assertEqual(len(data["data"]), 8)
        self.report.refresh_from_db()
        self.assertNotIn("a05_rt", self.report.ai_review)
        self.assertEqual(self.report.ai_review["a01_rt"], "<p>ok</p>")

    def test_total_failure_returns_502(self):
        self.enable_openai()
        with mock.patch(GENERATE_TARGET, return_value=None):
            response = self.client_mgr.post(self.generate_uri, {"section": "a02_rt"})
        self.assertEqual(response.status_code, 502)
        data = response.json()
        self.assertEqual(data["result"], "warning")
        self.assertEqual(data["data"], {})
        self.report.refresh_from_db()
        self.assertEqual(self.report.ai_review, {})

    def test_admin_prompt_override_is_used(self):
        from ghostwriter.commandcenter.models import AIReviewPromptTemplate

        self.enable_openai()
        AIReviewPromptTemplate.objects.create(
            section_key="a04_rt", instruction="Crypto review for {label}.", footer="Finish with {label}."
        )
        with mock.patch(GENERATE_TARGET, return_value="ok") as submit:
            self.client_mgr.post(self.generate_uri, {"section": "a04_rt"})
        prompt = submit.call_args.args[0]
        self.assertTrue(prompt.startswith("Crypto review for A04:2025 Cryptographic Failures.\n\n"))
        self.assertTrue(prompt.endswith("\n\nFinish with A04:2025 Cryptographic Failures."))


@override_settings(MEDIA_ROOT=MEDIA_ROOT)
class ReportAiReviewSaveTests(AiReviewViewTestsBase):
    """Collection of tests for :view:`reporting.ReportAiReviewSave`."""

    def test_view_requires_login_and_permissions(self):
        response = self.client.post(self.save_uri, {"ai_review_a01_rt": "<p>x</p>"})
        self.assertEqual(response.status_code, 302)
        self.report.refresh_from_db()
        self.assertEqual(self.report.ai_review, {})

        response = self.client_auth.post(self.save_uri, {"ai_review_a01_rt": "<p>x</p>"})
        self.assertRedirects(response, reverse("home:dashboard"), fetch_redirect_response=False)
        self.report.refresh_from_db()
        self.assertEqual(self.report.ai_review, {})

        ProjectAssignmentFactory(project=self.report.project, operator=self.user)
        response = self.client_auth.post(self.save_uri, {"ai_review_a01_rt": "<p>x</p>"})
        self.assertRedirects(response, self.detail_uri + "#ai-review", fetch_redirect_response=False)
        self.report.refresh_from_db()
        self.assertEqual(self.report.ai_review["a01_rt"], "<p>x</p>")

    def test_get_is_not_allowed(self):
        response = self.client_mgr.get(self.save_uri)
        self.assertEqual(response.status_code, 405)

    def test_save_round_trip(self):
        self.report.ai_review = {"a02_rt": "<p>old</p>", "legacy": "<p>kept</p>"}
        self.report.save()
        payload = {"ai_review_a02_rt": "<p>new</p>", "ai_review_a10_rt": "<p>ten</p>"}
        response = self.client_mgr.post(self.save_uri, payload)
        self.assertRedirects(response, self.detail_uri + "#ai-review", fetch_redirect_response=False)
        self.assertIn("AI review updates saved.", messages_for(response))

        self.report.refresh_from_db()
        self.assertEqual(self.report.ai_review["a02_rt"], "<p>new</p>")
        self.assertEqual(self.report.ai_review["a10_rt"], "<p>ten</p>")
        self.assertEqual(self.report.ai_review["a01_rt"], "", "Missing fields are stored as empty")
        self.assertEqual(self.report.ai_review["legacy"], "<p>kept</p>")
        self.assertEqual(len(self.report.ai_review), 11)


@override_settings(MEDIA_ROOT=MEDIA_ROOT)
class ReportDetailAiReviewTabTests(AiReviewViewTestsBase):
    """The AI Review tab on :view:`reporting.ReportDetailView`."""

    def test_tab_renders_every_category(self):
        self.report.ai_review = {"a05_rt": "<p>Injection summary</p>"}
        self.report.save()
        response = self.client_mgr.get(self.detail_uri)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'href="#ai-review"')
        self.assertContains(response, 'id="ai-review"')
        self.assertContains(response, 'id="generateAiReviewButton"')
        self.assertContains(response, 'mt-md-0 js-generate-ai-section"', count=10)
        for key in AI_REVIEW_SECTION_KEYS:
            self.assertContains(response, f'id="id_ai_review_{key}"')
        self.assertContains(response, "<p>Injection summary</p>")
        self.assertContains(response, "A10:2025 Mishandling of Exceptional Conditions")
        self.assertContains(response, "AI review generation is not enabled")
        self.assertEqual(len(response.context["ai_review_sections"]), 10)
        self.assertFalse(response.context["ai_review_enabled"])

    def test_enabled_hides_hint_and_viewer_has_no_buttons(self):
        OpenAIConfigurationFactory(enable=True, api_key="sk-test", model="gpt-test")
        response = self.client_mgr.get(self.detail_uri)
        self.assertNotContains(response, "AI review generation is not enabled")
        self.assertTrue(response.context["ai_review_enabled"])

        # A user who can only view the report sees the text but no generate buttons
        viewer = UserFactory(password=PASSWORD)
        ProjectAssignmentFactory(project=self.report.project, operator=viewer)
        with mock.patch("ghostwriter.reporting.models.Report.user_can_edit", return_value=False):
            client = Client()
            self.assertTrue(client.login(username=viewer.username, password=PASSWORD))
            response = client.get(self.detail_uri)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'id="ai-review"')
        self.assertNotContains(response, 'id="generateAiReviewButton"')
        self.assertNotContains(response, 'mt-md-0 js-generate-ai-section"')


@override_settings(MEDIA_ROOT=MEDIA_ROOT)
class AiReviewExportTests(TestCase):
    """``ai_review`` in the report export context and the template linter data."""

    @classmethod
    def setUpTestData(cls):
        cls.report = ReportFactory()
        cls.report.ai_review = {"a01_rt": "<p>Access control summary</p>", "stray": "<p>ignored</p>"}
        cls.report.save()

    def test_json_export_includes_stored_text(self):
        exporter = ExportReportJson(self.report)
        self.assertEqual(exporter.data["ai_review"]["a01_rt"], "<p>Access control summary</p>")
        output = json.loads(exporter.run().getvalue().decode("utf-8"))
        self.assertEqual(output["ai_review"]["a01_rt"], "<p>Access control summary</p>")

    def test_rich_text_context_has_every_category(self):
        context = ExportReportJson(self.report).map_rich_texts()
        self.assertEqual(set(context["ai_review"]), set(AI_REVIEW_SECTION_KEYS))
        self.assertEqual(context["ai_review"]["a01_rt"].render_html(), "<p>Access control summary</p>")
        self.assertEqual(context["ai_review"]["a02_rt"].render_html(), "")

    def test_lint_data_knows_every_category(self):
        self.assertEqual(set(LINTER_CONTEXT["ai_review"]), set(AI_REVIEW_SECTION_KEYS))
        lint_data = ExportReportJson.generate_lint_data()
        self.assertEqual(set(lint_data["ai_review"]), set(AI_REVIEW_SECTION_KEYS))
