from collections import ChainMap
import copy

from ghostwriter.commandcenter.models import ExtraFieldSpec
from ghostwriter.modules.custom_serializers import FullProjectSerializer
from ghostwriter.modules.linting_utils import LINTER_CONTEXT
from ghostwriter.modules.reportwriter import jinja_funcs
from ghostwriter.modules.reportwriter.base.base import ExportBase
from ghostwriter.modules.reportwriter.base.html_rich_text import LazilyRenderedTemplate
from ghostwriter.oplog.models import OplogEntry
from ghostwriter.reporting.models import Report, RiskScoreRangeMapping
from ghostwriter.rolodex.models import Client, Project
from ghostwriter.shepherd.models import Domain, StaticServer


class ExportProjectBase(ExportBase):
    """
    Mixin class for exporting projects.

    Provides a `serialize_object` implementation for serializing the `Project` database object,
    and helper functions for creating Jinja contexts.
    """

    def serialize_object(self, object):
        return FullProjectSerializer(object).data

    def map_rich_texts(self):
        base_context = copy.deepcopy(self.data)
        rich_text_context = ChainMap(ExportProjectBase.rich_text_jinja_overlay(self.data), base_context)

        # Fields on Project
        ExportProjectBase.process_projects_richtext(self, base_context, rich_text_context)

        return base_context

    @staticmethod
    def rich_text_jinja_overlay(data):
        return {
            # `{{.foo}}` converts to `{{_old_dot_vars.foo}}`
            "_old_dot_vars": {
                "client": data["client"]["short_name"] or data["client"]["name"],
                "project_start": data["project"]["start_date"],
                "project_end": data["project"]["end_date"],
                "project_type": data["project"]["type"].lower(),
            },
            "mk_caption": jinja_funcs.caption,
            "mk_ref": jinja_funcs.ref,
            # "get_type": type,
        }

    @staticmethod
    def process_projects_richtext(
        ex: ExportBase,
        base_context: dict,
        rich_text_context: dict,
    ):
        """
        Helper for processing the project-related rich text fields in both the `ProjectSerializer` and
        `ReportDataSerializer`.

        Arguments are the serialized data to read and alter, the render function, and the bound `process_extra_fields`
        method.
        """

        # Client
        base_context["client"]["note_rt"] = ex.create_lazy_template(
            f"the note of client {base_context['client']['name']}",
            base_context["client"]["note"],
            rich_text_context,
        )
        base_context["client"]["address_rt"] = ex.create_lazy_template(
            f"the address of client {base_context['client']['name']}",
            base_context["client"]["address"],
            rich_text_context,
        )
        ex.process_extra_fields(
            f"client {base_context['client']['name']}",
            base_context["client"]["extra_fields"],
            Client,
            rich_text_context,
        )

        # Project
        base_context["project"]["note_rt"] = ex.create_lazy_template(
            "the project note", base_context["project"]["note"], rich_text_context
        )
        ex.process_extra_fields("the project", base_context["project"]["extra_fields"], Project, rich_text_context)

        # Assignments
        for assignment in base_context["team"]:
            if isinstance(assignment, dict):
                if assignment["note"]:
                    assignment["note_rt"] = ex.create_lazy_template(
                        f"the note of person {assignment['name']}", assignment["note"], rich_text_context
                    )

        # Contacts
        for contact in base_context["client"]["contacts"]:
            if isinstance(contact, dict):
                if contact["note"]:
                    contact["note_rt"] = ex.create_lazy_template(
                        f"the note of contact {contact['name']}", contact["note"], rich_text_context
                    )

        # Objectives
        for objective in base_context["objectives"]:
            if isinstance(objective, dict):
                if objective["description"]:
                    objective["description_rt"] = ex.create_lazy_template(
                        f"the description of objective {objective['objective']}",
                        objective["description"],
                        rich_text_context,
                    )
                if objective["result"]:
                    objective["result_rt"] = ex.create_lazy_template(
                        f"the result of objective {objective['objective']}",
                        objective["result"],
                        rich_text_context,
                    )

        # Scope Lists
        for scope_list in base_context["scope"]:
            if isinstance(scope_list, dict):
                if scope_list["description"]:
                    scope_list["description_rt"] = ex.create_lazy_template(
                        f"the description of scope {scope_list['name']}", scope_list["description"], rich_text_context
                    )

        # Targets
        for target in base_context["targets"]:
            if isinstance(target, dict):
                if target["note"]:
                    target["note_rt"] = ex.create_lazy_template(
                        f"the note of target {target['ip_address']}", target["note"], rich_text_context
                    )

        # Deconfliction Events
        for event in base_context["deconflictions"]:
            if isinstance(event, dict):
                if event["description"]:
                    event["description_rt"] = ex.create_lazy_template(
                        f"the description of deconfliction event {event['title']}",
                        event["description"],
                        rich_text_context,
                    )

        # White Cards
        for card in base_context["whitecards"]:
            if isinstance(card, dict):
                if card["description"]:
                    card["description_rt"] = ex.create_lazy_template(
                        f"the description of whitecard {card['title']}", card["description"], rich_text_context
                    )

        # Infrastructure
        for asset_type in base_context["infrastructure"]:
            for asset in base_context["infrastructure"][asset_type]:
                if isinstance(asset, dict):
                    if asset["note"]:
                        asset["note_rt"] = ex.create_lazy_template(
                            f"the note of {asset_type} {asset.get('name') or asset.get('domain') or asset['ip_address']}",
                            asset["note"],
                            rich_text_context,
                        )

        for asset in base_context["infrastructure"]["domains"]:
            ex.process_extra_fields(f"domain {asset['domain']}", asset["extra_fields"], Domain, rich_text_context)
        for asset in base_context["infrastructure"]["servers"]:
            ex.process_extra_fields(f"server {asset['name']}", asset["extra_fields"], StaticServer, rich_text_context)

        # Logs
        for log in base_context["logs"]:
            for entry in log["entries"]:
                ex.process_extra_fields(
                    f"log entry {entry['description']} of log {log['name']}",
                    entry["extra_fields"],
                    OplogEntry,
                    rich_text_context,
                )

        def render_risk_rich_text_fields(container: dict | list | None, location: str):
            ExportProjectBase._render_risk_rich_text_fields(
                ex, container, location, rich_text_context
            )

        project_context = base_context.get("project", {}) if isinstance(base_context.get("project"), dict) else {}
        render_risk_rich_text_fields(project_context.get("risks"), "the project risk label")

        workbook_data = project_context.get("workbook_data") if isinstance(project_context, dict) else {}
        if isinstance(workbook_data, dict):
            render_risk_rich_text_fields(workbook_data.get("report_card"), "the report card risk label")

            grades = workbook_data.get("external_internal_grades")
            if isinstance(grades, dict):
                for category_key, category_data in grades.items():
                    render_risk_rich_text_fields(
                        category_data if isinstance(category_data, dict) else {},
                        f"the {category_key} grade",
                    )
                    if isinstance(category_data, dict):
                        for subkey, subvalue in category_data.items():
                            render_risk_rich_text_fields(
                                subvalue if isinstance(subvalue, dict) else {},
                                f"the {category_key} {subkey} risk label",
                            )

    @staticmethod
    def _render_risk_rich_text_fields(
        ex: ExportBase,
        container: dict | list | None,
        location: str,
        rich_text_context: dict,
    ) -> None:
        if isinstance(container, dict):
            for key, value in list(container.items()):
                child_location = location
                if isinstance(key, str):
                    child_location = f"{location} ({key})"

                if isinstance(value, (dict, list)):
                    ExportProjectBase._render_risk_rich_text_fields(
                        ex, value, child_location, rich_text_context
                    )

                if not (isinstance(key, str) and key.endswith("_rt")):
                    continue
                if value in (None, ""):
                    continue
                if isinstance(value, LazilyRenderedTemplate):
                    continue

                sanitized_value = ExportProjectBase._sanitize_rich_text_html(str(value))
                wrapped_value = RiskScoreRangeMapping._wrap_inline_rich_text(
                    sanitized_value
                )

                container[key] = ex.create_lazy_template(
                    child_location, wrapped_value, rich_text_context
                )
        elif isinstance(container, list):
            for index, item in enumerate(container):
                ExportProjectBase._render_risk_rich_text_fields(
                    ex, item, f"{location} item {index + 1}", rich_text_context
                )

    @staticmethod
    def _sanitize_rich_text_html(html: str) -> str:
        """Remove dangerous/unsupported tags and normalize HTML for DOCX conversion.

        The DOCX exporter is sensitive to malformed or unsupported HTML. We keep the
        visible content while stripping tags that could produce invalid XML (for
        example, ``<script>``), drop comments, remove invalid XML characters, and
        reserialize the fragment so it is well-formed before converting it to a
        sub-document.
        """

        from bs4 import BeautifulSoup, Comment

        from ghostwriter.modules.reportwriter.richtext.ooxml import (
            remove_invalid_xml_chars,
        )

        soup = BeautifulSoup(html, "html.parser")

        for tag in soup(["script", "style"]):
            tag.decompose()

        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            comment.extract()

        body = soup.body if soup.body else soup
        cleaned = "".join(str(child) for child in body.contents)
        cleaned = remove_invalid_xml_chars(cleaned)

        return cleaned if cleaned.strip() else html

    @classmethod
    def generate_lint_data(cls):
        context = {
            name: copy.deepcopy(LINTER_CONTEXT[name])
            for name in [
                # This should match the list of fields in `custom_serializers.py` `FullProjectSerializer`
                "project",
                "client",
                "contacts",
                "team",
                "objectives",
                "targets",
                "scope",
                "deconflictions",
                "whitecards",
                "infrastructure",
                "logs",
                "company",
                "report_date",
                "company",
                "tools",
                "recipient",
                "extra_fields",
            ]
        }

        for field in ExtraFieldSpec.objects.filter(target_model=Report._meta.label):
            context["extra_fields"][field.internal_name] = field.empty_value()
        for field in ExtraFieldSpec.objects.filter(target_model=Project._meta.label):
            context["project"]["extra_fields"][field.internal_name] = field.empty_value()
        for field in ExtraFieldSpec.objects.filter(target_model=Client._meta.label):
            context["client"]["extra_fields"][field.internal_name] = field.empty_value()
        for field in ExtraFieldSpec.objects.filter(target_model=OplogEntry._meta.label):
            for log in context["logs"]:
                for entry in log["entries"]:
                    entry["extra_fields"][field.internal_name] = field.empty_value()
        for field in ExtraFieldSpec.objects.filter(target_model=Domain._meta.label):
            for domain in context["infrastructure"]["domains"]:
                domain["extra_fields"][field.internal_name] = field.empty_value()
        for field in ExtraFieldSpec.objects.filter(target_model=StaticServer._meta.label):
            for server in context["infrastructure"]["servers"]:
                server["extra_fields"][field.internal_name] = field.empty_value()

        project_context = context.get("project", {})
        general_defaults = (
            LINTER_CONTEXT.get("project", {})
            .get("data_responses", {})
            .get("general", {})
        )
        general_context = project_context.setdefault("data_responses", {}).setdefault("general", {})
        for key in ("scope_count", "scope_string"):
            if key not in general_context and key in general_defaults:
                general_context[key] = copy.deepcopy(general_defaults[key])

        return context
