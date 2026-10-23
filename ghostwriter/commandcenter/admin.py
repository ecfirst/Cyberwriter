"""This contains customizations for displaying the CommandCenter application models in the admin panel."""

# Django Imports
from django.contrib import admin
from django import forms
from django.db import models

# Ghostwriter Libraries
from ghostwriter.commandcenter.forms import ReportConfigurationForm, OpenAIConfigurationForm
from ghostwriter.commandcenter.models import (
    AIReviewPromptTemplate,
    BannerConfiguration,
    CloudServicesConfiguration,
    CompanyInformation,
    ExtraFieldModel,
    ExtraFieldSpec,
    GeneralConfiguration,
    BloodHoundConfiguration,
    NamecheapConfiguration,
    OpenAIConfiguration,
    ReportConfiguration,
    ScoringConfiguration,
    SlackConfiguration,
    VirusTotalConfiguration,
    EXTRA_FIELD_TYPES,
)
from ghostwriter.singleton.admin import SingletonModelAdmin

admin.site.register(CloudServicesConfiguration, SingletonModelAdmin)
admin.site.register(CompanyInformation, SingletonModelAdmin)
admin.site.register(NamecheapConfiguration, SingletonModelAdmin)
admin.site.register(SlackConfiguration, SingletonModelAdmin)
admin.site.register(VirusTotalConfiguration, SingletonModelAdmin)
class OpenAIConfigurationAdmin(SingletonModelAdmin):
    form = OpenAIConfigurationForm


admin.site.register(OpenAIConfiguration, OpenAIConfigurationAdmin)
admin.site.register(GeneralConfiguration, SingletonModelAdmin)
admin.site.register(ScoringConfiguration, SingletonModelAdmin)


class AIReviewPromptTemplateAdmin(admin.ModelAdmin):
    list_display = ("section_label", "instruction_preview", "has_footer")
    search_fields = ("section_key", "instruction", "footer")
    actions = ("restore_default_prompt_text",)
    formfield_overrides = {
        models.TextField: {"widget": forms.Textarea(attrs={"rows": 8, "cols": 120})},
    }

    def get_readonly_fields(self, request, obj=None):
        # The area is fixed once a row exists; it stays editable on "add" so a
        # deleted row can be recreated.
        return ("section_key",) if obj else ()

    @admin.display(description="Area", ordering="section_key")
    def section_label(self, obj):
        return obj.section_label

    @admin.display(description="Instruction")
    def instruction_preview(self, obj):
        text = (obj.instruction or "").strip()
        return text if len(text) <= 120 else text[:117] + "..."

    @admin.display(description="Footer", boolean=True)
    def has_footer(self, obj):
        return bool((obj.footer or "").strip())

    @admin.action(description="Restore default prompt text")
    def restore_default_prompt_text(self, request, queryset):
        count = 0
        for template in queryset:
            template.reset_to_default()
            count += 1
        self.message_user(request, f"Restored the default prompt text for {count} area(s).")


admin.site.register(AIReviewPromptTemplate, AIReviewPromptTemplateAdmin)
admin.site.register(BannerConfiguration, SingletonModelAdmin)


class ReportConfigurationAdmin(SingletonModelAdmin):
    form = ReportConfigurationForm
    fieldsets = (
        (
            "Borders",
            {
                "fields": (
                    "enable_borders",
                    "border_weight",
                    "border_color",
                )
            },
        ),
        (
            "Captions",
            {
                "fields": (
                    "title_case_captions",
                    "title_case_exceptions",
                )
            },
        ),
        (
            "Figures",
            {
                "fields": (
                    "prefix_figure",
                    "label_figure",
                    "figure_caption_location",
                )
            },
        ),
        (
            "Tables",
            {
                "fields": (
                    "prefix_table",
                    "label_table",
                    "table_caption_location",
                )
            },
        ),
        (
            "Report Generation",
            {
                "fields": (
                    "report_filename",
                    "project_filename",
                    "target_delivery_date",
                    "default_docx_template",
                    "default_pptx_template",
                )
            },
        ),
    )


admin.site.register(ReportConfiguration, ReportConfigurationAdmin)


class ExtraFieldSpecForm(forms.ModelForm):
    internal_name = forms.RegexField(
        r"^[_a-zA-Z][_a-zA-Z0-9]*$",
        max_length=255,
        help_text="Name used in report templates and storage (no spaces)",
    )

    user_default_value = forms.CharField(
        required=False,
        strip=True,
        help_text="Value used in newly created objects. Changing this will not change existing objects, and newly created fields will be set to blank on existing objects.",
    )

    description = forms.CharField(
        required=False, strip=True, help_text="Help text shown under the extra field in forms"
    )

    def clean_user_default_value(self):
        field_type = self.cleaned_data.get("type")
        default_value = self.cleaned_data.get("user_default_value")
        if field_type is None:
            return default_value
        try:
            EXTRA_FIELD_TYPES[field_type].from_str(default_value)
        except ValueError:
            raise forms.ValidationError(f"Invalid default value for a(n) {field_type} extra field")
        return default_value

    class Meta:
        model = ExtraFieldSpec
        exclude = ["target_model"]


class ExtraFieldSpecInline(admin.TabularInline):
    model = ExtraFieldSpec
    form = ExtraFieldSpecForm


class ExtraFieldModelAdmin(admin.ModelAdmin):
    fields = ["model_display_name"]
    readonly_fields = ["model_display_name"]
    inlines = [
        ExtraFieldSpecInline,
    ]
    change_form_template = "user_extra_fields/admin_change_form.html"

    # These objects correspond to our app's models, so they should be added/removed only via fixtures
    def has_add_permission(self, request) -> bool:
        return False

    def has_delete_permission(self, request, obj=None) -> bool:
        return False


admin.site.register(ExtraFieldModel, ExtraFieldModelAdmin)

class BloodhoundConfigurationAdmin(SingletonModelAdmin):
    change_form_template = "bloodhound_admin_change_form.html"

admin.site.register(BloodHoundConfiguration, BloodhoundConfigurationAdmin)

class CollabAdminBase(admin.ModelAdmin):
    """
    Model Admin for collab-editor-enabled models.
    """
    change_form_template = "collab_editing/admin/change_form.html"
    change_list_template = "collab_editing/admin/change_list.html"
