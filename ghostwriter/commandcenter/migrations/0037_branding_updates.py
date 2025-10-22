from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        (
            "commandcenter",
            "0036_bannerconfiguration_and_more_squashed_0041_alter_bannerconfiguration_public_banner",
        ),
    ]

    operations = [
        migrations.AlterField(
            model_name="cloudservicesconfiguration",
            name="ignore_tag",
            field=models.CharField(
                "Ignore Tags",
                default="gw_ignore",
                help_text="CyberWriter will ignore cloud assets with one of these tags (comma-separated list)",
                max_length=255,
            ),
        ),
        migrations.AlterField(
            model_name="companyinformation",
            name="company_email",
            field=models.CharField(
                blank=True,
                default="info@ecfirst.com",
                help_text="Email address to reference in reports",
                max_length=255,
            ),
        ),
        migrations.AlterField(
            model_name="companyinformation",
            name="company_name",
            field=models.CharField(
                default="ecfirst",
                help_text="Company name handle to reference in reports",
                max_length=255,
            ),
        ),
        migrations.AlterField(
            model_name="companyinformation",
            name="company_short_name",
            field=models.CharField(
                default="ECF",
                help_text="Abbreviated company name to reference in reports",
                max_length=255,
            ),
        ),
        migrations.AlterField(
            model_name="companyinformation",
            name="company_twitter",
            field=models.CharField(
                "Twitter Handle",
                blank=True,
                default="@ecfirst",
                help_text="Twitter handle to reference in reports",
                max_length=255,
            ),
        ),
        migrations.AlterField(
            model_name="generalconfiguration",
            name="hostname",
            field=models.CharField(
                default="cyberwriter.local",
                help_text="Hostname or IP address for CyberWriter (used for links in notifications)",
                max_length=255,
            ),
        ),
        migrations.AlterField(
            model_name="slackconfiguration",
            name="slack_channel",
            field=models.CharField(
                default="#cyberwriter",
                help_text="Default channel for Slack notifications",
                max_length=255,
            ),
        ),
        migrations.AlterField(
            model_name="slackconfiguration",
            name="slack_username",
            field=models.CharField(
                default="CyberWriter",
                help_text="Display name for the Slack bot",
                max_length=255,
            ),
        ),
    ]
