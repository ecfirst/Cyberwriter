# Standard Libraries
from unittest import mock

# Django Imports
from django.test import TestCase

# Ghostwriter Libraries
from ghostwriter.factories import OpenAIConfigurationFactory
from ghostwriter.modules.openai_client import submit_prompt_to_assistant
from ghostwriter.rolodex.ai_review_prompts import DEFAULT_OPENAI_INSTRUCTIONS


class OpenAIClientTests(TestCase):
    def test_returns_none_when_disabled(self):
        config = OpenAIConfigurationFactory(enable=False)
        self.assertIsNone(submit_prompt_to_assistant("Example", config=config))

    def test_returns_none_without_model(self):
        config = OpenAIConfigurationFactory(enable=True, api_key="sk-test", model="")
        self.assertIsNone(submit_prompt_to_assistant("Example", config=config))

    @mock.patch("ghostwriter.modules.openai_client.OpenAI")
    def test_submits_prompt_and_returns_text(self, mock_openai):
        config = OpenAIConfigurationFactory(
            enable=True,
            api_key="sk-test",
            model="gpt-test",
            reasoning_effort="high",
            verbosity="low",
            instructions="Custom instructions",
        )

        client = mock.Mock()
        client.responses.create.return_value = mock.Mock(output_text="First Second")
        mock_openai.return_value = client

        response = submit_prompt_to_assistant("Prompt", config=config)
        self.assertEqual(response, "First Second")
        mock_openai.assert_called_once_with(api_key="sk-test")
        client.responses.create.assert_called_once_with(
            model="gpt-test",
            input="Prompt",
            reasoning={"effort": "high"},
            text={"verbosity": "low"},
            instructions="Custom instructions",
        )

    @mock.patch("ghostwriter.modules.openai_client.OpenAI")
    def test_blank_instructions_use_default(self, mock_openai):
        config = OpenAIConfigurationFactory(
            enable=True, api_key="sk-test", instructions=""
        )

        client = mock.Mock()
        client.responses.create.return_value = mock.Mock(output_text="Done")
        mock_openai.return_value = client

        self.assertEqual(submit_prompt_to_assistant("Prompt", config=config), "Done")
        kwargs = client.responses.create.call_args.kwargs
        self.assertEqual(kwargs["instructions"], DEFAULT_OPENAI_INSTRUCTIONS)
        self.assertEqual(kwargs["model"], "gpt-6-sol")
