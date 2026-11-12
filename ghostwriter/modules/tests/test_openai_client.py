# Standard Libraries
import logging
from unittest import mock

# Django Imports
from django.test import TestCase

# Ghostwriter Libraries
from ghostwriter.factories import OpenAIConfigurationFactory
from ghostwriter.modules.openai_client import _extract_response_text, submit_prompt_to_assistant
from ghostwriter.reporting.ai_review_prompts import DEFAULT_OPENAI_INSTRUCTIONS

logging.disable(logging.CRITICAL)


class OpenAIClientTests(TestCase):
    """Tests for :func:`modules.openai_client.submit_prompt_to_assistant`."""

    def test_returns_none_when_disabled(self):
        config = OpenAIConfigurationFactory(enable=False)
        self.assertIsNone(submit_prompt_to_assistant("Example", config=config))

    def test_returns_none_without_model_or_key(self):
        config = OpenAIConfigurationFactory(enable=True, api_key="sk-test", model="")
        self.assertIsNone(submit_prompt_to_assistant("Example", config=config))
        config.model = "gpt-test"
        config.api_key = ""
        self.assertIsNone(submit_prompt_to_assistant("Example", config=config))

    def test_returns_none_for_blank_prompt(self):
        config = OpenAIConfigurationFactory(enable=True, api_key="sk-test")
        with mock.patch("ghostwriter.modules.openai_client.OpenAI") as mock_openai:
            self.assertIsNone(submit_prompt_to_assistant("   ", config=config))
        mock_openai.assert_not_called()

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
        config = OpenAIConfigurationFactory(enable=True, api_key="sk-test", instructions="")

        client = mock.Mock()
        client.responses.create.return_value = mock.Mock(output_text="Done")
        mock_openai.return_value = client

        self.assertEqual(submit_prompt_to_assistant("Prompt", config=config), "Done")
        kwargs = client.responses.create.call_args.kwargs
        self.assertEqual(kwargs["instructions"], DEFAULT_OPENAI_INSTRUCTIONS)
        self.assertEqual(kwargs["model"], "gpt-6-sol")

    @mock.patch("ghostwriter.modules.openai_client.OpenAI")
    def test_request_failure_returns_none(self, mock_openai):
        config = OpenAIConfigurationFactory(enable=True, api_key="sk-test")
        client = mock.Mock()
        client.responses.create.side_effect = RuntimeError("boom")
        mock_openai.return_value = client

        self.assertIsNone(submit_prompt_to_assistant("Prompt", config=config))

    def test_extract_response_text_falls_back_to_output_items(self):
        response = {
            "output": [
                {"type": "reasoning", "content": []},
                {
                    "type": "message",
                    "content": [
                        {"type": "output_text", "text": "Alpha"},
                        {"type": "text", "text": {"value": "Beta"}},
                        {"type": "refusal", "text": "ignored"},
                    ],
                },
            ]
        }
        self.assertEqual(_extract_response_text(response), "Alpha Beta")
        self.assertIsNone(_extract_response_text({"output": []}))
        self.assertIsNone(_extract_response_text("not a response"))
