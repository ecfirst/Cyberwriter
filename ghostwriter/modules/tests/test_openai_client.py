from unittest import mock

from django.test import TestCase

from ghostwriter.factories import OpenAIConfigurationFactory
from ghostwriter.modules.openai_client import submit_prompt_to_assistant


class OpenAIClientTests(TestCase):
    def test_returns_none_when_disabled(self):
        config = OpenAIConfigurationFactory(enable=False)
        self.assertIsNone(submit_prompt_to_assistant("Example", config=config))

    @mock.patch("ghostwriter.modules.openai_client.requests.get")
    @mock.patch("ghostwriter.modules.openai_client.requests.post")
    def test_submits_prompt_and_returns_text(self, mock_post, mock_get):
        config = OpenAIConfigurationFactory(enable=True, assistant_id="asst_123", api_key="sk-test")

        thread_response = mock.Mock()
        thread_response.json.return_value = {"id": "thread_1"}
        thread_response.raise_for_status.return_value = None

        message_response = mock.Mock()
        message_response.raise_for_status.return_value = None

        run_response = mock.Mock()
        run_response.json.return_value = {"id": "run_1"}
        run_response.raise_for_status.return_value = None

        mock_post.side_effect = [thread_response, message_response, run_response]

        status_response = mock.Mock()
        status_response.json.return_value = {"status": "completed"}
        status_response.raise_for_status.return_value = None

        messages_response = mock.Mock()
        messages_response.json.return_value = {
            "data": [
                {
                    "role": "assistant",
                    "run_id": "run_1",
                    "content": [
                        {"type": "text", "text": {"value": "First"}},
                        {"type": "text", "text": {"value": "Second"}},
                    ],
                }
            ]
        }
        messages_response.raise_for_status.return_value = None

        mock_get.side_effect = [status_response, messages_response]

        response = submit_prompt_to_assistant("Prompt", config=config)
        self.assertEqual(response, "First Second")
        self.assertEqual(mock_post.call_count, 3)
        self.assertEqual(mock_get.call_count, 2)
