"""Azure AI Foundry backend (Foundry Model Inference).

Talks to a Foundry model-inference endpoint via the `azure-ai-inference` SDK
(`ChatCompletionsClient`) with an API key. Any chat model deployed on Foundry
(Claude, Llama, Mistral, Phi, ...) works — the model name is configured in
`llm.model`. Prompts, JSON extraction and classification parsing are shared with
the other backends via :class:`~cybersecnews.llm.chat.ChatJSONClient`; this
module only adds the Azure API call.
"""

from __future__ import annotations

from typing import Optional

from ..config import LLMConfig
from ..logging_setup import get_logger
from .chat import ChatJSONClient

log = get_logger(__name__)

# Foundry model-inference API version used when the config doesn't pin one.
DEFAULT_API_VERSION = "2024-05-01-preview"


class AzureFoundryClient(ChatJSONClient):
    def __init__(self, config: LLMConfig) -> None:
        super().__init__()
        if not config.endpoint:
            raise ValueError(
                "llm.endpoint is not set; the Azure Foundry backend needs the "
                "model-inference endpoint URL (e.g. "
                "https://<resource>.services.ai.azure.com/models)."
            )
        if not config.api_key:
            raise ValueError(
                "Azure API key is not set; export it and point llm.api_key_env "
                "at its variable name (default AZURE_AI_API_KEY)."
            )
        # Imported lazily so the package imports (and tests / --dry-run) work
        # without the Azure SDK installed.
        from azure.ai.inference import ChatCompletionsClient
        from azure.core.credentials import AzureKeyCredential

        self._client = ChatCompletionsClient(
            endpoint=config.endpoint,
            credential=AzureKeyCredential(config.api_key),
            api_version=config.api_version or DEFAULT_API_VERSION,
        )
        self._model = config.model
        self._max_tokens = config.max_tokens

    def _text_call(self, system: str, user: str) -> Optional[str]:
        from azure.ai.inference.models import SystemMessage, UserMessage

        kwargs = {
            "messages": [SystemMessage(content=system), UserMessage(content=user)],
            "max_tokens": self._max_tokens,
        }
        # A unified Foundry "models" endpoint routes by model name; a single-model
        # serverless endpoint ignores it. Pass it only when configured.
        if self._model:
            kwargs["model"] = self._model
        try:
            resp = self._client.complete(**kwargs)
        except Exception as exc:
            log.error("[llm] API call failed: %s", exc)
            return None
        try:
            return resp.choices[0].message.content
        except (AttributeError, IndexError, KeyError) as exc:
            log.error("[llm] unexpected Azure response shape: %s", exc)
            return None
