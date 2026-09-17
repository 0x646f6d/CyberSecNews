"""Azure AI Foundry backend — Claude hosted on Azure AI Foundry.

Claude models on Azure/Microsoft Foundry are served through the Anthropic
Messages API at ``https://<resource>.services.ai.azure.com/anthropic/v1/messages``
(NOT the OpenAI-style ``/chat/completions`` route), so we use the Anthropic SDK's
``AnthropicFoundry`` client with an API key. It exposes the same ``messages.create``
surface as the first-party client, so prompts, parsing and the classify/summarize
call are all reused from :class:`_AnthropicMessagesClient`.
"""

from __future__ import annotations

from urllib.parse import urlparse

from ..config import LLMConfig
from ..logging_setup import get_logger
from .anthropic_client import _AnthropicMessagesClient

log = get_logger(__name__)


def _foundry_base_url(endpoint: str) -> str:
    """Normalise a Foundry endpoint to the Anthropic base URL the SDK expects.

    Accepts a full URL (any path — e.g. ``.../anthropic`` or ``.../models`` — is
    discarded), a bare host, or a bare resource name, and always returns
    ``https://<host>/anthropic/`` (trailing slash matters for the SDK's path join).
    """
    e = endpoint.strip()
    host = urlparse(e).netloc if "://" in e else e.split("/", 1)[0]
    if "." not in host:  # bare resource name -> standard Foundry host
        host = f"{host}.services.ai.azure.com"
    return f"https://{host}/anthropic/"


class AzureFoundryClient(_AnthropicMessagesClient):
    def __init__(self, config: LLMConfig) -> None:
        super().__init__()
        if not config.endpoint:
            raise ValueError(
                "llm.endpoint is not set; the Azure Foundry backend needs the "
                "resource endpoint (e.g. "
                "https://<resource>.services.ai.azure.com)."
            )
        if not config.api_key:
            raise ValueError(
                "Azure API key is not set; export it and point llm.api_key_env "
                "at its variable name (default AZURE_AI_API_KEY)."
            )
        # Imported lazily so the package imports (and tests / --dry-run) work
        # without the SDK being exercised.
        from anthropic import AnthropicFoundry

        self._client = AnthropicFoundry(
            base_url=_foundry_base_url(config.endpoint),
            api_key=config.api_key,
        )
        self._model = config.model
        self._max_tokens = config.max_tokens
