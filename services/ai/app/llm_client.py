"""
AI/LLM Integration Service - Ollama Client
===========================================
Async HTTP wrapper around the Ollama REST API with:
- Retry logic (3 attempts, exponential backoff via tenacity)
- Graceful degradation when Ollama is unreachable
- Configurable model and base URL via environment variables
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Optional

import httpx
from tenacity import (
    AsyncRetrying,
    RetryError,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
_DEFAULT_MODEL = os.getenv("OLLAMA_MODEL", "llama3")
_REQUEST_TIMEOUT = float(os.getenv("OLLAMA_TIMEOUT_SECONDS", "120"))
_MAX_RETRIES = int(os.getenv("OLLAMA_MAX_RETRIES", "3"))

# Fallback text returned when Ollama is completely unreachable
_OLLAMA_UNAVAILABLE_FALLBACK = (
    "AI analysis is currently unavailable because the Ollama service could not be reached. "
    "Please ensure Ollama is running and the OLLAMA_BASE_URL environment variable is correct."
)


# ---------------------------------------------------------------------------
# Ollama Client
# ---------------------------------------------------------------------------


class OllamaClient:
    """
    Async client for the Ollama local LLM server.

    Usage::

        client = OllamaClient(base_url="http://localhost:11434", model="llama3")
        response = await client.generate(
            prompt="Analyze this vulnerability...",
            system="You are a security expert."
        )
    """

    def __init__(
        self,
        base_url: str = _DEFAULT_BASE_URL,
        model: str = _DEFAULT_MODEL,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self._generation_semaphore = asyncio.Semaphore(max(1, int(os.getenv("OLLAMA_MAX_CONCURRENCY", "2"))))
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(
                connect=10.0,
                read=_REQUEST_TIMEOUT,
                write=30.0,
                pool=5.0,
            ),
            headers={"Content-Type": "application/json"},
        )
        logger.info(
            "OllamaClient initialized",
            extra={"base_url": self.base_url, "model": self.model},
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.1,
        top_p: float = 0.9,
    ) -> str:
        """
        Send a generation request to Ollama's /api/generate endpoint.

        Parameters
        ----------
        prompt:      The user prompt / instruction.
        system:      Optional system-level instruction prepended to the conversation.
        temperature: Sampling temperature (lower = more deterministic).
        top_p:       Nucleus sampling probability threshold.

        Returns
        -------
        str: The model's text response, or a fallback string on failure.
        """
        payload = self._build_payload(prompt, system, temperature, top_p)

        try:
            async for attempt in AsyncRetrying(
                stop=stop_after_attempt(_MAX_RETRIES),
                wait=wait_exponential(multiplier=1, min=2, max=10),
                retry=retry_if_exception_type((httpx.ConnectError, httpx.TimeoutException, httpx.RemoteProtocolError)),
                reraise=False,
            ):
                with attempt:
                    start = time.monotonic()
                    response_text = await self._call_ollama(payload)
                    elapsed = time.monotonic() - start
                    logger.info(
                        "Ollama generation succeeded",
                        extra={"model": self.model, "elapsed_s": round(elapsed, 2)},
                    )
                    return response_text

        except RetryError as exc:
            logger.warning(
                "Ollama generation failed after %d retries: %s",
                _MAX_RETRIES,
                exc,
            )
            return _OLLAMA_UNAVAILABLE_FALLBACK

        except httpx.HTTPStatusError as exc:
            logger.error(
                "Ollama generation returned HTTP %s for model %s: %s",
                exc.response.status_code,
                self.model,
                exc.response.text[:500],
            )
            if exc.response.status_code == 404:
                return (
                    f"AI analysis is unavailable because the Ollama model '{self.model}' "
                    f"is not installed. Install it with `ollama pull {self.model}`."
                )
            return _OLLAMA_UNAVAILABLE_FALLBACK

        except Exception as exc:  # pragma: no cover
            logger.error("Unexpected error during Ollama generation: %s", exc, exc_info=True)
            return _OLLAMA_UNAVAILABLE_FALLBACK

        # Tenacity may swallow the last exception on reraise=False
        return _OLLAMA_UNAVAILABLE_FALLBACK

    async def health_check(self) -> bool:
        """
        Verify that Ollama is reachable and the configured model is installed.

        Returns True if the service responds successfully, False otherwise.
        """
        try:
            resp = await self._client.get("/api/tags", timeout=5.0)
            resp.raise_for_status()
            data = resp.json()
            models = {m.get("name", "").lower() for m in data.get("models", [])}
            configured_model = self.model.lower()
            if ":" not in configured_model:
                configured_model += ":latest"
            is_available = configured_model in models or self.model.lower() in models
            if not is_available:
                logger.warning(
                    "Configured Ollama model %s is not installed; available models: %s",
                    self.model,
                    sorted(models),
                )
            return is_available
        except httpx.HTTPStatusError as exc:
            logger.warning("Ollama health check HTTP error: %s", exc)
            return False
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            logger.warning("Ollama health check connection failed: %s", exc)
            return False
        except Exception as exc:  # pragma: no cover
            logger.error("Ollama health check unexpected error: %s", exc, exc_info=True)
            return False

    def _build_prompt(self, template: str, **kwargs: object) -> str:
        """
        Render a prompt template by substituting keyword arguments.

        Parameters
        ----------
        template: A str.format-compatible template string.
        **kwargs: Values to substitute into the template placeholders.

        Returns
        -------
        str: The rendered prompt.
        """
        # Replace None values with "N/A" to avoid 'None' appearing in prompts
        safe_kwargs = {k: (v if v is not None else "N/A") for k, v in kwargs.items()}
        try:
            return template.format(**safe_kwargs)
        except KeyError as exc:
            logger.warning("Prompt template missing key: %s", exc)
            return template  # Return raw template as fallback

    async def close(self) -> None:
        """Close the underlying httpx client. Call on application shutdown."""
        await self._client.aclose()
        logger.info("OllamaClient HTTP client closed")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_payload(
        self,
        prompt: str,
        system: Optional[str],
        temperature: float,
        top_p: float,
    ) -> dict:
        """Construct the JSON payload for /api/generate."""
        payload: dict = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "top_p": top_p,
                "num_predict": 2048,  # max tokens in response
            },
        }
        if system:
            payload["system"] = system
        return payload

    async def _call_ollama(self, payload: dict) -> str:
        """
        Execute a single HTTP POST to /api/generate and parse the response.

        Raises httpx exceptions so tenacity can catch and retry them.
        """
        async with self._generation_semaphore:
            resp = await self._client.post("/api/generate", json=payload)
        resp.raise_for_status()

        data = resp.json()

        # Ollama returns {"response": "...", "done": true, ...}
        response_text: str = data.get("response", "").strip()

        if not response_text:
            logger.warning("Ollama returned an empty response for model %s", self.model)
            return _OLLAMA_UNAVAILABLE_FALLBACK

        return response_text
