import asyncio
import json

import httpx

from services.ai.app.llm_client import OllamaClient


def test_health_check_requires_configured_model():
    async def run():
        client = OllamaClient(base_url="http://ollama.test", model="llama3")
        await client.close()
        client._client = httpx.AsyncClient(
            base_url=client.base_url,
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    200,
                    json={"models": [{"name": "llama3:latest"}]},
                )
            ),
        )
        try:
            assert await client.health_check()
        finally:
            await client.close()

    asyncio.run(run())


def test_health_check_reports_missing_model_as_unavailable():
    async def run():
        client = OllamaClient(base_url="http://ollama.test", model="llama3")
        await client.close()
        client._client = httpx.AsyncClient(
            base_url=client.base_url,
            transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"models": []})),
        )
        try:
            assert not await client.health_check()
        finally:
            await client.close()

    asyncio.run(run())


def test_generate_uses_ollama_generate_endpoint_and_returns_suggestion():
    async def run():
        client = OllamaClient(base_url="http://ollama.test", model="llama3")
        await client.close()
        client._client = httpx.AsyncClient(
            base_url=client.base_url,
            transport=httpx.MockTransport(
                lambda request: (
                    httpx.Response(
                        200,
                        json={"response": "Use a parameterized query."},
                    )
                    if request.url.path == "/api/generate" and json.loads(request.content)["model"] == "llama3"
                    else httpx.Response(404)
                )
            ),
        )
        try:
            result = await client.generate("Suggest a fix")
            assert result == "Use a parameterized query."
        finally:
            await client.close()

    asyncio.run(run())


def test_generate_reports_missing_model_with_pull_instruction():
    async def run():
        client = OllamaClient(base_url="http://ollama.test", model="llama3")
        await client.close()
        client._client = httpx.AsyncClient(
            base_url=client.base_url,
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    404,
                    json={"error": "model not found"},
                )
            ),
        )
        try:
            result = await client.generate("Suggest a fix")
            assert "ollama pull llama3" in result
        finally:
            await client.close()

    asyncio.run(run())
