from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import httpx
from app.core.config import settings
from app.core.logger import logger


# Explicit Custom Exceptions for Ollama Error Classification
class OllamaConnectionError(Exception):
    """Raised when connection to local Ollama server fails."""
    pass


class OllamaModelNotFound(Exception):
    """Raised when specified model is not available on Ollama server."""
    pass


class OllamaTimeout(Exception):
    """Raised when Ollama request times out."""
    pass


class OllamaInvalidResponse(Exception):
    """Raised when Ollama response format is invalid or unparseable."""
    pass


class OllamaHTTPError(Exception):
    """Raised when Ollama server returns an HTTP error status."""
    pass


class BaseLLMAdapter(ABC):
    """Abstract interface for LLM downstream integrations."""

    @abstractmethod
    async def generate_response(self, prompt: str, system_prompt: Optional[str] = None, security_verdict: Optional[str] = None) -> Dict[str, Any]:
        pass


class OllamaAdapter(BaseLLMAdapter):
    """Local Ollama Inference Adapter with Diagnostic Logging & Specific Error Categorization."""

    def __init__(self, base_url: Optional[str] = None, model: Optional[str] = None):
        self.base_url = base_url or settings.OLLAMA_BASE_URL
        self.model = model or settings.OLLAMA_MODEL

    async def generate_response(self, prompt: str, system_prompt: Optional[str] = None, security_verdict: Optional[str] = None) -> Dict[str, Any]:
        if security_verdict != "FORWARDED":
            raise RuntimeError(f"CRITICAL SECURITY INVARIANT VIOLATION: Cannot invoke Ollama adapter when security verdict is '{security_verdict}'. Must be FORWARDED.")

        url = f"{self.base_url.rstrip('/')}/api/generate"

        logger.info(f"[OLLAMA] request started")
        logger.info(f"[OLLAMA] endpoint = {url}")
        logger.info(f"[OLLAMA] model = {self.model}")

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False
        }
        if system_prompt:
            payload["system"] = system_prompt

        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                logger.info(f"[OLLAMA] request sent")
                response = await client.post(url, json=payload)
                
                logger.info(f"[OLLAMA] response received")
                logger.info(f"[OLLAMA] response status = {response.status_code}")

                if response.status_code == 404 or ("model" in response.text.lower() and "not found" in response.text.lower()):
                    raise OllamaModelNotFound(f"Model '{self.model}' not found on Ollama server at {self.base_url}.")

                response.raise_for_status()
                data = response.json()

                if not isinstance(data, dict) or "response" not in data:
                    raise OllamaInvalidResponse("Ollama API response missing 'response' field.")

                logger.info(f"[OLLAMA] generation successful")
                return {
                    "provider": "ollama",
                    "model": self.model,
                    "response_text": data.get("response", ""),
                    "tokens_eval": data.get("eval_count", 0),
                    "raw": data
                }

            except httpx.ConnectError as e:
                err = OllamaConnectionError(f"Failed to connect to Ollama daemon at {self.base_url}: {str(e)}")
                logger.error(f"[OLLAMA] OllamaConnectionError: {str(err)}")
                return {
                    "provider": "ollama",
                    "model": self.model,
                    "response_text": f"LLM Service Unavailable: Downstream Ollama engine is not reachable at {self.base_url}.",
                    "status": "service_unavailable",
                    "error_type": "OllamaConnectionError",
                    "error_details": str(err)
                }
            except httpx.TimeoutException as e:
                err = OllamaTimeout(f"Ollama request timed out after 30 seconds: {str(e)}")
                logger.error(f"[OLLAMA] OllamaTimeout: {str(err)}")
                return {
                    "provider": "ollama",
                    "model": self.model,
                    "response_text": f"LLM Service Timeout: Ollama inference timed out at {self.base_url}.",
                    "status": "timeout",
                    "error_type": "OllamaTimeout",
                    "error_details": str(err)
                }
            except OllamaModelNotFound as e:
                logger.error(f"[OLLAMA] OllamaModelNotFound: {str(e)}")
                return {
                    "provider": "ollama",
                    "model": self.model,
                    "response_text": f"LLM Model Error: Model '{self.model}' is not installed in Ollama.",
                    "status": "model_not_found",
                    "error_type": "OllamaModelNotFound",
                    "error_details": str(e)
                }
            except OllamaInvalidResponse as e:
                logger.error(f"[OLLAMA] OllamaInvalidResponse: {str(e)}")
                return {
                    "provider": "ollama",
                    "model": self.model,
                    "response_text": "LLM Response Error: Invalid JSON response format from Ollama.",
                    "status": "invalid_response",
                    "error_type": "OllamaInvalidResponse",
                    "error_details": str(e)
                }
            except httpx.HTTPStatusError as e:
                err = OllamaHTTPError(f"HTTP error {e.response.status_code} from Ollama: {str(e)}")
                logger.error(f"[OLLAMA] OllamaHTTPError: {str(err)}")
                return {
                    "provider": "ollama",
                    "model": self.model,
                    "response_text": f"LLM HTTP Error: Ollama returned HTTP status {e.response.status_code}.",
                    "status": "http_error",
                    "error_type": "OllamaHTTPError",
                    "error_details": str(err)
                }
            except Exception as e:
                logger.error(f"[OLLAMA] Execution failure ({type(e).__name__}): {str(e)}")
                return {
                    "provider": "ollama",
                    "model": self.model,
                    "response_text": f"LLM Service Exception: Unexpected error during Ollama invocation ({type(e).__name__}).",
                    "status": "execution_error",
                    "error_type": type(e).__name__,
                    "error_details": str(e)
                }


class OpenAIAdapter(BaseLLMAdapter):
    """OpenAI API Adapter."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or settings.OPENAI_API_KEY
        self.model = model or settings.OPENAI_MODEL

    async def generate_response(self, prompt: str, system_prompt: Optional[str] = None, security_verdict: Optional[str] = None) -> Dict[str, Any]:
        if security_verdict != "FORWARDED":
            raise RuntimeError(f"CRITICAL SECURITY INVARIANT VIOLATION: Cannot invoke OpenAI adapter when security verdict is '{security_verdict}'. Must be FORWARDED.")

        if not self.api_key:
            return {
                "provider": "openai",
                "model": self.model,
                "response_text": "[OpenAI Mock Response] Set OPENAI_API_KEY in .env to use live OpenAI models.",
                "status": "mocked_no_key"
            }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.7
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                res = await client.post("https://api.openai.com/v1/chat/completions", json=payload, headers=headers)
                res.raise_for_status()
                data = res.json()
                return {
                    "provider": "openai",
                    "model": self.model,
                    "response_text": data["choices"][0]["message"]["content"],
                    "raw": data
                }
            except Exception as e:
                return {
                    "provider": "openai",
                    "model": self.model,
                    "response_text": f"OpenAI Execution Error: {str(e)}",
                    "status": "error"
                }


class LLMAdapterFactory:
    """Factory to retrieve requested LLM Adapter."""

    @staticmethod
    def get_adapter(provider: str = "ollama") -> BaseLLMAdapter:
        provider_lower = provider.lower()
        if provider_lower == "ollama":
            return OllamaAdapter()
        elif provider_lower == "openai":
            return OpenAIAdapter()
        else:
            return OllamaAdapter()
