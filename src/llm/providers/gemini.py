from google import genai
from google.genai import types


class GeminiProvider:
    DEFAULT_MODEL = "gemini-3.1-pro"

    def __init__(self, api_key: str, model: str) -> None:
        self._client = genai.Client(api_key=api_key)
        self._model = model or self.DEFAULT_MODEL

    def call_model(self, prompt: str, *, system: str | None = None) -> dict:
        """Returns an `LLMResult`-shaped dict for interface consistency with
        `AnthropicProvider`. Token usage is not exercised by this project's
        tests (Gemini is never selected here) — `0, 0` is an accepted stub
        per `spec/agent.md` -> Cost Accounting.
        """
        config = types.GenerateContentConfig(
            system_instruction=system,
        ) if system else None
        response = self._client.models.generate_content(
            model=self._model,
            contents=prompt,
            config=config,
        )
        return {
            "text": response.text,
            "input_tokens": 0,
            "output_tokens": 0,
            "model": self._model,
        }
