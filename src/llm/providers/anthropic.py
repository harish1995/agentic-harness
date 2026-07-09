import anthropic as _sdk


class AnthropicProvider:
    DEFAULT_MODEL = "claude-sonnet-4-6"

    DEFAULT_MAX_TOKENS = 32000

    def __init__(self, api_key: str, model: str, max_tokens: int | None = None) -> None:
        self._client = _sdk.Anthropic(api_key=api_key)
        self._model = model or self.DEFAULT_MODEL
        self._max_tokens = max_tokens or self.DEFAULT_MAX_TOKENS

    def call_model(self, prompt: str, *, system: str | None = None) -> dict:
        """Returns an `LLMResult`-shaped dict (`text`, `input_tokens`,
        `output_tokens`, `model`) — token counts are read from the real
        Anthropic SDK response's `msg.usage`, never estimated.
        """
        kwargs: dict = dict(
            model=self._model,
            max_tokens=self._max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        if system:
            kwargs["system"] = system
        # The Anthropic SDK requires streaming (rather than a single blocking
        # `create()` call) once `max_tokens` is large enough that generation
        # could plausibly exceed its 10-minute non-streaming timeout. Our
        # configured `max_tokens` budget is intentionally generous (to avoid
        # truncating evidence-rich, multi-finding category reviews), so we
        # always stream and reassemble the final message — this is
        # functionally identical to a blocking call from the caller's
        # perspective, just delivered incrementally under the hood.
        with self._client.messages.stream(**kwargs) as stream:
            msg = stream.get_final_message()
        text = "".join(
            block.text for block in msg.content if getattr(block, "type", None) == "text"
        )
        return {
            "text": text,
            "input_tokens": msg.usage.input_tokens,
            "output_tokens": msg.usage.output_tokens,
            "model": self._model,
        }
