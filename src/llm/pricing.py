"""Hardcoded, versioned, approximate Anthropic pricing table + cost estimator.

See `spec/agent.md` -> Cost Accounting. `AGENT_PRICING_TABLE_VERSION` (env,
default "2026-07") documents when this table was last verified against
Anthropic's published pricing — bump both when pricing changes.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from graph.state import TokenUsageEntry

PRICING_USD_PER_MTOK: dict[str, dict[str, float]] = {
    "claude-sonnet-4-6": {"input": 3.00, "output": 15.00},
    "claude-opus-4-8": {"input": 15.00, "output": 75.00},
    "claude-haiku-4-5-20251001": {"input": 0.80, "output": 4.00},
}

# Fallback pricing used when a token-usage entry references a model that is
# not (yet) in the table above — avoids a KeyError crashing report assembly
# for an unexpected/overridden AGENT_LLM_MODEL; conservatively priced at the
# sonnet tier so cost is never silently under-reported.
_FALLBACK_PRICE = {"input": 3.00, "output": 15.00}


def estimate_cost_usd(token_usage: "list[TokenUsageEntry]") -> float:
    """`sum over every TokenUsageEntry of
    (input_tokens/1_000_000 * price["input"] + output_tokens/1_000_000 * price["output"])`.
    """
    total = 0.0
    for entry in token_usage:
        price = PRICING_USD_PER_MTOK.get(entry["model"], _FALLBACK_PRICE)
        total += entry["input_tokens"] / 1_000_000 * price["input"]
        total += entry["output_tokens"] / 1_000_000 * price["output"]
    return total
