from llm.pricing import PRICING_USD_PER_MTOK, estimate_cost_usd


def test_pricing_table_has_sonnet_entry():
    assert "claude-sonnet-4-6" in PRICING_USD_PER_MTOK
    assert PRICING_USD_PER_MTOK["claude-sonnet-4-6"]["input"] > 0
    assert PRICING_USD_PER_MTOK["claude-sonnet-4-6"]["output"] > 0


def test_estimate_cost_usd_happy_path():
    usage = [
        {"node": "review_injection", "model": "claude-sonnet-4-6", "input_tokens": 1_000_000, "output_tokens": 1_000_000},
    ]
    cost = estimate_cost_usd(usage)
    assert cost == PRICING_USD_PER_MTOK["claude-sonnet-4-6"]["input"] + PRICING_USD_PER_MTOK["claude-sonnet-4-6"]["output"]


def test_estimate_cost_usd_empty_list_is_zero():
    assert estimate_cost_usd([]) == 0.0


def test_estimate_cost_usd_sums_multiple_entries():
    usage = [
        {"node": "a", "model": "claude-sonnet-4-6", "input_tokens": 500_000, "output_tokens": 0},
        {"node": "b", "model": "claude-sonnet-4-6", "input_tokens": 500_000, "output_tokens": 0},
    ]
    cost = estimate_cost_usd(usage)
    assert cost == PRICING_USD_PER_MTOK["claude-sonnet-4-6"]["input"]


def test_estimate_cost_usd_unknown_model_falls_back_instead_of_crashing():
    usage = [
        {"node": "a", "model": "some-future-model-not-in-table", "input_tokens": 1_000_000, "output_tokens": 0},
    ]
    cost = estimate_cost_usd(usage)
    assert cost > 0
