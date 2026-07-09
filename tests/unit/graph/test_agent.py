"""Graph compiles and wires all 15 nodes correctly. No external calls."""


def test_graph_compiles():
    from graph.agent import agentic_ai
    assert agentic_ai is not None


def test_graph_has_all_pipeline_nodes():
    from graph.agent import agentic_ai

    node_names = set(agentic_ai.get_graph().nodes.keys())
    expected = {
        "decompile",
        "scan_dependencies",
        "scan_secrets",
        "extract_config",
        "triage",
        "review_injection",
        "review_authn_authz",
        "review_crypto_secrets",
        "review_deserialization_upload",
        "review_config_logging",
        "review_dependencies",
        "verify_findings",
        "assemble_report",
        "handle_error",
        "finalize",
    }
    assert expected.issubset(node_names)


def test_after_routes_to_handle_error_on_error():
    from graph.edges import after

    edge = after("next_node")
    assert edge({"error": "boom"}) == "handle_error"


def test_after_routes_to_next_node_without_error():
    from graph.edges import after

    edge = after("next_node")
    assert edge({"error": None}) == "next_node"
    assert edge({}) == "next_node"
