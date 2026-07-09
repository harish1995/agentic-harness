from langgraph.graph import StateGraph, END

from graph.state import ScanState
from graph.nodes import (
    decompile, scan_dependencies, scan_secrets, extract_config, triage,
    review_injection, review_authn_authz, review_crypto_secrets,
    review_deserialization_upload, review_config_logging, review_dependencies,
    verify_findings, assemble_report, handle_error, finalize,
)
from graph.edges import after

_PIPELINE = [
    ("decompile", decompile),
    ("scan_dependencies", scan_dependencies),
    ("scan_secrets", scan_secrets),
    ("extract_config", extract_config),
    ("triage", triage),
    ("review_injection", review_injection),
    ("review_authn_authz", review_authn_authz),
    ("review_crypto_secrets", review_crypto_secrets),
    ("review_deserialization_upload", review_deserialization_upload),
    ("review_config_logging", review_config_logging),
    ("review_dependencies", review_dependencies),
    ("verify_findings", verify_findings),
    ("assemble_report", assemble_report),
]


def _build_graph() -> StateGraph:
    g = StateGraph(ScanState)
    for name, fn in _PIPELINE:
        g.add_node(name, fn)
    g.add_node("handle_error", handle_error)
    g.add_node("finalize", finalize)

    g.set_entry_point(_PIPELINE[0][0])
    for (name, _), (next_name, _) in zip(_PIPELINE, _PIPELINE[1:]):
        g.add_conditional_edges(name, after(next_name), {next_name: next_name, "handle_error": "handle_error"})
    g.add_conditional_edges(
        _PIPELINE[-1][0], after("finalize"), {"finalize": "finalize", "handle_error": "handle_error"}
    )
    g.add_edge("finalize", END)
    g.add_edge("handle_error", END)
    return g.compile()


agentic_ai = _build_graph()
