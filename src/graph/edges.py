"""Single reusable conditional-edge factory for the scan pipeline.

Pinned per `spec/agent.md` -> Graph / Flow Topology: every node routes to
`handle_error` if `state["error"]` is set, otherwise to the fixed next node.
"""

from graph.state import ScanState


def after(next_node: str):
    def _edge(state: ScanState) -> str:
        return "handle_error" if state.get("error") else next_node

    return _edge
