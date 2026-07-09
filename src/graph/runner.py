"""Pipeline entry point invoked by the API layer's background thread.

Pinned contract (`api-and-db` imports and calls this exact signature):

    run_scan(scan_id: str, jar_path: str) -> None

All persistence happens as side effects inside the graph's nodes themselves
(`_set_progress` in every node, `finalize`/`handle_error` for terminal state)
per `spec/agent.md` -> Progress Reporting. `run_scan` itself does not write
to the DB directly — it only drives the graph.
"""

from db.models import ScanRow
from db.session import create_db_session
from graph.agent import agentic_ai
from graph.state import ScanState
from observability.events import get_logger

_logger = get_logger("graph.runner")


def run_scan(scan_id: str, jar_path: str) -> None:
    initial_state: ScanState = {
        "scan_id": scan_id,
        "jar_path": jar_path,
        "error": None,
    }
    try:
        agentic_ai.invoke(initial_state, config={"recursion_limit": 50})
    except Exception as exc:  # noqa: BLE001 — last-resort safety net; nodes
        # themselves catch and route to handle_error, but an exception
        # escaping the graph entirely (e.g. a LangGraph internal error)
        # must still not vanish silently — mark the scan failed directly
        # so it never gets stuck in "processing" forever.
        _logger.error("scan_pipeline_crashed", scan_id=scan_id, error=str(exc))
        try:
            with create_db_session() as session:
                row = session.get(ScanRow, scan_id)
                if row is not None and row.status == "processing":
                    row.status = "failed"
                    row.error_message = str(exc)
                    row.current_phase = "failed"
        except Exception:  # noqa: BLE001 — nothing more we can do here
            _logger.error("scan_pipeline_crash_db_write_failed", scan_id=scan_id)
