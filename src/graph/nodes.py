"""The 15 LangGraph nodes of the JAR security scan pipeline.

See `spec/agent.md` -> Nodes / Steps for the full behavioural spec of each
node. Progress reporting (`current_phase`/`current_detail` DB writes at the
start of every node's work) is a mandatory side effect, per `spec/agent.md`
-> Progress Reporting.
"""

import json
import time
from pathlib import Path

from analysis.config_files import extract_config_files
from analysis.dependencies import extract_dependencies
from analysis.secrets import scan_secrets as _run_secret_scan
from analysis.triage import triage_classes
from db.models import ScanRow
from db.session import create_db_session
from decompile.cfr import decompile_classes
from decompile.unpack import UnpackResult, unpack_jar
from config.settings import get_settings
from graph.prompt_builder import (
    build_chunks_message,
    build_config_message,
    build_dependencies_message,
    build_secret_findings_message,
    filter_chunks_for_category,
    parse_findings_json,
    parse_verification_decisions,
)
from graph.state import Finding, ScanState, TokenUsageEntry
from llm.client import LLMClient
from llm.pricing import estimate_cost_usd
from observability.events import get_logger

_PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"


def _load_prompt(filename: str) -> str:
    return (_PROMPTS_DIR / filename).read_text(encoding="utf-8").strip()


def _set_progress(scan_id: str, current_phase: str, current_detail: str | None = None) -> None:
    """Mandatory side-effect DB write at the start of every node's work —
    the ONLY way the polling API sees live progress, per
    `spec/agent.md` -> Progress Reporting. Never raises past the caller;
    a progress-write failure should not itself fail the scan.
    """
    try:
        with create_db_session() as session:
            row = session.get(ScanRow, scan_id)
            if row is not None:
                row.current_phase = current_phase
                if current_detail is not None:
                    row.current_detail = current_detail
    except Exception:  # noqa: BLE001 — progress reporting must never crash a node
        get_logger("graph.progress").warning("progress_write_failed", scan_id=scan_id, phase=current_phase)


def _rebuild_unpack_result(state: ScanState) -> UnpackResult:
    """Reconstruct the nested-jar-paths + manifest data the static-analysis
    functions need but which `ScanState` (pinned in `spec/agent.md`) does not
    carry directly — `decompile` already extracted everything to
    `state["extract_dir"]` on local disk, so re-deriving these two small,
    cheap signals here (mirroring `decompile/unpack.py`'s own logic, the same
    duplication pattern `analysis/spring_detect.py` already uses) avoids
    widening the pinned state contract.
    """
    extract_root = Path(state["extract_dir"])
    lib_dir = extract_root / "BOOT-INF" / "lib"
    nested_jars = sorted(str(p) for p in lib_dir.glob("*.jar")) if lib_dir.is_dir() else []

    manifest: dict[str, str] = {}
    manifest_path = extract_root / "META-INF" / "MANIFEST.MF"
    if manifest_path.is_file():
        lines: list[str] = []
        for line in manifest_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith(" ") and lines:
                lines[-1] += line[1:]
            else:
                lines.append(line)
        for line in lines:
            if ":" in line:
                key, _, value = line.partition(":")
                manifest[key.strip()] = value.strip()

    return UnpackResult(
        extract_dir=state["extract_dir"],
        is_spring_boot=state.get("is_spring_boot", False),
        has_spring_security=state.get("has_spring_security", False),
        spring_evidence=state.get("spring_evidence", []),
        classes_root=state.get("decompiled_app_dir", ""),
        nested_jars=nested_jars,
        manifest=manifest,
        config_file_paths=state.get("config_file_paths", {}),
    )


# ---------------------------------------------------------------------------
# decompile
# ---------------------------------------------------------------------------


def decompile(state: ScanState) -> ScanState:
    scan_id = state["scan_id"]
    _set_progress(scan_id, "decompiling")
    logger = get_logger("graph.decompile")
    t0 = time.monotonic()
    try:
        settings = get_settings()
        extract_dir = str(Path(settings.scan_work_dir) / scan_id / "extract")
        unpack_result = unpack_jar(state["jar_path"], extract_dir)

        decompile_errors: list[str] = []
        app_output_dir = str(Path(settings.scan_work_dir) / scan_id / "decompiled" / "app")
        app_result = decompile_classes(
            unpack_result["classes_root"],
            app_output_dir,
            cfr_jar_path=settings.cfr_jar_path,
            java_bin=settings.java_bin,
            timeout_s=settings.cfr_timeout_s,
        )
        decompile_errors.extend(app_result["errors"])
        total_class_count = app_result["class_count"]

        lib_dirs: list[str] = []
        for idx, nested_jar in enumerate(unpack_result["nested_jars"]):
            lib_output_dir = str(Path(settings.scan_work_dir) / scan_id / "decompiled" / f"lib_{idx}")
            lib_result = decompile_classes(
                nested_jar,
                lib_output_dir,
                cfr_jar_path=settings.cfr_jar_path,
                java_bin=settings.java_bin,
                timeout_s=settings.cfr_timeout_s,
            )
            decompile_errors.extend(lib_result["errors"])
            if lib_result["class_count"] > 0:
                lib_dirs.append(lib_output_dir)
                total_class_count += lib_result["class_count"]

        if total_class_count == 0:
            raise RuntimeError(
                "Decompilation produced zero classes anywhere (app classes + every nested "
                "jar failed to decompile): " + "; ".join(decompile_errors)
            )

        duration_ms = int((time.monotonic() - t0) * 1000)
        logger.info(
            "tool_call",
            tool="decompile",
            scan_id=scan_id,
            duration_ms=duration_ms,
            errors=decompile_errors,
        )

        with create_db_session() as session:
            row = session.get(ScanRow, scan_id)
            if row is not None:
                row.is_spring_boot = unpack_result["is_spring_boot"]
                row.has_spring_security = unpack_result["has_spring_security"]
                row.class_count = total_class_count
                row.decompile_errors_json = json.dumps(decompile_errors) if decompile_errors else None

        return {
            **state,
            "extract_dir": unpack_result["extract_dir"],
            "decompiled_app_dir": app_output_dir,
            "decompiled_lib_dirs": lib_dirs,
            "is_spring_boot": unpack_result["is_spring_boot"],
            "has_spring_security": unpack_result["has_spring_security"],
            "spring_evidence": unpack_result["spring_evidence"],
            "class_count": total_class_count,
            "decompile_errors": decompile_errors,
            "config_file_paths": unpack_result["config_file_paths"],
        }
    except Exception as exc:  # noqa: BLE001 — fatal per spec/agent.md Tools table
        logger.error("tool_call_failed", tool="decompile", scan_id=scan_id, error=str(exc))
        return {**state, "error": str(exc)}


# ---------------------------------------------------------------------------
# scan_dependencies
# ---------------------------------------------------------------------------


def scan_dependencies(state: ScanState) -> ScanState:
    scan_id = state["scan_id"]
    _set_progress(scan_id, "scanning_dependencies")
    logger = get_logger("graph.scan_dependencies")
    t0 = time.monotonic()
    try:
        unpack_result = _rebuild_unpack_result(state)
        dependencies = extract_dependencies(unpack_result)

        duration_ms = int((time.monotonic() - t0) * 1000)
        logger.info(
            "tool_call", tool="scan_dependencies", scan_id=scan_id, duration_ms=duration_ms, errors=[]
        )

        with create_db_session() as session:
            row = session.get(ScanRow, scan_id)
            if row is not None:
                row.dependencies_json = json.dumps(dependencies)

        return {**state, "dependencies": dependencies}
    except Exception as exc:  # noqa: BLE001
        logger.error("tool_call_failed", tool="scan_dependencies", scan_id=scan_id, error=str(exc))
        return {**state, "error": str(exc)}


# ---------------------------------------------------------------------------
# scan_secrets
# ---------------------------------------------------------------------------


def scan_secrets(state: ScanState) -> ScanState:
    scan_id = state["scan_id"]
    _set_progress(scan_id, "scanning_secrets")
    logger = get_logger("graph.scan_secrets")
    t0 = time.monotonic()
    try:
        decompiled_dirs = [state["decompiled_app_dir"], *state.get("decompiled_lib_dirs", [])]
        secret_findings = _run_secret_scan(decompiled_dirs, state.get("config_file_paths", {}))

        duration_ms = int((time.monotonic() - t0) * 1000)
        logger.info(
            "tool_call", tool="scan_secrets", scan_id=scan_id, duration_ms=duration_ms, errors=[]
        )

        with create_db_session() as session:
            row = session.get(ScanRow, scan_id)
            if row is not None:
                row.secret_findings_count = len(secret_findings)

        return {**state, "secret_findings": secret_findings}
    except Exception as exc:  # noqa: BLE001
        logger.error("tool_call_failed", tool="scan_secrets", scan_id=scan_id, error=str(exc))
        return {**state, "error": str(exc)}


# ---------------------------------------------------------------------------
# extract_config
# ---------------------------------------------------------------------------


def extract_config(state: ScanState) -> ScanState:
    scan_id = state["scan_id"]
    _set_progress(scan_id, "extracting_config")
    logger = get_logger("graph.extract_config")
    try:
        config_files = extract_config_files({"config_file_paths": state.get("config_file_paths", {})})
        return {**state, "config_files": config_files}
    except Exception as exc:  # noqa: BLE001
        logger.error("tool_call_failed", tool="extract_config", scan_id=scan_id, error=str(exc))
        return {**state, "error": str(exc)}


# ---------------------------------------------------------------------------
# triage
# ---------------------------------------------------------------------------


def triage(state: ScanState) -> ScanState:
    scan_id = state["scan_id"]
    _set_progress(scan_id, "triaging")
    logger = get_logger("graph.triage")
    t0 = time.monotonic()
    try:
        settings = get_settings()
        triaged_chunks = triage_classes(
            state["decompiled_app_dir"],
            state.get("decompiled_lib_dirs", []),
            max_classes=settings.triage_max_classes,
            max_total_chars=settings.triage_max_chars,
            per_category_max_chars=settings.triage_per_category_max_chars,
        )

        duration_ms = int((time.monotonic() - t0) * 1000)
        logger.info(
            "tool_call", tool="triage", scan_id=scan_id, duration_ms=duration_ms, errors=[]
        )

        with create_db_session() as session:
            row = session.get(ScanRow, scan_id)
            if row is not None:
                row.triaged_class_count = len(triaged_chunks)

        return {**state, "triaged_chunks": triaged_chunks}
    except Exception as exc:  # noqa: BLE001
        logger.error("tool_call_failed", tool="triage", scan_id=scan_id, error=str(exc))
        return {**state, "error": str(exc)}


# ---------------------------------------------------------------------------
# review_* — six sequential category-partitioned LLM review nodes
# ---------------------------------------------------------------------------


def _append_token_usage(
    state: ScanState, node_name: str, model: str, input_tokens: int, output_tokens: int
) -> list[TokenUsageEntry]:
    usage = list(state.get("token_usage", []))
    usage.append(
        TokenUsageEntry(node=node_name, model=model, input_tokens=input_tokens, output_tokens=output_tokens)
    )
    return usage


def _review_category(state: ScanState, *, node_name: str, phase: str, detail: str, prompt_file: str, build_user_message) -> ScanState:
    scan_id = state["scan_id"]
    _set_progress(scan_id, phase, detail)
    logger = get_logger(f"graph.{node_name}")
    try:
        settings = get_settings()
        system_prompt = _load_prompt(prompt_file)
        user_message = build_user_message(state, settings)

        t0 = time.monotonic()
        result = LLMClient().call_model(user_message, system=system_prompt)
        latency_ms = int((time.monotonic() - t0) * 1000)

        logger.info(
            "llm_call",
            node=node_name,
            input_tokens=result["input_tokens"],
            output_tokens=result["output_tokens"],
            latency_ms=latency_ms,
            model=result["model"],
        )

        findings = parse_findings_json(result["text"], category_source=node_name)

        raw_findings = list(state.get("raw_findings", []))
        raw_findings.extend(findings)

        token_usage = _append_token_usage(
            state, node_name, result["model"], result["input_tokens"], result["output_tokens"]
        )

        return {**state, "raw_findings": raw_findings, "token_usage": token_usage}
    except Exception as exc:  # noqa: BLE001 — fatal in Phase 1 per spec/agent.md
        logger.error("node_failed", node=node_name, scan_id=scan_id, error=str(exc))
        return {**state, "error": str(exc)}


def review_injection(state: ScanState) -> ScanState:
    def build(s: ScanState, settings) -> str:
        chunks = filter_chunks_for_category(s.get("triaged_chunks", []), "injection")
        return build_chunks_message(chunks, settings.triage_per_category_max_chars)

    return _review_category(
        state,
        node_name="review_injection",
        phase="reviewing_injection",
        detail="injection",
        prompt_file="review_injection.md",
        build_user_message=build,
    )


def review_authn_authz(state: ScanState) -> ScanState:
    def build(s: ScanState, settings) -> str:
        has_spring_security = bool(s.get("has_spring_security", False))
        chunks = filter_chunks_for_category(s.get("triaged_chunks", []), "authn_authz")
        chunks_msg = build_chunks_message(chunks, settings.triage_per_category_max_chars)
        if has_spring_security:
            spring_note = (
                "has_spring_security: true\n"
                "Spring Security IS present on the classpath — perform the Spring-Security-specific "
                "sub-checks (filter chain configuration, @PreAuthorize coverage, CSRF configuration) "
                "IN ADDITION to the generic authN/authZ/JWT checks."
            )
        else:
            spring_note = (
                "has_spring_security: false\n"
                "Spring Security is NOT present on the classpath — skip the Spring-Security-specific "
                "sub-checks entirely (do not fabricate findings about a framework that is not used); "
                "still perform every generic authN/authZ/JWT check."
            )
        return f"{spring_note}\n\n{chunks_msg}"

    return _review_category(
        state,
        node_name="review_authn_authz",
        phase="reviewing_authn_authz",
        detail="authn_authz",
        prompt_file="review_authn_authz.md",
        build_user_message=build,
    )


def review_crypto_secrets(state: ScanState) -> ScanState:
    def build(s: ScanState, settings) -> str:
        secrets_msg = build_secret_findings_message(s.get("secret_findings", []))
        chunks = filter_chunks_for_category(s.get("triaged_chunks", []), "crypto_secrets")
        chunks_msg = build_chunks_message(chunks, settings.triage_per_category_max_chars)
        return (
            f"=== Candidate secret-scan matches (secret_findings, already redacted) ===\n{secrets_msg}\n\n"
            f"=== Triaged source ===\n{chunks_msg}"
        )

    return _review_category(
        state,
        node_name="review_crypto_secrets",
        phase="reviewing_crypto_secrets",
        detail="crypto_secrets",
        prompt_file="review_crypto_secrets.md",
        build_user_message=build,
    )


def review_deserialization_upload(state: ScanState) -> ScanState:
    def build(s: ScanState, settings) -> str:
        chunks = filter_chunks_for_category(s.get("triaged_chunks", []), "deserialization_upload")
        return build_chunks_message(chunks, settings.triage_per_category_max_chars)

    return _review_category(
        state,
        node_name="review_deserialization_upload",
        phase="reviewing_deserialization_upload",
        detail="deserialization_upload",
        prompt_file="review_deserialization_upload.md",
        build_user_message=build,
    )


def review_config_logging(state: ScanState) -> ScanState:
    def build(s: ScanState, settings) -> str:
        config_msg = build_config_message(s.get("config_files", {}), settings.triage_per_category_max_chars)
        chunks = filter_chunks_for_category(s.get("triaged_chunks", []), "config_logging")
        chunks_msg = build_chunks_message(chunks, settings.triage_per_category_max_chars)
        return f"{config_msg}\n\n=== Triaged source ===\n{chunks_msg}"

    return _review_category(
        state,
        node_name="review_config_logging",
        phase="reviewing_config_logging",
        detail="config_logging",
        prompt_file="review_config_logging.md",
        build_user_message=build,
    )


def review_dependencies(state: ScanState) -> ScanState:
    def build(s: ScanState, settings) -> str:
        return build_dependencies_message(s.get("dependencies", []))

    return _review_category(
        state,
        node_name="review_dependencies",
        phase="reviewing_dependencies",
        detail="dependencies",
        prompt_file="review_dependencies.md",
        build_user_message=build,
    )


# ---------------------------------------------------------------------------
# verify_findings — Reflection / LLM-as-judge pass
# ---------------------------------------------------------------------------


def _batch_findings_for_verification(
    items: list[tuple[int, Finding]], max_chars: int
) -> list[list[tuple[int, Finding]]]:
    """Group findings into per-call batches bounded by `max_chars` over the
    serialized evidence/code_snippet/description payload — mirrors the
    per_category_max_chars-style budget used for the review nodes, applied
    here to the verification payload per `spec/agent.md`'s `verify_findings`
    Behaviour note.
    """
    batches: list[list[tuple[int, Finding]]] = []
    current: list[tuple[int, Finding]] = []
    running = 0
    for idx, finding in items:
        approx_len = (
            len(finding.get("evidence", ""))
            + len(finding.get("code_snippet", ""))
            + len(finding.get("description", ""))
            + 200
        )
        if current and running + approx_len > max_chars:
            batches.append(current)
            current = []
            running = 0
        current.append((idx, finding))
        running += approx_len
    if current:
        batches.append(current)
    return batches


def verify_findings(state: ScanState) -> ScanState:
    scan_id = state["scan_id"]
    _set_progress(scan_id, "verifying")
    logger = get_logger("graph.verify_findings")
    try:
        settings = get_settings()
        system_prompt = _load_prompt("verify_findings.md")
        raw_findings = state.get("raw_findings", [])

        to_verify: list[tuple[int, Finding]] = [
            (idx, f) for idx, f in enumerate(raw_findings) if not f.get("no_evidence_marker")
        ]
        passthrough = [f for f in raw_findings if f.get("no_evidence_marker")]

        token_usage = list(state.get("token_usage", []))
        decisions_by_index: dict[int, dict] = {}

        if to_verify:
            batches = _batch_findings_for_verification(to_verify, settings.triage_per_category_max_chars)
            for batch in batches:
                payload = [
                    {
                        "index": idx,
                        "title": f["title"],
                        "severity": f["severity"],
                        "confidence": f["confidence"],
                        "evidence": f["evidence"],
                        "code_snippet": f["code_snippet"],
                        "description": f["description"],
                    }
                    for idx, f in batch
                ]
                user_message = json.dumps(payload, indent=2)

                t0 = time.monotonic()
                result = LLMClient().call_model(user_message, system=system_prompt)
                latency_ms = int((time.monotonic() - t0) * 1000)

                logger.info(
                    "llm_call",
                    node="verify_findings",
                    input_tokens=result["input_tokens"],
                    output_tokens=result["output_tokens"],
                    latency_ms=latency_ms,
                    model=result["model"],
                )

                token_usage.append(
                    TokenUsageEntry(
                        node="verify_findings",
                        model=result["model"],
                        input_tokens=result["input_tokens"],
                        output_tokens=result["output_tokens"],
                    )
                )

                for decision in parse_verification_decisions(result["text"]):
                    decisions_by_index[decision["index"]] = decision

        verified_findings: list[Finding] = []
        for idx, finding in to_verify:
            decision = decisions_by_index.get(idx)
            if decision is None:
                verified_findings.append(
                    {
                        **finding,
                        "verified": True,
                        "verification_note": (
                            "Verification pass did not return a decision for this finding; "
                            "kept by default rather than silently dropped."
                        ),
                    }
                )
                continue

            is_drop = decision["decision"] == "drop"
            is_downgrade = decision["decision"] == "downgrade"
            verified_findings.append(
                {
                    **finding,
                    "severity": decision["severity"] if is_downgrade else finding["severity"],
                    "confidence": decision["confidence"] if is_downgrade else finding["confidence"],
                    "verified": not is_drop,
                    "verification_note": decision.get("verification_note"),
                }
            )

        for f in passthrough:
            verified_findings.append({**f, "verified": True, "verification_note": None})

        return {**state, "verified_findings": verified_findings, "token_usage": token_usage}
    except Exception as exc:  # noqa: BLE001 — fatal in Phase 1 per spec/agent.md
        logger.error("node_failed", node="verify_findings", scan_id=scan_id, error=str(exc))
        return {**state, "error": str(exc)}


# ---------------------------------------------------------------------------
# assemble_report — deterministic, no LLM call
# ---------------------------------------------------------------------------

_SEVERITY_WEIGHTS = {"Critical": 10, "High": 6, "Medium": 3, "Low": 1, "Informational": 0}


def _risk_band(score: int) -> str:
    if score >= 80:
        return "Critical Risk"
    if score >= 60:
        return "High Risk"
    if score >= 35:
        return "Medium Risk"
    if score >= 15:
        return "Low Risk"
    return "Minimal Risk"


def _compute_risk_score(reportable: list[Finding]) -> int:
    total = sum(_SEVERITY_WEIGHTS.get(f["severity"], 0) for f in reportable)
    return min(100, total)


def _is_data_exposure_finding(f: Finding) -> bool:
    keywords = ("secret", "password", "credential", "api key", "hardcoded", "token")
    haystack = f"{f['title']} {f['description']}".lower()
    if f.get("cwe_id") in ("CWE-798", "CWE-321", "CWE-330"):
        return True
    return any(k in haystack for k in keywords)


def _is_authentication_finding(f: Finding) -> bool:
    if f.get("cwe_id") in ("CWE-287", "CWE-798", "CWE-347", "CWE-613", "CWE-384"):
        return True
    keywords = ("authentic", "login", "jwt", "session", "password", "credential")
    haystack = f"{f['title']} {f.get('owasp_category') or ''} {f['description']}".lower()
    return any(k in haystack for k in keywords)


def _is_logging_finding(f: Finding) -> bool:
    keywords = ("log", "logger", "logging")
    haystack = f"{f['title']} {f.get('owasp_category') or ''} {f['description']}".lower()
    return any(k in haystack for k in keywords)


def _render_finding(f: Finding) -> str:
    lines = [
        f"#### {f['title']}",
        "",
        f"- **Severity:** {f['severity']}",
        f"- **CVSS Score:** {f['cvss_score'] if f['cvss_score'] is not None else 'N/A'}",
        f"- **OWASP Category:** {f['owasp_category'] or 'N/A'}",
        f"- **STRIDE Category:** {f['stride_category'] or 'N/A'}",
        f"- **CWE ID:** {f['cwe_id'] or 'N/A'}",
        f"- **Affected Classes:** {', '.join(f['affected_classes']) or 'N/A'}",
        f"- **Affected Methods:** {', '.join(f['affected_methods']) or 'N/A'}",
        f"- **Description:** {f['description']}",
        f"- **Business Impact:** {f['business_impact']}",
        f"- **Technical Impact:** {f['technical_impact']}",
        f"- **Attack Scenario:** {f['attack_scenario']}",
        "- **Evidence:**",
        "```",
        f["evidence"],
        "```",
        "- **Code Snippet:**",
        "```java",
        f["code_snippet"],
        "```",
        f"- **Why it is vulnerable:** {f['why_vulnerable']}",
        f"- **How attacker can exploit:** {f['how_exploitable']}",
        f"- **Recommended Fix:** {f['recommended_fix']}",
        "- **Secure Code Example:**",
        "```java",
        f["secure_code_example"],
        "```",
        f"- **References:** {', '.join(f['references']) or 'N/A'}",
        f"- **Confidence Level:** {f['confidence']}",
    ]
    if f.get("verification_note"):
        lines.append(f"- **Verification Note:** {f['verification_note']}")
    return "\n".join(lines)


def _render_findings_or_no_evidence(findings: list[Finding]) -> str:
    real = [f for f in findings if not f.get("no_evidence_marker")]
    if not real:
        return "No evidence found."
    return "\n\n".join(_render_finding(f) for f in real)


def assemble_report(state: ScanState) -> ScanState:
    scan_id = state["scan_id"]
    _set_progress(scan_id, "assembling_report")
    logger = get_logger("graph.assemble_report")
    try:
        verified_findings: list[Finding] = state.get("verified_findings", [])
        dependencies = state.get("dependencies", [])
        secret_findings = state.get("secret_findings", [])
        class_count = state.get("class_count", 0)
        triaged_chunks = state.get("triaged_chunks", [])
        decompile_errors = state.get("decompile_errors", [])
        is_spring_boot = state.get("is_spring_boot", False)
        has_spring_security = state.get("has_spring_security", False)
        spring_evidence = state.get("spring_evidence", [])
        token_usage = state.get("token_usage", [])

        # Only verified=True, non-marker findings count toward risk/report content.
        reportable = [
            f for f in verified_findings if f.get("verified") and not f.get("no_evidence_marker")
        ]
        risk_score = _compute_risk_score(reportable)
        band = _risk_band(risk_score)

        total_input_tokens = sum(t["input_tokens"] for t in token_usage)
        total_output_tokens = sum(t["output_tokens"] for t in token_usage)
        estimated_cost_usd = estimate_cost_usd(token_usage)

        by_category: dict[str, list[Finding]] = {}
        for f in verified_findings:
            if not f.get("verified"):
                continue
            by_category.setdefault(f["category_source"], []).append(f)

        injection_findings = by_category.get("review_injection", [])
        authn_authz_findings = by_category.get("review_authn_authz", [])
        crypto_secrets_findings = by_category.get("review_crypto_secrets", [])
        deserialization_upload_findings = by_category.get("review_deserialization_upload", [])
        config_logging_findings = by_category.get("review_config_logging", [])
        dependencies_findings = by_category.get("review_dependencies", [])

        authentication_findings = [f for f in authn_authz_findings if _is_authentication_finding(f)]
        authorization_findings = [f for f in authn_authz_findings if not _is_authentication_finding(f)]

        data_exposure_findings = [f for f in crypto_secrets_findings if _is_data_exposure_finding(f)]
        cryptography_findings = [f for f in crypto_secrets_findings if not _is_data_exposure_finding(f)]

        logging_findings = [f for f in config_logging_findings if _is_logging_finding(f)]
        configuration_findings = [f for f in config_logging_findings if not _is_logging_finding(f)]

        # Include deserialization/upload findings under the closest matching
        # required sections too — they're not one of the 16 verbatim headers,
        # so fold them into Injection Issues (closest topical match: unsafe
        # input handling) in addition to being counted for the risk score.
        injection_and_upload_findings = injection_findings + deserialization_upload_findings

        owasp_groups: dict[str, list[Finding]] = {}
        for f in reportable:
            owasp_groups.setdefault(f.get("owasp_category") or "Uncategorized", []).append(f)

        stride_groups: dict[str, list[Finding]] = {}
        for f in reportable:
            stride_groups.setdefault(f.get("stride_category") or "Uncategorized", []).append(f)

        severity_counts = {sev: 0 for sev in _SEVERITY_WEIGHTS}
        for f in reportable:
            severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

        exec_summary = (
            f"This automated, evidence-based security review analyzed {class_count} structurally "
            f"discovered classes, deep-reviewing {len(triaged_chunks)} of them across six security "
            f"categories (injection, authentication/authorization, cryptography/secrets, "
            f"deserialization/file-upload, configuration/logging, and dependency risk), followed by "
            f"an independent verification pass. {len(reportable)} finding(s) were verified as real "
            f"after that pass, yielding an overall risk score of {risk_score}/100 ({band}). "
            f"This application {'was' if is_spring_boot else 'was not'} detected as Spring Boot"
            f"{' with Spring Security present' if has_spring_security else ''}."
        )

        owasp_section_lines = []
        if not owasp_groups:
            owasp_section_lines.append("No evidence found.")
        else:
            for category, items in sorted(owasp_groups.items()):
                owasp_section_lines.append(f"### {category}\n")
                owasp_section_lines.append(_render_findings_or_no_evidence(items))
        owasp_section = "\n\n".join(owasp_section_lines)

        stride_section_lines = []
        if not stride_groups:
            stride_section_lines.append("No evidence found.")
        else:
            for category, items in sorted(stride_groups.items()):
                stride_section_lines.append(f"### {category}\n")
                stride_section_lines.append(_render_findings_or_no_evidence(items))
        stride_section = "\n\n".join(stride_section_lines)

        severity_table = "\n".join(
            f"| {sev} | {severity_counts.get(sev, 0)} |" for sev in _SEVERITY_WEIGHTS
        )

        dependency_table = "\n".join(
            f"| {d['artifact_id']} | {d.get('group_id') or 'N/A'} | {d.get('version') or 'N/A'} | {d['source']} |"
            for d in dependencies
        ) or "| (none extracted) | | | |"

        secret_scan_table = "\n".join(
            f"| {s['pattern_name']} | {s['file_path']} | {s['line_number']} | {s['matched_text_redacted']} | {s['confidence']} |"
            for s in secret_findings
        ) or "| (none detected) | | | | |"

        # Priority 1-4 Developer Fix Roadmap: Priority 1=Critical, 2=High, 3=Medium, 4=Low/Informational,
        # ordered within each priority by the finding's own risk_score contribution (severity weight).
        priority_buckets: dict[int, list[Finding]] = {1: [], 2: [], 3: [], 4: []}
        for f in reportable:
            sev = f["severity"]
            if sev == "Critical":
                priority_buckets[1].append(f)
            elif sev == "High":
                priority_buckets[2].append(f)
            elif sev == "Medium":
                priority_buckets[3].append(f)
            else:
                priority_buckets[4].append(f)
        for bucket in priority_buckets.values():
            bucket.sort(key=lambda f: _SEVERITY_WEIGHTS.get(f["severity"], 0), reverse=True)

        roadmap_lines = []
        priority_labels = {
            1: "Priority 1 (Critical)",
            2: "Priority 2 (High)",
            3: "Priority 3 (Medium)",
            4: "Priority 4 (Low / Informational)",
        }
        for priority, items in priority_buckets.items():
            roadmap_lines.append(f"### {priority_labels[priority]}\n")
            if not items:
                roadmap_lines.append("No evidence found.")
            else:
                for f in items:
                    roadmap_lines.append(f"- **{f['title']}** ({f['affected_classes'] or ['N/A']}): {f['recommended_fix']}")
        remediation_plan = "\n".join(roadmap_lines)

        deep_reviewed_classes = sorted(
            {c["class_name"] for c in triaged_chunks}
        )
        appendix_lines = [
            f"- **Total classes scanned:** {class_count}",
            f"- **Classes deep-reviewed (triaged into LLM review):** {len(triaged_chunks)}",
            f"- **Deep-reviewed class names:** {', '.join(deep_reviewed_classes) or 'N/A'}",
            f"- **Decompile errors:** {'; '.join(decompile_errors) if decompile_errors else 'None'}",
            f"- **Spring Boot detected:** {is_spring_boot}",
            f"- **Spring Security detected:** {has_spring_security}",
            f"- **Spring-detection evidence:** {'; '.join(spring_evidence) if spring_evidence else 'None'}",
            "",
            "**Dependency-vulnerability disclaimer:** dependency-vulnerability findings in this report "
            "are Claude's evidence-based reasoning over the extracted dependency list, **not** a live "
            "CVE database (NVD/OSV) query — always independently verify against a live CVE feed before "
            "acting on these findings alone.",
        ]

        report_sections = [
            "# Executive Summary\n\n" + exec_summary,
            f"# Risk Score\n\n**{risk_score}/100 — {band}**",
            (
                "# Severity Dashboard\n\n"
                "| Severity | Count |\n|---|---|\n" + severity_table
            ),
            "# OWASP Top 10 Findings\n\n" + owasp_section,
            "# STRIDE Findings\n\n" + stride_section,
            "# Dependency Vulnerabilities\n\n" + _render_findings_or_no_evidence(dependencies_findings),
            "# Sensitive Data Exposure\n\n"
            + "## Regex Secret Scan Matches\n\n"
            + "| Pattern | File | Line | Redacted Match | Confidence |\n|---|---|---|---|---|\n"
            + secret_scan_table
            + "\n\n## LLM-Reviewed Secret/Data-Exposure Findings\n\n"
            + _render_findings_or_no_evidence(data_exposure_findings),
            "# Authentication Issues\n\n" + _render_findings_or_no_evidence(authentication_findings),
            "# Authorization Issues\n\n" + _render_findings_or_no_evidence(authorization_findings),
            "# Cryptography Issues\n\n" + _render_findings_or_no_evidence(cryptography_findings),
            "# Injection Issues\n\n" + _render_findings_or_no_evidence(injection_and_upload_findings),
            "# Configuration Issues\n\n" + _render_findings_or_no_evidence(configuration_findings),
            "# Logging Issues\n\n" + _render_findings_or_no_evidence(logging_findings),
            (
                "# Secure Coding Recommendations\n\n"
                "Adopt parameterized queries/PreparedStatements universally, enforce centralized "
                "authentication/authorization via Spring Security filter chains and method-level "
                "`@PreAuthorize` annotations, use `SecureRandom` and modern authenticated-encryption "
                "modes (AES/GCM) for all cryptographic operations, never hardcode secrets (source them "
                "from environment/secret managers), validate and sandbox all file uploads, and never log "
                "sensitive data."
            ),
            "# Developer Remediation Plan\n\n" + remediation_plan,
            "# Appendix\n\n" + "\n".join(appendix_lines),
        ]

        cost_footer = (
            f"\n\n---\n*Estimated cost: ${estimated_cost_usd:.4f} USD "
            f"({total_input_tokens} input tokens, {total_output_tokens} output tokens) "
            f"— (estimated, approximate pricing).*"
        )

        report_markdown = "\n\n".join(report_sections) + cost_footer

        logger.info(
            "scan_report_assembled",
            scan_id=scan_id,
            risk_score=risk_score,
            reportable_findings=len(reportable),
            total_input_tokens=total_input_tokens,
            total_output_tokens=total_output_tokens,
            estimated_cost_usd=estimated_cost_usd,
        )

        return {
            **state,
            "risk_score": risk_score,
            "total_input_tokens": total_input_tokens,
            "total_output_tokens": total_output_tokens,
            "estimated_cost_usd": estimated_cost_usd,
            "report_markdown": report_markdown,
        }
    except Exception as exc:  # noqa: BLE001
        logger.error("node_failed", node="assemble_report", scan_id=scan_id, error=str(exc))
        return {**state, "error": str(exc)}


# ---------------------------------------------------------------------------
# handle_error / finalize
# ---------------------------------------------------------------------------


def handle_error(state: ScanState) -> ScanState:
    scan_id = state["scan_id"]
    error = state.get("error") or "Unknown error"
    logger = get_logger("graph.handle_error")
    logger.error("scan_failed", scan_id=scan_id, error=error)

    with create_db_session() as session:
        row = session.get(ScanRow, scan_id)
        if row is not None:
            row.status = "failed"
            row.error_message = error
            row.current_phase = "failed"

    return {**state, "status": "failed"}


def finalize(state: ScanState) -> ScanState:
    scan_id = state["scan_id"]
    logger = get_logger("graph.finalize")

    verified_findings = state.get("verified_findings", [])

    with create_db_session() as session:
        row = session.get(ScanRow, scan_id)
        if row is not None:
            row.status = "completed"
            row.current_phase = "completed"
            row.report_markdown = state.get("report_markdown")
            row.risk_score = state.get("risk_score")
            row.findings_json = json.dumps(verified_findings)
            row.total_input_tokens = state.get("total_input_tokens")
            row.total_output_tokens = state.get("total_output_tokens")
            row.estimated_cost_usd = state.get("estimated_cost_usd")

    logger.info(
        "scan_completed",
        scan_id=scan_id,
        risk_score=state.get("risk_score"),
        total_input_tokens=state.get("total_input_tokens"),
        total_output_tokens=state.get("total_output_tokens"),
        estimated_cost_usd=state.get("estimated_cost_usd"),
    )

    return {**state, "status": "completed"}
