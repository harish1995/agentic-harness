# Architecture

---

## System Overview

A single-user, locally-run web application. The user uploads a Java/Spring Boot JAR through a Next.js UI; a FastAPI backend saves it to local disk, kicks off a LangGraph pipeline in a background thread, and the UI polls a status endpoint for live phase progress. The pipeline unpacks and decompiles the JAR locally (CFR), runs deterministic static analysis (dependency extraction, secret regex scan, config-file surfacing, security-relevant-class triage), then drives Claude through a category-partitioned exhaustive security review with a verification/reflection pass, and deterministically assembles one Markdown report with dashboard data. The report and scan metadata are persisted to local SQLite. Nothing about the JAR or its decompiled contents ever leaves the machine except the small, triage-selected code/config snippets each LLM call needs.

## Component Map

```
Next.js UI (upload / progress / report)
    │  HTTP (fetch, polling)
    ▼
FastAPI app (src/api)
    │  spawns background thread            │  reads/writes
    ▼                                       ▼
LangGraph pipeline (src/graph)  ──────►  SQLite (scans table)
    │
    ├─► src/decompile  ──shells out──►  CFR (local JVM subprocess)
    ├─► src/analysis   (pure local functions: deps/secrets/config/triage)
    └─► src/llm/client  ──HTTPS (bounded snippets only)──►  Anthropic API
```

## Layers

| Layer | Responsibility |
|-------|----------------|
| **UI (Next.js)** | Upload form, phase-stepper progress view (polling), report renderer with dashboards, download/export affordances (some stubbed until Phase 2). |
| **API (FastAPI)** | Validate uploads, persist the scan record, spawn the pipeline in the background, expose status/report/download endpoints. Never touches the JAR's contents itself — delegates entirely to the pipeline. |
| **Pipeline (LangGraph)** | Orchestrates decompile → static analysis → triage → category-partitioned LLM review → verification → report assembly. Writes progress to the DB as it advances (see `spec/agent.md`). |
| **Decompile tools (src/decompile)** | Local, pure-Python + subprocess wrappers around JAR unpacking and CFR invocation. No network calls. |
| **Analysis tools (src/analysis)** | Pure, deterministic local functions: Spring detection, dependency extraction, secret regex scanning, config-file surfacing, triage/chunking. No LLM calls, no network calls. |
| **LLM (src/llm)** | Thin wrapper over the Anthropic SDK; every call returns text **and** token usage so the pipeline can accumulate cost. |
| **Storage (SQLite)** | One row per scan: metadata, progress, final report markdown + structured findings JSON, token/cost totals. |

## Data Flow

1. **Trigger:** user drags a `.jar` onto the upload screen and clicks **Start Scan**; the browser `POST`s it as multipart form data to `/scans`.
2. The API validates it's a readable ZIP/JAR and under the size cap, rejects immediately (400/413) if not, otherwise saves it to `data/uploads/<scan_id>.jar`, creates a `scans` row (`status="processing"`, `current_phase="decompiling"`), spawns the pipeline in a background thread, and returns `scan_id` immediately.
3. The pipeline unpacks the JAR locally (detecting Spring Boot fat-JAR structure vs. a plain/vendor JAR), decompiles via CFR, extracts dependencies/secrets/config, triages security-relevant classes into a bounded set of code chunks, and runs six category-partitioned Claude review calls followed by one verification pass — writing `current_phase`/`current_detail` to the DB before each step so the UI's poll reflects live progress.
4. The report-assembly step deterministically computes the risk score, buckets verified findings into the required dashboard tables and the Priority 1-4 remediation roadmap, renders the full Markdown report, and writes it plus token/cost totals to the `scans` row (`status="completed"`).
5. **Output:** the UI polls `/scans/{id}/status` until `completed`, fetches `/scans/{id}` for the full report + structured findings, renders the dashboards and syntax-highlighted evidence, and offers a `/scans/{id}/download` link for the raw Markdown.

## External Dependencies

| Dependency | Purpose | Failure Mode |
|------------|---------|--------------|
| Anthropic API (`claude-sonnet-4-6`) | Category-partitioned security review + verification/reflection pass | Phase 1: the affected node sets `state.error`, the scan is marked `failed` with a clear message. Phase 3 (`spec/roadmap.md`): retried with backoff; a single category's persistent failure degrades that category to "Review failed" rather than failing the whole scan. |
| CFR decompiler (local JVM subprocess, `tools/cfr-0.152.jar`) | Local decompilation of `.class` → readable `.java`-like source | Phase 1: per-class/per-jar decompile errors are collected in `decompile_errors` and surfaced in the Appendix, never silently dropped; a totally unreadable JAR fails the scan with a clear error. Phase 3: hard subprocess timeout, partial-failure isolation per component. |
| Local JVM (`java` on `PATH`, or `AGENT_JAVA_BIN`) | Required to invoke CFR | Startup-time check: if `java -version` fails, the app logs a clear startup warning; a scan attempted without a working JVM fails fast with an actionable error, not a silent hang. |
| SQLite (`data/agent.db`) | Scan metadata + report persistence | Standard SQLAlchemy failure propagation; `init_db()` / Alembic migration required before first run. |

## Stack

> This project's concrete technology choices, extending the existing repo skeleton in place (no new parallel structure). The generic, every-project rules — model-naming, DB driver, dev port, real-key test rule — live in `harness/patterns/tech-stack.md`.

- **Language:** Python 3.12+ (backend, extending `src/` in place) for the pipeline/API; TypeScript for the UI (existing `frontend/` Next.js skeleton).
- **Agent framework:** LangGraph — a multi-node pipeline with conditional error edges and a reflection/verification node; see `spec/agent.md` for the full graph.
- **LLM provider + model:** Anthropic, `claude-sonnet-4-6` for every LLM call in this pipeline (category review + verification). `AGENT_ANTHROPIC_API_KEY` is already set in `.env`. One model throughout — this task is quality/evidence-sensitive (false positives and false negatives both cost real developer time), so no cheaper-model tiering in Phase 1; see `spec/agent.md` for per-node detail.
- **Backend:** FastAPI (existing skeleton), with a background-thread execution model for the (multi-minute) scan pipeline — the HTTP request that creates a scan returns immediately with a `scan_id`; the frontend polls for progress.
- **Database + ORM:** SQLite + SQLAlchemy 2.0 (existing skeleton default, `AGENT_DATABASE_URL=sqlite:///./data/agent.db`) — this **is** the project's chosen production DB (single-user, local, ad hoc tool), not a substitute for anything else. Alembic migrations are still mandatory (`harness/patterns/project-layout.md`) even though the driver is SQLite.
- **Frontend:** Next.js 15 + React 19 (existing skeleton), static-exported and served by FastAPI at `/app` per `harness/patterns/tech-stack.md`. Markdown-adjacent rendering (dashboards, syntax highlighting) is done with real React components, not raw markdown pass-through, per `harness/patterns/ui-ux.md`.
- **Decompiler (new local tool dependency):** **CFR** (Class File Reader), chosen over Vineflower for this project because it ships as a single self-contained JAR invoked via `java -jar cfr-<version>.jar <target> --outputdir <dir>` — the simplest possible integration surface for a Python backend that shells out via `subprocess`, with no build step and a stable, long-lived CLI contract. Vineflower is a reasonable alternative but has a less stable CLI surface across releases; CFR's single-JAR-and-flags model is the more reliable subprocess target for an autonomous build.
  - **Version pin:** CFR 0.152 (`tools/cfr-0.152.jar`, downloaded from Maven Central: `https://repo1.maven.org/maven2/org/benf/cfr/0.152/cfr-0.152.jar`).
    > **Assumed:** 0.152 is the pinned version as of spec-writing; verify against `https://www.benf.org/other/cfr/` for the current latest stable release before installing, and update the pin (and the README) if a newer version exists.
  - **License:** CFR is MIT-licensed (per its distribution) — safe to bundle the JAR in `tools/` and document its provenance in the README; no attribution beyond the standard MIT notice is required.
  - **Invocation contract:** pinned precisely in `spec/agent.md` (Internal Module Contracts, `src/decompile/cfr.py`).
  - **Java runtime requirement (new prerequisite):** a JDK or JRE, Java 17+, must be present on the host and resolvable as `java` on `PATH` (overridable via `AGENT_JAVA_BIN`). This is required both to run CFR at scan time and (test-only) to compile the multi-class fixture JAR used by the Phase 1 integration gate (`javac` + `jar`, hence a **JDK**, not a JRE-only install, is required for development/testing; a JRE-only host is sufficient for a deployed instance that never runs the test suite).
    > **Assumed:** Java 17 is the minimum verified-safe version for CFR 0.152's supported bytecode range (covers Spring Boot 3.x's typical Java 17/21 compile targets); reverify against CFR's release notes if scanning JARs compiled for a newer Java version starts producing decompile errors.
- **Dependency management:** uv + `pyproject.toml` (Python), pnpm (TypeScript) — both already the skeleton's convention.

| Key library | Version | Purpose |
|-------------|---------|---------|
| `anthropic` | >=0.28 (existing) | Claude API client |
| `langgraph` | >=0.1 (existing) | Pipeline orchestration |
| `fastapi` / `uvicorn` | existing pins | HTTP API + server |
| `sqlalchemy` / `alembic` | existing pins | ORM + migrations |
| `python-multipart` | >=0.0.9 (new) | Required by FastAPI to accept the multipart JAR upload |
| `react-markdown` + `remark-gfm` | latest (new, frontend) | Renders the Executive Summary / free-text portions of the report as real markdown, never a raw string node |
| `react-syntax-highlighter` (or `shiki`) | latest (new, frontend) | Syntax-highlighted code-evidence and secure-code-example blocks |
| `@playwright/test` | latest (new, frontend, dev) | Required Phase-1 E2E smoke suite |

**Avoid:**
- A live NVD/OSV network lookup for dependency CVEs in Phase 1 — this project's data-residency constraint plus scope discipline keeps dependency-vulnerability reasoning to Claude's evidence-based judgment over the extracted dependency list, explicitly labelled as such in the report (not a live database).
- Feeding the full decompiled output of a JAR to any single LLM call — the triage/chunk-budget mechanism in `spec/agent.md` is mandatory, not optional, for every category-review node.
- A job queue (Celery/RQ/etc.) — a single background thread per scan is sufficient for a single-user, one-scan-at-a-time tool; do not over-engineer.

## Data Residency (hard constraint)

The uploaded JAR file (`data/uploads/`) and every decompiled artifact (`data/decompiled/<scan_id>/`) live only on the local filesystem for the lifetime of the process and are never transmitted anywhere. The **only** network egress from this system is the Anthropic API calls made by the six category-review nodes and the verification node, each carrying only the bounded set of triaged code/config snippets (and, for the dependency-review node, the extracted dependency list — names/versions only, never source code) that node's prompt needs. No step in the pipeline uploads the JAR itself, the full decompiled tree, or any untriaged class to any external service.

## Deployment Model

A long-running local process: `uv run python -m src` starts the FastAPI server (port 8001) which serves the built Next.js static export at `/app` and owns the SQLite database file and the local `data/` working directories. Scans run as background threads within that same process — there is no separate worker process or queue in Phase 1–3. Intended to run on the developer's own machine (or a machine they control) for the lifetime of a scan session; not designed for multi-tenant hosting.
