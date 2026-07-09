# JAR Security Scanner

> **All commands below run from the repo root** (`/Users/harishkushwaha/My Drive/agent/agentic-harness` on this machine, or wherever you've cloned this repo) unless a command block explicitly says otherwise (e.g. the frontend build steps, which run from `frontend/`). There is no backend subdirectory to `cd` into — `src/` lives at the repo root.

A local-first, AI-powered security scanner for Java/Spring Boot JAR files. Drag a `.jar` onto the web UI and the agent decompiles it entirely on your machine (CFR), runs deterministic static analysis (dependency extraction, secret scanning, config-file surfacing), then drives an exhaustive, evidence-based Claude security review — covering OWASP Top 10 2021, STRIDE, CWE, CVSS v3.1, Spring Security, authN/authZ, injection classes, deserialization, file upload, crypto, secrets, config, logging, and dependency CVEs — with a verification pass, and assembles one structured, dashboarded Markdown report. You watch phase-by-phase progress live, then read the report, download it as `.md`, and see the tokens/cost spent.

This is a solo, ad hoc tool: a single AppSec-minded developer scanning **their own** Spring Boot / Java JARs for a defensive code-review pass — not a multi-tenant service, and not a tool for scanning third-party or adversarial targets.

## Data Residency (read this before uploading anything)

**The JAR file and every decompiled artifact stay entirely on your local machine, for the full lifetime of the process.** They are never uploaded or transmitted anywhere. The *only* network traffic this system generates is a small number of Anthropic API calls, and each one carries only a bounded, triage-selected subset of code/config snippets (never the full JAR, never the full decompiled tree, never an untriaged class). This is a hard architectural guarantee, not a preference — see `spec/architecture.md` → Data Residency for the full detail.

There is also no live CVE database lookup: dependency-vulnerability findings are Claude's evidence-based reasoning over the extracted dependency list (names/versions only), always labelled as such in the report — this is a permanent, documented design choice, not a gap.

---

## Prerequisites

Beyond a typical Python/Node project, this repo needs a **real local JDK/JRE** to run the vendored decompiler:

- **Java 17+** on `PATH` as `java` (override with `AGENT_JAVA_BIN` in `.env` if it's installed elsewhere). Required to invoke the vendored `tools/cfr-0.152.jar` decompiler (already included in the repo — no separate download needed) at scan time.
- **A full JDK (not JRE-only)** if you plan to run the test suite — `javac` is used to compile the multi-class fixture JAR the integration tests decompile. A JRE-only host is fine if you only ever run the app itself, never the tests.
- **`uv`** (Python package/venv manager) — https://docs.astral.sh/uv/
- **Node.js 20+** and a package manager for `frontend/`. Plain `pnpm` may not be on `PATH` on every host — this README uses the `npx --yes pnpm@10 <command>` form throughout, which works everywhere `npx` does; if you already have `pnpm` on `PATH`, feel free to drop the `npx --yes pnpm@10` prefix and just run `pnpm <command>`.

Verify Java is set up correctly:

```bash
java -version
```

You should see `17` or higher. If `java` isn't found, either add it to `PATH` or set `AGENT_JAVA_BIN=/full/path/to/java` in `.env`.

---

## Setup

All commands in this section run **from the repo root** unless a step says otherwise.

**1. Configure environment variables**

```bash
cp .env.example .env
```

Then open `.env` and fill in `AGENT_ANTHROPIC_API_KEY` with a real Anthropic API key (it may already be filled in for local dev — check before requesting a new one). See [Environment Variables](#environment-variables) below for what every setting does.

**2. Install Python dependencies (including dev/test tooling)**

```bash
uv sync --extra dev
```

A bare `uv sync` will **not** install `pytest`/`pytest-asyncio`/`httpx` — they're declared as an optional `dev` extra in `pyproject.toml`. Always use `--extra dev` for local development so the test suite is available.

**3. Run database migrations, then verify they applied**

```bash
uv run alembic upgrade head
uv run alembic current
```

The second command must print a real revision id followed by `(head)` (e.g. `0002 (head)`) — not a blank line. If it's blank, the migration didn't apply; re-run `uv run alembic upgrade head` and check for errors.

**4. Build the frontend static export**

Working directory: `frontend/`.

```bash
cd frontend
npx --yes pnpm@10 install
npx --yes pnpm@10 build
```

(If you have `pnpm` on `PATH`, `pnpm install && pnpm build` works identically.) This step must run **before** starting the server — FastAPI serves the built static export at `/app`, it does not build it on the fly.

**5. Start the server**

Working directory: repo root.

```bash
uv run python -m src
```

This starts the FastAPI server at `http://localhost:8001`, serving the API and the built frontend together (single-origin, per `harness/patterns/tech-stack.md`).

**6. Open the app**

Visit **http://localhost:8001/app/** in a browser.

---

## How to Use It

1. Drag and drop a `.jar` file (a real Spring Boot fat JAR gives the richest report, but any `.jar` works) onto the upload zone, or click to browse for one, then click **Start Scan**.
2. Watch the live phase stepper advance through Decompiling → Dependency Scan → Secret Scan → Config Extraction → Triage → LLM Security Review (with a per-category sub-label) → Verification → Report Generation. This is real, polled progress from the running pipeline — not a fake animation.
3. Once complete, read the full report: risk score, severity/OWASP/STRIDE/dependency dashboards, syntax-highlighted evidence per finding, secure-coding recommendations, a prioritized remediation plan, and an appendix.
4. Click **Download .md** to save the report as a Markdown file. A cost footer shows the real input/output token counts and estimated USD spend for the scan.
5. Try uploading an invalid file (e.g. a `.txt` renamed to `.jar`) to see the clear error handling — never a blank or broken report.

**Labelled stubs (Phase 1):** the top-nav **Scan History** link, and on the report screen **Export JSON/SARIF**, **Ask a follow-up**, **Mark as accepted risk**, and **Compare with another scan** are all visibly greyed-out, disabled buttons with a "Coming soon" tooltip. These are deliberate placeholders for Phase 2 — not bugs.

---

## Running Tests

All commands run **from the repo root** unless stated otherwise.

**Unit tests** — fast, deterministic, no external network calls beyond one gated real-LLM unit test (which runs automatically since `AGENT_ANTHROPIC_API_KEY` is set):

```bash
uv run pytest tests/unit -v
```

**Integration tests** — **slow** (roughly 8-10 minutes). Makes 7 real Anthropic API calls plus a real CFR decompile of a fixture JAR built at test time. Requires a working `AGENT_ANTHROPIC_API_KEY` with available credits:

```bash
uv run pytest tests/integration/test_scan_pipeline.py -v -s
```

**End-to-end tests** — **slow**, drives a real Chromium browser through a full multi-minute scan against the live server. One-time setup:

```bash
cd frontend
npx playwright install --with-deps chromium
```

Then, with the server already running (per Setup step 5 above, from the repo root, in a separate terminal), run from `frontend/`:

```bash
cd frontend
npx playwright test --reporter=line
```

---

## Tech Stack

- **Backend:** Python 3.12+, FastAPI, LangGraph (multi-node pipeline with a verification/reflection node), SQLite + SQLAlchemy 2.0 + Alembic migrations.
- **Frontend:** Next.js 15 + React 19 + Tailwind v4, static-exported and served by FastAPI at `/app`; `react-markdown`/`remark-gfm` for prose, `react-syntax-highlighter` for code evidence.
- **Decompiler:** CFR 0.152 (vendored, MIT-licensed, `tools/cfr-0.152.jar`), invoked locally as a JVM subprocess — no network egress, no build step.
- **LLM:** Anthropic Claude (`claude-sonnet-4-6`) — the single model used for every category review and the verification pass.

See `spec/architecture.md` for the full component map, data flow, and stack rationale.

---

## Project Status / Roadmap

This is **Phase 1** of a 3-phase build (full detail in `spec/roadmap.md`):

- **Phase 1 (this build):** the complete upload → decompile → static analysis → exhaustive LLM review → verification → rendered report journey, real end-to-end.
- **Phase 2:** turns every Phase-1 stub into a real feature — scan-history browsing, JSON/SARIF export, accepted-risk/false-positive tracking, multi-scan comparison, and follow-up chat Q&A with turn memory on a completed report.
- **Phase 3:** resilience/hardening — retry-with-backoff on Anthropic API failures, CFR subprocess timeouts with partial-failure isolation, and observability thresholds. No new user-facing capability.

---

## Environment Variables

All variables are `AGENT_`-prefixed except the LangSmith tracing variables (read directly by the LangChain/LangGraph SDKs). See `.env.example` for the authoritative, up-to-date list.

| Variable | Description |
|---|---|
| `AGENT_DATABASE_URL` | SQLAlchemy connection string for the scan database (default: local SQLite file at `./data/agent.db`). |
| `AGENT_LLM_PROVIDER` | Optional override for the LLM provider (`anthropic` \| `gemini`); auto-detected from whichever API key below is set if left blank. |
| `AGENT_LLM_MODEL` | Optional override for the model name; defaults to `claude-sonnet-4-6` for Anthropic. |
| `AGENT_ANTHROPIC_API_KEY` | Your Anthropic API key. Set exactly one of this or `AGENT_GEMINI_API_KEY`. |
| `AGENT_GEMINI_API_KEY` | Your Gemini API key (alternative provider). Set exactly one of this or `AGENT_ANTHROPIC_API_KEY`. |
| `PORT` | Port the FastAPI server listens on (default `8001`). |
| `AGENT_CFR_JAR_PATH` | Path to the vendored CFR decompiler jar (`tools/cfr-0.152.jar`). |
| `AGENT_JAVA_BIN` | The `java` executable to invoke for decompiling (default `java`, assumes it's on `PATH`). |
| `AGENT_CFR_TIMEOUT_S` | Per-invocation timeout (seconds) for the CFR subprocess (default `180`). |
| `AGENT_SCAN_UPLOAD_DIR` | Local directory where uploaded JARs are saved (default `data/uploads`, gitignored). |
| `AGENT_SCAN_WORK_DIR` | Local directory where decompiled output is written (default `data/decompiled`, gitignored). |
| `AGENT_TRIAGE_MAX_CLASSES` | Max number of classes triaged into LLM-reviewable chunks per scan (default `60`) — bounds cost. |
| `AGENT_TRIAGE_MAX_CHARS` | Max total characters of triaged code sent across all LLM calls per scan (default `150000`). |
| `AGENT_TRIAGE_PER_CATEGORY_MAX_CHARS` | Max characters of triaged code sent to any single category-review call (default `30000`). |
| `AGENT_MAX_UPLOAD_MB` | Max accepted JAR upload size in MB (default `200`). |
| `AGENT_PRICING_TABLE_VERSION` | Version tag for the hardcoded Anthropic pricing table used to estimate cost (`src/llm/pricing.py`). |
| `AGENT_LLM_MAX_TOKENS` | Max output tokens per LLM call (default `32000`) — bounds output size so evidence-rich, multi-finding responses are never truncated mid-JSON. |
| `LANGCHAIN_TRACING_V2` | Optional: set `true` to enable LangSmith tracing of the pipeline. |
| `LANGCHAIN_API_KEY` | Optional: your LangSmith API key, required if tracing is enabled. |
| `LANGCHAIN_PROJECT` | Optional: LangSmith project name to group traces under. |
