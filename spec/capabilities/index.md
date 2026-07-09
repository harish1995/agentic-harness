# Capabilities Index

---

## What Is a Capability?

A capability is a single, discrete action or behavior the agent performs.

## Capabilities in This Project

### Phase 1 (built now)

| Capability | File |
|-----------|------|
| JAR Upload & Validation | [jar-upload-validation.md](jar-upload-validation.md) |
| Local Decompilation & Static Analysis | [decompile-and-static-analysis.md](decompile-and-static-analysis.md) |
| Exhaustive LLM Security Review & Verification | [llm-security-review-and-verification.md](llm-security-review-and-verification.md) |
| Scan Progress & Report Delivery | [scan-progress-and-report-delivery.md](scan-progress-and-report-delivery.md) |

### Phase 2 (deferred — named here for traceability, detailed capability files created when Phase 2 is built per `spec/roadmap.md`)

| Capability | Status |
|-----------|--------|
| Scan-history browsing | Deferred to Phase 2 |
| JSON/SARIF export | Deferred to Phase 2 |
| Accepted-risk / false-positive tracking | Deferred to Phase 2 |
| Multi-JAR / version comparison | Deferred to Phase 2 |
| Follow-up Q&A chat on a completed report (with turn memory) | Deferred to Phase 2 |

## How to Add a New Capability

Run `/zero-shot-build [description]` on the existing spec. The spec-writer sub-agent will:
1. Create a new file in this directory (`<name>.md`, no number prefix)
2. Update this index
3. Flag any dependencies on existing capabilities
4. Self-review that it fits the architecture and data model before returning

## Capability File Template

Each capability file should answer:
- **What it does** (one sentence)
- **Inputs** (what data it receives)
- **Outputs** (what it produces)
- **External calls** (APIs, LLMs, databases it touches)
- **Error cases** (what can go wrong and how it's handled)
- **Success criteria** (how we test it)
