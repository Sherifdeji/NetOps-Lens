# NetOps Lens V1 — Implementation Plan

> Status: Revised draft for review — no implementation started. Stack: Python 3.14, Batfish (Docker) + Pybatfish, Muse Spark 1.3 via Meta Model API, Streamlit, Pydantic, Pytest. V1 is read-only; Python produces all factual findings and decides the final assessment; Muse Spark only investigates via tools and explains validated findings.

## Goal

Ship NetOps Lens V1: a network engineer selects a baseline and a proposed snapshot, declares required connectivity in `intent.yaml` (`must_reach` / `must_not_reach`), runs an assessment, watches Muse Spark investigate with real Batfish tools, and receives an evidence-backed report whose verdict — `REGRESSION_DETECTED`, `NO_REGRESSION_DETECTED`, or `INCONCLUSIVE` — is computed by deterministic Python, with every claim traceable to a stored tool result.

## Current State & Reusable Code

### Verified and to preserve (do not move, rename, or rewrite)

| Artifact | What it proves | V1 reuse |
|---|---|---|
| [test_batfish.py](/Users/sherifibrahim/Developer/Meta-Hackathon/test_batfish.py) | `Session(host="localhost")`, network `netops-lens-lab`, `init_snapshot("lab/baseline")`, `fileParseStatus`, `nodeProperties`, traceroute `192.0.2.10 -> 198.51.100.1` via `@enter(r1[GigabitEthernet0/1])` | Becomes the reference for `batfish_client.py`; kept as a manual smoke script |
| [test_diff.py](/Users/sherifibrahim/Developer/Meta-Hackathon/test_diff.py) | Proposed snapshot init, traceroute + `differentialReachability` with ICMP + `PathConstraints`, `maxTraces=5` | Becomes the reference for `compare_snapshots` / `check_intent` |
| [r1 baseline](/Users/sherifibrahim/Developer/Meta-Hackathon/lab/baseline/configs/r1.cfg) / [r2 baseline](/Users/sherifibrahim/Developer/Meta-Hackathon/lab/baseline/configs/r2.cfg) | Two-router Cisco IOS topology that parses; static routes both ways (`198.51.100.0/24` via `10.0.12.2`, `192.0.2.0/24` via `10.0.12.1`) | Baseline for all scenarios |
| [r1 proposed](/Users/sherifibrahim/Developer/Meta-Hackathon/lab/proposed/configs/r1.cfg) | Static route removed -> `NO_ROUTE` regression | The `removed_route` scenario; baseline `r2.cfg` is identical in both snapshots |

Topology facts: App LAN `192.0.2.0/24` on `r1 Gig0/1`, DB LAN `198.51.100.0/24` on `r2 Gig0/1`, transit `10.0.12.0/30`. Documentation IPs are intentional and Batfish-safe.

### Limitations to fix in V1 (not by editing the preserved files)

- Both scripts are top-level print scripts, not pytest tests: no assertions, no fixtures, hard-coded host/network, DataFrames printed raw. V1 wraps this logic in functions and keeps DataFrames inside the analysis layer.
- No package, `pyproject.toml`, `requirements`, `.gitignore`, `docs/`, or `README` exists yet. Runtime has Python 3.14.2 + `pybatfish 2026.9.17.3748`, `pandas`, `PyYAML`, `requests`; `pytest`, `streamlit`, `pydantic` are not yet installed.
- Only the removed-route scenario exists. Healthy-proposed and ACL-blocked scenarios still need fixtures.
- Batfish Docker reachability cannot be assumed in every shell; every test phase must check `Session` health before trusting results.
- No `.env` handling, no intent model, no evidence store, no agent, no UI yet.

## Success Criteria

V1 is done when all of the following hold:

1. Engineer can pick any baseline/proposed snapshot pair and an `intent.yaml` in Streamlit and run one assessment end to end.
2. All five backend tools return structured, JSON-serializable results; no raw DataFrame crosses the tool boundary.
3. Every factual finding is produced by Python from stored tool results, carries a structured claim type + flow ID + evidence IDs, and passes predicate validation (not mere ID existence); Muse narrative may only explain validated findings and is rejected/flagged if it introduces new factual claims.
4. Python — never the LLM — emits exactly one of `REGRESSION_DETECTED` / `NO_REGRESSION_DETECTED` / `INCONCLUSIVE` by the per-flow comparison and precedence rules in §Assessment Engine, and the verdict is displayed in the UI independently of any model narrative.
5. Essential scenarios pass in pytest: healthy (`NO_REGRESSION_DETECTED`), removed-route (`REGRESSION_DETECTED`), ACL-blocked (`REGRESSION_DETECTED`). The incomplete/degraded-parse scenario (`INCONCLUSIVE`) is a stretch goal “where feasible” and must not block the essential path.
6. Preserved files (`test_batfish.py`, `test_diff.py`, `lab/baseline/**`, `lab/proposed/**`) are byte-identical to today.
7. No live-device writes, patching, remediation, voice, multimodal, or local model hosting exist in the codebase.

## Approach

Three layers with a hard evidence boundary:

```
Streamlit UI (app.py)
   |  AssessmentRequest (snapshots + intent + question)
   v
Agent Orchestrator (agent.py)  -- tool schemas --> Muse Spark (Meta Model API)
   |  validated tool calls (bounded loop)              ^ interpreted results
   v                                                    |
Tools (tools.py) -> Evidence Store (evidence.py) ------+
   |  typed tool results, each minted an evidence ID
   v
Batfish Client (batfish_client.py) -> Pybatfish -> Batfish Docker
   |
   v
Assessment Engine (assessment.py)  # deterministic, LLM-free
   |  AssessmentResult + validated report
   v
Report (report.py) -> UI
```

Design choices and why:

- **Single package `src/netops_lens/`** (KISS, typed, no framework). Why not a web API + frontend split: Streamlit already serves the UI; a separate service adds deploy and auth scope V1 does not need.
- **Pydantic at every boundary** (tool args, tool results, intent, evidence, report). Rejected: raw dicts (the current scripts' failure mode — untyped and untestable) and a database (V1 evidence is per-run, in-memory + JSON export is enough).
- **Deterministic assessment in Python.** The LLM selects tools and narrates; it never votes on the verdict. This is the core safety contract.
- **CLI-first, UI-second.** Every phase is testable headlessly via pytest before Streamlit exists, so the UI never blocks the analysis core.

## Proposed Directory Structure

```
NetOps Lens (repo root)
├── AGENTS.md                     # unchanged
├── README.md                     # NEW: run instructions, Docker prerequisite
├── pyproject.toml                # NEW: deps, pytest + mypy/ruff config
├── .gitignore                    # NEW: .env, .venv, __pycache__, snapshots cache
├── .env.example                  # NEW: META_API_KEY=, BATFISH_HOST=localhost (no secrets)
├── app.py                        # NEW: Streamlit entry — `streamlit run app.py`
├── test_batfish.py               # PRESERVED — manual smoke script
├── test_diff.py                  # PRESERVED — manual smoke script
├── src/netops_lens/
│   ├── __init__.py
│   ├── config.py                 # env loading, Batfish host/network, limits
│   ├── models.py                 # Pydantic: FlowSpec, Intent, ToolResult, EvidenceRecord, AssessmentResult, Report
│   ├── batfish_client.py         # Session lifecycle, snapshot init, health gate
│   ├── tools.py                  # get_snapshot_health, compare_snapshots, check_intent, trace_flow, get_routes
│   ├── intent.py                 # intent.yaml load + validation -> Intent
│   ├── evidence.py               # EvidenceStore: mint IDs, store, validate references
│   ├── assessment.py             # deterministic verdict rules (no LLM import)
│   ├── agent.py                  # Muse Spark tool-calling loop (bounded)
│   ├── prompts.py                # system prompt + tool-selection guidance
│   └── report.py                 # validated narrative -> Report assembly
├── lab/
│   ├── baseline/configs/         # PRESERVED — shared baseline for healthy / removed_route / incomplete
│   ├── proposed/configs/         # PRESERVED — removed_route proposed (route deleted)
│   └── scenarios/                # NEW — only deltas that preserved snapshots cannot express
│       ├── manifest.yaml         # scenario -> baseline_path, proposed_path, intent_path, expected_verdict
│       ├── healthy/proposed/configs/*.cfg                 # copy of preserved baseline (no-change proposed)
│       ├── acl_blocks_db/baseline/configs/*.cfg           # preserved configs + correct ACL (permits DB service, blocks unauthorized port)
│       ├── acl_blocks_db/proposed/configs/*.cfg           # same ACL baseline + ACL edit that blocks the authorized DB service
│       └── incomplete/proposed/configs/*.cfg              # STRETCH: one malformed/partial config + intact peer
├── examples/
│   ├── intent.yaml               # core intent (healthy / removed_route): App->DB must reach (ICMP)
│   ├── intent-acl.yaml           # ACL intent: authorized DB port must reach, unauthorized port must not reach
│   └── questions.md              # sample engineer questions per scenario
├── scripts/
│   └── spike_meta_api.py         # Phase 0/1 Meta API + tool-calling smoke check (no secrets logged)
├── tests/
│   ├── conftest.py               # Batfish session fixture, skip-if-unhealthy guard
│   ├── test_models.py            # contract/serialization tests (no Batfish)
│   ├── test_intent.py            # intent.yaml parse/validation tests
│   ├── test_evidence.py          # ID minting, dangling-ref rejection, missing-vs-confirmed
│   ├── test_assessment.py        # verdict truth-table tests with synthetic tool results
│   ├── test_tools_integration.py # real Batfish: 5 tools x scenarios (ICMP pinned)
│   ├── test_agent.py             # tool-calling loop with recorded/fake Muse responses
│   └── test_e2e.py               # full pipeline per scenario -> expected verdict
└── docs/
    ├── implementation-plan.md    # this plan
    └── demo-script.md            # timed 3-minute hackathon video script + rehearsal checklist
```

Scenario policy: new scenarios live under `lab/scenarios/`; preserved snapshots are never edited to create them. A Batfish snapshot directory must physically contain its configs, so the peer file that does not change is copied verbatim — that copy is snapshot completeness, not scenario duplication. The *semantic* delta per scenario stays exactly one change (see §Fixture Mapping for the authoritative path table; `lab/scenarios/manifest.yaml` is the machine-readable source of truth).

### intent.yaml format

Core intent (`examples/intent.yaml`, used by healthy and removed_route — ICMP reachability is what the preserved, ACL-free topology can express):

```yaml
version: 1
description: App tier must reach the DB host
must_reach:
  - id: app-to-db-icmp
    src: "192.0.2.10"
    dst: "198.51.100.1"
    protocol: ICMP
    start_location: "@enter(r1[GigabitEthernet0/1])"
must_not_reach: []   # core topology has no blocking control; see ACL intent for a must_not_reach test
```

ACL intent (`examples/intent-acl.yaml`, used only by `acl_blocks_db`). The prohibited flow is application traffic to an *unauthorized database service port* on the same hosts. This replaces the previous `db-to-app` reverse-ICMP example, which the ACL-free baseline could not satisfy (nothing blocked the reverse path, so baseline already violated it) and which tested direction reversal rather than a security policy:

```yaml
version: 1
description: App may use the authorized DB service; App must not reach the unauthorized DB admin port
must_reach:
  - id: app-to-db-authorized
    src: "192.0.2.10"
    dst: "198.51.100.1"
    protocol: TCP
    dst_port: 1433            # authorized DB service (SQL Server port as the service stand-in)
    start_location: "@enter(r1[GigabitEthernet0/1])"
must_not_reach:
  - id: app-to-db-unauthorized
    src: "192.0.2.10"
    dst: "198.51.100.1"
    protocol: TCP
    dst_port: 22              # unauthorized admin service (SSH) on the DB host
    start_location: "@enter(r1[GigabitEthernet0/1])"
```

ACL scenario contract (makes baseline satisfy intent by construction):

- **ACL baseline** (`acl_blocks_db/baseline`): preserved routing plus one extended ACL applied on the App-facing path that *permits* `tcp 192.0.2.0/24 -> 198.51.100.0/24 eq 1433` and *denies* `tcp … eq 22` (explicit deny before any broad permit). Required baseline outcomes: `app-to-db-authorized` REACHABLE, `app-to-db-unauthorized` UNREACHABLE (blocked). Both intent clauses satisfied.
- **ACL proposed** (`acl_blocks_db/proposed`): identical except the ACL is edited so the authorized service is denied (e.g., a `deny tcp … eq 1433` inserted ahead of the permit, or the permit removed). The unauthorized-port deny is untouched. Required proposed outcomes: `app-to-db-authorized` UNREACHABLE (regression on `must_reach`), `app-to-db-unauthorized` still UNREACHABLE (security clause still satisfied, so the security test remains valid and the regression attribution is unambiguous).
- An explicit untrusted subnet (e.g., guest `203.0.113.0/24` that `must_not_reach` the DB) is the alternative prohibited-flow design. It is a stretch goal only: it needs new interfaces/subnets on the two-router topology, while the port-based design tests the same policy class with zero topology change.

Rules for all intent files: `id` unique per file (this `id` is the `flow_id` used by findings, traces, and the truth tables); IPs validated as addresses; protocol in `{ICMP, TCP, UDP}`; `dst_port` required iff TCP/UDP and forbidden for ICMP; unknown keys rejected. One intent file maps 1:1 to one assessment run, and each scenario in the manifest names exactly one intent file.

## Data Contracts & Module Responsibilities

All models in `models.py`, all `extra="forbid"`, all JSON-serializable. Key contracts:

| Contract | Fields (essence) | Owner |
|---|---|---|
| `FlowSpec` | `flow_id (= intent id), src_ip, dst_ip, protocol, dst_port?, start_location` | `intent.py`, `tools.py` |
| `Intent` | `version, must_reach: list[FlowSpec], must_not_reach: list[FlowSpec]` | `intent.py` |
| `SnapshotRef` | `name, path` | `batfish_client.py` |
| `SnapshotHealth` | `snapshot, level: HEALTHY|DEGRADED|UNHEALTHY, per_file_parse, init_issues, nodes, reasons: list[str]` | `tools.py` (`get_snapshot_health`) |
| `ToolResult` | `tool, snapshot(s), flow_id?, status: ok|error|inconclusive, summary, details: dict, evidence_id` | `tools.py` |
| `EvidenceRecord` | `evidence_id (ev-0001…)`, `tool`, `snapshots`, `flow_id?`, `disposition?`, `details`, `created_order` | `evidence.py` |
| `ClaimType` (enum) | `REACHABILITY_CHANGED, INTENT_SATISFIED, INTENT_VIOLATED, ROUTE_PRESENT, ROUTE_ABSENT, TRACE_DISPOSITION, SNAPSHOT_HEALTH` | `models.py` |
| `FlowComparison` | `flow_id, kind: must_reach|must_not_reach, baseline_reach: REACHABLE|UNREACHABLE|UNKNOWN, proposed_reach: …, classification: REGRESSION|IMPROVEMENT|NO_CHANGE_OK|PRE_EXISTING_VIOLATION|UNKNOWN` | `assessment.py` |
| `Finding` | `finding_id (f-0001…)`, `claim_type: ClaimType`, `flow_id?`, `statement` (Python-templated factual text), `evidence_ids: list[str]`, `severity` | `assessment.py` / `tools.py` (Python-produced only) |
| `AssessmentResult` | `verdict, flow_comparisons: list[FlowComparison], findings: list[Finding], inconclusive_reasons: list[str], health: list[SnapshotHealth]` | `assessment.py` (sole writer of `verdict` and `findings`) |
| `Report` | `assessment: AssessmentResult`, `narrative: str|None` (Muse explanation of findings, separately labelled), `evidence_index, traces, tool_activity: list[ToolCallLog]` | `report.py` |

Module boundaries: `batfish_client.py` is the only module importing Pybatfish; `tools.py` is the only caller of the client; `assessment.py` imports no LLM or UI code; `app.py` imports no Pybatfish. DataFrames are converted to records inside `batfish_client.py`/`tools.py` and never escape.

## Backend Tools (all in `tools.py`, each returns `ToolResult`)

| Tool | Batfish query | Returns | Failure semantics |
|---|---|---|---|
| `get_snapshot_health` | `fileParseStatus` + `initIssues` + `nodeProperties` per snapshot | `SnapshotHealth` (see §Snapshot Health): per-file parse status, init issues with severity, node list, `level: HEALTHY|DEGRADED|UNHEALTHY` | Init/parse failure -> `level=UNHEALTHY`, `status=error`; partial/unsupported -> `DEGRADED`; never raises to agent |
| `compare_snapshots` | `differentialReachability` (ICMP-pinned headers unless flow says otherwise, `maxTraces=5`) | per-flow baseline vs proposed disposition pairs + `changed: bool` | No baseline snapshot -> `inconclusive`, not success |
| `check_intent` | `reachability`/`traceroute` per intent flow on proposed (and baseline for context) | per-flow `satisfied / violated / unknown` mapped from dispositions | Untestable flow (bad location, no route info) -> `unknown` -> feeds `INCONCLUSIVE` |
| `trace_flow` | `traceroute` with `HeaderConstraints` | ordered hops with per-hop disposition (`ACCEPTED`, `NO_ROUTE`, `DENIED_IN/OUT`, …), final disposition | Same `unknown` rule; trace always stored as evidence |
| `get_routes` | `routes` question per node | routes for node/prefix, next-hop, protocol | Missing node -> `error` with reason, not empty success |

Shared rules: headers always pin protocol explicitly (ICMP in comparable tests, per `FlowSpec` otherwise); every successful call mints exactly one `EvidenceRecord`; every error is a typed `ToolResult`, never an exception across the tool boundary; tool arguments are Pydantic-validated before any Batfish call.

## Snapshot Health (`get_snapshot_health` in `tools.py`, conversion in `batfish_client.py`)

Three Batfish questions are combined per snapshot; none alone is sufficient (`fileParseStatus` can look clean while `initIssues` reports constructs Batfish could not model):

| Source | What is read | Failure it catches |
|---|---|---|
| `fileParseStatus` | per-file parse status (`PASSED` / partially-parsed / `FAILED` token values as returned — exact tokens recorded empirically in Phase 1) | syntax errors, truncated configs |
| `initIssues` | initialization issues with severity/detail text (questions, files/nodes affected where present) | unparseable constructs, missing references, unsupported/ignored features modelled differently than configured |
| `nodeProperties` | recognized nodes | files that parsed to nothing, wrong vendor/format, empty snapshots |

Health levels and their effect (the only three values `SnapshotHealth.level` may take):

| Level | Condition | Effect on the run |
|---|---|---|
| `UNHEALTHY` (blocking) | snapshot init raises/fails; OR any file `FAILED`; OR `initIssues` contains an error-severity/parse-failure entry; OR zero nodes recognized | Assessment stops at the gate: verdict `INCONCLUSIVE` with health reasons. No reachability/route evidence from that snapshot is trusted or minted as factual support. |
| `DEGRADED` (partial) | no blocking condition, but: any file partially parsed; OR `initIssues` contains warning-severity entries, including unsupported-feature notices, that touch a node/feature a queried flow depends on; OR an expected node is absent | Run proceeds. Flows whose path/feature intersects the degraded node/feature are forced to `UNKNOWN` (see truth tables) with the init issue cited; unaffected flows are evaluated normally. Degraded reasons are listed in the report. |
| `HEALTHY` | all files fully parsed, no error/warning init issues relevant to the topology, expected nodes present | Flows evaluated normally. |

Rules: health is computed for baseline and proposed independently and both results are stored as `SNAPSHOT_HEALTH` evidence; “relevant” init-issue filtering is by node/file/feature mention where Batfish provides it, otherwise any warning downgrades to `DEGRADED` (conservative — never silently ignored); an `UNHEALTHY` baseline is as blocking as an unhealthy proposed snapshot, since every verdict is a baseline-vs-proposed comparison. Exact `initIssues` column names, severity spellings, and partial-parse tokens are unverified assumptions (see Risks) and must be pinned by a Phase 1 observation test before these string matches are coded.

## Evidence System (`evidence.py`)

Python is the only author of factual findings. Muse Spark investigates (chooses tools) and *explains* Python-validated findings; it never originates a factual conclusion. Evidence-ID existence is necessary but never sufficient.

- **Minting:** sequential IDs `ev-0001`, `ev-0002`, … scoped to one assessment run; ID assigned at tool-return time, never by the LLM.
- **Storage:** `EvidenceStore` (in-run dict + JSON export) holds the full `ToolResult` payload behind each ID, including `tool`, `snapshots`, `flow_id`, and `disposition` where applicable.
- **Python findings:** `assessment.py` (and health evaluation in `tools.py`) generate each `Finding` programmatically: `claim_type` from the `ClaimType` enum, `flow_id` copied from the intent/tool call, `statement` rendered from a Python template with the actual disposition values, `evidence_ids` set to the exact records the statement was derived from. There is no code path where model text becomes a `Finding`.
- **Predicate validation (`validate_finding`):** a finding is kept iff *all* hold — (a) every `evidence_id` exists in the store; (b) each cited record's `flow_id` equals the finding's `flow_id` (health findings excepted, which must cite the matching snapshot's `SNAPSHOT_HEALTH` record); (c) cited tools are allowed for the `claim_type` per this matrix: `INTENT_*`/`REACHABILITY_CHANGED` require `check_intent`/`compare_snapshots`/`trace_flow`, `TRACE_DISPOSITION` requires `trace_flow`, `ROUTE_*` requires `get_routes`, `SNAPSHOT_HEALTH` requires `get_snapshot_health`; (d) the cited dispositions actually satisfy the claim — e.g., `INTENT_VIOLATED` for `must_reach` requires a proposed `UNREACHABLE` disposition record, `ROUTE_ABSENT` requires an empty/negative route result — a mismatch rejects the finding even when IDs exist; (e) cited snapshots match the claim's baseline/proposed roles. Failures are logged in `tool_activity` with the failed predicate named; nothing is silently repaired.
- **Narrative validation:** Muse receives only validated `Finding`s + the Python verdict. Its explanation must reference `finding_id`s (`f-0001`…); `report.py` checks every referenced ID exists and rejects (then regenerates once without the offending text, else drops the narrative to `None`) any passage asserting a new disposition, route, or health fact not present in the cited finding. The narrative is stored in `Report.narrative`, visually and structurally separate from `Report.assessment`.
- **Missing vs confirmed:** absence of evidence yields `UNKNOWN` flow comparisons and `INCONCLUSIVE` reasons. Only a stored disposition confirms a finding. The report renders these distinctly: “confirmed”, “violated”, “not tested / inconclusive”.

## Assessment Engine (`assessment.py`) — Python decides

Inputs: `SnapshotHealth` for both snapshots + stored reachability evidence only. The engine runs in three stages: per-snapshot reachability -> per-flow comparison -> overall verdict. No stage may be skipped, and proposed-only satisfaction/violation (without the baseline value) never determines a verdict — that was the ambiguity in the previous draft, where “violated in proposed” and “already violated in baseline” could both fire for the same flow with no stated winner.

### Stage 1 — Per-snapshot reachability (per intent flow)

From `check_intent` / `trace_flow` / `compare_snapshots` evidence, each flow gets, *independently for baseline and proposed*: `REACHABLE` (final disposition `ACCEPTED`), `UNREACHABLE` (`NO_ROUTE`, `DENIED_IN`, `DENIED_OUT`, `INSUFFICIENT_INFO`-free deny/drop dispositions as observed in Phase 1), or `UNKNOWN` (no evidence collected, tool error, `DEGRADED` health intersecting the flow, or an unmapped disposition — unmapped dispositions are always `UNKNOWN`, never guessed).

### Stage 2 — Per-flow comparison (`FlowComparison.classification`)

`must_reach` — required connectivity. Regression is **reachable -> unreachable**:

| Baseline | Proposed | Classification |
|---|---|---|
| REACHABLE | REACHABLE | `NO_CHANGE_OK` |
| REACHABLE | UNREACHABLE | `REGRESSION` |
| REACHABLE | UNKNOWN | `UNKNOWN` |
| UNREACHABLE | REACHABLE | `IMPROVEMENT` |
| UNREACHABLE | UNREACHABLE | `PRE_EXISTING_VIOLATION` |
| UNREACHABLE | UNKNOWN | `UNKNOWN` |
| UNKNOWN | REACHABLE | `UNKNOWN` |
| UNKNOWN | UNREACHABLE | `UNKNOWN` |
| UNKNOWN | UNKNOWN | `UNKNOWN` |

`must_not_reach` — prohibited connectivity. Regression is **blocked -> reachable** (the mirror image; “blocked” is `UNREACHABLE`):

| Baseline | Proposed | Classification |
|---|---|---|
| UNREACHABLE (blocked) | UNREACHABLE (blocked) | `NO_CHANGE_OK` |
| UNREACHABLE (blocked) | REACHABLE | `REGRESSION` |
| UNREACHABLE (blocked) | UNKNOWN | `UNKNOWN` |
| REACHABLE | UNREACHABLE | `IMPROVEMENT` (newly blocked — noted, not a regression of this clause) |
| REACHABLE | REACHABLE | `PRE_EXISTING_VIOLATION` (prohibition never held) |
| REACHABLE | UNKNOWN | `UNKNOWN` |
| UNKNOWN | UNREACHABLE | `UNKNOWN` |
| UNKNOWN | REACHABLE | `UNKNOWN` |
| UNKNOWN | UNKNOWN | `UNKNOWN` |

Note the symmetry: the two tables are identical as `REACHABLE`/`UNREACHABLE` grids; only the *meaning* of the diagonal cells differs by clause kind, and the engine implements one grid lookup keyed by `kind` for the `REGRESSION`/`IMPROVEMENT` labels. `PRE_EXISTING_VIOLATION` means the proposed snapshot still fails the intent but the change did not cause it; `IMPROVEMENT` is always reported as a finding but never affects the verdict.

### Stage 3 — Overall verdict (precedence, highest first)

Contradiction resolution: the old rules made “any proposed violation” and “any baseline violation” competing overall rules. Under per-flow classification they cannot compete — every flow yields exactly one classification, and aggregation is by presence over classifications:

| Priority | Condition (over all flows, after health gate) | Verdict |
|---|---|---|
| 0 (gate) | Either snapshot `UNHEALTHY` | `INCONCLUSIVE` (flow analysis not trusted; health findings only) |
| 1 | >= 1 flow `REGRESSION` | `REGRESSION_DETECTED` — a *confirmed* regression dominates: co-existing `UNKNOWN`/`PRE_EXISTING_VIOLATION` flows are reported as residual findings/reasons but do **not** downgrade the verdict, because the regression is proven by stored baseline-vs-proposed evidence on its own flow |
| 2 | No `REGRESSION`, >= 1 flow `UNKNOWN` | `INCONCLUSIVE` (unproven territory could hide a regression) |
| 3 | No `REGRESSION`/`UNKNOWN`, >= 1 flow `PRE_EXISTING_VIOLATION` | `INCONCLUSIVE` with reason “pre-existing intent failure persists; no new regression on tested flows” — never `NO_REGRESSION_DETECTED`, since the intent still fails in the proposed snapshot and certifying it would claim a failing state is safe |
| 4 | All flows `NO_CHANGE_OK`/`IMPROVEMENT` | `NO_REGRESSION_DETECTED`, scoped strictly to tested flows; report must state untested traffic is not claimed safe |

Worked mixed cases: regressions + unknowns -> `REGRESSION_DETECTED` (priority 1 beats 2); pre-existing violation + regression on another flow -> `REGRESSION_DETECTED` (the regression is new damage; the pre-existing failure is listed as a separate finding, not a veto); pre-existing violation + unknown, no regression -> `INCONCLUSIVE` (reason lists both).

### Unit-test cases (`tests/test_assessment.py`, synthetic `FlowComparison` inputs — no Batfish, no LLM)

Per-flow grid: all 18 rows above (9 per clause kind) as parametrized cases, including every `UNKNOWN`-involving row mapping to `UNKNOWN`. Aggregation: (1) healthy + all `NO_CHANGE_OK` -> `NO_REGRESSION_DETECTED`; (2) single `must_reach` `REGRESSION` -> `REGRESSION_DETECTED`; (3) single `must_not_reach` blocked->reachable -> `REGRESSION_DETECTED`; (4) `REGRESSION` + `UNKNOWN` -> `REGRESSION_DETECTED` with the unknown flow present in `inconclusive_reasons`/findings; (5) `UNKNOWN` only -> `INCONCLUSIVE`; (6) `PRE_EXISTING_VIOLATION` only (both kinds) -> `INCONCLUSIVE`; (7) `PRE_EXISTING_VIOLATION` + `REGRESSION` -> `REGRESSION_DETECTED`; (8) `IMPROVEMENT` only (both kinds) -> `NO_REGRESSION_DETECTED` with improvement finding; (9) either snapshot `UNHEALTHY` overrides even a synthetic `REGRESSION` input -> `INCONCLUSIVE`; (10) `DEGRADED`-forced `UNKNOWN` flow + `NO_CHANGE_OK` flow -> `INCONCLUSIVE`. The same ten cases drive the verdict assertions in `test_e2e.py` with real Batfish evidence substituted.

The LLM receives `AssessmentResult` as read-only context for explanation and cannot override it; the verdict shown anywhere comes from `AssessmentResult.verdict`, and `report.py` rejects narrative text that restates a different verdict (see §Evidence System, narrative validation).

## Muse Spark Agent (`agent.py` + `prompts.py`)

Interaction sequence per run:

1. UI builds `AssessmentRequest` (snapshot pair, `Intent`, free-text engineer question).
2. Python pre-flight (not LLM): `get_snapshot_health` on both snapshots; unhealthy -> skip agent, emit `INCONCLUSIVE` report directly.
3. Agent loop (bounded, default max 8 tool calls, configurable in `config.py`): system prompt states the goal, the five tool JSON schemas, the evidence-ID rule, and “Python computes all findings and the verdict — investigate with tools, then explain Python's validated findings; do not state new facts or declare a verdict”. Muse Spark selects a tool; Python validates args with Pydantic, executes, stores evidence, returns the `ToolResult` JSON to the model. Repeat until the model stops or the bound is hit (bound hit -> `INCONCLUSIVE` reason recorded).
4. Python then runs deterministically, with no model in the loop: `assessment.py` builds `FlowComparison`s and `Finding`s from stored evidence, `validate_finding` checks each one, and the verdict is fixed. Only then does the model write its explanation, over the validated findings + verdict; `report.py` narrative-validates it (see §Evidence System) and assembles the final `Report`.
5. Full `tool_activity` log (tool, args, evidence ID, latency) is returned for the UI activity panel.

Guards: real Meta Model API tool calling only (no text-parsing of tool calls); API key from `.env` via `config.py`, never logged; malformed tool args get one corrective retry with the validation error, then count toward the bound; two narrative-validation failures drop the narrative (`Report.narrative = None`) without touching findings or verdict; no tool can write files, snapshots, or devices (read-only enforced by the tool set itself — there is no write tool).

## Streamlit UI (`app.py`)

Single page, four regions, all state in `st.session_state`:

1. **Setup (sidebar):** baseline snapshot select, proposed snapshot select (from discovered `lab/**` snapshot dirs, defaulting to preserved baseline/proposed), intent source (upload `intent.yaml`, pick from `examples/`, or edit YAML in a text area with inline validation errors), engineer question input.
2. **Run:** “Run assessment” button; disabled with a reason when Batfish health check fails or intent is invalid. Progress via `st.status` streaming `tool_activity` entries as the agent works.
3. **Verdict (Python, independent):** verdict banner rendered *directly and only* from `Report.assessment.verdict` (color-coded), with the per-flow comparison table (`flow_id`, kind, baseline, proposed, classification) from `Report.assessment.flow_comparisons`. This region renders even when `Report.narrative` is `None`, and no model text may appear inside it.
4. **Explanation & evidence:** a separately headed “Investigation explanation (Muse Spark)” panel shows `Report.narrative` (or “explanation unavailable — findings below stand on their own” when dropped); below it, expandable Python findings, each showing `claim_type`, `flow_id`, and its evidence IDs; clicking an ID shows the stored tool result JSON and, for traces, the hop table. Raw JSON export download for the full `Report`.

UI never calls Batfish or the LLM directly; it calls one function `run_assessment(request) -> Report` in `agent.py` (or the deterministic pre-flight path). UI copy must distinguish confirmed / violated / inconclusive and must not claim untested traffic is safe.

## Configuration & Dependencies

- `pyproject.toml` pins: `pybatfish`, `pandas`, `streamlit`, `pydantic>=2`, `pyyaml`, `python-dotenv`, `httpx` (or the official Meta API client if provided — decide in Phase 3 spike, see Risks), dev: `pytest`, `mypy`, `ruff`.
- `.env` (git-ignored, `.env.example` committed): `META_API_KEY`, `BATFISH_HOST=localhost`, optional `AGENT_MAX_TOOL_CALLS=8`, `BATFISH_NETWORK=netops-lens-lab`.
- Batfish prerequisite documented in `README.md`: Docker container running and reachable at `BATFISH_HOST` before any test or UI run; `conftest.py` pings it and skips integration tests with a clear message when down — skips are reported, never silent.

## Fixture Mapping (authoritative; mirrored in `lab/scenarios/manifest.yaml`)

Every scenario names an explicit baseline snapshot path, proposed snapshot path, intent file, and expected verdict. Preserved snapshots are referenced in place — never copied — wherever they already express the needed side of a comparison:

| Scenario | Baseline snapshot | Proposed snapshot | Intent | Expected verdict | New config files |
|---|---|---|---|---|---|
| `healthy` | `lab/baseline` (preserved) | `lab/scenarios/healthy/proposed` | `examples/intent.yaml` | `NO_REGRESSION_DETECTED` | Proposed = verbatim copy of preserved baseline (the “no change” case cannot reuse `lab/proposed`, which is the broken variant) |
| `removed_route` | `lab/baseline` (preserved) | `lab/proposed` (preserved) | `examples/intent.yaml` | `REGRESSION_DETECTED` (`app-to-db-icmp`: REACHABLE -> UNREACHABLE / `NO_ROUTE`) | None — fully preserved pair |
| `acl_blocks_db` | `lab/scenarios/acl_blocks_db/baseline` | `lab/scenarios/acl_blocks_db/proposed` | `examples/intent-acl.yaml` | `REGRESSION_DETECTED` (`app-to-db-authorized`: REACHABLE -> UNREACHABLE; `app-to-db-unauthorized`: blocked -> blocked) | Baseline adds the correct ACL to preserved configs; proposed changes only the ACL. Peer `r2.cfg` copied verbatim inside each snapshot (snapshot completeness) |
| `incomplete` (stretch) | `lab/baseline` (preserved) | `lab/scenarios/incomplete/proposed` | `examples/intent.yaml` | `INCONCLUSIVE` (health gate) | One malformed/partial file; peer copied verbatim |

Rules: tests and the UI resolve scenarios *only* through the manifest (no hard-coded path pairs in test code); adding a scenario means adding manifest rows + fixtures, not editing preserved files; the UI snapshot pickers default to the manifest pairs but still allow any discovered snapshot directory for ad-hoc pairs.

## Delivery Priorities (essential vs stretch)

**Essential V1 (ship-blocking, in dependency order):** package + contracts; Meta API smoke check; Batfish client + snapshot health (3 questions); core tools `get_snapshot_health`, `compare_snapshots`, `check_intent`, `trace_flow`; evidence store + predicate validation; per-flow assessment + verdict precedence; minimal Muse agent loop over validated findings; minimal Streamlit path (pick scenario -> run -> Python verdict + findings + traces); scenarios `healthy`, `removed_route`, `acl_blocks_db`; 3-minute demo script. The smallest *complete* application (M2, below) is the priority: it beats polish on every stretch item.

**Stretch (only after the essential path is green; none may delay it):** `incomplete` scenario fixture; `get_routes` depth beyond what findings need (the tool ships essential, its richer output is stretch); untrusted-subnet ACL variant; Streamlit extras (JSON export, in-app YAML editor niceties); strict `mypy`/`ruff` zero-warning gates (essential bar is only: code type-checks with no errors on new modules — extensive lint configuration is stretch tooling); additional protocols/ports and engineer-question breadth. Lint/type tooling is configured minimally in Phase 0 and tightened in Phase 5 only if time remains.

## Steps (phases, dependencies, acceptance)

### Phase 0 — Foundation + Meta API smoke test (no network-behavior change)

Create `pyproject.toml`, `.gitignore`, `.env.example`, `README.md` (prerequisites + how to run preserved smoke scripts), `src/netops_lens/` skeleton with `config.py` + `models.py` (contracts above), empty `tests/` with `conftest.py` Batfish-health fixture. Install deps into project `.venv`. **In the same phase**, add `scripts/spike_meta_api.py`: the earliest possible verification of the Muse Spark integration, deliberately before any backend build-out — (a) one authenticated chat completion against the Meta Model API using the `.env` key, asserting the configured Muse Spark 1.3 model responds; (b) one tool-calling round-trip with a single dummy `echo` tool (model must emit a structured tool call, script executes it locally, returns the result, model acknowledges), asserting the exact tool-schema dialect, tool-call message shape, and result-return shape the adapter in `agent.py` will use. Output is pass/fail + the observed shapes (key never printed; failures exit non-zero with the API error class only).
**Depends on:** nothing. **Acceptance:** install succeeds on Python 3.14; `pytest tests/test_models.py` passes (serialization round-trips); `python scripts/spike_meta_api.py` passes (or, with no key/network, fails loudly and is recorded as the Phase 3 blocker — the failure must be known *now*, not discovered in Phase 3); preserved files untouched (`git status` shows only new files).

### Phase 1 — Fixtures & Batfish client

Create fixtures *exactly* per §Fixture Mapping (`lab/scenarios/manifest.yaml`, `healthy/proposed`, `acl_blocks_db/{baseline,proposed}`; `incomplete/` deferred to stretch), `examples/intent.yaml` + `examples/intent-acl.yaml`, and `batfish_client.py` (session, `init_snapshot` with overwrite, DataFrame->records conversion, health gate combining `fileParseStatus` + `initIssues` + `nodeProperties`). First test in this phase is observational: capture real `initIssues` columns/severities, partial-parse tokens, and TCP/UDP traceroute dispositions for the ACL ports, and pin them as fixtures/constants — health string-matching is coded only against observed values.
**Depends on:** Phase 0. **Acceptance:** pytest integration proves preserved baseline `HEALTHY`; healthy proposed traceroute `ACCEPTED`; preserved proposed `NO_ROUTE`; ACL baseline TCP/1433 `ACCEPTED` + TCP/22 `DENIED_*` (baseline satisfies both ACL intent clauses); ACL proposed TCP/1433 `DENIED_*` + TCP/22 still `DENIED_*`. ICMP pinned in comparable tests; protocols/ports pinned per `FlowSpec` otherwise.

### Phase 2 — Tools, evidence, deterministic assessment (no LLM)

Implement `tools.py` (5 tools), `intent.py`, `evidence.py`, `assessment.py`, `report.py` (validated-findings assembly; `narrative=None` until Phase 3). Wire a headless `run_assessment_deterministic()` that runs health -> compare -> check_intent -> traces-for-changed-flows, builds Python findings, and returns a validated `Report`.
**Depends on:** Phase 1. **Acceptance:** `test_tools_integration.py`, `test_evidence.py`, `test_assessment.py`, `test_e2e.py` (deterministic path) pass against live Batfish: removed-route -> `REGRESSION_DETECTED`, healthy -> `NO_REGRESSION_DETECTED`, ACL -> `REGRESSION_DETECTED` (stretch: incomplete -> `INCONCLUSIVE`). All 18 per-flow grid rows + 10 aggregation cases in §Assessment Engine pass synthetically; findings with existing-but-wrong-flow/tool/disposition evidence are rejected in unit tests; no code path lets narrative text alter findings or verdict.

### Phase 3 — Muse Spark agent

Build `prompts.py` + `agent.py` on the tool-calling shapes already proven by the Phase 0 smoke test (no API discovery remains here), with arg validation, evidence-ID enforcement, bound, and activity log. Add `test_agent.py` with recorded/fake model responses (valid call, bad args, fabricated evidence/finding ID, narrative inventing a new disposition, loop-until-bound).
**Depends on:** Phase 2 (tools + evidence must exist first) and a passing Phase 0 Meta smoke test. **Acceptance:** live run on removed-route scenario: agent calls at least `compare_snapshots` + `trace_flow`, final report verdict equals the deterministic verdict for the same input, Python findings unchanged by anything the model emits, narrative dropped (not findings altered) when it invents facts, loop terminates at the bound in the fake-runaway test.

### Phase 4 — Streamlit UI

Implement `app.py` per UI spec, including streaming activity, intent editor validation, evidence explorer, JSON export. Add a smoke test (AppTest or subprocess + health endpoint check) for the four scenarios' verdict banners.
**Depends on:** Phase 3 (UI renders agent activity; a Phase-2-only stub page may be built in parallel, see Delegation). **Acceptance:** manual + automated check: select preserved baseline/proposed, run, see `REGRESSION_DETECTED` with `NO_ROUTE` trace and clickable evidence; healthy pair shows `NO_REGRESSION_DETECTED`; Batfish-down state shows a disabled Run with reason, not a crash.

### Phase 5 — Hardening & evaluation

Essential first: scenario matrix run (essential scenarios x both paths), error-path tests (missing snapshot dir, malformed YAML, empty intent, model timeout), README finalization, secret scan, preserved-file byte check. Stretch thereafter, only if time remains: `incomplete` fixture + its tests, strict lint/type tightening, UI extras. Write `docs/demo-script.md` and rehearse against §Demo (3-Minute Hackathon Video).
**Depends on:** Phases 2–4. **Acceptance:** essential `pytest` green with Batfish up; documented skip behavior with Batfish down; no secrets in git; timed demo rehearsal <= 3:00 from README + demo script alone.

## Validation Plan

| Gate | Command / check | Expected evidence |
|---|---|---|
| Contracts | `pytest tests/test_models.py tests/test_intent.py tests/test_evidence.py tests/test_assessment.py` | All pass without Batfish; 18 per-flow grid rows + 10 aggregation cases covered; wrong-flow/tool/disposition evidence rejected |
| Integration | `pytest tests/test_tools_integration.py -v` (Batfish up) | 5 tools exercised; dispositions asserted (not printed): `ACCEPTED` / `NO_ROUTE` / `DENIED_*`; health levels asserted incl. `initIssues`-driven `DEGRADED`/`UNHEALTHY` |
| E2E deterministic | `pytest tests/test_e2e.py -v` | Essential scenarios -> expected verdicts in §Fixture Mapping (stretch: `incomplete` -> `INCONCLUSIVE`) |
| Meta smoke | `python scripts/spike_meta_api.py` (Phase 0, re-run before Phase 3) | Auth + dummy-tool round-trip pass; observed schemas recorded for the adapter |
| Agent | `pytest tests/test_agent.py -v` + one live removed-route run | Fake-response tests pass (incl. invented-fact narrative dropped); live report verdict matches deterministic verdict; activity log non-empty |
| UI | `streamlit run app.py` + scenario click-through; UI smoke test | Python verdict banner correct per scenario and rendered with `narrative=None`; evidence IDs resolve; Batfish-down state graceful |
| Preservation | `git diff --stat` on preserved paths; full `pytest` | Zero diff on `test_batfish.py`, `test_diff.py`, `lab/baseline/**`, `lab/proposed/**` |
| Types (essential bar) | `mypy src/` | No errors on new modules; strict lint tightening is Phase 5 stretch, not a ship gate |

Highest-risk validation: the Phase 2 E2E verdict matrix against live Batfish — if dispositions differ from the preserved scripts' observed behavior, stop and reconcile before any agent or UI work.

## Risks / Open Questions

| Risk | Impact | Mitigation in this plan |
|---|---|---|
| Meta Model API endpoint/model/tool-calling surface differs from assumptions | Phase 3 rework if found late | Discovered in Phase 0 by `scripts/spike_meta_api.py` (auth + dummy-tool round-trip); `agent.py` isolates the API behind one adapter function built on the observed shapes |
| Batfish not running during tests/demo | False failures, blocked demo | Health gate + explicit skip-with-message; README prerequisite; UI disabled-state |
| Pybatfish/DataFrame shape drift across versions | Tool parsing breaks | DataFrame conversion isolated in `batfish_client.py`; integration tests assert dispositions, not column layouts, where feasible |
| LLM fabricates evidence or verdict language | Unsafe report | Python-only findings with claim-type/flow/predicate validation; narrative validated against finding IDs and dropped (never edits findings) on invention; verdict rendered independently from `AssessmentResult` |
| Intent semantics ambiguous (e.g., “reach” = any protocol?) | Wrong verdicts | Protocol/port pinned per flow in `FlowSpec`; unmapped disposition or missing evidence -> `UNKNOWN` instead of guessing |
| ACL scenario disposition naming varies (`DENIED_IN` vs `DENIED_OUT`), TCP traceroute behavior unverified | Brittle tests | Assert disposition family/prefix and per-flow classification, not one exact string, after Phase 1 observation; ACL baseline-satisfies-intent outcomes are an explicit Phase 1 acceptance gate |
| `initIssues` schema/severity spellings and partial-parse tokens unverified | Health gate misclassifies | Phase 1 observational test pins real columns/values before string matching is coded; conservative default (any unexplained warning -> `DEGRADED`) |
| Incomplete-config scenario may parse with warnings, not errors | Weak inconclusive fixture | Stretch only: confirm empirically in Phase 5; if Batfish tolerates it, use a missing-interface reference that yields `UNKNOWN` outcomes instead. Never blocks essential path |
| Scope creep to remediation/patching | Safety + time | Explicit non-goals; no write tools exist to call |

Unresolved technical assumptions (to pin empirically, in order): (1) Meta Model API base URL, Muse Spark 1.3 model identifier, and tool-calling message/schema dialect — resolved by the Phase 0 smoke test; whether an official client or raw `httpx` is the right transport follows from what the smoke test observes. (2) Batfish `initIssues` column names, severity values, and partial-parse status tokens — resolved by the Phase 1 observational test. (3) Exact Batfish dispositions for TCP flows to ports 1433/22 through the ACL (`DENIED_IN` vs `DENIED_OUT`, and whether host-port filtering is modelled as expected) — resolved in Phase 1. (4) Batfish Docker image already proven by the preserved scripts; Streamlit single-user local demo (no auth) acceptable for V1. No blocking product questions remain.

## Sequential vs Delegable Work

Must stay sequential (single owner, in order): Phase 0 contracts (`models.py`) -> Phase 1 `batfish_client.py` -> Phase 2 `tools.py`/`evidence.py`/`assessment.py` -> Phase 3 `agent.py`. Each layer's contract is the next layer's input; parallel edits here create integration churn.

Safe to delegate to independent subagents once the preceding contract lands:

| Work package | Can start after | Notes |
|---|---|---|
| Scenario fixtures + `examples/intent.yaml` | Phase 0 | Config-only; validated by Phase 1 tests |
| `test_evidence.py` / `test_assessment.py` (synthetic, no Batfish) | `models.py` frozen | Pure unit tests, no shared state |
| Streamlit page shell with fake `Report` data | `models.py` frozen | Merge behind `run_assessment()` before Phase 4 acceptance |
| README / demo script / `.env.example` docs | Phase 0 | No code coupling |
| Agent fake-response test corpus | Tool schemas frozen (Phase 2) | Recorded JSON fixtures only |

Rule: subagents never edit preserved files or another package's module concurrently; integration (Phase 2 E2E, Phase 4 wiring) stays with one owner.

## Smallest Working End-to-End V1 Milestone

**Milestone M1 (end of Phase 2, deterministic core):** headless pipeline — preserved baseline vs proposed + `examples/intent.yaml` -> `REGRESSION_DETECTED` with `NO_ROUTE` evidence and hop trace, printable as JSON from one command (`python -m netops_lens` or a pytest E2E). No LLM, no UI. Proves snapshots, intent, tools, evidence, and verdict before AI/frontend risk.

**Milestone M2 (end of Phase 4, smallest *complete* application — the delivery priority):** M1 + minimal Muse loop + minimal Streamlit (scenario pick -> run -> independent Python verdict, findings, traces, Muse explanation). If time forces a choice, M2 ships and every stretch item (incomplete scenario, strict lint, UI extras, untrusted-subnet variant) is cut — a complete small application beats a polished partial one.

## Demo (3-Minute Hackathon Video) — `docs/demo-script.md`

The final submission demo is a **3-minute** video; the script is timed, rehearsed, and treated as an acceptance artifact, not an afterthought:

| Time | Beat | On screen |
|---|---|---|
| 0:00–0:25 | Problem | “A route/ACL edit can silently break app-to-DB traffic. NetOps Lens checks the change *before* deployment.” Show the two-router topology + intent |
| 0:25–0:50 | Healthy baseline | Pick `healthy` from the manifest, run: agent activity streams, Python verdict `NO_REGRESSION_DETECTED` |
| 0:50–1:50 | Regression investigation | Pick `removed_route` (preserved pair), ask “will the app still reach the DB?”: Muse calls `compare_snapshots`/`trace_flow`, hop trace shows `NO_ROUTE`, Python findings cite evidence IDs, verdict banner — rendered independently of the narrative — shows `REGRESSION_DETECTED`; click one evidence ID to show the stored Batfish result |
| 1:50–2:30 | Security intent | Pick `acl_blocks_db` with `intent-acl.yaml`: authorized port regression detected while the unauthorized port stays blocked; show the per-flow table (one `REGRESSION`, one `NO_CHANGE_OK`) |
| 2:30–3:00 | Trust & close | Point at the separation: Python verdict + validated findings vs Muse explanation; restate read-only V1 scope and the `INCONCLUSIVE`-not-safe rule. End card: stack (Batfish, Muse Spark, Streamlit) |

Rehearsal checklist (Phase 5 acceptance): Batfish pre-warmed and snapshots pre-initialized so no Docker wait lands on camera; API key loaded from `.env` (never visible); each run rehearsed end-to-end at least twice with a stopwatch (hard cap 3:00, target 2:45); fallback if the live API is unavailable during recording — record the deterministic M1 path plus findings and narrate the agent's role over the activity log, and disclose the substitution in the video notes rather than faking a live call.

## V1 vs Future

**Essential V1 (this plan):** snapshot-pair assessment, `must_reach`/`must_not_reach` intent, 5 read-only Batfish tools, evidence-validated Muse investigation over Python findings, Python verdict shown independently, Streamlit report, scenarios `healthy`/`removed_route`/`acl_blocks_db`, 3-minute demo.

**Stretch within V1 time (only if essential path is green):** `incomplete` scenario, untrusted-subnet ACL variant, strict lint gates, UI extras (see §Delivery Priorities).

**Future (explicitly out):** candidate config generation/patching, remediation suggestions with diffs, live-device interaction, multi-vendor/topology upload beyond snapshot dirs, auth/multi-user, saved-run history/database, voice/multimodal, local models, broader protocol/port intent language, CI Batfish service. Each needs its own plan and safety review; none is stubbed in V1 beyond the clean module boundaries above.
