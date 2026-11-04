# NetOps Lens V1 — Implementation Plan

> Status: Revised draft for review — no implementation started. Stack: Python 3.14, Batfish (Docker) + Pybatfish, Muse Spark 1.3 via Meta Model API, Streamlit, Pydantic, Pytest. Python always runs the mandatory checks, produces all factual findings and verdicts, and verifies every candidate patch on a disposable snapshot copy. Muse Spark never gates mandatory checks; after the Python verdict it investigates root causes and proposes structured candidate patches. Original snapshots and live devices are never modified.

## Goal

Ship NetOps Lens V1: a network engineer selects a baseline and a proposed snapshot, declares required connectivity in `intent.yaml` (`must_reach` / `must_not_reach`), and runs an assessment from the CLI (Streamlit is the later visual demo target). Python *always* runs snapshot health, baseline intent, proposed intent, and differential reachability for every declared flow, and computes the verdict — `REGRESSION_DETECTED`, `NO_REGRESSION_DETECTED`, or `INCONCLUSIVE`. Only then does Muse Spark investigate root causes with `trace_flow`/`get_routes` and propose structured candidate patches, which Python applies solely to disposable copies of the proposed snapshot and marks `VERIFIED`, `REJECTED`, or `UNVERIFIABLE`. Every factual claim remains traceable to a stored tool result, and a human approves or rejects any verified candidate — approval never applies anything to a device.

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

1. Engineer can run one assessment end to end from the CLI (`python -m netops_lens assess …`): baseline/proposed pair + `intent.yaml` -> Python assessment -> Muse investigation -> candidate verification -> human decision. A minimal Streamlit UI over the same pipeline is the visual demo target once the CLI works.
2. Python unconditionally executes the four mandatory checks for *every* declared flow (health; baseline intent; proposed intent; differential reachability). No Muse decision can skip, reorder away, or early-exit them.
3. All six backend tools return structured, JSON-serializable results; no raw DataFrame crosses the tool boundary.
4. Every factual finding is produced by Python from stored tool results, carries a claim type + flow ID + evidence IDs, and passes the four evidence checks (ID existence, flow identity, snapshot identity, disposition supports the finding). Muse may not change the Python assessment; narrative segments referencing unknown finding IDs are hidden.
5. Python — never the LLM — emits exactly one of `REGRESSION_DETECTED` / `NO_REGRESSION_DETECTED` / `INCONCLUSIVE` by the per-flow comparison and precedence rules in §Assessment Engine, and the verdict is displayed independently of any model narrative in both CLI and UI.
6. Every candidate patch is applied only to a disposable copy of the proposed snapshot; a candidate is `VERIFIED` only under the §Patch & Verify conditions, otherwise `REJECTED` or `UNVERIFIABLE` with reasons. Original baseline/proposed files and live devices are never modified. Candidate count and retries are bounded.
7. Essential scenarios pass in pytest: healthy (`NO_REGRESSION_DETECTED`), removed-route (`REGRESSION_DETECTED`), ACL-blocked (`REGRESSION_DETECTED`). The incomplete-configuration scenario is a stretch goal and must not block the essential path.
8. Preserved files (`test_batfish.py`, `test_diff.py`, `lab/baseline/**`, `lab/proposed/**`) are byte-identical to today.
9. No live-device writes, no autonomous remediation, no voice, multimodal, or local model hosting exist in the codebase. Generating and verifying a candidate *proposal* for human approval is in scope; applying it anywhere real is not.

## Approach

Pipeline with a hard control boundary: the mandatory stage cannot be influenced by the model, and the investigation stage cannot influence the mandatory stage's outputs.

```
CLI (cli.py)  ── later also ──>  Streamlit UI (app.py)
   |  AssessmentRequest (snapshots + intent + question)
   v
STAGE A — Mandatory deterministic assessment (assessment.py, NO LLM)
   Python always runs, for BOTH snapshots and EVERY intent flow:
     get_snapshot_health -> baseline check_intent -> proposed check_intent
     -> compare_snapshots (differential reachability)
   via Tools (tools.py) -> Evidence Store (evidence.py) -> Batfish (batfish_client.py)
   => AssessmentResult (findings + verdict, immutable from here on)
   |
   v
STAGE B — Muse investigation (agent.py, bounded tool loop)
   Input: AssessmentResult + engineer question (read-only)
   Muse calls trace_flow / get_routes for root cause, then emits
   candidate patches ONLY as structured PatchOperation lists
   => InvestigationResult (explanation + candidates; cannot edit Stage A)
   |
   v
STAGE C — Patch & verify (patch.py + verify.py, NO LLM)
   Copy proposed snapshot -> apply ops -> Batfish re-checks health +
   must_reach + must_not_reach + differential vs baseline
   => per-candidate VERIFIED | REJECTED | UNVERIFIABLE + reasons
   |
   v
Report (report.py) -> CLI JSON/text -> UI (assessment, investigation,
   candidates, verification, human approve/reject — records a decision only)
```

Design choices and why:

- **Single package `src/netops_lens/`** (KISS, typed, no framework). Why not a web API + frontend split: Streamlit already serves the UI; a separate service adds deploy and auth scope V1 does not need.
- **Pydantic at every boundary** (tool args, tool results, intent, evidence, patches, report). Rejected: raw dicts (the current scripts' failure mode — untyped and untestable) and a database (V1 evidence is per-run, in-memory + JSON export is enough).
- **Mandatory-before-model ordering.** The LLM investigates and proposes; it never decides which mandatory checks run, never votes on the verdict, and never authors findings. This is the core safety contract.
- **Patches as restricted operations, never free text.** Muse emits typed operations from a small allowlist (§Patch & Verify); Python renders them into config text on the disposable copy. The model never writes config files directly.
- **CLI-first, UI-second.** The full pipeline is testable headlessly via pytest + CLI before Streamlit exists, so the UI never blocks the analysis core.

## Proposed Directory Structure

```
NetOps Lens (repo root)
├── AGENTS.md                     # unchanged
├── README.md                     # NEW: run instructions, Docker prerequisite
├── pyproject.toml                # NEW: deps, pytest (testpaths=["tests"]) + mypy/ruff config
├── .gitignore                    # NEW: .env, netops-env/, .venv/, __pycache__, snapshots cache
├── .env.example                  # NEW: META_API_KEY=, BATFISH_HOST=localhost (no secrets)
├── app.py                        # NEW: Streamlit entry — `streamlit run app.py`
├── test_batfish.py               # PRESERVED — manual smoke script
├── test_diff.py                  # PRESERVED — manual smoke script
├── src/netops_lens/
│   ├── __init__.py
│   ├── config.py                 # env loading, Batfish host/network, limits
│   ├── models.py                 # Pydantic: FlowSpec, Intent, ToolResult, EvidenceRecord, AssessmentResult, Report
│   ├── batfish_client.py         # Session lifecycle, snapshot init, health gate
│   ├── tools.py                  # get_snapshot_health, compare_snapshots, check_intent, trace_flow, get_routes, get_acl_rules
│   ├── intent.py                 # intent.yaml load + validation -> Intent
│   ├── evidence.py               # EvidenceStore: mint IDs, store, validate references
│   ├── assessment.py             # Stage A: mandatory checks -> findings + verdict (no LLM import)
│   ├── agent.py                  # Stage B: Muse investigation loop + candidate elicitation (bounded)
│   ├── prompts.py                # system prompts: investigation + restricted patch proposal
│   ├── patch.py                  # PatchOperation allowlist, apply ops to a disposable copy
│   ├── verify.py                 # Stage C: re-check candidate -> VERIFIED|REJECTED|UNVERIFIABLE
│   ├── cli.py                    # first functional interface: assess / verify / report commands
│   └── report.py                 # Report assembly (assessment + investigation + verifications)
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
│   ├── test_tools_integration.py # real Batfish: 6 tools x scenarios (ICMP pinned)
│   ├── test_agent.py             # investigation loop with recorded/fake Muse responses
│   ├── test_patch_verify.py      # op allowlist, copy isolation, VERIFIED/REJECTED/UNVERIFIABLE cases
│   └── test_e2e.py               # full pipeline per scenario -> verdict + verification outcomes
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

- **ACL baseline** (`acl_blocks_db/baseline`): preserved routing plus one sequence-numbered extended ACL applied on the App-facing path, exactly: sequence **10** `permit tcp 192.0.2.0/24 -> 198.51.100.0/24 eq 1433`; sequence **20** `deny tcp 192.0.2.0/24 -> 198.51.100.0/24 eq 22`. Required baseline outcomes: `app-to-db-authorized` REACHABLE, `app-to-db-unauthorized` UNREACHABLE (blocked). Both intent clauses satisfied.
- **ACL proposed** (`acl_blocks_db/proposed`): identical except sequence 10 is *replaced* — the TCP/1433 permit at sequence 10 becomes an explicit `deny tcp … eq 1433` at sequence **10**; the TCP/22 deny at sequence **20** is untouched. Required proposed outcomes: `app-to-db-authorized` UNREACHABLE (regression on `must_reach`), `app-to-db-unauthorized` still UNREACHABLE (security clause still satisfied, so the security test remains valid and the regression attribution is unambiguous).
- **ACL repair candidate (the only V1 ACL repair shape):** `remove_acl_line{sequence_number: 10, expected_rule: deny tcp … eq 1433}` followed by `acl_permit{sequence_number: 10, tcp … eq 1433}` — remove the exact sequence-10 deny (expected-rule verified) and insert the permit at that same freed sequence. No other ACL insertion sequence is supported in this workflow (see §Patch & Verify).
- An explicit untrusted subnet (e.g., guest `203.0.113.0/24` that `must_not_reach` the DB) is the alternative prohibited-flow design. It is a stretch goal only: it needs new interfaces/subnets on the two-router topology, while the port-based design tests the same policy class with zero topology change.

Rules for all intent files: `id` unique per file (this `id` is the `flow_id` used by findings, traces, and the truth tables); IPs validated as addresses; protocol in `{ICMP, TCP, UDP}`; `dst_port` required iff TCP/UDP and forbidden for ICMP; unknown keys rejected. One intent file maps 1:1 to one assessment run, and each scenario in the manifest names exactly one intent file.

## Data Contracts & Module Responsibilities

All models in `models.py`, all `extra="forbid"`, all JSON-serializable. Key contracts:

| Contract | Fields (essence) | Owner |
|---|---|---|
| `FlowSpec` | `flow_id (= intent id), src_ip, dst_ip, protocol, dst_port?, start_location` | `intent.py`, `tools.py` |
| `Intent` | `version, must_reach: list[FlowSpec], must_not_reach: list[FlowSpec]` | `intent.py` |
| `SnapshotRef` | `name, path` | `batfish_client.py` |
| `SnapshotHealth` | `snapshot, status: OK|NOT_OK, per_file_parse, init_issues, nodes, reasons: list[str]` (blocking details, verbatim), `benign_warnings: list[str]` (allowlisted warnings, verbatim, non-blocking) — exactly two status values, no third state | `tools.py` (`get_snapshot_health`) |
| `ToolResult` | `tool, snapshot(s), flow_id?, status: ok|error|inconclusive, summary, details: dict, evidence_id` | `tools.py` |
| `EvidenceRecord` | `evidence_id (ev-0001…)`, `tool`, `snapshots`, `flow_id?`, `disposition?`, `details`, `created_order` | `evidence.py` |
| `ClaimType` (enum, label only) | `REACHABILITY_CHANGED, INTENT_SATISFIED, INTENT_VIOLATED, ROUTE_PRESENT, ROUTE_ABSENT, TRACE_DISPOSITION, SNAPSHOT_HEALTH` | `models.py` |
| `FlowComparison` | `flow_id, kind: must_reach|must_not_reach, baseline_reach: REACHABLE|UNREACHABLE|UNKNOWN, proposed_reach: …, classification: REGRESSION|IMPROVEMENT|NO_CHANGE_OK|PRE_EXISTING_VIOLATION|UNKNOWN` | `assessment.py` |
| `Finding` | `finding_id (f-0001…)`, `claim_type: ClaimType`, `flow_id?`, `statement` (Python-templated factual text), `evidence_ids: list[str]`, `severity` | `assessment.py` (Python-produced only) |
| `AssessmentResult` | `verdict, flow_comparisons: list[FlowComparison], findings: list[Finding], inconclusive_reasons: list[str], health: list[SnapshotHealth]` — immutable once Stage A returns | `assessment.py` (sole writer of `verdict` and `findings`) |
| `PatchOperation` (discriminated union) | `add_static_route{node,prefix,next_hop}` \| `remove_static_route{node,prefix,next_hop}` \| `acl_permit{node,acl,sequence_number,src,dst,protocol,dst_port}` \| `acl_deny{node,acl,sequence_number,src,dst,protocol,dst_port}` \| `remove_acl_line{node,acl,sequence_number,expected_rule: AclRule}` — no free-text op exists. V1 Stage B submission validation accepts only the §Stage C repair shapes (route ops bound to target flows; exactly one `remove_acl_line` + one `acl_permit` at the same freed sequence); `acl_deny` and mixed route/ACL candidates are rejected before Stage C | `models.py` / `patch.py` |
| `AclRule` | `action: permit|deny, src, dst, protocol, dst_port?` — the full match of one existing ACL line, used as `expected_rule` | `models.py` |
| `CandidatePatch` | `candidate_id (c-01…, assigned by Python on acceptance — never supplied by the model)`, `rationale` (model text, non-factual), `operations: list[PatchOperation]` (1..5 ops), `target_flow_ids: list[str]` | model submits via `submit_candidate_patch`, `agent.py` validates/collects, `patch.py` applies |
| `ApplicationResult` | `candidate_id, applied: bool, changed_files: list[str]` (basenames / snapshot-relative names only — never absolute paths), `diff: list[FileDiff], reasons: list[str]` — `FrozenModel`, immutable like all Stage C results feeding the report | `patch.py` |
| `FileDiff` | `file` (basename / snapshot-relative), `removed: list[str], added: list[str]` — only the touched lines, no surrounding configuration context | `patch.py` |
| `VerificationResult` | `candidate_id, status: VERIFIED|REJECTED|UNVERIFIABLE, reasons: list[str], checks` (explicit IDs — `candidate_health`, `intent:{flow_id}`, `no_regression:{flow_id}`, `differential:{flow_id}` — each pass/fail/unknown), `evidence_ids: list[str]` (monotonic in the run `EvidenceStore`), `candidate_snapshot` (Batfish snapshot name only, never a filesystem path) — `FrozenModel` | `verify.py` |
| `InvestigationResult` | `narrative: str|None, candidates: list[CandidatePatch], tool_activity: list[ToolCallLog]` | `agent.py` |
| `Report` | `assessment: AssessmentResult`, `investigation: InvestigationResult|None`, `applications: list[ApplicationResult]` (introduced in Phase 4.1; full report assembly and serialization integration in Phase 4.3), `verifications: list[VerificationResult]`, `human_decision` (per candidate — every candidate starts `PENDING`, including `REJECTED`/`UNVERIFIABLE`; only `VERIFIED` may be approved), `evidence_index, traces` | `report.py` |

Module boundaries: `batfish_client.py` is the only module importing Pybatfish; `tools.py` is the only caller of the client; `assessment.py` and `verify.py` import no LLM code; `agent.py` cannot import `assessment.py` writers (it receives a read-only `AssessmentResult`); `patch.py` writes only under the ephemeral candidate directory; `cli.py`/`app.py` import no Pybatfish. DataFrames are converted to records inside `batfish_client.py`/`tools.py` and never escape.

## Backend Tools (all in `tools.py`, each returns `ToolResult`)

| Tool | Batfish query | Returns | Failure semantics |
|---|---|---|---|
| `get_snapshot_health` | `fileParseStatus` + `initIssues` + `nodeProperties` per snapshot | `SnapshotHealth` (see §Snapshot Health): per-file parse status, init issues, node list, `status: OK|NOT_OK` + reasons | Any failure condition -> `status=NOT_OK` with reason(s); never raises across the tool boundary |
| `compare_snapshots` | `differentialReachability` built from the **complete `FlowSpec` of one declared flow**: `HeaderConstraints(srcIps=flow.src_ip, dstIps=flow.dst_ip, ipProtocols=[flow.protocol], dstPorts=[flow.dst_port] when applicable)` + `PathConstraints(startLocation=flow.start_location)`, `maxTraces=5` — exactly the same flow `check_intent` evaluates for that `flow_id` | **Cross-check only:** whether Batfish reports *that flow* as changed, with differential traces. It does **not** return — and must not be read as — a complete disposition row for every declared flow: a flow absent from the result is “not reported changed”, never “proven unchanged”. **Mandatory:** Stage A calls it once per declared flow, unconditionally, as the independent check on the direct `check_intent` results (see §Assessment Engine) | Missing reference snapshot or query error -> `inconclusive` evidence (differential unknown), not success and not “no change”. Widening the query (dropping the port, the start location, or either IP to “search more broadly”) is forbidden: it would cross-check a different flow than the one assessed, and any such broadening must fail argument validation instead |
| `check_intent` | `reachability`/`traceroute` per intent flow, executed separately on the named snapshot, with `HeaderConstraints` built from the complete `FlowSpec` exactly as in `compare_snapshots` (same src/dst/protocol/port; start location from `flow.start_location`) so both tools always denote the identical declared flow | per-flow disposition on that snapshot. **Mandatory:** Stage A calls it for every flow on baseline *and* on proposed (and Stage C on every candidate); the model never selects whether this happens | Untestable flow (bad location, no route info) -> `UNKNOWN` -> feeds `INCONCLUSIVE` / `UNVERIFIABLE` |
| `trace_flow` | `traceroute` with `HeaderConstraints`; when a hop is `DENIED_*` without identified filter detail, followed by Batfish `testFilters` for that flow's headers against the candidate ACL(s) to identify the matched filter/rule | ordered hops with per-hop disposition (`ACCEPTED`, `NO_ROUTE`, `DENIED_IN/OUT`, …), final disposition. **ACL evidence fields (three distinct values, never conflated):** `matched_line_content` — the deciding rule's action + match fields exactly as trace/step or `testFilters` returns them; `batfish_line_index` — Batfish's internal row index (`Line_Index`-style) when returned, kept purely as provenance; `sequence_number` — the Cisco IOS ACL sequence number, which comes **only** from the `get_acl_rules` config parser and is attached to the hop record only after `matched_line_content` is reconciled against the parser's rule list for that ACL (content match -> that rule's `sequence_number`). None of the three is ever dropped in DataFrame->record conversion, inferred, or substituted for another; in particular `batfish_line_index` is never read as `sequence_number` | Unidentified filter after trace + `testFilters`: Phase 1 must establish whether `testFilters` run across the relevant filters on the denying node can identify the deciding ACL (see §Phase 1). At runtime, if the filter name stays unidentified, or multiple candidate ACLs/rules remain unresolved after trace + `testFilters` + parser reconciliation, ACL candidate generation for that flow returns **UNVERIFIABLE-candidate status** (recorded reason: deciding ACL not uniquely identified) instead of guessing a filter, rule, or sequence; same `unknown` rule; trace always stored as evidence |
| `get_routes` | `routes` question per node | routes for node/prefix, next-hop, protocol | Missing node -> `error` with reason, not empty success |
| `get_acl_rules` (read-only, restricted) | **Config parser, not a Batfish query:** reads the named sequence-numbered extended ACL stanza (`ip access-list extended <acl>`) from the named node's config file *inside the named snapshot directory* | ordered rule list: `sequence_number, action, src, dst, protocol, dst_port, raw_line` per line, in file order. This is the sequence authority for patching: Batfish `Line_Index`-style row numbers are internal parse indices and must **never** be treated as, or converted into, Cisco IOS ACL sequence numbers | Missing node/ACL/config -> `error` with reason. Any unsupported or ambiguous ACL syntax (unnumbered lines, unparseable match fields, duplicate sequences, non-extended stanza) -> `error` naming the offending `raw_line`; lines are never silently omitted or guessed. Required before any ACL patch op: the `sequence_number` may only come from this parser output; `testFilters`/trace output may identify *which* rule matched (`matched_line_content`, filter name) but its sequence value is valid only after content reconciliation against this output |

Shared rules: headers always pin protocol explicitly (ICMP in comparable tests, per `FlowSpec` otherwise); every successful call mints exactly one `EvidenceRecord`; every error is a typed `ToolResult`, never an exception across the tool boundary; tool arguments are Pydantic-validated before any Batfish call.

## Snapshot Health (`get_snapshot_health` in `tools.py`, conversion in `batfish_client.py`)

Three Batfish questions are combined per snapshot; none alone is sufficient (`fileParseStatus` can look clean while `initIssues` reports constructs Batfish could not model):

| Source | What is read | Failure it catches |
|---|---|---|
| `fileParseStatus` | per-file parse status (`PASSED` / partially-parsed / `FAILED` token values as returned — exact tokens recorded empirically in Phase 1) | syntax errors, truncated configs |
| `initIssues` | initialization issues with severity/detail text (questions, files/nodes affected where present) | unparseable constructs, missing references, unsupported/ignored features modelled differently than configured |
| `nodeProperties` | recognized nodes | files that parsed to nothing, wrong vendor/format, empty snapshots |

Health states — exactly two (the only values `SnapshotHealth.status` may take). There is no intermediate or degraded state anywhere in the plan: detail lives in `reasons` (blocking) and `benign_warnings` (non-blocking), never in a third status.

| Status | Condition | Effect on the run |
|---|---|---|
| `NOT_OK` | Any one of: snapshot init raises/fails; OR any file fails to parse; OR any file is only partially parsed; OR `initIssues` reports an error-severity or parse-failure entry; OR `initIssues` reports **any issue that is not on the explicitly recognized benign-warning allowlist** — including unsupported-feature entries and any unrecognized or unexplained text that cannot be established as harmless (V1 never grades an unknown issue as probably fine); OR zero nodes recognized; OR an expected node is absent. Every triggering entry is recorded verbatim in `reasons` (original file/issue details preserved) | Stage A gate: verdict `INCONCLUSIVE` with the health reasons; no reachability/route evidence from that snapshot is trusted. In Stage C the same condition makes the candidate `UNVERIFIABLE` (health failure) rather than merely rejected — see §Patch & Verify for the exact split |
| `OK` | No `NOT_OK` condition holds: all files fully parsed, expected nodes present, and every `initIssues` entry (if any) matches the benign-warning allowlist exactly | Flows evaluated normally; allowlisted entries are still recorded verbatim in `benign_warnings` and shown in the report — benign means non-blocking, not invisible |

Benign-warning allowlist: a finite, explicit list of exact `initIssues` signatures (source question + severity + matched text pattern), initially **empty**. An entry may be added only with Phase 1 evidence that the warning is harmless for the declared flows (e.g., a notice about a construct no intent flow traverses), recorded alongside the observed example text in the allowlist definition. Matching is exact-signature only: an issue that merely resembles an allowlisted one, or arrives with different severity/text, is unrecognized and therefore `NOT_OK`. This resolves the earlier contradiction in which partially trusted snapshots were described with a third, degraded notion while the status type claimed two values: warnings now either block (`reasons`) or are explicitly allowlisted (`benign_warnings`); nothing is “somewhat trusted”.

Rules: health is computed for baseline, proposed, and every candidate snapshot independently and each result is stored as `SNAPSHOT_HEALTH` evidence; a `NOT_OK` baseline is as blocking as a `NOT_OK` proposed snapshot, since every verdict is a baseline-vs-proposed comparison; reasons always quote the originating file/issue text so an engineer can act without re-running Batfish by hand. Exact `initIssues` column names, severity spellings, and partial-parse tokens are unverified assumptions (see Risks) and must be pinned by a Phase 1 observation test before these string matches are coded.

## Evidence System (`evidence.py`)

Python is the only author of factual findings. Muse Spark investigates (chooses tools) and *explains* Python-validated findings; it never originates a factual conclusion. Evidence-ID existence is necessary but never sufficient.

- **Minting:** sequential IDs `ev-0001`, `ev-0002`, … scoped to one assessment run; ID assigned at tool-return time, never by the LLM.
- **Storage:** `EvidenceStore` (in-run dict + JSON export) holds the full `ToolResult` payload behind each ID, including `tool`, `snapshots`, `flow_id`, and `disposition` where applicable.
- **Python findings:** `assessment.py` (and health evaluation in `tools.py`) generate each `Finding` programmatically: `claim_type` from the `ClaimType` enum, `flow_id` copied from the intent/tool call, `statement` rendered from a Python template with the actual disposition values, `evidence_ids` set to the exact records the statement was derived from. There is no code path where model text becomes a `Finding`.
- **Evidence validation (`validate_finding`) — four checks, deliberately no more:** a finding is kept iff (1) every cited `evidence_id` exists in the store; (2) **flow identity** — each cited record's `flow_id` equals the finding's `flow_id` (health findings instead cite the `SNAPSHOT_HEALTH` record for their snapshot); (3) **snapshot identity** — cited records come from the snapshot(s) the finding is about (baseline/proposed/candidate roles match); (4) **disposition support** — the cited records' dispositions actually entail the finding (e.g., an `INTENT_VIOLATED` finding for `must_reach` needs a proposed `UNREACHABLE` record; `ROUTE_ABSENT` needs a negative route result). Existing-but-wrong evidence fails checks 2–4 even though check 1 passes. Failures are logged in `tool_activity` with the failed check named; nothing is silently repaired. V1 explicitly does *not* implement a natural-language truth validator: `claim_type` is a structural label, and no component grades prose for truth.
- **Narrative handling (simplified):** Muse receives only validated `Finding`s + the Python verdict and references findings as `f-0001`…. `report.py` performs one mechanical pass: any narrative segment (sentence/paragraph) referencing an unknown finding ID is *hidden* (dropped from the rendered narrative and logged); segments referencing known IDs are shown as-is. The narrative lives in `InvestigationResult.narrative`, visually and structurally separate from `Report.assessment`, and is excluded entirely when Stage B is skipped.
- **Missing vs confirmed:** absence of evidence yields `UNKNOWN` flow comparisons and `INCONCLUSIVE` reasons. Only a stored disposition confirms a finding. The report renders these distinctly: “confirmed”, “violated”, “not tested / inconclusive”.

## Assessment Engine (`assessment.py`) — Python decides

Inputs: `SnapshotHealth` for both snapshots + stored reachability evidence only. The engine runs in three stages: per-snapshot reachability -> per-flow comparison -> overall verdict. No stage may be skipped, and proposed-only satisfaction/violation (without the baseline value) never determines a verdict — that was the ambiguity in the previous draft, where “violated in proposed” and “already violated in baseline” could both fire for the same flow with no stated winner.

**Mandatory execution contract (Stage A).** `run_mandatory_assessment(baseline, proposed, intent)` is a pure-Python entry point with no LLM parameter, callback, or early-exit hook. On every invocation it executes, in fixed order: (1) `get_snapshot_health` on baseline and proposed; (2) `check_intent` for *every* `must_reach` and `must_not_reach` flow on the baseline snapshot; (3) the same for every flow on the proposed snapshot; (4) `compare_snapshots` (differential reachability) for every declared flow. If health is `NOT_OK`, flow checks still run only where Batfish can answer, but their results are marked untrusted and the gate (verdict precedence priority 0) decides `INCONCLUSIVE`. Completeness is asserted, not assumed: the returned `AssessmentResult` must contain a `FlowComparison` for every intent flow, and `report.py` refuses to render an assessment missing one. Agent code receives the finished `AssessmentResult` and has no API to trigger, skip, or re-run any part of Stage A.

### Stage 1 — Per-snapshot reachability (per intent flow)

Authoritative source: the two direct `check_intent` results. Each flow gets, *independently for baseline and proposed*, from `check_intent` on that snapshot alone: `REACHABLE` (final disposition `ACCEPTED`), `UNREACHABLE` (`NO_ROUTE`, `DENIED_IN`, `DENIED_OUT`, deny/drop dispositions as observed in Phase 1), or `UNKNOWN` (tool error, snapshot `NOT_OK`, or an unmapped disposition — unmapped dispositions are always `UNKNOWN`, never guessed). `compare_snapshots` never supplies these values; it only corroborates or contradicts the change implied by them (Stage 2). Because Stage A is mandatory, “no evidence collected” cannot occur for a declared flow; if it somehow does (internal bug), the flow is `UNKNOWN` and the completeness assertion above fails the run loudly rather than emitting a verdict.

**Differential cross-check (applied in Stage 2 before classification).** `assessment.py` computes every `FlowComparison` from the two direct dispositions, then reconciles with `compare_snapshots` for that flow: (a) direct results imply a change (baseline disposition != proposed disposition) but differential evidence does not report the flow as changed -> classification forced to `UNKNOWN`, discrepancy recorded in `inconclusive_reasons` and as a finding note (“direct checks indicate change, differential does not corroborate”); (b) differential evidence reports a change (or directions) conflicting with the direct results -> `UNKNOWN` with the conflict recorded; (c) direct results imply no change and differential reports none -> proceed (absence of a differential row is consistent with, but is never itself the proof of, no-change — the proof is the two direct `check_intent` results); (d) differential query errored/inconclusive while direct results are known -> `UNKNOWN` (the mandatory cross-check could not be completed). An empty differential result therefore proves nothing on its own and must never be surfaced as “all traffic unchanged”.

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
| 0 (gate) | Either snapshot `NOT_OK` | `INCONCLUSIVE` (flow analysis not trusted; health findings only) |
| 1 | >= 1 flow `REGRESSION` | `REGRESSION_DETECTED` — a *confirmed* regression dominates: co-existing `UNKNOWN`/`PRE_EXISTING_VIOLATION` flows are reported as residual findings/reasons but do **not** downgrade the verdict, because the regression is proven by stored baseline-vs-proposed evidence on its own flow |
| 2 | No `REGRESSION`, >= 1 flow `UNKNOWN` | `INCONCLUSIVE` (unproven territory could hide a regression) |
| 3 | No `REGRESSION`/`UNKNOWN`, >= 1 flow `PRE_EXISTING_VIOLATION` | `INCONCLUSIVE` with reason “pre-existing intent failure persists; no new regression on tested flows” — never `NO_REGRESSION_DETECTED`, since the intent still fails in the proposed snapshot and certifying it would claim a failing state is safe |
| 4 | All flows `NO_CHANGE_OK`/`IMPROVEMENT` | `NO_REGRESSION_DETECTED`, scoped strictly to tested flows; report must state untested traffic is not claimed safe |

Worked mixed cases: regressions + unknowns -> `REGRESSION_DETECTED` (priority 1 beats 2); pre-existing violation + regression on another flow -> `REGRESSION_DETECTED` (the regression is new damage; the pre-existing failure is listed as a separate finding, not a veto); pre-existing violation + unknown, no regression -> `INCONCLUSIVE` (reason lists both).

### Unit-test cases (`tests/test_assessment.py`, synthetic `FlowComparison` inputs — no Batfish, no LLM)

Per-flow grid: all 18 rows above (9 per clause kind) as parametrized cases (`pytest.mark.parametrize` over `(kind, baseline, proposed, expected)`), including every `UNKNOWN`-involving row mapping to `UNKNOWN` — both `must_reach` and `must_not_reach` stay meaningfully parametrized. Aggregation: (1) health OK + all `NO_CHANGE_OK` -> `NO_REGRESSION_DETECTED`; (2) single `must_reach` `REGRESSION` -> `REGRESSION_DETECTED`; (3) single `must_not_reach` blocked->reachable -> `REGRESSION_DETECTED`; (4) `REGRESSION` + `UNKNOWN` -> `REGRESSION_DETECTED` with the unknown flow present in `inconclusive_reasons`/findings; (5) `UNKNOWN` only -> `INCONCLUSIVE`; (6) `PRE_EXISTING_VIOLATION` only (both kinds) -> `INCONCLUSIVE`; (7) `PRE_EXISTING_VIOLATION` + `REGRESSION` -> `REGRESSION_DETECTED`; (8) `IMPROVEMENT` only (both kinds) -> `NO_REGRESSION_DETECTED` with improvement finding; (9) either snapshot `NOT_OK` overrides even a synthetic `REGRESSION` input -> `INCONCLUSIVE`; (10) one `UNKNOWN` flow + one `NO_CHANGE_OK` flow -> `INCONCLUSIVE`; (11) direct change without differential corroboration -> flow `UNKNOWN`, discrepancy recorded, verdict follows Stage 3 for `UNKNOWN`; (12) differential/direct conflict -> flow `UNKNOWN`; (13) empty differential result with equal direct dispositions -> classification from direct results only (never `UNKNOWN` solely for the empty differential, never “unchanged” claimed from the differential); (14) differential error with known direct results -> flow `UNKNOWN`. Test placement: the 18 grid rows and aggregation cases 1–10 are **synthetic unit tests in `tests/test_assessment.py` only** (stubbed dispositions, no Batfish, no LLM) and are *not* reproduced in the E2E suite; `tests/test_e2e.py` instead covers the three essential real-Batfish scenarios (healthy, removed-route, acl_blocks_db) end to end through the CLI. Discrepancy cases 11–14 are likewise synthetic tool-result unit tests (stubbed `compare_snapshots` records) in `test_assessment.py`, grounded by the real differential-output observations captured in Phase 1.

The LLM receives `AssessmentResult` as read-only context and cannot override it; the verdict shown anywhere comes from `AssessmentResult.verdict`. Narrative segments referencing unknown finding IDs are hidden (see §Evidence System); no prose-truth check is performed.

## Muse Spark Investigation (`agent.py` + `prompts.py`) — Stage B

Runs only *after* Stage A has returned a complete `AssessmentResult`. The model's job is root-cause investigation and — only for confirmed regressions — candidate generation, never reassessment. Behaviour is gated by the Python verdict:

| Stage A verdict | Stage B behaviour | Candidates | Stage C |
|---|---|---|---|
| `REGRESSION_DETECTED` | Full investigation loop (`trace_flow` / `get_routes` / `get_acl_rules`) + candidate elicitation via the submission tool (below) | 0..`MAX_CANDIDATES` accepted submissions | Verifies every accepted candidate |
| `NO_REGRESSION_DETECTED` | Explain-only: narrative reports the successful Python checks (per-flow `NO_CHANGE_OK`/`IMPROVEMENT`, health `OK`) citing finding IDs. The submission tool is **not registered** for this run; no fixes are proposed for a passing change | None — any submission attempt is rejected by Python as `candidates_not_allowed` | Skipped (nothing to verify) |
| `INCONCLUSIVE` | Uncertainty explanation only: narrative explains *why* Python could not decide (health `NOT_OK` reasons, `UNKNOWN` flows, pre-existing violations) from Stage A evidence. No investigation tools run against an untrusted snapshot, and the submission tool is **not registered** — V1 never proposes patches for unverified failures | None — any submission attempt is rejected as above | Skipped |

Interaction sequence per run:

1. CLI/UI builds `AssessmentRequest` (snapshot pair, `Intent`, free-text engineer question). Python runs Stage A unconditionally (see §Assessment Engine). No model code has executed yet.
2. Python selects the row above from `AssessmentResult.verdict` and configures the conversation accordingly (which tools are registered is a Python decision the model cannot change). Investigation loop (bounded, default max 8 tool calls, configurable in `config.py`): the model receives the `AssessmentResult` (read-only) plus the investigation tools with fresh evidence minting: `trace_flow` (preserving ACL name/matched rule/sequence per hop, see §Backend Tools), `get_routes` (routing table where a trace stopped, e.g., confirm a missing static route), and `get_acl_rules` (the config-parser sequence authority; workflow for a denied flow is: preserve trace ACL detail where present -> if unidentified, Batfish `testFilters` for the flow's matched filter/rule -> reconcile the matched rule against `get_acl_rules` output to obtain the IOS `sequence_number` — sequence numbers must come from tool/parser output, never from the model's prior knowledge or from Batfish `Line_Index`; the prompt states this explicitly and Python enforces it at submission validation). The system prompt directs: explain *why* each `REGRESSION`/`PRE_EXISTING_VIOLATION` flow fails, citing finding IDs; trace before routes/ACL reads; do not restate a different verdict. Python validates every tool call's args with Pydantic, executes, stores evidence, returns `ToolResult` JSON.
3. Candidate elicitation (`REGRESSION_DETECTED` runs only; see “Structured candidate submission” below): the model submits each candidate by calling the named submission tool. Free-text config, shell, or “remediation advice” in place of operations is a validation error returned to the model, retried once, then that candidate slot is abandoned.
4. Python assembles `InvestigationResult` (hidden-ID-filtered narrative, accepted candidates, `tool_activity` log with tool/args/evidence ID/latency) and hands candidates to Stage C. `AssessmentResult` is passed by value and is byte-compared before/after Stage B in tests to prove the model cannot mutate it.

**Structured candidate submission (the only path from model to Stage C).** Candidates reach Python exclusively through a named, non-executing submission tool:

- Tool name: `submit_candidate_patch`. Its input schema is the JSON Schema of `CandidatePatch` *without* `candidate_id` (fields: `rationale`, `operations: PatchOperation[]`, `target_flow_ids`). Exactly this schema — not prose, not a code block — is what the model fills in.
- Handler contract (`agent.py`): validate the payload with Pydantic (allowlist, field formats, `target_flow_ids` exist in the intent, ACL sequence numbers present, ACL ops backed by `trace_flow`/`get_acl_rules` evidence from this run); on success assign the next `candidate_id` (`c-01`…), append to the run's collected-candidates list, and return `{accepted: true, candidate_id}`; on failure return `{accepted: false, errors: [...]}` for the one allowed corrective retry. The handler contains no Batfish call, no file write, and no verification logic — collection and validation only. Python alone (Stage C) applies and verifies.
- If the Phase 0 smoke test shows the Meta API cannot carry a tool with this nested schema, the fallback is a validated structured-output response schema of the same shape, parsed and Pydantic-validated identically; free-text parsing of candidates is never acceptable under either variant. Which variant is live is recorded in `config.py` from the smoke-test result.

Guards: real Meta Model API tool calling only (no text-parsing of tool calls); API key from `.env` via `config.py`, never logged; malformed tool args get one corrective retry with the validation error, then count toward the bound; investigation tools are read-only Batfish queries — no tool can write files, snapshots, or devices; the only write path in the system is `patch.py` onto a disposable copy (Stage C).

## Patch & Verify (`patch.py` + `verify.py`) — Stage C

**Restricted operations.** Muse proposes candidates *only* via `submit_candidate_patch` (§Stage B), each operation a `PatchOperation` from this allowlist (Pydantic discriminated union; anything else fails validation):

- `add_static_route{node, prefix, next_hop}`, `remove_static_route{node, prefix, next_hop}`
- `acl_permit{node, acl, sequence_number, src, dst, protocol, dst_port}`, `acl_deny{node, acl, sequence_number, src, dst, protocol, dst_port}` — `sequence_number` is a positive integer giving the exact position in the named ACL; both ops always carry it (no append-by-default).
- `remove_acl_line{node, acl, sequence_number, expected_rule}` — `expected_rule: AclRule{action, src, dst, protocol, dst_port?}` is the full content of the line the model believes sits at `sequence_number`. Before applying, `patch.py` parses the disposable copy's ACL and verifies a line exists at exactly `sequence_number` whose action/match equals `expected_rule`; any mismatch (wrong sequence, different rule, missing ACL) aborts that candidate as an apply failure (-> `UNVERIFIABLE` with reason `remove_acl_line expected-rule mismatch at seq <n>`), never a best-effort delete of a neighbouring line.

`patch.py` renders each op into the vendor config syntax of the target node's file *inside the disposable copy only*; op fields are validated as IPs/prefixes/ports before rendering. `patch.py` independently revalidates the complete accepted Stage B candidate contract before rendering: `acl_deny`, mixed route/ACL operations, invalid repair shapes, and every unsupported operation are rejected even when they arrive as accepted candidates (R4-06 rule 1). A candidate carries 1–5 operations. This allowlist covers both essential regressions (restore the deleted static route; re-permit the authorized DB port ahead of the deny) without giving the model arbitrary config authorship.

**ACL application: line-level splice, no stanza reconstruction (C-1).** The renderer treats each named extended ACL as an ordered sequence of source lines and mutates exactly one of them: `acl_parser.py` is extended additively (existing parser semantics preserved) to expose, for the target node's file, the target stanza's line span and each parsed rule's source line index. Application: (1) locate the single `ip access-list extended <acl>` stanza — zero or multiple same-name stanzas fail closed; (2) verify the stanza contains no remarks, unnumbered lines, unsupported syntax, or ambiguous structures — any such content aborts the candidate as an application failure, never a best-effort edit; (3) verify the line at the parser-reported index matches `expected_rule` exactly (the V1 repair removes the validated sequence-10 deny); (4) delete only that line and insert the replacement permit at the same position, reusing the removed line's sequence number and indentation and preserving the file's existing newline convention. Every untouched byte is preserved — blank lines, comments, separators, other stanzas, line endings, and all untouched rules (which are never re-emitted or normalized). The rendered `FileDiff` therefore shows exactly one removed and one added line, and what the human reviews is the order Batfish evaluates (first match wins — spike-verified below for seq-10 permit ahead of seq-20 deny). Test requirements: byte-exact splice on LF and CRLF fixtures; multi-stanza same-name rejection; remark/unnumbered-line rejection; indentation and newline-convention preservation assertions.

**Exact V1 rendering rules (R4-03).** CIDR prefix → network address and dotted wildcard mask (`198.51.100.0/24` → `198.51.100.0 0.0.0.255`); `/32` host prefixes → `host <address>`; `any` → `any`; a plain address stays in its unchanged address representation; destination port → `eq <dst_port>`; protocol → lowercase. The recorded lifecycle spike applied a deny→permit flip to the fixture line ` 10 deny tcp 192.0.2.0 0.0.0.255 198.51.100.0 0.0.0.255 eq 1433` (`lab/scenarios/acl_blocks_db/proposed/configs/r1.cfg`, line 16), yielding the rendered line ` 10 permit tcp 192.0.2.0 0.0.0.255 198.51.100.0 0.0.0.255 eq 1433`, which Batfish parsed (`PASSED`, Q6) and evaluated first-match (Q7). No other rendered line is claimed from the spike.

**Strict route parsing (F4-06, R4-06 rule 2).** The renderer accepts only the fixture dialect `ip route <network> <dotted-mask> <next-hop>`: candidate CIDR prefixes are converted to dotted masks when rendering; lines with extra tokens (distance, name, tag, track, permanent, interface next-hop variants) are unsupported. Every `ip route` line in a target route file must conform to this five-token dialect (`ip`, `route`, network, dotted mask, next-hop) — an unsupported line anywhere in that file makes semantic duplicate detection ambiguous and therefore rejects the candidate. Adding an already-present equivalent route is an application failure, not a silent no-op; removal requires exactly one matching route — zero or multiple matches fail closed.

**Apply-to-copy with atomic application (F4-09, F4-12).** Per candidate, in fixed order: (1) copy pristine proposed files into `runs/<run_id>/candidate-<candidate_id>/` (git-ignored; `KEEP_CANDIDATE_DIRS` (default `false`) decides delete vs keep for debugging; application-failure directories are quarantined/deleted and never mistaken for completed candidates); (2) render all operations for all target files in memory; (3) validate every operation and every target file, including the F4-06 route checks and the C-1 splice preconditions; (4) validate the resulting configurations; (5) write staged temporary files inside the candidate directory; (6) replace targets by temp-file-and-rename; (7) re-parse and validate all written files. Only after all application steps succeed may Batfish initialize the candidate snapshot — a partial or failed application is never loaded. If a write or rename fails partway, the disposable directory is quarantined or deleted; the original proposed snapshot is untouched. **Isolation invariant (F4-12):** every candidate starts from a fresh copy of the original proposed directory, never from another candidate's directory — candidate B has the same starting bytes as the original proposed snapshot even after candidate A was applied, verified, and cleaned up; verification always compares against the original baseline, never another candidate. The original baseline, original proposed, and any live device are never opened for writing — enforced by `patch.py` accepting only paths under the ephemeral root, plus tests asserting original file hashes are unchanged after a full run and asserting the candidate-B-pristine invariant.

**Batfish snapshot lifecycle protections (C-4, F4-11).** Candidate snapshots initialize with `overwrite=False` under validated names `{tag}-candidate-{candidate_id}` (`candidate_id` follows the existing Python-generated `c-NN` contract). A guarded `delete_snapshot(name)` wrapper in `batfish_client.py` (R4-04) deletes only names the current `BatfishClient`/run registered on successful candidate-snapshot creation — current-run tracking is mandatory, never pattern-based. It unconditionally refuses baseline and proposed snapshot names. A name leaves the registry only after successful deletion or an explicitly handled missing-snapshot outcome. Underlying Pybatfish exceptions are wrapped in `BatfishError` (matching the existing `connect`/`delete_network`/`ask` convention), so callers only ever see `BatfishError`. The run tag and candidate ID in `{tag}-candidate-{candidate_id}` are validated and sanitized with the existing network-name convention (`run_network_name`'s lowercase alphanumeric-plus-dash sanitizer; `candidate_id` keeps the Python `c-NN` contract). Each successfully created candidate snapshot is deleted in a `finally` block after its verification finishes — deletion failure produces a warning but never overwrites or masks the candidate outcome. Candidate directories are cleaned up per `KEEP_CANDIDATE_DIRS` (default `false`). The run-scoped network is deleted last using the existing protected cleanup mechanism, which must never modify or delete the shared `netops-lens-lab` network or its volumes. The lifecycle spike below verified the exact collision, deletion-error, and session semantics this design relies on.

**Verification (Python, per candidate).** Using the same tools as Stage A, with baseline values reused — never recomputed or re-derived (C-3): per-flow baseline reachability comes from `assessment.flow_comparisons[*].baseline_reach`; baseline health comes from `assessment.health` mapped by `SnapshotHealth.snapshot` name, never by tuple position; nothing is derived from findings or narrative text. Stage C then: (1) `get_snapshot_health` on the candidate; (2) `check_intent` for every declared flow on the candidate; (3) `compare_snapshots(client, store, flow, baseline_ref, candidate_ref)` per flow — the baseline stays the reference snapshot and the candidate is the subject — reconciled by reusing the existing `classify_flow` and `reconcile_flow` functions rather than reimplementing Stage A's direct/differential consistency logic. If the consistency-flag logic that feeds `reconcile_flow` is inline and not reusable, it is factored into the smallest shared helper without changing Stage A behavior, with regression tests proving existing classifications and verdicts unchanged. Stage C writes evidence into the same run-scoped `EvidenceStore`, so evidence IDs stay monotonic across Stages A, B, and C. Every Batfish call passes an explicit snapshot name: session initialization changes the session default snapshot (spike-verified), so no Stage C code may depend on the implicit session snapshot. The baseline is a *reference for comparison*, not a second intent gate: it does **not** need to satisfy every intent clause (a baseline carrying a known pre-existing violation is still a valid reference, and fixing that violation is a legitimate candidate goal). A candidate is **`VERIFIED`** only when *all* hold:

- baseline health is `OK` and every baseline flow disposition is known (no baseline `UNKNOWN`) — the comparison reference must be complete, though it may fail intent;
- candidate health is `OK`;
- the candidate satisfies *every* declared intent requirement: each `must_reach` flow REACHABLE on the candidate, each `must_not_reach` flow UNREACHABLE (blocked) on the candidate — including any requirement the baseline itself failed;
- no flow has regressed relative to baseline (every baseline-vs-candidate `FlowComparison`, computed from direct `check_intent` results and differential-reconciled, is `NO_CHANGE_OK` or `IMPROVEMENT`, never `REGRESSION`).

Otherwise: **`REJECTED`** when verification executed cleanly and at least one candidate requirement definitively failed — a `must_reach` still `UNREACHABLE` on the candidate, a `must_not_reach` REACHABLE on the candidate, or a protected-flow `REGRESSION` vs baseline — with each failed check listed (this includes the case where the candidate fixes the new regression but leaves a pre-existing violation standing: the intent requirement is definitively unmet, so the candidate is rejected, not verified); **`UNVERIFIABLE`** when verification itself cannot be trusted — baseline or candidate health `NOT_OK`, any baseline or candidate flow `UNKNOWN` (including differential-discrepancy `UNKNOWN`s), Batfish/tool error, or ops that failed to apply/parse — with the blocking reason listed. `REJECTED` means “proven not a fix”; `UNVERIFIABLE` means “could not be proven either way”, and neither may be presented as safe.

**Bounds.** `MAX_CANDIDATES = 3` per run — configurable in `config.py`, enforced in Python regardless of model behaviour. `MAX_PATCH_RETRIES` remains exclusively the Stage B submission-correction budget. **No post-verification model interaction (C-2):** no `revise_candidates`, no automatic candidate revision, no retry round after verification, no model-generated closing summary, no model call after Stage B. Stage C consumes validated candidates and performs deterministic Python application and Batfish verification only. Verification outcomes are findings-grade Python output with their own evidence records. Stage A's original verdict and findings remain unchanged by Stage C.

**Human approval and CLI ordering (F4-10).** A `VERIFIED` candidate surfaces in CLI/UI as *proposed, not applied*. The pipeline order is fixed: Stage A → Stage B → Stage C → collect human decisions → assemble the `Report` once → print/write once. The structured `FileDiff` is captured into `Report.applications` before candidate directories are cleaned up (R4-01); full report assembly and serialization integration belong to Phase 4.3. Every candidate entry carries `human_decision`, initialized `PENDING` — including `REJECTED` and `UNVERIFIABLE` candidates; only `VERIFIED` candidates may transition to `APPROVED`/`REJECTED` (R4-06 rule 3). Approval records a decision and authorizes nothing automatically — exporting the rendered config diff for manual change control is the end of the V1 workflow. Under `--json`, approval prompts are disabled and every candidate remains `PENDING`, so stdout stays machine-readable JSON (R4-06 rule 4); interactive approval prompts go to stderr. The assessment-driven exit codes (§CLI) are unchanged by Stage C.

### Phase 4.0 revision — finding traceability (C-1 to C-5, F4-06 to F4-12)

| Finding | Correction | Where specified |
|---|---|---|
| C-1 line-level splice | Replace stanza reconstruction with single-line delete/insert; additive parser span exposure; LF/CRLF byte-preservation tests | §Stage C “ACL application”; models `FileDiff`; Validation Plan patch row |
| C-2 no Stage C model calls | Remove retry round, revision, closing summary; `MAX_PATCH_RETRIES` Stage B only | §Stage C “Bounds” |
| C-3 baseline reuse | `flow_comparisons[*].baseline_reach`, health-by-name, reuse `classify_flow`/`reconcile_flow`, correct `compare_snapshots` arg order, shared store/monotonic IDs, explicit snapshot names | §Stage C “Verification” |
| C-4 lifecycle protections | `overwrite=False`, `{tag}-candidate-{candidate_id}`, guarded `delete_snapshot`, tracked-name deletion, `finally` cleanup | §Stage C “Batfish snapshot lifecycle”; lifecycle spike below |
| C-5 result models | `ApplicationResult` / `FileDiff` / `VerificationResult` (`FrozenModel`), explicit check IDs, touched-lines-only diff, snapshot-name-only, path-leak test | Models table; §Stage C “Human approval” (diff before cleanup); Validation Plan patch row |
| F4-06 strict routes | Fixture-dialect-only parsing, dotted-mask rendering, fail-closed duplicates/ambiguity | §Stage C “Strict route parsing” |
| F4-09 atomicity | 7-step render→validate→stage→rename→re-verify; never load partial application | §Stage C “Apply-to-copy” |
| F4-10 ordering | A→B→C→decisions→report once; VERIFIED-only approval; PENDING non-interactive; stderr prompts; JSON stays valid | §Stage C “Human approval”; §CLI exit codes unchanged |
| F4-11 cleanup | `finally` snapshot deletion, warning-not-mask, retention, network-last | §Stage C “Batfish snapshot lifecycle” |
| F4-12 isolation | Fresh-from-proposed invariant + test; baseline-relative verification | §Stage C “Apply-to-copy” |

### Final Phase 4.0 amendments — finding traceability (R4-01 to R4-06)

| Finding | Correction | Where specified |
|---|---|---|
| R4-01 application reporting | `Report.applications: list[ApplicationResult]`; models in 4.1, full assembly/serialization in 4.3; diff captured before cleanup | Models table; §Stage C “Human approval”; Phase 4.1–4.3 steps |
| R4-02 milestone map | Phase 4 split into 4.1 (application), 4.2 (verification), 4.3 (reporting + CLI), each with its own acceptance gate; no later milestone early | Steps §§Phase 4.1–4.3; Validation Plan gates |
| R4-03 rendering syntax | Exact V1 rules (CIDR→network+wildcard, `/32`→host, `any`, `eq` port, lowercase protocol) + recorded seq-10 permit line with provenance | §Stage C “Exact V1 rendering rules” |
| R4-04 snapshot deletion | Mandatory current-run registry; unconditional baseline/proposed refusal; registry removal only after success/handled-missing; `BatfishError` surface; tag/ID sanitization per existing convention | §Stage C “Batfish snapshot lifecycle” |
| R4-05 observation record | Spike preserved as recorded observation; Q3 and cleanup wording corrected to past-tense observation | §Phase 4.0 lifecycle spike |
| R4-06 explicit rules | Contract revalidation (1); every-line five-token route dialect (2); all-`PENDING`, VERIFIED-only approval (3); `--json` all-`PENDING` (4); `KEEP_CANDIDATE_DIRS=false` (5) | §Stage C (Restricted ops, Strict routes, Human approval); §CLI; Configuration |

### Phase 4.0 lifecycle spike — verified results

Isolated disposable run-scoped networks (`netops-lens-p40-<ts>`, never `netops-lens-lab`); probes kept in `/tmp`, outside the repo; throwaway networks and temp dirs removed in `finally`. Batfish reachable via Pybatfish at `localhost`. The table below preserves the Phase 4.0 spike observations exactly as recorded at the time; it was not independently re-run or re-verified since.

| # | Question | Observed result |
|---|---|---|
| Q1 | `init_snapshot(..., overwrite=False)` on an existing name | Raises — the existing snapshot is not overwritten |
| Q2 | Exception on collision | `ValueError: A snapshot named <name> already exists in network <net>. Use overwrite = True if you want to overwrite the existing snapshot.` |
| Q3 | State after collision | Snapshot list unchanged; the existing snapshot still answers `fileParseStatus` (2 rows, `PASSED`) — collision is non-destructive |
| Q4 | `delete_snapshot` on a nonexistent name | Raises `HTTPError: 404 Client Error` for `.../v2/networks/<net>/snapshots/<name>` — cleanup code must treat this as a warning, never a mask |
| Q5 | Session snapshot tracking | The session tracks a default: `get_snapshot()` raises `ValueError: snapshot must be either provided or set using set_snapshot` before any init, and returns the new name after `init_snapshot` — init **changes** the session default, so every call must pass an explicit snapshot name |
| Q6 | Rendered ACL (seq-10 permit + seq-20 deny) parses | `fileParseStatus`: 2 rows, statuses `[PASSED]` |
| Q7 | First-match evaluation | Same TCP/1433 flow: proposed `DENIED_IN`, candidate `ACCEPTED`; TCP/22 `DENIED_IN` on both — permit-10 evaluated first, untouched deny-20 still enforced |
| Q8 | Independent candidate parsing | Per-snapshot answers differ as rendered (no stale parse); candidate snapshot answers immediately after init alongside proposed in the same network |

Cleanup observed: `delete_snapshot` + `delete_network` in `finally` with zero errors; `list_networks` afterwards showed only `netops-lens-lab`; all `/tmp` probe workdirs removed; repo `git status` showed no unintended modifications at observation time. **Explicitly unverified:** multi-row `differentialReachability` output (only single-Flow-row answers observed live — the candidate verification path inherits the Stage A single-row observation plus synthetic multi-row tests); live CRLF-fixture splice (specified and test-gated in Phase 4.1, not probed).

### Phase 4.0 residual risks and Phase 4.1 recommendation

Risks carried into Phase 4.1: (1) real-world stanzas with remarks or unnumbered lines fail closed by design — correct for V1 fixtures but may reject repairs on richer configs; (2) CRLF byte-preservation is specified, not yet live-proven — the LF/CRLF test gate covers it; (3) session default-snapshot switching is mitigated by the explicit-name discipline plus the guarded wrapper; (4) a process crash mid-verification can orphan a candidate snapshot — backstop is run-network deletion, which never touches `netops-lens-lab`; (5) the `delete_snapshot` 404 contract is pybatfish-version-specific — the wrapper treats any deletion error as a warning. **Recommendation: Phase 4.1 GO.** All eight lifecycle assumptions the design depends on are empirically verified (Q1–Q8); the two unverified items are covered by fail-closed reconciliation and explicit test gates, not by optimism. Phases 4.1–4.3 implement `patch.py` / `verify.py` / report-and-CLI integration per this revised section with no further model interaction and no production source changes beyond Stage C modules, CLI wiring, and tests.

## CLI (`cli.py`) — first functional interface

The CLI is how V1 is used and tested before any UI exists; the UI is a thin shell over the same pipeline functions.

- `python -m netops_lens assess --baseline <path> --proposed <path> --intent <intent.yaml> [--question "…"] [--scenario <name>]` — runs Stage A; Stage B in the verdict-gated mode of §Stage B (investigate+propose only on `REGRESSION_DETECTED`; explain-only otherwise; `--no-investigate` skips the narrative but can never skip Stage A); Stage C only when candidates were accepted. Prints the Python verdict + per-flow table first, then investigation, then per-candidate verification; `--json` emits the full `Report` JSON to stdout/file for machines and tests. Exit codes: 0 = completed `REGRESSION_DETECTED` or `NO_REGRESSION_DETECTED` assessment, 2 = **any** `INCONCLUSIVE` assessment — health `NOT_OK`, unknown flows, differential discrepancies, or pre-existing violations — 1 = input/usage error (bad paths, malformed intent, invalid arguments; no assessment ran). Scripts can thus distinguish “assessed, with verdict” (0, verdict in output) from “could not conclusively assess” (2) and “never ran” (1).
- Scenario shortcut resolves baseline/proposed/intent exclusively through `lab/scenarios/manifest.yaml`.
- Interactive human decision: after a `VERIFIED` candidate, `assess` prompts `Approve candidate c-01? [a]pprove / [r]eject / [s]kip`; the decision is written into the report JSON. Every candidate entry carries `human_decision` starting at `PENDING` — `REJECTED` and `UNVERIFIABLE` candidates stay `PENDING` and can never be approved. Under `--json` (or any non-interactive run) prompts are disabled and every candidate remains `PENDING`, keeping stdout machine-readable. Approval applies nothing.

## Streamlit UI (`app.py`) — minimal visual demo target (after CLI works)

Single page, all state in `st.session_state`, built only once the CLI pipeline passes its E2E tests:

1. **Setup (sidebar):** scenario picker (from the manifest) *or* manual baseline/proposed snapshot selects, intent file display (read-only summary of flows; editing is stretch), engineer question input.
2. **Run:** “Run assessment” button; progress via `st.status` streaming Stage A completion, Stage B `tool_activity`, then Stage C per-candidate progress.
3. **Assessment (Python, independent):** verdict banner rendered *directly and only* from `Report.assessment.verdict` (color-coded) with the per-flow comparison table and expandable Python findings/evidence (stored tool-result JSON, hop tables). Renders with no investigation present; no model text inside this region.
4. **Investigation, candidates & verification:** “Investigation (Muse Spark)” narrative panel; each candidate rendered as an operations table (op, node, parameters) plus its rendered config diff against the proposed copy; each `VerificationResult` as a checklist (baseline reference valid, candidate health, each `must_reach`, each `must_not_reach`, protected-flow regression check) ending in `VERIFIED`/`REJECTED`/`UNVERIFIABLE`.
5. **Human approval:** for each `VERIFIED` candidate, Approve/Reject buttons that record `human_decision` on the report and offer the config-diff download. Buttons state explicitly that approval does not deploy anything.

UI never calls Batfish or the LLM directly; it calls the same pipeline entry point as the CLI. UI copy must distinguish confirmed / violated / inconclusive and must not claim untested traffic is safe.

## Configuration & Dependencies

- `pyproject.toml` pins: `pybatfish`, `pandas`, `streamlit`, `pydantic>=2`, `pyyaml`, `python-dotenv`, `httpx` (or the official Meta API client if provided — decide in Phase 3 spike, see Risks); dev extra: `pytest`, `mypy`, `ruff`. The file must contain, verbatim in effect:

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
```

  This keeps routine `pytest` runs scoped to `tests/` so the preserved top-level manual smoke scripts (`test_batfish.py`, `test_diff.py` — Batfish-connecting scripts with no assertions) are never collected as tests. They remain runnable by hand (`python test_batfish.py`) exactly as today.
- Environment: reuse the existing `netops-env` environment — do **not** create a new project `.venv`. Activate `netops-env`, then install the project plus development dependencies with `python -m pip install -e ".[dev]"` (run from the repo root; `python` is the `netops-env` interpreter). `.gitignore` keeps both `netops-env/` and `.venv/` ignored so either layout stays out of Git.
- `.env` (git-ignored, `.env.example` committed): `META_API_KEY`, `BATFISH_HOST=localhost`, optional `AGENT_MAX_TOOL_CALLS=8`, `MAX_CANDIDATES=3`, `MAX_PATCH_RETRIES=1`, `BATFISH_NETWORK=netops-lens-lab`, `KEEP_CANDIDATE_DIRS=false`. Ephemeral candidate dirs under `runs/` are git-ignored.
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

**Essential V1 (ship-blocking, in dependency order):** (1) working deterministic assessment (mandatory Stage A: health OK/NOT_OK, baseline+proposed intent and differential checks for every flow, evidence four-check validation, verdict precedence) exposed through the CLI; (2) the three network scenarios (`healthy`, `removed_route`, `acl_blocks_db`) via the manifest; (3) real Muse Spark tool calling (Phase 0 smoke test, then Stage B investigation with `trace_flow`/`get_routes` and restricted candidate generation); (4) candidate patch verification (Stage C, `VERIFIED`/`REJECTED`/`UNVERIFIABLE`); (5) minimal Streamlit over the finished CLI pipeline (assessment, investigation, candidates, verification, human approval); (6) a reproducible demo (CLI commands + timed 3-minute video script). The smallest *complete* application (M2, below) is the priority: it beats polish on every stretch item.

**Stretch (only after the essential path is green; none may delay it):** incomplete-configuration scenario handling; extensive linting/type-strictness beyond “no errors on new modules”; large benchmarks or scenario matrices beyond the three essential scenarios; optional UI features (in-app YAML editing, run history, JSON-export niceties); untrusted-subnet ACL variant; richer `get_routes` output beyond root-cause needs. Lint/type tooling is configured minimally in Phase 0 and tightened only if time remains.

## Steps (phases, dependencies, acceptance)

### Phase 0 — Foundation + Meta API smoke test (no network-behavior change)

Create `pyproject.toml` (including `[tool.pytest.ini_options] testpaths = ["tests"]`, §Configuration), `.gitignore` (both `netops-env/` and `.venv/`), `.env.example`, `README.md` (prerequisites + how to run preserved smoke scripts), `src/netops_lens/` skeleton with `config.py` + `models.py` (contracts above), empty `tests/` with `conftest.py` Batfish-health fixture. Reuse the existing `netops-env` environment (no new `.venv`); install with `python -m pip install -e ".[dev]"`. **In the same phase**, add `scripts/spike_meta_api.py`: the earliest possible verification of the Muse Spark integration, deliberately before any backend build-out — (a) one authenticated chat completion against the Meta Model API using the `.env` key, asserting the configured Muse Spark 1.3 model responds; (b) one tool-calling round-trip with a single dummy `echo` tool (model must emit a structured tool call, script executes it locally, returns the result, model acknowledges), asserting the exact tool-schema dialect, tool-call message shape, and result-return shape the adapter in `agent.py` will use; (c) register the real nested `submit_candidate_patch` schema (without executing anything) and confirm the API accepts it — if it does not, record the structured-output fallback as the live submission variant in `config.py`. Output is pass/fail + the observed shapes (key never printed; failures exit non-zero with the API error class only).
**Depends on:** nothing. **Acceptance:** `python -m pip install -e ".[dev]"` succeeds inside `netops-env` on Python 3.14 (no new `.venv` created); `pytest tests/test_models.py` passes (serialization round-trips) and a bare `pytest` run collects only `tests/` (neither preserved smoke script is collected); `python scripts/spike_meta_api.py` passes (or, with no key/network, fails loudly and is recorded as the Phase 3 blocker — the failure must be known *now*, not discovered in Phase 3); preserved files untouched (`git status` shows only new files).

### Phase 1 — Fixtures & Batfish client

Create fixtures *exactly* per §Fixture Mapping (`lab/scenarios/manifest.yaml`, `healthy/proposed`, `acl_blocks_db/{baseline,proposed}`; `incomplete/` deferred to stretch), `examples/intent.yaml` + `examples/intent-acl.yaml`, and `batfish_client.py` (session, `init_snapshot` with overwrite, DataFrame->records conversion, health gate combining `fileParseStatus` + `initIssues` + `nodeProperties`). First test in this phase is observational: capture real `initIssues` columns/severities, partial-parse tokens, TCP/UDP traceroute dispositions for the ACL ports, whether traceroute step detail exposes ACL name/matched rule (and what Batfish `testFilters` returns for the denied TCP/1433 flow), the real `differentialReachability` output shape (which flows appear, trace fields), and pin them as fixtures/constants — health string-matching, ACL identification, and differential reconciliation are coded only against observed values.
**Depends on:** Phase 0. **Acceptance:** pytest integration proves preserved baseline health `OK`; healthy proposed traceroute `ACCEPTED`; preserved proposed `NO_ROUTE`; ACL baseline TCP/1433 `ACCEPTED` + TCP/22 `DENIED_*` (baseline satisfies both ACL intent clauses); ACL proposed TCP/1433 `DENIED_*` + TCP/22 still `DENIED_*`. Health tests: an exactly allowlisted benign warning (once one is evidenced and added) yields `OK` with the warning verbatim in `benign_warnings`; an unrecognized/synthetic warning text yields `NOT_OK` with its original details verbatim in `reasons`; a partially parsed file yields `NOT_OK`. ACL tests: `get_acl_rules` on both ACL snapshots returns exactly sequences 10/20 with the expected actions/ports and `raw_line`s (proposed sequence 10 = deny 1433, sequence 20 = deny 22), and errors — omitting nothing — on a deliberately malformed ACL line; Trace/`testFilters` identification of the sequence-10 deny is demonstrated by reconciling `matched_line_content` against parser output (sequence from the config, `batfish_line_index` kept as provenance only, never as the sequence); if the trace does not name the filter, `testFilters` across the relevant filters on the denying node must be shown to identify the deciding ACL — and a synthetic ambiguous case (multiple unresolved candidate rules) is tested to produce UNVERIFIABLE-candidate handling rather than a guessed sequence. Differential observation: the changed-flow output for removed-route is captured, and a test asserts an absent flow is recorded as “not reported”, never as unchanged proof. ICMP pinned in comparable tests; protocols/ports pinned per `FlowSpec` otherwise.

### Phase 2 — Mandatory deterministic assessment + CLI (no LLM) — Milestone M1

Implement `tools.py` (6 tools), `intent.py`, `evidence.py`, `assessment.py`, `report.py` (findings assembly; investigation/verifications empty), and `cli.py` with `run_mandatory_assessment()` executing the §Assessment Engine contract in fixed order: health on both snapshots -> `check_intent` for every flow on baseline -> every flow on proposed -> `compare_snapshots` for every flow. There is no flag, prompt, or callback that skips a mandatory check.
**Depends on:** Phase 1. **Acceptance:** `pytest tests/test_tools_integration.py tests/test_evidence.py tests/test_assessment.py tests/test_e2e.py` pass against live Batfish via the CLI (`--scenario` for each essential scenario): removed-route -> `REGRESSION_DETECTED`, healthy -> `NO_REGRESSION_DETECTED`, ACL -> `REGRESSION_DETECTED`. All 18 per-flow grid rows + 10 aggregation cases pass synthetically; findings failing any of the four evidence checks are rejected in unit tests; a completeness test proves a `FlowComparison` exists for every declared flow; preserved/original hashes untouched.

### Phase 3 — Muse investigation & candidate generation

Build `prompts.py` + `agent.py` on the tool-calling shapes already proven by the Phase 0 smoke test (no API discovery remains here): verdict-gated Stage B loop over `trace_flow`/`get_routes`/`get_acl_rules` with arg validation, evidence minting, bound, and `tool_activity` log, plus the non-executing `submit_candidate_patch` tool (registered only on `REGRESSION_DETECTED`) into `CandidatePatch`/`PatchOperation` models. Add `test_agent.py` with recorded/fake model responses (valid investigation, bad args, unknown finding-ID reference hidden, ACL op with an un-evidenced/guessed sequence rejected, free-text patch rejected then abandoned, submission attempted on `NO_REGRESSION_DETECTED`/`INCONCLUSIVE` rejected as `candidates_not_allowed`, loop-until-bound).
**Depends on:** Phase 2 and a passing Phase 0 Meta smoke test. **Acceptance:** live CLI runs: removed-route — Stage A output identical with investigation on or off (`--no-investigate` byte-compares the assessment section), agent calls `trace_flow` (and `get_routes` for the missing-route root cause); ACL scenario — agent identifies the denying rule from trace detail or `get_acl_rules` before submitting; healthy scenario — successful checks reported with zero candidates and Stage C skipped; `AssessmentResult` hash unchanged after Stage B in all cases.

### Phase 4.1 — Candidate application

Implement `patch.py` (atomic apply-to-copy under `runs/`, original-path refusal, line-level ACL splice per C-1 with `remove_acl_line` expected-rule pre-verification, strict fixture-dialect route rendering per F4-06, exact V1 rendering rules per R4-03), the `ApplicationResult` and `FileDiff` models, and the guarded `BatfishClient.delete_snapshot()` per R4-04. `patch.py` independently revalidates the complete Stage B candidate contract (R4-06 rule 1); every `ip route` line in a target route file must meet the five-token dialect (R4-06 rule 2). No verification, report assembly, or CLI Stage C wiring in this milestone — later milestones are not implemented early.
**Depends on:** Phase 3. **Acceptance:** V1 ACL repair lands as a byte-exact line-level splice on LF and CRLF fixtures (rendered seq-10 line per R4-03, ahead of seq-20); multi-stanza same-name and remark/unnumbered-line rejection; wrong-sequence/wrong-`expected_rule` removal aborts as an application failure deleting nothing; arbitrary/occupied-sequence insertion rejected; `acl_deny`, mixed, and malformed candidates rejected by the revalidation gate; an unsupported route line anywhere in a target file rejects; candidate-B-pristine isolation; `delete_snapshot` wrapper tests (registry-only deletion, baseline/proposed refusal, `BatfishError` surface, tag/ID sanitization); `FileDiff` touched-lines-only; original baseline/proposed hashes unchanged.

### Phase 4.2 — Independent verification

Implement `verify.py` (candidate health + all `must_reach` + all `must_not_reach` + baseline-vs-candidate differential per candidate -> `VERIFIED`/`REJECTED`/`UNVERIFIABLE` with explicit check IDs, reusing the factored `classify_flow`/`reconcile_flow` helper per C-3) and the frozen `VerificationResult` model. No model calls, no report changes, no CLI wiring in this milestone.
**Depends on:** Phase 4.1 (applied candidates exist to verify; the `verify.py` logic itself depends only on Phase 2). **Acceptance:** removed-route `add_static_route` -> `VERIFIED`; ACL repair (remove seq-10 deny, insert TCP/1433 permit at freed seq-10) -> `VERIFIED` with seq-20 (TCP/22) still blocked; a candidate that opens TCP/22 or leaves `must_reach` broken -> `REJECTED` with failed checks listed; the two baseline-reference cases (fixes regression + pre-existing violation -> `VERIFIED`; fixes regression only -> `REJECTED`); a candidate breaking config parse -> `UNVERIFIABLE`; any baseline/candidate `UNKNOWN` -> `UNVERIFIABLE`.

### Phase 4.3 — Reporting and CLI integration

Assemble `Report.applications`/`verifications` with full serialization, wire CLI Stage C orchestration with the F4-10 ordering, human-decision handling per R4-06 rules 3–4, candidate and network cleanup integration (`KEEP_CANDIDATE_DIRS`, `finally` snapshot deletion, network-last), and JSON plus human-readable report output. Add end-to-end CLI tests in `tests/test_patch_verify.py` alongside the 4.1/4.2 unit scopes.
**Depends on:** Phase 4.2. **Acceptance:** full CLI runs produce `VERIFIED` candidates with structured diffs present in `Report.applications`; `--json` output stays machine-readable with every candidate `PENDING`; interactive approval offered for `VERIFIED` candidates only; a report-serialization test proves no repository/home paths leak; `MAX_CANDIDATES` bound enforced; no post-verification model calls.

### Phase 5 — Minimal Streamlit UI, hardening & demo

Implement `app.py` per §Streamlit UI (assessment, investigation, candidates, verification checklists, human approval) over the CLI-proven pipeline; add a UI smoke test for the three essential scenarios' verdict/verification displays. Then hardening: error-path tests (missing snapshot dir, malformed YAML, empty intent, model timeout), README finalization, secret scan, preserved-file byte check. Stretch thereafter only: `incomplete` fixture, strict lint tightening, UI extras, large benchmarks. Write `docs/demo-script.md` and rehearse against §Demo (3-Minute Hackathon Video).
**Depends on:** Phase 4.3. **Acceptance:** `streamlit run app.py` click-through reproduces the CLI verdict + verification for each essential scenario and records a human decision; essential `pytest` green with Batfish up; documented skip behaviour with Batfish down; no secrets in git; timed demo rehearsal <= 3:00 from README + demo script alone.

## Validation Plan

| Gate | Command / check | Expected evidence |
|---|---|---|
| Contracts | `pytest tests/test_models.py tests/test_intent.py tests/test_evidence.py tests/test_assessment.py` | All pass without Batfish; 18 per-flow grid rows + 10 aggregation cases covered; each of the four evidence checks fails independently |
| Integration | `pytest tests/test_tools_integration.py -v` (Batfish up) | 6 tools exercised; dispositions asserted (not printed): `ACCEPTED` / `NO_ROUTE` / `DENIED_*`; health `OK`/`NOT_OK` + reasons asserted incl. `initIssues`-driven cases |
| E2E deterministic (CLI) | `pytest tests/test_e2e.py -v` + `python -m netops_lens assess --scenario <each>` | Essential scenarios -> expected verdicts in §Fixture Mapping; assessment identical with/without investigation |
| Meta smoke | `python scripts/spike_meta_api.py` (Phase 0, re-run before Phase 3) | Auth + dummy-tool round-trip pass; observed schemas recorded for the adapter |
| Investigation | `pytest tests/test_agent.py -v` + live removed-route + ACL + healthy runs | Fake-response tests pass (incl. unknown finding-ID segment hidden, guessed ACL sequence rejected, free-text patch rejected, off-verdict submission rejected); live ACL run evidences the denying rule (trace detail or `get_acl_rules`) before submitting; healthy run yields zero candidates; assessment hash unchanged |
| Candidate application (4.1) | `pytest tests/test_patch_verify.py -v` (application scope; Batfish up) | Byte-exact seq-10 splice on LF + CRLF (rendered line per R4-03); multi-stanza/remark rejection; wrong-sequence/`expected_rule` aborts deleting nothing; arbitrary/occupied-sequence insertion rejected; `acl_deny`/mixed/malformed rejected by revalidation; unsupported route line anywhere rejects; candidate-B-pristine isolation; `delete_snapshot` wrapper (registry-only, baseline/proposed refusal, `BatfishError`); `FileDiff` touched-lines-only; originals hash-unchanged |
| Independent verification (4.2) | `pytest tests/test_patch_verify.py -v` (verification scope; Batfish up) | Restored-route `VERIFIED`; ACL repair `VERIFIED` with seq-20 blocked; security-breaking `REJECTED`; unparseable `UNVERIFIABLE`; baseline-reference cases; any `UNKNOWN` → `UNVERIFIABLE` |
| Reporting + CLI (4.3) | CLI e2e on both scenarios, incl. `--json` | Structured diffs in `Report.applications` before cleanup; `--json` machine-readable with every candidate `PENDING`; interactive approval VERIFIED-only; no repository/home paths in serialized report; `MAX_CANDIDATES` enforced; no post-verification model calls |
| UI | `streamlit run app.py` + scenario click-through; UI smoke test | Assessment/investigation/candidates/verification/approval all shown matching CLI output; Batfish-down state graceful |
| Preservation | `git diff --stat` on preserved paths; full `pytest` | Zero diff on `test_batfish.py`, `test_diff.py`, `lab/baseline/**`, `lab/proposed/**` |
| Types (essential bar) | `mypy src/` | No errors on new modules; strict lint tightening is Phase 5 stretch, not a ship gate |

Highest-risk validations, in order: the Phase 2 CLI verdict matrix against live Batfish (reconcile before any model work), then the Phase 4 verification split — a candidate that merely *looks* like a fix must land in exactly one of `VERIFIED`/`REJECTED`/`UNVERIFIABLE` for the stated reason, with originals proven untouched.

## Risks / Open Questions

| Risk | Impact | Mitigation in this plan |
|---|---|---|
| Meta Model API endpoint/model/tool-calling surface differs from assumptions | Phase 3 rework if found late | Discovered in Phase 0 by `scripts/spike_meta_api.py` (auth + dummy-tool round-trip); `agent.py` isolates the API behind one adapter function built on the observed shapes |
| Batfish not running during tests/demo | False failures, blocked demo | Health gate + explicit skip-with-message; README prerequisite; UI disabled-state |
| Pybatfish/DataFrame shape drift across versions | Tool parsing breaks | DataFrame conversion isolated in `batfish_client.py`; integration tests assert dispositions, not column layouts, where feasible |
| LLM fabricates evidence, skips checks, or restates a verdict | Unsafe report | Mandatory Stage A has no model hook; Python-only findings with the four evidence checks; narrative segments citing unknown finding IDs hidden; verdict rendered independently from `AssessmentResult`; assessment hash-checked across Stage B |
| Model proposes unsafe/unbounded patches, or guesses ACL sequences | Bad config reaches a network; wrong ACL line edited | Candidates only via non-executing `submit_candidate_patch`, only on `REGRESSION_DETECTED`; allowlist ops with explicit `sequence_number`, sequences must trace to `trace_flow`/`get_acl_rules` evidence; `remove_acl_line` expected-rule pre-verified; Python renders onto ephemeral copies and Batfish-verifies (`VERIFIED` needs all intent + no protected regression); human approval records a decision and deploys nothing; originals hash-tested |
| Intent semantics ambiguous (e.g., “reach” = any protocol?) | Wrong verdicts | Protocol/port pinned per flow in `FlowSpec`; unmapped disposition or missing evidence -> `UNKNOWN` instead of guessing |
| ACL scenario disposition naming varies (`DENIED_IN` vs `DENIED_OUT`), TCP traceroute behavior unverified | Brittle tests | Assert disposition family/prefix and per-flow classification, not one exact string, after Phase 1 observation; ACL baseline-satisfies-intent outcomes are an explicit Phase 1 acceptance gate |
| `initIssues` schema/severity spellings and partial-parse tokens unverified | Health gate misclassifies | Phase 1 observational test pins real columns/values before string matching is coded; conservative default (any issue not exactly matching the benign-warning allowlist -> `NOT_OK` with verbatim details) |
| Incomplete-config scenario may parse with warnings, not errors | Weak inconclusive fixture | Stretch only: confirm empirically in Phase 5; if Batfish tolerates it, use a missing-interface reference that yields `UNKNOWN` outcomes instead. Never blocks essential path |
| Scope creep from candidate proposals to deployment | Safety + time | Candidates stop at verified proposal + human decision + diff export; no device/apply path exists in code; op allowlist cannot express arbitrary config |

Unresolved technical assumptions (to pin empirically, in order): (1) Meta Model API base URL, Muse Spark 1.3 model identifier, and tool-calling message/schema dialect — including whether a tool can carry the nested `submit_candidate_patch` schema or the structured-output fallback is required — resolved by the Phase 0 smoke test; whether an official client or raw `httpx` is the right transport follows from what the smoke test observes. (2) Batfish `initIssues` column names, severity values, and partial-parse status tokens — resolved by the Phase 1 observational test. (3) Exact Batfish dispositions for TCP flows to ports 1433/22 through the ACL (`DENIED_IN` vs `DENIED_OUT`, and whether host-port filtering is modelled as expected) — resolved in Phase 1. (4) Whether Batfish traceroute step detail and/or `testFilters` expose the deciding ACL name and matched rule for a `DENIED_*` TCP/1433 hop, in a form reconcilable (by rule content) against the `get_acl_rules` config-parser output — resolved in Phase 1; `get_acl_rules` itself no longer depends on Batfish (it parses config text), but if neither trace nor `testFilters` can identify *which* rule matched, ACL root-cause attribution — not the sequence numbering — is the Phase 1 gap (route candidates would proceed, ACL repair candidates would return `UNVERIFIABLE`). (5) Batfish Docker image already proven by the preserved scripts; Streamlit single-user local demo (no auth) acceptable for V1. No blocking product questions remain.

## Sequential vs Delegable Work

Must stay sequential (single owner, in order): Phase 0 contracts (`models.py`) -> Phase 1 `batfish_client.py` -> Phase 2 `tools.py`/`evidence.py`/`assessment.py`/`cli.py` -> Phase 3 `agent.py` -> Phase 4.1 `patch.py` -> Phase 4.2 `verify.py` -> Phase 4.3 report/CLI wiring -> Phase 5 `app.py`. Each stage's contract is the next stage's input; parallel edits here create integration churn. No milestone is implemented early: 4.2 lands in its own milestone (hand-written candidate fixtures may be used as test inputs within 4.2), and 4.3 owns all report/CLI integration.

Safe to delegate to independent subagents once the preceding contract lands:

| Work package | Can start after | Notes |
|---|---|---|
| Scenario fixtures + `examples/intent.yaml` | Phase 0 | Config-only; validated by Phase 1 tests |
| `test_evidence.py` / `test_assessment.py` (synthetic, no Batfish) | `models.py` frozen | Pure unit tests, no shared state |
| Streamlit page shell with fake `Report` data | `models.py` frozen | Merge behind `run_assessment()` before Phase 4.3 acceptance |
| README / demo script / `.env.example` docs | Phase 0 | No code coupling |
| Agent fake-response test corpus | Tool schemas frozen (Phase 2) | Recorded JSON fixtures only |

Rule: subagents never edit preserved files or another package's module concurrently; integration (Phase 2 E2E, Phase 4.3 wiring) stays with one owner.

## Smallest Working End-to-End V1 Milestone

**Milestone M1 (end of Phase 2, deterministic core):** CLI pipeline — `python -m netops_lens assess --scenario removed_route` -> mandatory Stage A -> `REGRESSION_DETECTED` with per-flow evidence, printable as JSON. No LLM, no UI. Proves snapshots, intent, tools, evidence, and verdict before AI/frontend risk.

**Milestone M2 (end of Phase 5, smallest *complete* application — the delivery priority):** M1 + Muse investigation with a `VERIFIED` restored-route candidate + minimal Streamlit showing assessment, investigation, candidate, verification, and human approval. If time forces a choice, M2 ships and every stretch item (incomplete scenario, strict lint, benchmarks, UI extras, untrusted-subnet variant) is cut — a complete small application beats a polished partial one.

## Demo (3-Minute Hackathon Video) — `docs/demo-script.md`

The final submission demo is a **3-minute** video; the script is timed, rehearsed, and treated as an acceptance artifact, not an afterthought:

| Time | Beat | On screen |
|---|---|---|
| 0:00–0:25 | Problem | “A route/ACL edit can silently break app-to-DB traffic. NetOps Lens checks the change *before* deployment.” Show the two-router topology + intent |
| 0:25–0:50 | Healthy baseline | Pick `healthy` from the manifest, run: agent activity streams, Python verdict `NO_REGRESSION_DETECTED` |
| 0:50–1:50 | Regression investigation | Pick `removed_route` (preserved pair), ask “will the app still reach the DB?”: Python's mandatory checks show `REGRESSION_DETECTED` (`NO_ROUTE`, evidence IDs visible); Muse then traces the flow and reads routes to root-cause the missing static route |
| 1:50–2:30 | Patch & verify | Muse proposes `add_static_route` as structured operations; Python applies it to a disposable copy only, re-runs health + intent + differential checks, and marks it `VERIFIED`; engineer clicks Approve (on-screen note: approval deploys nothing). Cutaway if time is tight: `acl_blocks_db` per-flow table (one `REGRESSION`, one `NO_CHANGE_OK`) |
| 2:30–3:00 | Trust & close | Point at the separation: Python owns checks/findings/verdict/verification, Muse owns investigation/proposals; originals never modified; `INCONCLUSIVE`/`UNVERIFIABLE` never mean safe. End card: stack (Batfish, Muse Spark, Streamlit) |

Rehearsal checklist (Phase 5 acceptance): Batfish pre-warmed and snapshots pre-initialized so no Docker wait lands on camera; API key loaded from `.env` (never visible); each run rehearsed end-to-end at least twice with a stopwatch (hard cap 3:00, target 2:45); fallback if the live API is unavailable during recording — record the deterministic M1 path plus findings and narrate the agent's role over the activity log, and disclose the substitution in the video notes rather than faking a live call.

## V1 vs Future

**Essential V1 (this plan):** mandatory deterministic assessment (CLI) with `must_reach`/`must_not_reach` intent, 6 read-only Batfish tools, four-check evidence validation, Muse root-cause investigation + restricted candidate patches, Python patch verification on disposable copies, Python verdict shown independently, minimal Streamlit (assessment/investigation/candidates/verification/approval), scenarios `healthy`/`removed_route`/`acl_blocks_db`, 3-minute demo.

**Stretch within V1 time (only if essential path is green):** incomplete-configuration handling, untrusted-subnet ACL variant, extensive lint gates, large benchmarks, optional UI features (see §Delivery Priorities).

**Future (explicitly out):** applying any patch to a real snapshot or live device, autonomous remediation, free-form config generation beyond the op allowlist, multi-vendor/topology upload beyond snapshot dirs, auth/multi-user, saved-run history/database, voice/multimodal, local models, broader protocol/port intent language, CI Batfish service. Each needs its own plan and safety review; none is stubbed in V1 beyond the clean module boundaries above.
