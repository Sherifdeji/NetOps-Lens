# NetOps Lens

NetOps Lens is an AI-assisted network change investigation tool (Meta Global AI Developer Hackathon). A network engineer declares required connectivity in an intent file (`must_reach` / `must_not_reach`) for a baseline/proposed snapshot pair, and NetOps Lens checks the proposed change *before* deployment. The trust model, in one breath: **Batfish decides facts, Muse Spark investigates and proposes, Python validates and owns every verdict** — and the whole system is read-only, so nothing is ever deployed, pushed, or applied to any device.

## Architecture

One backend entry point serves both frontends: `run_assessment_pipeline` in `src/netops_lens/pipeline.py`, called by the CLI (`src/netops_lens/cli.py`) and the Streamlit UI (`app.py`).

- **Stage A — mandatory deterministic assessment.** Python runs read-only Batfish checks (snapshot health, intent reachability, baseline-vs-proposed differential) over every declared flow and computes the verdict: `REGRESSION_DETECTED`, `NO_REGRESSION_DETECTED`, or `INCONCLUSIVE`. This stage always runs and never needs the model.
- **Stage B — bounded investigation.** Runs after Stage A on every verdict unless skipped (`--no-investigate`) or no `META_API_KEY` is configured (recorded skip). The investigation tools (`trace_flow`, `get_routes`, `get_acl_rules`) and the candidate-submission tool are registered only on `REGRESSION_DETECTED`; on `NO_REGRESSION_DETECTED` and `INCONCLUSIVE` the model explains the Python findings in narrative only — no tools, no candidates, any submission rejected. Candidate patches are typed (`add_static_route`, `remove_static_route`, `acl_permit`, `remove_acl_line`; `acl_deny` is schema-present but rejected by Python validation in V1). Every submission is validated against run-scoped Batfish evidence; anything un-evidenced is rejected.
- **Stage C — independent verification.** Python applies each accepted candidate to a disposable copy of the proposed snapshot, re-runs health, intent, and differential checks against the candidate, and marks it `VERIFIED`, `REJECTED`, or `UNVERIFIABLE`. Human review then records `APPROVED`/`REJECTED`/`PENDING` — approval is a recorded decision only and deploys nothing.

## Prerequisites

- Python 3.14 with the existing `netops-env` environment. Do not create a new virtualenv.
- A Batfish service reachable at `$BATFISH_HOST` (default `localhost`) before any Batfish-backed test or run.
- A Meta Model API key for live investigation. If the key is absent, Stage B is skipped with a recorded note and the deterministic assessment still works.

## Setup

```bash
python -m pip install -e ".[dev]"
cp .env.example .env   # then fill in values; .env is git-ignored and never committed
```

| Variable | Purpose | Default |
|---|---|---|
| `META_API_KEY` | Meta Model API key for live investigation; absent/blank disables live calls | (unset) |
| `META_API_BASE` | Meta Model API base URL (`/chat/completions` lives under it) | `https://api.meta.ai/v1` |
| `META_MODEL` | Chat model identifier for Stage B investigation | `muse-spark-1.3` |
| `CANDIDATE_SUBMISSION_VARIANT` | `tool` or `structured_output` candidate submission style | `tool` |
| `BATFISH_HOST` | Host of the Batfish service | `localhost` |
| `BATFISH_NETWORK` | Shared Batfish network name (protected; never used as a disposable run network) | `netops-lens-lab` |
| `AGENT_MAX_TOOL_CALLS` | Investigation loop bound | `8` |
| `MAX_CANDIDATES` | Candidate submission bound | `3` |
| `MAX_PATCH_RETRIES` | Candidate resubmission bound | `1` |
| `KEEP_CANDIDATE_DIRS` | Keep per-candidate disposable directories after a run (debugging aid) | `false` |

Never print or log `META_API_KEY`.

## CLI usage

```bash
python -m netops_lens assess --scenario <name>
python -m netops_lens assess --baseline <dir> --proposed <dir> --intent <file>
```

| Scenario | What changed | Expected verdict |
|---|---|---|
| `healthy` | Nothing (baseline `lab/baseline` vs matching proposed) | `NO_REGRESSION_DETECTED` |
| `removed_route` | A static route to the DB network is missing in the proposed snapshot | `REGRESSION_DETECTED` |
| `acl_blocks_db` | An ACL denies the authorized DB port in the proposed snapshot | `REGRESSION_DETECTED` |

Useful flags: `--question "..."` records an engineer question; `--no-investigate` skips Stage B (Stage A output is unchanged); `--json` prints the full report JSON; `--out <file>` also writes it to a file. Interactive approval prompts appear only for `VERIFIED` candidates in terminal (non-JSON) runs; under `--json` every decision stays `PENDING`.

| Exit code | Meaning |
|---|---|
| `0` | Assessment completed (`REGRESSION_DETECTED` or `NO_REGRESSION_DETECTED`) |
| `1` | Input/usage error (no assessment ran) |
| `2` | Assessment completed `INCONCLUSIVE` |

## Streamlit usage

```bash
streamlit run app.py
```

The page walks the same pipeline run top to bottom: assessment verdict banner, flow comparisons, findings, snapshot health, evidence → investigation narrative and tool activity → candidates with operations, config diffs, and per-check verification → approval controls for `VERIFIED` candidates only. The sidebar offers Scenario mode (picker from `lab/scenarios/manifest.yaml`) or Manual paths mode (baseline/proposed/intent fields), plus the engineer question and Skip AI investigation checkbox; Run assessment executes the shared backend with live progress. Session rule: only the completed report is retained between runs — a new Run replaces it wholesale — and approval records a decision without deploying anything.

## Testing

```bash
python -m pytest
```

The default run executes the deterministic suite only. It deselects `live` tests (live Muse/Meta API calls) and `integration` tests (controlled real-Batfish lifecycle), because those need external services; Batfish-backed unit fixtures skip with a message when Batfish is down. Opt-in runs, requiring Batfish and Meta access:

```bash
python -m pytest -m live
NETOPS_LENS_RUN_BATFISH_INTEGRATION=1 python -m pytest -m integration tests/integration
```

Quality gates:

```bash
python -m ruff check src tests app.py
python -m mypy src
python -m mypy app.py
python -m pip check
```

## Safety & scope

V1 is read-only and deliberately narrow: no deployment, no autonomous remediation, no authentication, no saved-run history, no database. The original lab snapshots under `lab/baseline/**` and `lab/proposed/**` and the preserved smoke scripts `test_batfish.py` and `test_diff.py` are byte-preserved and never modified by runs. Every assessment runs on a uniquely named disposable Batfish network plus disposable candidate snapshots and directories, all deleted during cleanup; the protected shared network `netops-lens-lab` is never selected as a working network and never deleted.

## Troubleshooting

- `Batfish unavailable` (CLI) / connection error (UI) → the Batfish service is down or unreachable; start it and check `BATFISH_HOST`. Batfish-backed tests skip with a message instead of failing.
- Stage B skipped with `META_API_KEY is not configured` → set the key in `.env` for live investigation; deterministic assessment is unaffected.
- `input error` mentioning the intent file → the intent YAML is malformed or a referenced path is missing; fix the file and rerun.
