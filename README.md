# NetOps Lens

AI-powered network configuration change investigation (Meta Global AI Developer Hackathon).

A network engineer declares required connectivity in `intent.yaml`
(`must_reach` / `must_not_reach`) for a baseline/proposed snapshot pair.
Python always runs the mandatory deterministic checks and computes the
verdict (`REGRESSION_DETECTED`, `NO_REGRESSION_DETECTED`, `INCONCLUSIVE`).
Only then does Muse Spark investigate root causes and propose structured
candidate patches, which Python verifies on disposable snapshot copies.
V1 is read-only: original snapshots and live devices are never modified.

> Phase 0 status: foundation + data contracts + Meta API smoke test only.
> Later phases (Batfish client, assessment engine, agent loop, patch
> verification, UI) are not yet implemented.

## Prerequisites

- Python 3.14 with the existing `netops-env` environment. Do not create
  another virtualenv.
- Batfish running locally in Docker and reachable at `BATFISH_HOST`
  (default `localhost`) before any Batfish-backed test or run.
- A Meta Model API key in `.env` as `META_API_KEY` for the smoke test
  and later investigation phases. Never commit `.env`.

## Setup

```bash
source ~/netops-env/bin/activate   # or wherever your netops-env lives
python -m pip install -e ".[dev]"
cp .env.example .env   # then fill in META_API_KEY
```

## Preserved smoke scripts

These pre-date the package and are kept byte-identical as manual checks:

```bash
python test_batfish.py   # snapshot init, parse status, traceroute
python test_diff.py      # proposed traceroute + differential reachability
```

Routine `pytest` runs collect only `tests/` and never these scripts.

## Verification (Phase 0)

```bash
python -m pip install -e ".[dev]"
pytest tests/test_models.py
pytest --collect-only
python scripts/spike_meta_api.py
```

`scripts/spike_meta_api.py` performs an authenticated Muse Spark 1.3 chat
completion, a dummy `echo` tool-calling round trip, and a nested
`submit_candidate_patch` schema acceptance check. It prints pass/fail plus
observed message shapes, never the API key. With no key or network it fails
loudly with the API error class and is recorded as the Phase 3 blocker.

## Layout

- `src/netops_lens/` — `config.py` (env loading), `models.py` (Pydantic
  data contracts used by every later phase)
- `tests/` — contract tests (`test_models.py`); `conftest.py` provides the
  Batfish-health fixture used by later integration tests
- `scripts/spike_meta_api.py` — Meta API smoke test
- `lab/baseline/`, `lab/proposed/` — preserved fixtures (do not modify)
