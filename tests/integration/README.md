# Batfish integration tests (opt-in)

This directory holds the controlled live-Batfish harness. These tests
talk to the **real, already-running Batfish service** and exercise the
genuine production lifecycle. They never run as part of an ordinary
``pytest -q``.

## What is exercised

`test_batfish_candidate_lifecycle.py` contains two tests:

1. **Smoke** (`test_smoke_connect_init_health_and_cleanup`): connects,
   creates a unique disposable network, initializes the real
   `lab/baseline` + `lab/proposed` snapshots, checks both are healthy,
   then deletes the network in a `finally` block.
2. **Lifecycle** (`test_route_repair_lifecycle_end_to_end`): runs the
   real `run_assess --scenario removed_route` path — real Stage A,
   deterministic scripted Stage B (a canned transport driving the
   genuine `run_stage_b` validation; no model, no API key), real Phase 4.1
   patch application, real candidate snapshot init + registration, real
   Phase 4.2 verification (expected `VERIFIED`), guarded snapshot
   deletion, and run-network cleanup. It records lifecycle events with a
   thin recording subclass and asserts exact order and arguments.

## Why excluded by default

Live Batfish runs are slow, stateful, and require the Docker service.
Default runs stay deterministic and offline. Exclusion is two-layered:

- the `integration` pytest marker (deselected by `addopts`), and
- the `tests/integration/conftest.py` gate, which skips everything
  unless the environment variable below is set.

## Prerequisites

- The Batfish Docker container is already running (do not rebuild,
  restart, or remove it; never run `docker compose down -v`,
  `docker volume prune`, or broad Docker cleanup).
- `BATFISH_HOST` points at it (default `localhost`).
- The `netops-lens-lab` shared network exists and is left alone by
  every test here.

## Run

```text
NETOPS_LENS_RUN_BATFISH_INTEGRATION=1 \
    python -m pytest -m integration tests/integration -q
```

Without the variable, the tests skip with an explanatory message.
Without `-m integration`, they are deselected.

## Expected behavior

- Both tests pass; the lifecycle test reports `REGRESSION_DETECTED`
  for Stage A and `VERIFIED` for the `c-01` route repair.
- A uniquely named disposable network
  (`<batfish-network>-<tag>-<8 hex>`) is created and deleted per test.
- No `candidate-*` directories remain under `runs/` afterwards
  (an empty `runs/` directory itself may remain; it is untracked).

## After an interrupted run

If a run is killed mid-flight, list the leftover disposable network(s)
with a read-only probe and delete exactly those names — never a
wildcard, never the shared network. Derive the prefix from
configuration (`BATFISH_NETWORK`, default `netops-lens-lab`); the exact
disposable name is also printed by each test as
`[integration] disposable network: ...`, which is the most direct
identifier to compare against:

```python
from netops_lens.config import load_settings
from pybatfish.client.session import Session

settings = load_settings()  # reads host/network names only; prints nothing
prefix = settings.batfish_network
names = Session(host=settings.batfish_host).list_networks()
leftovers = [n for n in names if n.startswith(prefix + "-") and n != prefix]
```

Then delete each leftover individually (e.g. via
`BatfishClient(host, name).delete_network()` or
`Session(host=...).delete_network(name)`), and confirm the shared
network (`settings.batfish_network`) is still listed. If cleanup itself
failed inside a test, the test failure message names the exact
disposable network to investigate.

## Offline vs live

These tests perform **offline snapshot analysis** inside Batfish:
parsing configs, answering reachability questions, and managing
disposable analysis networks/snapshots. They never contact physical
routers, switches, or production networks, and never deploy or write
configuration to real devices.
