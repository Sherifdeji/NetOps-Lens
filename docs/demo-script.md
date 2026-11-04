# NetOps Lens — 3-Minute Demo Script

Target 2:45, hard cap 3:00. All commands and UI selections below are exact; rehearse against §Demo in `docs/implementation-plan.md`.

## Pre-recording checklist

- [ ] A Batfish service reachable at `$BATFISH_HOST` (default `localhost`); snapshots pre-warmed so no connection wait lands on camera.
- [ ] `.env` loaded with the Meta Model API key. The key is never shown on screen or read aloud.
- [ ] Each scenario rehearsed end-to-end at least twice, timed.
- [ ] Stopwatch visible; target 2:45, hard cap 3:00.
- [ ] Open and ready: the two-router topology plus the intent (`examples/intent.yaml`), and either a terminal (CLI) or the Streamlit page (`streamlit run app.py`).

## Beats

### 0:00–0:25 — Problem and topology

- On screen: the two-router topology and the intent file (`must_reach` the DB host).
- Narration:
  - "A route or ACL edit can silently break app-to-DB traffic."
  - "NetOps Lens checks the change *before* deployment, against declared intent."
- Trust line: "Batfish decides the facts, Muse Spark investigates, Python owns every verdict — and nothing here touches a live device."

### 0:25–0:50 — Healthy baseline

- On screen: pick `healthy` from the manifest and run (`python -m netops_lens assess --scenario healthy`, or the Scenario picker + Run in the UI).
- Narration:
  - "Same intent, unchanged configs: Python checks pass per flow, verdict `NO_REGRESSION_DETECTED`."
  - "Muse explains the successful checks citing the findings — no candidates are proposed for a passing change."
  - "The report still scopes itself: only tested flows are covered."
- Trust line: "No regression claimed beyond what was actually tested."

### 0:50–1:50 — Regression investigation (removed_route)

- On screen: pick `removed_route`; ask "will the app still reach the DB?"; run.
- Narration:
  - "Python's mandatory checks fire first: `REGRESSION_DETECTED`, flow gone `REACHABLE → NO_ROUTE`, evidence IDs on screen."
  - "Muse then traces the flow and reads routes to root-cause the missing static route — narrative only, the verdict was already decided."
- Trust line: "The model explains; it never overrules Python."

### 1:50–2:30 — Patch, verify, approve

- On screen: the `add_static_route` candidate as structured operations; Python applies it to a disposable copy only; health + intent + differential re-run; status flips to `VERIFIED`; evidence IDs listed. Click Approve.
- Narration:
  - "`VERIFIED` means the disposable copy restored reachability — originals untouched."
  - "Approval records my decision on the report."
- Trust line (say verbatim): "Approval deploys nothing."

### 2:30–3:00 — Trust model and close

- On screen: end card — Batfish, Muse Spark, Streamlit.
- Narration:
  - "Python owns checks, findings, verdict, and verification; Muse owns investigation and proposals."
  - "`INCONCLUSIVE` and `UNVERIFIABLE` never mean safe."
- Trust line: "Read-only by design — originals never modified, devices never contacted."

## ACL cutaway (only if time is tight)

Swap the 0:50–2:30 block for `acl_blocks_db`: the per-flow table shows one `REGRESSION` (authorized DB port 1433) beside one `NO_CHANGE_OK` (unauthorized port 22), then the ACL repair candidate verifying `VERIFIED`. Same beats, same trust lines, smaller surface.

## Fallback: live API unavailable during recording

Record the deterministic path (`--no-investigate`, or a run whose report shows Stage B skipped) and narrate the agent's role over the recorded tool-activity log. Disclose the substitution in the video notes. Never fake a live model call.

## Rehearsal checklist

- [ ] `healthy` end-to-end, twice, timed.
- [ ] `removed_route` end-to-end, twice, timed (verdict → candidate → `VERIFIED` → approval).
- [ ] `acl_blocks_db` cutaway rehearsed once, timed.
- [ ] Every run under its beat budget; total under 2:45 with the 3:00 hard cap.
- [ ] No secrets visible in any take; key stays in `.env`, off screen.
