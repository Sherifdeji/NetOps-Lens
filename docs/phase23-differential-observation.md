# Phase 2.3 Part A — Isolated differentialReachability observation

Method: unique Batfish network `netops-lens-p23-<ts>` (created via
`set_network`, verified `delete_network` exists), four uniquely named
snapshots initialised read-only from `lab/` fixtures, all queries run inside
that network, then all four snapshots and the network deleted. The shared
`netops-lens-lab` network and its snapshots were never touched. Raw output
retained at `/tmp/p23_out.json` (scratch, not committed).

## Answers

1. **Is Flow a row-level identity?** Yes. Every returned row carries a full
   `Flow` object (`srcIp`, `dstIp`, `ipProtocol`, `dstPort`, `srcPort`,
   `ingressNode`, `ingressInterface`, plus ICMP/TCP flag fields). The query
   resolves headers to concrete flows; `srcPort` is ephemeral (`49152`) and
   must never be part of identity matching.
2. **Per-row Snapshot_Traces / Reference_Traces?** Yes. Each row carries its
   own `Snapshot_Traces` and `Reference_Traces` lists plus `Snapshot_TraceCount`
   / `Reference_TraceCount` scalars.
3. **Are counts per row?** Yes as observed: every returned row carried its own
   counts and each equalled the returned list length on that row
   (`TraceCount: 1`, one trace). No multi-row answer was produced, so
   cross-row count semantics (repeated vs split totals) are **not**
   established; per-row completeness is the only empirically grounded rule.
4. **Duplicate Flow identities?** Not observed — every probe returned exactly
   one row (see 6).
5. **Multiple traces in one row?** Not observed — every returned row carried
   exactly one trace per side. Multi-trace handling in code is defensive,
   not empirical.
6. **maxTraces limiting?** `maxTraces=1` vs `maxTraces=5` on the same broad
   query returned the identical single row (`TraceCount: 1`). Truncation
   (`TraceCount` > returned traces) could not be produced in this two-router
   topology and remains **unobserved**; code treats it conservatively.
7. **Missing/inconsistent counts?** Not observed. Conservative rule stands:
   missing, invalid, or inconsistent counts are never treated as complete.
8. **Snapshot vs reference attribution?** Verified: `Snapshot_Traces`
   disposition always equalled the direct traceroute disposition on the
   `.answer(snapshot=...)` snapshot, `Reference_Traces` equalled the direct
   disposition on `reference_snapshot`. E.g. ACL pair TCP/1433:
   snapshot `DENIED_IN` == proposed direct, reference `ACCEPTED` ==
   baseline direct.

## Observed broad-query behaviour

Even with unpinned TCP headers (`ipProtocols=["TCP"]`, no `dstPorts`),
Batfish returned a single representative row: port 1433 on the ACL pair
(the changed flow), port 80 on the removed-route pair. No scratch topology
was built: a single representative row is itself the finding — this
Batfish version does not enumerate changed flows row-per-flow for these
queries, so multi-row code paths are defensive-only and must never invent
certainty from partial samples.
