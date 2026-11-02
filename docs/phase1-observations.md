# Phase 1 — Empirical Batfish Observations

Recorded live against Batfish (pybatfish `2026.9.17.3748`) on 2026-11-02.
All Phase 1 string matching and reconciliation logic is coded only against
the values below. Anything not observed here is treated conservatively
(unknown = blocking / inconclusive), never guessed.

## Connection and session

- `Session(host="localhost")` connects; `set_network("netops-lens-lab")`
  selects (and creates if absent) the network. No auth, no extra params.
- `init_snapshot(path, name=name, overwrite=True)` succeeds for every
  Phase 1 snapshot directory, including the new ACL fixtures.

## fileParseStatus

- Columns: `File_Name`, `Status`, `File_Format`, `Nodes`.
- Observed status token: `PASSED` only (both files, all fixtures).
- `File_Format` is `CISCO_IOS`; `Nodes` is a list (e.g. `['r1']`).
- Partial-parse and failure tokens were **not** observed. Conservative rule:
  any file whose `Status` is not exactly `PASSED` blocks health.

## initIssues

- Columns: `Nodes`, `Source_Lines`, `Type`, `Details`, `Line_Text`,
  `Parser_Context`. There is **no** column literally named `Severity`;
  the severity-equivalent field is `Type`.
- All fixtures return **zero rows** (clean parse, no warnings at all).
- Conservative rule (allowlist is empty): any returned row blocks health,
  recorded verbatim. No benign-warning signature could be evidenced, so none
  is added.

## nodeProperties

- Very wide column set; the load-bearing column is `Node`.
- All fixtures recognize exactly `r1` and `r2`. Zero nodes, or a missing
  expected node, blocks health.

## Traceroute dispositions (TCP pinned per FlowSpec)

| Snapshot | Flow | Final disposition | Step detail |
|---|---|---|---|
| baseline / healthy | ICMP App->DB | `ACCEPTED` | `FORWARDED` cites the static route |
| proposed (removed route) | ICMP App->DB | `NO_ROUTE` | `NO_ROUTE(Discarded)` on r1 |
| acl baseline | TCP/1433 | `ACCEPTED` | `PERMITTED(DB-FILTER (INGRESS_FILTER))` |
| acl baseline | TCP/22 | `DENIED_IN` | `DENIED(DB-FILTER (INGRESS_FILTER))` |
| acl proposed | TCP/1433 | `DENIED_IN` | `DENIED(DB-FILTER (INGRESS_FILTER))` |
| acl proposed | TCP/22 | `DENIED_IN` | `DENIED(DB-FILTER (INGRESS_FILTER))` |

All four ACL outcomes match the plan's contract: baseline satisfies both
intent clauses; proposed regresses only the authorized port.

- `traceroute` answer columns: `Flow`, `Traces`, `TraceCount`.
- Trace cells are `Trace` objects with `.disposition` (`ACCEPTED`,
  `NO_ROUTE`, `DENIED_IN`, …) and `.hops`; hops have `.node` and `.steps`.
- A `DENIED` step's detail carries `filter` (`DB-FILTER`) and `filterType`
  (`INGRESS_FILTER`) — the filter **name**, but **no matched rule line**.
  Rule identification requires `testFilters` (below).
- TCP flows show an ephemeral source port (`192.0.2.10:49152`); `dstPorts`
  pinning works as specified.

## testFilters

- Call shape: `bf.q.testFilters(headers=<HeaderConstraints>, filters=<name>)`.
- `filters="DB-FILTER"` and `filters="r1[DB-FILTER]"` both return the match;
  `filters="r1/DB-FILTER"` returns **zero rows** (wrong specifier syntax).
- Columns: `Node`, `Filter_Name`, `Flow`, `Action`, `Line_Content`, `Trace`.
- For the denied TCP/1433 flow: `Action` = `DENY`, `Line_Content` =
  `10 deny tcp 192.0.2.0 0.0.0.255 198.51.100.0 0.0.0.255 eq 1433`
  (sequence number is a text prefix of the line content).
- There is **no** `Line_Index`-style column in this version, so the plan's
  `batfish_line_index` provenance field has no source: the sequence value
  used for patching comes from `Line_Content`'s prefix **only after**
  reconciling the rule body against the config-parser output, and from the
  parser's `sequence_number` thereafter. Nothing is inferred or substituted.
- `Trace` column text: `- Matched line 10 deny tcp … eq 1433`.

## differentialReachability

- Columns: `Flow`, `Snapshot_Traces`, `Snapshot_TraceCount`,
  `Reference_Traces`, `Reference_TraceCount`.
- removed_route (ICMP, proposed vs baseline): exactly one row —
  snapshot `NO_ROUTE` vs reference `ACCEPTED`.
- acl (TCP/1433, proposed vs baseline): exactly one row —
  snapshot `DENIED_IN` vs reference `ACCEPTED`.
- healthy (ICMP, no-change pair): **zero rows** — recorded as
  "not reported changed", never as proof of no change.

## DataFrame cell types (conversion contract for batfish_client.py)

- Cells may be `Flow` / `Trace` / `Hop` datamodel objects (all expose
  `.dict()` yielding JSON-serializable dicts), `ListWrapper` (list-like),
  plain lists/strings/numbers, or missing (`None`/`NaN`).
- Conversion rule: `.dict()` where available, recurse into lists,
  `NaN`/`NaT`/`None` -> `None`, numpy scalars -> native Python values.
  Anything else is kept only if `json.dumps` accepts it.
