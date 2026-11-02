"""Shared deterministic fakes for Phase 2 unit tests (no Batfish, no LLM)."""

from __future__ import annotations

from netops_lens.batfish_client import BatfishClient, BatfishError, HealthRecords


def flow_dict(
    *,
    src: str = "192.0.2.10",
    dst: str = "198.51.100.1",
    proto: str = "ICMP",
    dport: int | None = None,
    sport: int = 49152,
    node: str = "r1",
    iface: str = "GigabitEthernet0/1",
) -> dict:
    """Realistic Batfish Flow identity (synthetic values, observed shape).

    Mirrors the keys Batfish actually returns (see
    docs/phase23-differential-observation.md). ``sport`` is ephemeral and
    must never participate in identity matching.
    """
    return {
        "srcIp": src,
        "dstIp": dst,
        "ipProtocol": proto,
        "dstPort": dport,
        "srcPort": sport,
        "ingressNode": node,
        "ingressInterface": iface,
    }


def trace_row(
    disposition: str, hops: list | None = None, flow: dict | None = None
) -> dict:
    return {
        "Flow": flow if flow is not None else flow_dict(),
        "Traces": [{"disposition": disposition, "hops": hops if hops is not None else []}],
        "TraceCount": 1,
    }


def multi_trace_row(dispositions: list, flow: dict | None = None) -> dict:
    """One traceroute row with several traces (synthetic adversarial case)."""
    traces = [{"disposition": d, "hops": []} for d in dispositions]
    return {
        "Flow": flow if flow is not None else flow_dict(),
        "Traces": traces,
        "TraceCount": len(traces),
    }


def differential_row(
    snapshot_disp: str, reference_disp: str, flow: dict | None = None
) -> dict:
    return {
        "Flow": flow if flow is not None else flow_dict(),
        "Snapshot_Traces": [{"disposition": snapshot_disp, "hops": []}],
        "Snapshot_TraceCount": 1,
        "Reference_Traces": [{"disposition": reference_disp, "hops": []}],
        "Reference_TraceCount": 1,
    }


def multi_differential_row(
    snapshot_disps: list,
    reference_disps: list,
    snapshot_total: int | None = None,
    reference_total: int | None = None,
    flow: dict | None = None,
) -> dict:
    """One differential row with several traces per side.

    Reported totals default to the returned lengths (fully observed); pass
    explicit totals to simulate truncation.
    """
    return {
        "Flow": flow if flow is not None else flow_dict(),
        "Snapshot_Traces": [{"disposition": d, "hops": []} for d in snapshot_disps],
        "Snapshot_TraceCount": (len(snapshot_disps) if snapshot_total is None else snapshot_total),
        "Reference_Traces": [{"disposition": d, "hops": []} for d in reference_disps],
        "Reference_TraceCount": (
            len(reference_disps) if reference_total is None else reference_total
        ),
    }


def raw_differential_row(drop: tuple = (), **overrides) -> dict:
    """Differential row with caller-controlled count keys (missing/invalid)."""
    row = multi_differential_row(["NO_ROUTE"], ["ACCEPTED"])
    row.update(overrides)
    for key in drop:
        del row[key]
    return row


def healthy_records(node_names: tuple[str, ...] = ("r1", "r2")) -> HealthRecords:
    return HealthRecords(
        parse_status=(
            {"File_Name": "configs/r1.cfg", "Status": "PASSED"},
            {"File_Name": "configs/r2.cfg", "Status": "PASSED"},
        ),
        init_issues=(),
        nodes=tuple({"Node": name} for name in node_names),
    )


class FakeClient(BatfishClient):
    """Canned BatfishClient: scripted records keyed by (question, snapshot)."""

    def __init__(
        self,
        answers: dict | None = None,
        health: HealthRecords | None = None,
        failures: set | None = None,
    ) -> None:
        super().__init__("fake-host", "fake-network")
        self.answers: dict = answers or {}
        self.health = health if health is not None else healthy_records()
        self.failures: set = failures or set()
        self.calls: list[tuple] = []

    def ask(
        self,
        question: str,
        snapshot: str,
        reference_snapshot: str | None = None,
        **params: object,
    ) -> list:
        self.calls.append((question, snapshot, reference_snapshot))
        if (question, snapshot) in self.failures or question in self.failures:
            raise BatfishError(f"fake failure for {question} on {snapshot}")
        return list(self.answers.get((question, snapshot), []))

    def health_records(self, snapshot: str):
        self.calls.append(("__health__", snapshot, None))
        if ("__health__", snapshot) in self.failures:
            raise BatfishError(f"fake health failure on {snapshot}")
        return self.health

    def asked(self, question: str, snapshot: str) -> int:
        return sum(1 for call in self.calls if call[0] == question and call[1] == snapshot)
