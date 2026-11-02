from pybatfish.client.session import Session
from pybatfish.datamodel import HeaderConstraints, PathConstraints

# Connect to Batfish
bf = Session(host="localhost")

# Select our network
bf.set_network("netops-lens-lab")

# Load the proposed configuration
snapshot = bf.init_snapshot(
    "lab/proposed",
    name="proposed",
    overwrite=True,
)

print(f"Initialized snapshot: {snapshot}")

# Define the traffic we want to investigate
headers = HeaderConstraints(
    srcIps="192.0.2.10",
    dstIps="198.51.100.1",
    ipProtocols=["ICMP"],
)
path = PathConstraints(
    startLocation="@enter(r1[GigabitEthernet0/1])"
)

# Test connectivity in the proposed snapshot
print("\n--- Proposed Configuration: Traceroute ---")

trace = bf.q.traceroute(
    startLocation="@enter(r1[GigabitEthernet0/1])",
    headers=headers,
).answer(snapshot="proposed").frame()

print(trace.to_string(index=False))

# Compare proposed configuration with baseline
print("\n--- Differential Reachability ---")

diff = bf.q.differentialReachability(
    pathConstraints=path,
    headers=headers,
    maxTraces=5,
).answer(
    snapshot="proposed",
    reference_snapshot="baseline",
).frame()

print(diff.to_string(index=False))