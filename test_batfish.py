from pybatfish.client.session import Session
from pybatfish.datamodel import HeaderConstraints

# Connect to the Batfish service
bf = Session(host="localhost")

# Create/select a logical network
bf.set_network("netops-lens-lab")

# Load our Cisco configuration snapshot
snapshot = bf.init_snapshot(
    "lab/baseline",
    name="baseline",
    overwrite=True,
)

print(f"Successfully initialized snapshot: {snapshot}")

# Check configuration parsing status
print("\n--- Configuration Parsing Status ---")

parse_status = bf.q.fileParseStatus().answer().frame()
print(parse_status.to_string(index=False))

# Inspect recognized network devices
print("\n--- Recognized Network Devices ---")

nodes = bf.q.nodeProperties().answer().frame()
print(nodes.to_string(index=False))

print("\n--- Virtual Traceroute ---")

trace = bf.q.traceroute(
    startLocation="@enter(r1[GigabitEthernet0/1])",
    headers=HeaderConstraints(
        srcIps="192.0.2.10",
        dstIps="198.51.100.1",
    ),
).answer().frame()

print(trace.to_string(index=False))