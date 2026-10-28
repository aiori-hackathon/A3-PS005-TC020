
from pathlib import Path
import ipaddress
import pandas as pd

INPUT = Path("data/parsed/controlled_scenarios_revalidated.csv")
OUTPUT = Path("data/parsed/controlled_scenarios_features.csv")

df = pd.read_csv(INPUT, dtype={"prefix": "string"})

# Parse each prefix once.
networks = []
for prefix in df["prefix"]:
    try:
        networks.append(ipaddress.ip_network(str(prefix), strict=False))
    except ValueError:
        networks.append(None)

df["has_observed_parent_prefix"] = 0
df["has_observed_more_specific"] = 0

# Use the observed prefix set, not labels, to derive relationships.
# Keep IPv4 and IPv6 relationships separate.
prefix_set = {n for n in networks if n is not None}

for i, network in enumerate(networks):
    if network is None:
        continue

    same_family = [
        other for other in prefix_set
        if other.version == network.version and other != network
    ]

    # Is there a covering, less-specific prefix?
    df.loc[i, "has_observed_parent_prefix"] = int(
        any(network.subnet_of(other) for other in same_family)
    )

    # Is there a more-specific prefix contained by this prefix?
    df.loc[i, "has_observed_more_specific"] = int(
        any(other.subnet_of(network) for other in same_family)
    )

df.to_csv(OUTPUT, index=False)

print(f"Saved: {OUTPUT}")
print("\nNew feature counts:")
print(
    df[
        ["has_observed_parent_prefix", "has_observed_more_specific"]
    ].sum()
)
print("\nRows:", len(df))
