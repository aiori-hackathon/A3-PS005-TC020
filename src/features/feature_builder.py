
from pathlib import Path
import ipaddress
import pandas as pd

INPUT = Path("data/parsed/events_with_roa.csv")
OUTPUT = Path("data/parsed/ml_features.csv")

df = pd.read_csv(
    INPUT,
    dtype={
        "prefix": "string",
        "origin_as": "string",
        "rov_state": "string",
    },
)

df["timestamp"] = pd.to_datetime(
    df["timestamp"], unit="s", utc=True
)
df = df.sort_values("timestamp").reset_index(drop=True)

# Prefix characteristics
networks = df["prefix"].map(
    lambda p: ipaddress.ip_network(p, strict=True)
)
df["prefix_length"] = networks.map(lambda n: n.prefixlen)
df["ip_version"] = networks.map(lambda n: n.version)

# Event-level repetition: count observations of each route
# up to and including the current event.
route_key = df["prefix"].astype(str) + "|" + df["origin_as"].astype(str)
df["route_event_count_so_far"] = (
    df.groupby(route_key, sort=False).cumcount() + 1
)

# Number of announcements for each prefix in the feed.
df["prefix_event_count_so_far"] = (
    df.groupby("prefix", sort=False).cumcount() + 1
)

# Detect changes in observed origin for a prefix.
df["previous_origin_as"] = df.groupby("prefix")["origin_as"].shift(1)
df["origin_changed_from_previous_observation"] = (
    df["previous_origin_as"].notna()
    & (df["origin_as"] != df["previous_origin_as"])
).astype("int8")

# ROV status as model-friendly features.
for state in ["Valid", "Invalid", "NotFound"]:
    df[f"rov_{state.lower()}"] = (
        df["rov_state"] == state
    ).astype("int8")

df["origin_mismatch"] = df["origin_mismatch"].fillna(False).astype("int8")
df["max_length_exceeded"] = (
    df["max_length_exceeded"].fillna(False).astype("int8")
)

# Keep source columns and features together for traceability.
df["timestamp"] = df["timestamp"].dt.strftime("%Y-%m-%dT%H:%M:%SZ")
df.to_csv(OUTPUT, index=False)

print("Saved:", OUTPUT)
print("Rows:", len(df))
print("Columns:", len(df.columns))
print("\nROV status:")
print(df["rov_state"].value_counts(dropna=False))
print("\nOrigin-change flags:")
print(df["origin_changed_from_previous_observation"].value_counts())
