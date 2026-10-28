
import pandas as pd
import ipaddress
from pathlib import Path

INPUT = Path("data/parsed/bgp_events.csv")
OUTPUT = Path("data/parsed/announcement_events.csv")

df = pd.read_csv(
    INPUT,
    dtype={
        "peer_as": "string",
        "origin_as": "string",
        "prefix": "string",
        "event_type": "string",
    }
)

# Keep announcements for the initial origin/subprefix model.
ann = df[df["event_type"] == "announcement"].copy()

# Remove accidental whitespace; do not convert missing origins to "nan".
ann["origin_as"] = ann["origin_as"].str.strip()
ann["origin_as"] = ann["origin_as"].replace("", pd.NA)

# Derive network features from the announced prefix.
def get_prefix_length(value):
    try:
        return ipaddress.ip_network(value, strict=False).prefixlen
    except (ValueError, TypeError):
        return pd.NA

def get_ip_version(value):
    try:
        return ipaddress.ip_network(value, strict=False).version
    except (ValueError, TypeError):
        return pd.NA

ann["prefix_length"] = ann["prefix"].map(get_prefix_length)
ann["ip_version"] = ann["prefix"].map(get_ip_version)

# Labels remain unknown until we establish ground truth.
ann["label"] = pd.Series(
    pd.NA, index=ann.index, dtype="Int64"
)

ann["is_synthetic"] = 0

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
ann.to_csv(OUTPUT, index=False)

print("Announcements:", len(ann))
print("Missing origin AS:", ann["origin_as"].isna().sum())
print("Invalid prefixes:", ann["prefix_length"].isna().sum())
print("Label counts:")
print(ann["label"].value_counts(dropna=False))
print("Saved to:", OUTPUT)
print(ann.head().to_string(index=False))
