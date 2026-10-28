
from pathlib import Path
import ipaddress

import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

INPUT = Path("data/parsed/controlled_scenarios_features.csv")
OUT_DIR = Path("data/processed")
OUT_DIR.mkdir(parents=True, exist_ok=True)

df = pd.read_csv(
    INPUT,
    dtype={
        "prefix": "string",
        "origin_as": "string",
        "peer_as": "string",
        "scenario_id": "string",
    },
    low_memory=False,
)

# Recompute route-derived features consistently for all rows.
networks = df["prefix"].map(
    lambda p: ipaddress.ip_network(str(p), strict=True)
)
df["prefix_length"] = networks.map(lambda n: n.prefixlen).astype(int)
df["ip_version"] = networks.map(lambda n: n.version).astype(int)

for state in ["Valid", "Invalid", "NotFound"]:
    df[f"rov_{state.lower()}"] = (
        df["rov_state"] == state
    ).astype("int8")

df["origin_mismatch"] = (
    df["origin_mismatch"].fillna(False).astype(bool).astype("int8")
)
df["max_length_exceeded"] = (
    df["max_length_exceeded"].fillna(False).astype(bool).astype("int8")
)


feature_columns = [
    "prefix_length",
    "ip_version",
    "rov_valid",
    "rov_invalid",
    "rov_notfound",
    "origin_mismatch",
    "max_length_exceeded",
    "has_observed_parent_prefix",
    "has_observed_more_specific",
]

X = df[feature_columns].copy()
y = df["label"].astype(int)
groups = df["scenario_id"]

splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.25,
    random_state=42,
)
train_idx, test_idx = next(splitter.split(X, y, groups=groups))

train = df.iloc[train_idx].copy()
test = df.iloc[test_idx].copy()

train.to_csv(OUT_DIR / "train.csv", index=False)
test.to_csv(OUT_DIR / "test.csv", index=False)

print("Feature columns:", feature_columns)
print("Train rows:", len(train))
print("Test rows:", len(test))
print("Train scenarios:", train["scenario_id"].nunique())
print("Test scenarios:", test["scenario_id"].nunique())
print("\nTrain labels:")
print(train["label"].value_counts().sort_index())
print("\nTest labels:")
print(test["label"].value_counts().sort_index())

overlap = set(train["scenario_id"]) & set(test["scenario_id"])
print("\nScenario overlap:", len(overlap))
