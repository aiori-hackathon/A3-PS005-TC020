
import ipaddress
from pathlib import Path
from collections import defaultdict

import pandas as pd
from tqdm import tqdm

EVENTS_FILE = Path("data/parsed/announcement_events.csv")
ROA_FILE = Path("data/roa/combined_roas.csv.xz")
OUTPUT_FILE = Path("data/parsed/events_with_roa.csv")

# 1. Load announcement events
events = pd.read_csv(
    EVENTS_FILE,
    dtype={"origin_as": "string", "prefix": "string"}
)

events["event_time"] = pd.to_datetime(
    events["timestamp"], unit="s", utc=True, errors="coerce"
)

# 2. Load and normalize ROAs
roas = pd.read_csv(
    ROA_FILE,
    compression="xz",
    dtype={"ASN": "string", "IP Prefix": "string"}
)

roas["ASN"] = (
    roas["ASN"].str.strip().str.removeprefix("AS")
)

roas["Max Length"] = pd.to_numeric(
    roas["Max Length"], errors="coerce"
)

roas["Not Before"] = pd.to_datetime(
    roas["Not Before"], utc=True, errors="coerce"
)
roas["Not After"] = pd.to_datetime(
    roas["Not After"], utc=True, errors="coerce"
)

# 3. Build prefix index
roa_index = defaultdict(list)
skipped_roas = 0

for row in tqdm(
    roas.to_dict("records"),
    total=len(roas),
    desc="Indexing ROAs"
):
    try:
        network = ipaddress.ip_network(
            row["IP Prefix"], strict=True
        )

        max_length = row["Max Length"]
        if pd.isna(max_length):
            max_length = network.prefixlen
        else:
            max_length = int(max_length)

        # Reject impossible prefix-length constraints.
        if not network.prefixlen <= max_length <= network.max_prefixlen:
            skipped_roas += 1
            continue

        # Invalid/missing validity dates cannot establish
        # whether this ROA was active at event time.
        if pd.isna(row["Not Before"]) or pd.isna(row["Not After"]):
            skipped_roas += 1
            continue

        if row["Not Before"] > row["Not After"]:
            skipped_roas += 1
            continue

        asn = str(row["ASN"]).strip()
        if not asn.isdigit():
            skipped_roas += 1
            continue

        roa_index[(network.version, str(network))].append({
            "asn": asn,
            "prefix_length": network.prefixlen,
            "max_length": max_length,
            "not_before": row["Not Before"],
            "not_after": row["Not After"],
        })

    except (ValueError, TypeError):
        skipped_roas += 1

print(f"ROAs skipped during indexing: {skipped_roas:,}")


def validate(prefix, origin, timestamp):
    result = {
        "rov_state": "NotFound",
        "origin_mismatch": False,
        "max_length_exceeded": False,
        "invalid_reason": "no_covering_roa",
    }

    try:
        route = ipaddress.ip_network(str(prefix), strict=True)
        origin = str(origin).strip().removeprefix("AS")

        if not origin.isdigit() or pd.isna(timestamp):
            result["invalid_reason"] = "invalid_event_data"
            return result

    except (ValueError, TypeError, AttributeError):
        result["invalid_reason"] = "invalid_event_data"
        return result

    # Find active ROAs covering this route.
    covering = []

    for length in range(route.prefixlen + 1):
        parent = (
            route.supernet(new_prefix=length)
            if length < route.prefixlen
            else route
        )

        for roa in roa_index.get((route.version, str(parent)), []):
            if roa["not_before"] <= timestamp <= roa["not_after"]:
                covering.append(roa)

    if not covering:
        return result

    # Valid if at least one covering ROA authorizes both
    # the origin ASN and the route's prefix length.
    authorized = [
        roa for roa in covering
        if roa["asn"] == origin
        and route.prefixlen <= roa["max_length"]
    ]

    if authorized:
        result["rov_state"] = "Valid"
        result["invalid_reason"] = "none"
        return result

    # The route has covering ROAs, but none authorizes it.
    result["rov_state"] = "Invalid"
    matching_origin = [
        roa for roa in covering if roa["asn"] == origin
    ]

    result["origin_mismatch"] = not bool(matching_origin)

    result["max_length_exceeded"] = any(
        route.prefixlen > roa["max_length"]
        for roa in matching_origin
    )

    if result["origin_mismatch"]:
        result["invalid_reason"] = "origin_mismatch"
    elif result["max_length_exceeded"]:
        result["invalid_reason"] = "max_length_exceeded"
    else:
        result["invalid_reason"] = "unauthorized"

    return result


# 4. Validate every announcement
results = []

for prefix, origin, timestamp in tqdm(
    zip(events["prefix"], events["origin_as"], events["event_time"]),
    total=len(events),
    desc="Validating routes"
):
    results.append(validate(prefix, origin, timestamp))

result_df = pd.DataFrame(results, index=events.index)
events = pd.concat([events, result_df], axis=1)

# 5. Save output
events.drop(columns=["event_time"], inplace=True)
events.to_csv(OUTPUT_FILE, index=False)

print("\nROV results:")
print(events["rov_state"].value_counts(dropna=False))

print("\nInvalid reasons:")
print(
    events.loc[events["rov_state"] == "Invalid", "invalid_reason"]
    .value_counts(dropna=False)
)

print("\nSaved to:", OUTPUT_FILE)
