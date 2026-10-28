
import csv
import gzip
from pathlib import Path
import mrtparse

INPUT_FILE = Path("data/raw/updates.20261001.0000.gz")
OUTPUT_FILE = Path("data/parsed/bgp_events.csv")

OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

def get_origin_as(path_attributes):
    """Return the last AS in the final AS_PATH segment, if available."""
    for attr in path_attributes:
        attr_type = attr.get("type", {})
        if 2 in attr_type:  # AS_PATH
            segments = attr.get("value", [])
            for segment in reversed(segments):
                values = segment.get("value", [])
                if values:
                    return str(values[-1])
    return ""

rows_written = 0

with gzip.open(INPUT_FILE, "rb") as f, \
     OUTPUT_FILE.open("w", newline="", encoding="utf-8") as out:

    writer = csv.DictWriter(
        out,
        fieldnames=[
            "timestamp",
            "peer_as",
            "prefix",
            "origin_as",
            "event_type",
            "is_synthetic",
            "label"
        ]
    )
    writer.writeheader()

    for entry in mrtparse.Reader(f):
        record = entry.data

        # This parser currently handles BGP4MP UPDATE messages.
        if "bgp_message" not in record:
            continue

        message = record["bgp_message"]
        if message.get("type", {}).get(2) != "UPDATE":
            continue

        timestamp = next(iter(record.get("timestamp", {})), "")
        peer_as = record.get("peer_as", "")

        attrs = message.get("path_attributes", [])
        origin_as = get_origin_as(attrs)

        # Newly announced prefixes.
        for item in message.get("nlri", []):
            writer.writerow({
                "timestamp": timestamp,
                "peer_as": peer_as,
                "prefix": f'{item["prefix"]}/{item["length"]}',
                "origin_as": origin_as,
                "event_type": "announcement",
                "is_synthetic": 0,
                "label": ""
            })
            rows_written += 1

        # Withdrawals are recorded, but not labelled as anomalies.
        for item in message.get("withdrawn_routes", []):
            writer.writerow({
                "timestamp": timestamp,
                "peer_as": peer_as,
                "prefix": f'{item["prefix"]}/{item["length"]}',
                "origin_as": "",
                "event_type": "withdrawal",
                "is_synthetic": 0,
                "label": ""
            })
            rows_written += 1

print(f"Finished. Events written: {rows_written:,}")
print(f"Output: {OUTPUT_FILE}")
