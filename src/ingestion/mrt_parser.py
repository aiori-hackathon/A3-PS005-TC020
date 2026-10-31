"""MRT/BGP dump ingestion helpers.

The optional ``mrtparse`` dependency is imported only when this parser is used.
"""

import gzip
from pathlib import Path

from .bgp_parser import validate_prefix, validate_asn


def _origin_from_attributes(attributes):
    for attribute in attributes:
        attr_type = attribute.get("type", {})
        if 2 not in attr_type:
            continue
        for segment in reversed(attribute.get("value", [])):
            values = segment.get("value", [])
            if values:
                return validate_asn(values[-1])
    return None


def replay_mrt_events(file_path: str):
    """Yield normalized events from a BGP4MP MRT update dump."""
    try:
        import mrtparse
    except ImportError as exc:
        raise RuntimeError(
            "MRT support requires the mrtparse dependency"
        ) from exc

    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"MRT file not found: {path}")

    with gzip.open(path, "rb") if path.suffix == ".gz" else path.open("rb") as stream:
        for entry in mrtparse.Reader(stream):
            record = entry.data
            message = record.get("bgp_message")
            if not message or message.get("type", {}).get(2) != "UPDATE":
                continue

            timestamp = next(iter(record.get("timestamp", {})), None)
            attributes = message.get("path_attributes", [])
            origin_as = _origin_from_attributes(attributes)

            for item in message.get("nlri", []):
                yield {
                    "timestamp": timestamp,
                    "event_type": "announcement",
                    "prefix": validate_prefix(
                        f'{item["prefix"]}/{item["length"]}'
                    ),
                    "as_path": [],
                    "origin_as": origin_as,
                }

            for item in message.get("withdrawn_routes", []):
                yield {
                    "timestamp": timestamp,
                    "event_type": "withdrawal",
                    "prefix": validate_prefix(
                        f'{item["prefix"]}/{item["length"]}'
                    ),
                    "as_path": [],
                    "origin_as": None,
                }
