import json
import ipaddress
from pathlib import Path


def validate_inventory_record(record: dict) -> dict:
    """Validate and normalize one inventory record."""
    if not isinstance(record, dict):
        raise ValueError("Inventory record must be a dictionary")

    prefix = record.get("prefix")
    origin_as = record.get("origin_as")

    if not isinstance(prefix, str):
        raise ValueError("Inventory prefix must be a string")

    try:
        network = ipaddress.ip_network(prefix, strict=True)
    except ValueError as exc:
        raise ValueError(
            f"Invalid inventory prefix: {prefix}"
        ) from exc

    if isinstance(origin_as, (int, str)):
        origin_as = [origin_as]
    if not isinstance(origin_as, list) or not origin_as:
        raise ValueError("origin_as must be a non-empty list of ASNs")

    normalized_origins = []
    for asn in origin_as:
        if isinstance(asn, str) and asn.upper().startswith("AS"):
            asn = asn[2:]
        if isinstance(asn, str) and asn.isdigit():
            asn = int(asn)
        if isinstance(asn, bool) or not isinstance(asn, int):
            raise ValueError("origin_as values must be integers")
        if not 1 <= asn <= 4294967295:
            raise ValueError(f"Invalid origin ASN: {asn}")
        normalized_origins.append(asn)

    return {
        "prefix": str(network),
        "origin_as": sorted(set(normalized_origins)),
    }


def load_inventory(file_path: str) -> dict[str, list[int]]:
    """Load a JSON prefix inventory."""
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"Inventory file not found: {path}"
        )

    with path.open("r", encoding="utf-8") as file:
        records = json.load(file)

    if isinstance(records, dict):
        records = records.get("prefixes")
    if not isinstance(records, list):
        raise ValueError(
            "Inventory file must contain a JSON list or an object with prefixes"
        )

    inventory = {}

    for index, record in enumerate(records):
        if isinstance(record, dict) and "origin_asns" in record:
            record = {
                **record,
                "origin_as": record["origin_asns"],
            }
        try:
            validated = validate_inventory_record(record)
        except ValueError as exc:
            raise ValueError(
                f"Invalid inventory record at index {index}: {exc}"
            ) from exc

        prefix = validated["prefix"]
        origin_as = validated["origin_as"]

        if prefix in inventory:
            raise ValueError(
                f"Duplicate prefix in inventory: {prefix}"
            )

        inventory[prefix] = origin_as

    return inventory
