import json
import ipaddress
from datetime import datetime, timezone
from pathlib import Path


def validate_roa_record(record: dict) -> dict:
    """Validate and normalize one ROA record."""
    if not isinstance(record, dict):
        raise ValueError("ROA record must be a dictionary")

    prefix = record.get("prefix")
    asn = record.get("origin_as", record.get("asn"))
    max_length = record.get("max_length", record.get("maxLength"))

    if not isinstance(prefix, str):
        raise ValueError("ROA prefix must be a string")

    try:
        network = ipaddress.ip_network(prefix, strict=True)
    except ValueError as exc:
        raise ValueError(f"Invalid ROA prefix: {prefix}") from exc

    if isinstance(asn, str) and asn.upper().startswith("AS"):
        asn = asn[2:]
    if isinstance(asn, str) and asn.isdigit():
        asn = int(asn)
    if isinstance(asn, bool) or not isinstance(asn, int):
        raise ValueError("ROA ASN must be an integer")

    if not 1 <= asn <= 4294967295:
        raise ValueError(f"Invalid ROA ASN: {asn}")

    if isinstance(max_length, bool) or not isinstance(max_length, int):
        raise ValueError("max_length must be an integer")

    if not network.prefixlen <= max_length <= network.max_prefixlen:
        raise ValueError(
            f"Invalid max_length {max_length} for prefix {prefix}"
        )

    def parse_date(value, field, default):
        if value is None:
            return default
        if not isinstance(value, str):
            raise ValueError(f"{field} must be an ISO 8601 string")
        try:
            return datetime.fromisoformat(
                value.replace("Z", "+00:00")
            ).astimezone(timezone.utc).isoformat()
        except ValueError as exc:
            raise ValueError(f"Invalid {field}: {value}") from exc

    not_before = parse_date(
        record.get("not_before"),
        "not_before",
        "1970-01-01T00:00:00+00:00",
    )
    not_after = parse_date(
        record.get("not_after"),
        "not_after",
        "9999-12-31T23:59:59+00:00",
    )

    if not_before > not_after:
        raise ValueError("not_before must not be later than not_after")

    return {
        "prefix": str(network),
        "origin_as": asn,
        "max_length": max_length,
        "not_before": not_before,
        "not_after": not_after,
    }


def load_roas(file_path: str) -> list[dict]:
    """Load ROA records from a JSON file."""
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"ROA file not found: {path}")

    with path.open("r", encoding="utf-8") as file:
        records = json.load(file)

    if isinstance(records, dict):
        records = records.get("roas", records.get("vrps"))
    if not isinstance(records, list):
        raise ValueError(
            "ROA file must contain a JSON list or an object with roas/vrps"
        )

    validated_roas = []

    for index, record in enumerate(records):
        try:
            validated_roas.append(validate_roa_record(record))
        except ValueError as exc:
            raise ValueError(
                f"Invalid ROA record at index {index}: {exc}"
            ) from exc

    return validated_roas
