import ipaddress
from datetime import datetime


def validate_prefix(prefix: str) -> str:
    """Validate an IP prefix without silently normalizing host bits."""
    if not isinstance(prefix, str):
        raise ValueError("Prefix must be a string")

    try:
        network = ipaddress.ip_network(prefix, strict=True)
        return str(network)
    except ValueError as exc:
        raise ValueError(f"Invalid IP prefix: {prefix}") from exc


def validate_asn(asn) -> int:
    """Validate an ASN, accepting integer and AS-prefixed string forms."""
    if isinstance(asn, bool):
        raise ValueError("ASN must be an integer, not a boolean")

    if isinstance(asn, str):
        asn = asn.strip().upper()
        if asn.startswith("AS"):
            asn = asn[2:]
        if not asn.isdigit():
            raise ValueError(f"Invalid ASN: {asn}")

    try:
        value = int(asn)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Invalid ASN: {asn}") from exc

    if isinstance(asn, float):
        raise ValueError("ASN must not be a floating-point number")

    if not 1 <= value <= 4294967295:
        raise ValueError(f"ASN out of range: {value}")

    return value


def parse_as_path(as_path) -> list[int]:
    """Convert an AS path into a list of ASNs."""
    if isinstance(as_path, str):
        parts = as_path.split()
    elif isinstance(as_path, (list, tuple)):
        parts = as_path
    else:
        raise ValueError("AS path must be a string, list, or tuple")

    parsed = [validate_asn(asn) for asn in parts]
    if len(parsed) != len(set(parsed)):
        raise ValueError("AS path contains an ASN loop")
    return parsed


def extract_origin_as(as_path) -> int | None:
    """Extract the origin ASN from a simple AS path."""
    parsed_path = parse_as_path(as_path)

    if not parsed_path:
        return None

    return parsed_path[-1]


def parse_bgp_update(update: dict) -> dict:
    """Normalize a decoded BGP update."""
    if not isinstance(update, dict):
        raise ValueError("BGP update must be a dictionary")

    event_type = update.get("event_type")

    if not isinstance(event_type, str):
        raise ValueError("Missing or invalid event_type")

    event_type = event_type.lower()
    event_type = {
        "a": "announcement",
        "w": "withdrawal",
    }.get(event_type, event_type)

    if event_type not in {"announcement", "withdrawal"}:
        raise ValueError(f"Unsupported event type: {event_type}")

    prefix = validate_prefix(update.get("prefix"))
    timestamp = update.get("timestamp")

    if isinstance(timestamp, str):
        try:
            timestamp = datetime.fromisoformat(
                timestamp.replace("Z", "+00:00")
            ).timestamp()
        except ValueError as exc:
            raise ValueError("Timestamp must be Unix or ISO 8601") from exc
    elif isinstance(timestamp, bool) or not isinstance(
        timestamp, (int, float)
    ):
        raise ValueError("Timestamp must be numeric")

    if timestamp < 0:
        raise ValueError("Timestamp cannot be negative")

    if event_type == "withdrawal":
        return {
            "timestamp": timestamp,
            "event_type": "withdrawal",
            "prefix": prefix,
            "as_path": [],
            "origin_as": None,
            "peer_as": update.get("peer_as", update.get("peer_asn")),
            "source": update.get("source", "api"),
        }

    as_path = parse_as_path(update.get("as_path", []))
    supplied_origin = update.get("origin_as")
    origin_as = extract_origin_as(as_path)

    if supplied_origin is not None:
        supplied_origin = validate_asn(supplied_origin)

        if origin_as is not None and supplied_origin != origin_as:
            raise ValueError(
                "Supplied origin ASN does not match the AS path"
            )

        origin_as = supplied_origin

    return {
        "timestamp": timestamp,
        "event_type": "announcement",
        "prefix": prefix,
        "as_path": as_path,
        "origin_as": origin_as,
        "peer_as": update.get("peer_as", update.get("peer_asn")),
        "source": update.get("source", "api"),
    }
