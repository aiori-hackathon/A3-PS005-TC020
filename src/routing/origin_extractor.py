from ..ingestion.bgp_parser import (
    parse_as_path,
    validate_asn,
)


def extract_origin_as(as_path) -> int | None:
    """Extract the origin ASN from a simple AS path."""
    parsed_path = parse_as_path(as_path)

    if not parsed_path:
        return None

    return parsed_path[-1]


def get_event_origin(event: dict) -> int | None:
    """Obtain the origin ASN from a normalized BGP event."""
    if not isinstance(event, dict):
        raise ValueError("Event must be a dictionary")

    if event.get("event_type") == "withdrawal":
        return None

    as_path = event.get("as_path", [])
    extracted_origin = extract_origin_as(as_path)

    supplied_origin = event.get("origin_as")

    if supplied_origin is not None:
        supplied_origin = validate_asn(supplied_origin)

        if (
            extracted_origin is not None
            and extracted_origin != supplied_origin
        ):
            raise ValueError(
                "Event origin ASN does not match the AS path"
            )

        if extracted_origin is None:
            return supplied_origin

    return extracted_origin