"""
RPKI-based detection rules for the BGP Anomaly Detector.

This module determines whether a BGP announcement is authorized
by the available Route Origin Authorizations (ROAs).
"""

import ipaddress
from datetime import datetime, timezone


def validate_roa(
    announced_prefix: str,
    origin_as: int,
    roa: dict,
    validation_time: datetime | None = None,
) -> bool:
    """
    Check whether a single ROA authorizes a BGP announcement.
    """
    try:
        announced_network = ipaddress.ip_network(
            announced_prefix,
            strict=True
        )
    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"Invalid announced prefix: {announced_prefix}"
        ) from exc

    if isinstance(origin_as, bool) or not isinstance(origin_as, int):
        raise ValueError("Origin ASN must be an integer, not a boolean")

    if not 1 <= origin_as <= 4294967295:
        raise ValueError("Origin ASN is outside the valid ASN range")

    try:
        roa_network = ipaddress.ip_network(
            roa["prefix"],
            strict=True
        )
    except (ValueError, TypeError, KeyError) as exc:
        raise ValueError("Invalid or missing ROA prefix") from exc

    roa_asn = roa.get("origin_as")

    if isinstance(roa_asn, bool) or not isinstance(roa_asn, int):
        raise ValueError("ROA origin ASN must be an integer")

    if not 1 <= roa_asn <= 4294967295:
        raise ValueError("ROA origin ASN is outside the valid ASN range")

    max_length = roa.get("max_length")

    if isinstance(max_length, bool) or not isinstance(max_length, int):
        raise ValueError("ROA max_length must be an integer")

    if not roa_network.prefixlen <= max_length <= roa_network.max_prefixlen:
        raise ValueError("ROA max_length is invalid for its prefix")

    if announced_network.version != roa_network.version:
        return False

    now = validation_time or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    now = now.astimezone(timezone.utc)
    for field in ("not_before", "not_after"):
        value = roa.get(field)
        if value is None:
            raise ValueError(f"ROA {field} is required")
        try:
            parsed = datetime.fromisoformat(
                value.replace("Z", "+00:00")
            ).astimezone(timezone.utc)
        except (AttributeError, ValueError) as exc:
            raise ValueError(f"Invalid ROA {field}") from exc
        if field == "not_before" and now < parsed:
            return False
        if field == "not_after" and now > parsed:
            return False

    if not announced_network.subnet_of(roa_network):
        return False

    if announced_network.prefixlen > max_length:
        return False

    if origin_as != roa_asn:
        return False

    return True


def check_rpki(
    announced_prefix: str,
    origin_as: int,
    roas: list[dict],
    validation_time: datetime | None = None,
) -> dict:
    """
    Determine the RPKI origin validation state of a BGP announcement.
    """
    try:
        ipaddress.ip_network(announced_prefix, strict=True)
    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"Invalid announced prefix: {announced_prefix}"
        ) from exc

    if isinstance(origin_as, bool) or not isinstance(origin_as, int):
        raise ValueError("Origin ASN must be an integer")

    if not 1 <= origin_as <= 4294967295:
        raise ValueError("Origin ASN is outside the valid ASN range")

    if not isinstance(roas, list):
        raise ValueError("ROAs must be provided as a list")

    matching_roa_found = False
    announced_network = ipaddress.ip_network(
        announced_prefix,
        strict=True
    )

    for roa in roas:
        if not isinstance(roa, dict):
            raise ValueError("Each ROA must be a dictionary")

        try:
            roa_network = ipaddress.ip_network(
                roa["prefix"],
                strict=True
            )
        except (ValueError, TypeError, KeyError) as exc:
            raise ValueError("Invalid or missing ROA prefix") from exc

        if announced_network.version != roa_network.version:
            continue

        if not announced_network.subnet_of(roa_network):
            continue

        matching_roa_found = True

        if validate_roa(
            announced_prefix,
            origin_as,
            roa,
            validation_time=validation_time,
        ):
            return {
                "state": "Valid",
                "prefix": announced_prefix,
                "origin_as": origin_as,
                "suspicious": False,
                "findings": []
            }

    if not matching_roa_found:
        return {
            "state": "NotFound",
            "prefix": announced_prefix,
            "origin_as": origin_as,
            "suspicious": False,
            "findings": [
                "No covering ROA was found for the announced prefix."
            ]
        }

    return {
        "state": "Invalid",
        "prefix": announced_prefix,
        "origin_as": origin_as,
        "suspicious": True,
        "findings": [
            "The announcement is not authorized by any covering ROA."
        ]
    }