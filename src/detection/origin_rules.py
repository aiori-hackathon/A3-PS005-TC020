"""
Origin AS validation rules for the BGP Anomaly Detector.

Responsibilities:
    1. Validate BGP announcement prefixes and origin ASNs.
    2. Compare observed origin ASNs against authorized origins.
    3. Support prefixes with multiple legitimate origin ASNs.
    4. Generate explainable findings for unexpected origins.

This module does not perform RPKI validation or full AS_PATH analysis.
"""

import ipaddress
from typing import Any


def validate_prefix(prefix: str) -> str:
    """
    Validate an IP prefix without silently normalizing it.

    Example:
        192.0.2.0/24 -> valid
        192.0.2.10/24 -> invalid (host bits are set)
    """
    try:
        return str(ipaddress.ip_network(prefix, strict=True))
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Invalid IP prefix: {prefix}") from exc


def validate_asn(asn: int | str, field_name: str = "ASN") -> int:
    """
    Validate an Autonomous System Number (ASN).

    Accepts:
        64500
        "64500"
        "AS64500"

    Returns:
        The ASN as an integer.
    """
    if isinstance(asn, bool):
        raise ValueError(f"{field_name} must be a valid ASN")

    if isinstance(asn, str):
        asn = asn.strip().upper()

        if asn.startswith("AS"):
            asn = asn[2:]

        if not asn.isdigit():
            raise ValueError(f"{field_name} must be a valid ASN")

        asn = int(asn)

    if not isinstance(asn, int) or not 1 <= asn <= 4_294_967_295:
        raise ValueError(f"{field_name} must be between 0 and 4294967295")

    return asn


def check_origin(
    prefix: str,
    observed_origin: int | str,
    expected_origins: int | str | list[int | str] | set[int | str] | tuple[int | str, ...],
) -> dict[str, Any]:
    """
    Check whether an observed BGP origin ASN is authorized for a prefix.

    Args:
        prefix:
            The exact IP prefix announced through BGP.

        observed_origin:
            The origin ASN extracted from the BGP announcement.

        expected_origins:
            One or more authorized origin ASNs for this prefix.

    Returns:
        A dictionary describing the result.

    Example:
        check_origin(
            prefix="203.0.113.0/24",
            observed_origin="AS64501",
            expected_origins=["AS64500"],
        )
    """

    # Step 1: Validate the announced prefix.
    validated_prefix = validate_prefix(prefix)

    # Step 2: Validate the observed origin ASN.
    observed_asn = validate_asn(
        observed_origin,
        field_name="observed_origin",
    )

    # Step 3: Normalize expected origins into a collection.
    if isinstance(expected_origins, (str, int)):
        expected_origins = [expected_origins]
    elif isinstance(expected_origins, (list, set, tuple)):
        expected_origins = list(expected_origins)
    else:
        raise ValueError(
            "expected_origins must be an ASN or a collection of ASNs"
        )

    if not expected_origins:
        raise ValueError("expected_origins cannot be empty")

    # Step 4: Validate every authorized origin.
    authorized_asns = sorted(
        {
            validate_asn(asn, field_name="expected_origin")
            for asn in expected_origins
        }
    )

    # Step 5: Compare the observed origin with authorized origins.
    if observed_asn in authorized_asns:
        return {
            "rule": "origin_validation",
            "status": "PASS",
            "alert": False,
            "prefix": validated_prefix,
            "observed_origin": observed_asn,
            "expected_origins": authorized_asns,
            "reason": "Observed origin matches an authorized origin.",
        }

    # Step 6: Report an unexpected origin.
    return {
        "rule": "origin_validation",
        "status": "ALERT",
        "alert": True,
        "prefix": validated_prefix,
        "observed_origin": observed_asn,
        "expected_origins": authorized_asns,
        "reason": (
            f"Unexpected origin AS{observed_asn} announced "
            f"{validated_prefix}. "
            f"Authorized origins: "
            f"{', '.join(f'AS{asn}' for asn in authorized_asns)}."
        ),
    }


def check_announcement(event: dict[str, Any]) -> dict[str, Any]:
    """
    Check a normalized BGP announcement event.

    Expected event format:
        {
            "timestamp": "2026-10-28T10:00:00Z",
            "event_type": "A",
            "prefix": "203.0.113.0/24",
            "origin_as": 64501
        }

    The expected origins must be supplied separately from the event.
    """

    if not isinstance(event, dict):
        raise ValueError("event must be a dictionary")

    if event.get("event_type") != "A":
        raise ValueError(
            "Origin validation requires an announcement event ('A')"
        )

    required_fields = ("prefix", "origin_as", "expected_origins")

    for field in required_fields:
        if field not in event:
            raise ValueError(f"Missing required event field: {field}")

    return check_origin(
        prefix=event["prefix"],
        observed_origin=event["origin_as"],
        expected_origins=event["expected_origins"],
    )