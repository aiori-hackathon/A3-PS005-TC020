from .origin_rules import check_origin
from .rpki_rules import check_rpki
from .subprefix_rules import check_subprefix
from datetime import datetime, timezone
import ipaddress


def detect_anomaly(event, expected_origins, roas=None):
    """
    Combine RPKI, origin, and subprefix detection rules.

    Parameters:
        event (dict):
            A normalized BGP event containing:
            - event_type: "A" for announcement or "W" for withdrawal
            - prefix: announced or withdrawn IP prefix
            - origin_as: originating AS number (for announcements)
            - rpki_state: "VALID", "INVALID", or "NOT_FOUND"

        expected_origins (dict):
            Maps prefixes to their expected origin AS numbers.

        roas (list, optional):
            ROA records used by the RPKI detection rule.

    Returns:
        dict: Consolidated anomaly assessment.
    """

    if not isinstance(event, dict):
        raise ValueError("Event must be a dictionary")

    event_type = event.get("event_type")
    prefix = event.get("prefix")

    if event_type not in ("announcement", "withdrawal", "A", "W"):
        raise ValueError(
            "event_type must be 'announcement', 'withdrawal', 'A', or 'W'"
        )

    if not prefix:
        raise ValueError("Event must contain a prefix")

    findings = []
    timestamp = event.get("timestamp")

    # Withdrawals do not contain an origin AS.
    # Handle them separately from announcements.
    if event_type in ("W", "withdrawal"):
        return {
            "timestamp": timestamp,
            "prefix": prefix,
            "origin_as": None,
            "event_type": "withdrawal",
            "suspicious": False,
            "severity": "Informational",
            "confidence_score": 0.0,
            "rpki_state": "Unknown",
            "findings": [],
            "reason": (
                "Withdrawal received. Additional route history "
                "is required to determine whether it is anomalous."
            ),
            "recommended_action": "Update route state and review route history.",
        }

    origin_as = event.get("origin_as")

    if origin_as is None:
        raise ValueError(
            "Announcement must contain an origin_as"
        )

    # Rule 1: Check whether the origin AS is expected.
    expected_for_origin = expected_origins.get(prefix)
    if expected_for_origin is None:
        announced_network = ipaddress.ip_network(prefix, strict=True)
        covering = []
        for known_prefix, origins in expected_origins.items():
            known_network = ipaddress.ip_network(known_prefix, strict=True)
            if (
                announced_network.version == known_network.version
                and announced_network.subnet_of(known_network)
            ):
                covering.append((known_network.prefixlen, origins))
        if covering:
            expected_for_origin = max(covering, key=lambda item: item[0])[1]

    if expected_for_origin is None:
        raise ValueError(
            f"No inventory entry found for announced prefix: {prefix}"
        )

    origin_result = check_origin(
        prefix,
        origin_as,
        expected_for_origin,
    )

    findings.append(origin_result)

    # Rule 2: Check the RPKI validation state.
    if roas is not None:
        validation_time = event.get("timestamp")
        if isinstance(validation_time, (int, float)):
            validation_time = datetime.fromtimestamp(
                validation_time,
                tz=timezone.utc,
            )
        elif isinstance(validation_time, str):
            validation_time = datetime.fromisoformat(
                validation_time.replace("Z", "+00:00")
            )
        rpki_result = check_rpki(
            prefix,
            origin_as,
            roas,
            validation_time=validation_time,
        )

        findings.append(rpki_result)

    # Rule 3: Check for suspicious subprefix announcements.
    subprefix_result = check_subprefix(
        prefix,
        origin_as,
        expected_origins,
    )

    findings.append(subprefix_result)

    # Preserve all rule findings, including non-alert findings.
    alerts = [
        finding
        for finding in findings
        if finding.get("alert", False)
        or finding.get("suspicious", False)
    ]

    # Combine the evidence without assuming that one failed
    # rule automatically proves a BGP hijack.
    suspicious = len(alerts) > 0
    rpki_states = [
        finding.get("state")
        for finding in findings
        if "state" in finding
    ]
    rpki_state = rpki_states[0] if rpki_states else "Unknown"
    severity = "High" if len(alerts) > 1 or rpki_state == "Invalid" else (
        "Medium" if suspicious else "Informational"
    )
    confidence_score = min(0.99, 0.6 + 0.15 * len(alerts)) if suspicious else 0.0

    return {
        "timestamp": timestamp,
        "prefix": prefix,
        "origin_as": origin_as,
        "event_type": "announcement",
        "suspicious": suspicious,
        "severity": severity,
        "confidence_score": round(confidence_score, 2),
        "rpki_state": rpki_state,
        "findings": findings,
        "alerts": alerts,
        "reason": (
            "One or more detection rules raised an alert."
            if suspicious
            else "No detection rules raised an alert."
        ),
        "recommended_action": (
            "Investigate the origin AS, applicable ROAs, and route history."
            if suspicious
            else "Continue monitoring the route."
        ),
    }