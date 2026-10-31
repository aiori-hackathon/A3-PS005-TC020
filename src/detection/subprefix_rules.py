import ipaddress


def check_subprefix(prefix, origin_as, expected_origins):
    """
    Check whether a BGP announcement is a suspicious subprefix.
    """
    try:
        announced_network = ipaddress.ip_network(
            prefix,
            strict=True,
        )
    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"Invalid IP prefix: {prefix}"
        ) from exc

    if isinstance(origin_as, bool):
        raise ValueError("Origin AS must be a valid AS number")

    try:
        if isinstance(origin_as, str) and origin_as.upper().startswith("AS"):
            origin_as = origin_as[2:]
        origin_as = int(origin_as)
    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"Invalid origin AS: {origin_as}"
        ) from exc

    if not 1 <= origin_as <= 4294967295:
        raise ValueError("Origin AS must be between 1 and 4294967295")

    for known_prefix, known_origins in expected_origins.items():
        try:
            known_network = ipaddress.ip_network(
                known_prefix,
                strict=True,
            )
        except (ValueError, TypeError) as exc:
            raise ValueError(
                f"Invalid known prefix: {known_prefix}"
            ) from exc

        if announced_network.version != known_network.version:
            continue

        if (
            announced_network != known_network
            and announced_network.subnet_of(known_network)
        ):
            if isinstance(known_origins, (int, str)):
                known_origins = [known_origins]

            expected_asns = []

            for asn in known_origins:
                if isinstance(asn, bool):
                    raise ValueError(
                        f"Invalid expected origin AS: {asn}"
                    )

                try:
                    if isinstance(asn, str) and asn.upper().startswith("AS"):
                        asn = asn[2:]
                    asn = int(asn)
                except (ValueError, TypeError) as exc:
                    raise ValueError(
                        f"Invalid expected origin AS: {asn}"
                    ) from exc

                if not 1 <= asn <= 4294967295:
                    raise ValueError(
                        f"Invalid expected origin AS: {asn}"
                    )

                expected_asns.append(asn)

            if origin_as not in expected_asns:
                return {
                    "rule": "SUBPREFIX_CHECK",
                    "status": "ALERT",
                    "alert": True,
                    "suspicious": True,
                    "prefix": str(announced_network),
                    "origin_as": origin_as,
                    "covering_prefix": str(known_network),
                    "expected_origins": expected_asns,
                    "reason": (
                        "A more-specific prefix was announced "
                        "by an unexpected origin AS."
                    ),
                }

    return {
        "rule": "SUBPREFIX_CHECK",
        "status": "PASS",
        "alert": False,
        "suspicious": False,
        "prefix": str(announced_network),
        "origin_as": origin_as,
        "reason": "No suspicious subprefix announcement detected.",
    }