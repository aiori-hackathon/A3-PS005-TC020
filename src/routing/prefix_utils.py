import ipaddress


def normalize_prefix(prefix: str) -> str:
    """Validate an IP prefix and return its canonical representation."""
    if not isinstance(prefix, str):
        raise ValueError("Prefix must be a string")

    try:
        network = ipaddress.ip_network(prefix, strict=False)
        return str(network)
    except ValueError as exc:
        raise ValueError(f"Invalid IP prefix: {prefix}") from exc


def is_more_specific(candidate: str, reference: str) -> bool:
    """Return True if candidate is strictly more specific than reference."""
    candidate_network = ipaddress.ip_network(normalize_prefix(candidate))
    reference_network = ipaddress.ip_network(normalize_prefix(reference))

    return (
        candidate_network != reference_network
        and candidate_network.subnet_of(reference_network)
    )


def prefixes_overlap(prefix1: str, prefix2: str) -> bool:
    """Return True if two IP prefixes share any IP addresses."""
    network1 = ipaddress.ip_network(normalize_prefix(prefix1))
    network2 = ipaddress.ip_network(normalize_prefix(prefix2))

    if network1.version != network2.version:
        return False

    return network1.overlaps(network2)


def is_same_prefix(prefix1: str, prefix2: str) -> bool:
    """Return True if both inputs represent the same network."""
    network1 = ipaddress.ip_network(normalize_prefix(prefix1))
    network2 = ipaddress.ip_network(normalize_prefix(prefix2))

    return network1 == network2


def get_prefix_length(prefix: str) -> int:
    """Return the prefix length."""
    network = ipaddress.ip_network(normalize_prefix(prefix))
    return network.prefixlen