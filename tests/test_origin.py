import pytest

from src.detection.origin_rules import check_origin, validate_asn, validate_prefix


def test_origin_matches_authorized_asn():
    result = check_origin(
        "203.0.113.0/24",
        "AS64500",
        [64500, 64501],
    )
    assert result["status"] == "PASS"
    assert result["observed_origin"] == 64500


def test_origin_flags_unexpected_asn():
    result = check_origin("203.0.113.0/24", 64502, [64500])
    assert result["alert"] is True


def test_prefix_rejects_host_bits():
    with pytest.raises(ValueError):
        validate_prefix("203.0.113.1/24")


def test_asn_rejects_zero():
    with pytest.raises(ValueError):
        validate_asn(0)