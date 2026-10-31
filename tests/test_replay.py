from src.ingestion.bgp_parser import parse_bgp_update


def test_parser_accepts_aliases_and_iso_timestamp():
    event = parse_bgp_update({
        "timestamp": "2026-10-30T10:00:00Z",
        "event_type": "A",
        "prefix": "203.0.113.0/24",
        "as_path": ["AS64510", "AS64500"],
    })
    assert event["event_type"] == "announcement"
    assert event["origin_as"] == 64500


def test_parser_rejects_origin_path_mismatch():
    import pytest

    with pytest.raises(ValueError):
        parse_bgp_update({
            "timestamp": 1793260800,
            "event_type": "announcement",
            "prefix": "203.0.113.0/24",
            "as_path": [64500],
            "origin_as": 64501,
        })