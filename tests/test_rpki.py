from src.detection.rpki_rules import check_rpki


ROA = {
    "prefix": "203.0.113.0/24",
    "origin_as": 64500,
    "max_length": 24,
    "not_before": "2026-01-01T00:00:00Z",
    "not_after": "2030-01-01T00:00:00Z",
}


def test_rpki_valid_route():
    result = check_rpki("203.0.113.0/24", 64500, [ROA])
    assert result["state"] == "Valid"


def test_rpki_invalid_origin():
    result = check_rpki("203.0.113.0/24", 64501, [ROA])
    assert result["state"] == "Invalid"


def test_rpki_not_found():
    result = check_rpki("198.51.100.0/24", 64500, [ROA])
    assert result["state"] == "NotFound"