from src.detection.origin_rules import check_origin


def test_multiple_legitimate_origins_are_supported():
    result = check_origin(
        "203.0.113.0/24",
        64501,
        ["AS64500", "AS64501"],
    )
    assert result["alert"] is False