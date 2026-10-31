from src.detection.subprefix_rules import check_subprefix


def test_unexpected_more_specific_is_alerted():
    result = check_subprefix(
        "203.0.113.0/25",
        64501,
        {"203.0.113.0/24": [64500]},
    )
    assert result["alert"] is True


def test_expected_more_specific_is_not_alerted():
    result = check_subprefix(
        "203.0.113.0/25",
        64500,
        {"203.0.113.0/24": [64500]},
    )
    assert result["alert"] is False