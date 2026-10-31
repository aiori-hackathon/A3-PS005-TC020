from src.detection.hybrid_detector import detect_anomaly


def test_hybrid_detector_reports_origin_and_subprefix_alerts():
    result = detect_anomaly(
        {
            "timestamp": 1793260800,
            "event_type": "announcement",
            "prefix": "203.0.113.0/25",
            "origin_as": 64501,
        },
        {"203.0.113.0/24": [64500]},
    )
    assert result["suspicious"] is True
    assert result["alerts"]


def test_hybrid_detector_handles_withdrawal():
    result = detect_anomaly(
        {
            "event_type": "withdrawal",
            "prefix": "203.0.113.0/24",
        },
        {"203.0.113.0/24": [64500]},
    )
    assert result["event_type"] == "withdrawal"
    assert result["suspicious"] is False
