from src.routing.routing_state import RoutingState


def test_routing_state_tracks_addition_and_withdrawal():
    state = RoutingState()

    added = state.process_event({
        "timestamp": 1793260800,
        "event_type": "announcement",
        "prefix": "203.0.113.0/24",
        "as_path": [64510, 64500],
    })
    assert added["origin_as"] == 64500
    assert state.get_route("203.0.113.0/24") is not None

    removed = state.process_event({
        "timestamp": 1793260801,
        "event_type": "withdrawal",
        "prefix": "203.0.113.0/24",
    })
    assert removed["action"] == "route_removed"
    assert state.get_route("203.0.113.0/24") is None
