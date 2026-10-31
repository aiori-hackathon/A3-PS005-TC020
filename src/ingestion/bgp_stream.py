"""Incremental BGP event processing interface."""

from collections.abc import Callable, Iterable, Iterator
from typing import Any

from ..detection.hybrid_detector import detect_anomaly
from ..routing.routing_state import RoutingState
from .bgp_parser import parse_bgp_update


def process_events(
    events: Iterable[dict[str, Any]],
    expected_origins: dict[str, list[int]],
    roas: list[dict] | None = None,
    on_result: Callable[[dict[str, Any]], None] | None = None,
) -> Iterator[dict[str, Any]]:
    """Normalize, track, detect, and yield events incrementally."""
    state = RoutingState()

    for raw_event in events:
        event = parse_bgp_update(raw_event)
        state.process_event(event)
        result = detect_anomaly(event, expected_origins, roas)
        result["routing_state"] = {
            "active_route_count": len(state.active_routes),
        }
        if on_result is not None:
            on_result(result)
        yield result
