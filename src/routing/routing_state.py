from copy import deepcopy

from ..ingestion.bgp_parser import parse_bgp_update
from .origin_extractor import get_event_origin
from .prefix_utils import (
    normalize_prefix,
    is_more_specific,
)


class RoutingState:
    """Maintain a simplified view of currently observed BGP routes."""

    def __init__(self):
        self.active_routes = {}
        self.history = []

    def process_event(self, raw_event: dict) -> dict:
        """Normalize and process one BGP announcement or withdrawal."""
        event = parse_bgp_update(raw_event)

        prefix = normalize_prefix(event["prefix"])
        event_type = event["event_type"]

        previous_route = self.active_routes.get(prefix)

        if event_type == "announcement":
            origin_as = get_event_origin(event)

            if origin_as is None:
                raise ValueError(
                    "Cannot store an announcement without an origin ASN"
                )

            route = {
                "prefix": prefix,
                "origin_as": origin_as,
                "as_path": list(event["as_path"]),
                "timestamp": event["timestamp"],
            }

            self.active_routes[prefix] = route

            result = {
                "event_type": "announcement",
                "prefix": prefix,
                "origin_as": origin_as,
                "action": "route_added_or_updated",
                "previous_route": deepcopy(previous_route),
            }
        else:
            removed_route = self.active_routes.pop(prefix, None)

            result = {
                "event_type": "withdrawal",
                "prefix": prefix,
                "origin_as": None,
                "action": (
                    "route_removed"
                    if removed_route is not None
                    else "route_not_found"
                ),
                "previous_route": deepcopy(removed_route),
            }

        result["timestamp"] = event["timestamp"]
        self.history.append(deepcopy(result))

        return result

    def get_route(self, prefix: str) -> dict | None:
        """Return the currently stored route for a prefix."""
        normalized = normalize_prefix(prefix)
        route = self.active_routes.get(normalized)
        return deepcopy(route) if route is not None else None

    def get_all_routes(self) -> list[dict]:
        """Return all currently active routes."""
        return [
            deepcopy(route)
            for route in self.active_routes.values()
        ]

    def get_more_specific_routes(self, prefix: str) -> list[dict]:
        """Find active routes strictly more specific than a given prefix."""
        normalized = normalize_prefix(prefix)

        return [
            deepcopy(route)
            for route in self.active_routes.values()
            if is_more_specific(route["prefix"], normalized)
        ]

    def get_history(self) -> list[dict]:
        """Return the recorded sequence of state changes."""
        return deepcopy(self.history)