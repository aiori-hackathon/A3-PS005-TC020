import json
from pathlib import Path

try:
    from .bgp_parser import parse_bgp_update
except ImportError:
    from bgp_parser import parse_bgp_update


def load_bgp_events(file_path: str) -> list[dict]:
    """Read JSONL BGP events, normalize them, and sort by timestamp."""
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"BGP event file not found: {path}"
        )

    events = []

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            try:
                raw_event = json.loads(line)
                parsed_event = parse_bgp_update(raw_event)
                events.append(parsed_event)
            except (json.JSONDecodeError, ValueError) as exc:
                raise ValueError(
                    f"Invalid BGP event on line {line_number}: {exc}"
                ) from exc

    events.sort(key=lambda event: event["timestamp"])
    return events


def replay_bgp_events(file_path: str):
    """Yield normalized BGP events in chronological order."""
    events = load_bgp_events(file_path)

    for event in events:
        yield event
