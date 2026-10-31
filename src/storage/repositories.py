"""Persistence repositories mapped to the final Supabase schema."""

from datetime import datetime, timezone
import json
import sqlite3
from typing import Any
from uuid import uuid4


def _json(value: Any) -> str:
    return json.dumps(value if value is not None else {}, separators=(",", ":"))


def _timestamp(value: float | str) -> str:
    if isinstance(value, str):
        return value.replace("Z", "+00:00")
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()


def _decode(row: Any) -> dict | None:
    if row is None:
        return None
    result = dict(row)
    for field in (
        "raw_event", "as_path", "observed_value", "expected_value",
        "additional_evidence", "feature_values", "metadata",
    ):
        if field in result and isinstance(result[field], str):
            try:
                result[field] = json.loads(result[field])
            except json.JSONDecodeError:
                pass
    return result


class EventRepository:
    def __init__(self, database):
        self.database = database

    def create(self, event: dict) -> dict:
        event_id = str(uuid4())
        fingerprint = _json({
            "timestamp": event["timestamp"],
            "event_type": event["event_type"],
            "prefix": event["prefix"],
            "origin_as": event.get("origin_as"),
            "as_path": event.get("as_path", []),
        })
        with self.database.connect() as db:
            row = db.execute(
                """INSERT INTO bgp_events
                (id,event_timestamp,peer_asn,prefix,origin_asn,event_type,raw_event,ingestion_source,fingerprint)
                VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(fingerprint) DO UPDATE SET fingerprint=EXCLUDED.fingerprint
                RETURNING *""",
                (
                    event_id,
                    _timestamp(event["timestamp"]),
                    event.get("peer_as"),
                    event["prefix"],
                    event.get("origin_as"),
                    event["event_type"],
                    _json(event),
                    event.get("source", "api"),
                    fingerprint,
                ),
            ).fetchone()
        return _decode(row)

    add = create

    def list(self, prefix: str | None = None, limit: int = 100) -> list[dict]:
        query, args = "SELECT * FROM bgp_events", []
        if prefix:
            query += " WHERE prefix=?"
            args.append(prefix)
        query += " ORDER BY event_timestamp DESC, created_at DESC LIMIT ?"
        args.append(limit)
        with self.database.connect() as db:
            return [_decode(row) for row in db.execute(query, args)]


class ActiveRouteRepository:
    def __init__(self, database):
        self.database = database

    def upsert(self, route: dict) -> dict:
        route_id = str(uuid4())
        with self.database.connect() as db:
            db.execute(
                """INSERT INTO routing_state
                (id,prefix,origin_asn,as_path,last_seen,active)
                VALUES(?,?,?,?,?,?)
                ON CONFLICT(prefix) DO UPDATE SET
                origin_asn=excluded.origin_asn, as_path=excluded.as_path,
                last_seen=excluded.last_seen, active=excluded.active,
                updated_at=CURRENT_TIMESTAMP""",
                (
                    route_id, route["prefix"], route["origin_as"],
                    _json(route.get("as_path", [])), _timestamp(route["timestamp"]), True,
                ),
            )
            row = db.execute("SELECT * FROM routing_state WHERE prefix=?", (route["prefix"],)).fetchone()
        return _decode(row)

    def delete(self, prefix: str) -> None:
        with self.database.connect() as db:
            db.execute(
                "UPDATE routing_state SET active=FALSE, updated_at=CURRENT_TIMESTAMP "
                "WHERE prefix=?",
                (prefix,),
            )

    def get(self, prefix: str) -> dict | None:
        with self.database.connect() as db:
            return _decode(db.execute(
                "SELECT * FROM routing_state WHERE prefix=? AND active=TRUE", (prefix,)
            ).fetchone())

    def list(self) -> list[dict]:
        with self.database.connect() as db:
            return [_decode(row) for row in db.execute(
                "SELECT * FROM routing_state WHERE active=TRUE ORDER BY prefix"
            )]


class RouteHistoryRepository:
    """Expose event history from the final schema's bgp_events table."""

    def __init__(self, database):
        self.database = database

    def create(self, entry: dict, event_id: str | None = None) -> dict:
        with self.database.connect() as db:
            row = db.execute(
                "SELECT * FROM bgp_events WHERE id=?", (event_id,)
            ).fetchone()
        return _decode(row) or entry

    add = create

    def list(self, prefix: str | None = None, limit: int = 100) -> list[dict]:
        query, args = "SELECT * FROM bgp_events", []
        if prefix:
            query += " WHERE prefix=?"
            args.append(prefix)
        query += " ORDER BY event_timestamp DESC LIMIT ?"
        args.append(limit)
        with self.database.connect() as db:
            return [_decode(row) for row in db.execute(query, args)]


class RoaRepository:
    def __init__(self, database):
        self.database = database

    def replace_all(self, roas: list[dict]) -> None:
        with self.database.connect() as db:
            db.execute("DELETE FROM roa_records")
            db.executemany(
                """INSERT INTO roa_records
                (id,prefix,origin_asn,max_length,not_before,not_after)
                VALUES(?,?,?,?,?,?)""",
                [
                    (
                        str(uuid4()), r["prefix"], r["origin_as"], r["max_length"],
                        r.get("not_before"), r.get("not_after"),
                    )
                    for r in roas
                ],
            )

    def list(self) -> list[dict]:
        with self.database.connect() as db:
            return [dict(row) for row in db.execute(
                "SELECT * FROM roa_records ORDER BY prefix, origin_asn"
            )]


class InventoryRepository:
    def __init__(self, database):
        self.database = database

    def replace_all(self, inventory: dict[str, list[int]]) -> None:
        with self.database.connect() as db:
            db.execute("DELETE FROM prefix_inventory")
            db.executemany(
                """INSERT INTO prefix_inventory
                (id,prefix,expected_origin_asn,status)
                VALUES(?,?,?,'active')""",
                [
                    (str(uuid4()), prefix, asn)
                    for prefix, origins in inventory.items()
                    for asn in origins
                ],
            )

    def as_dict(self) -> dict[str, list[int]]:
        with self.database.connect() as db:
            result: dict[str, list[int]] = {}
            for row in db.execute(
                "SELECT prefix,expected_origin_asn FROM prefix_inventory "
                "WHERE status='active' ORDER BY prefix,expected_origin_asn"
            ):
                result.setdefault(row["prefix"], []).append(row["expected_origin_asn"])
            return result


class DetectionResultRepository:
    def __init__(self, database):
        self.database = database

    def create(self, result: dict, event_id: str | None = None) -> dict:
        alerts = []
        with self.database.connect() as db:
            for finding in result.get("findings", []):
                if not (finding.get("alert") or finding.get("suspicious")):
                    continue
                alert_id = str(uuid4())
                alert = db.execute(
                    """INSERT INTO anomaly_alerts
                    (id,event_id,prefix,observed_origin_asn,expected_origin_asn,
                     anomaly_type,severity,explanation,detection_source,ml_score)
                    VALUES(?,?,?,?,?,?,?,?,?,?) RETURNING *""",
                    (
                        alert_id, event_id, result["prefix"], result.get("origin_as"),
                        (
                            finding.get("expected_origin")
                            or finding.get("expected_origins", [None])[0]
                        ),
                        finding.get("rule", "anomaly"),
                        str(result.get("severity", "medium")).lower().replace(
                            "informational", "low"
                        ),
                        finding.get("reason", result.get("reason", "Detection rule alert")),
                        finding.get("rule", "rule_engine"), result.get("ml_score"),
                    ),
                ).fetchone()
                alerts.append(_decode(alert))
                db.execute(
                    """INSERT INTO detection_evidence
                    (id,alert_id,rule_name,evidence_description,observed_value,
                     expected_value,additional_evidence)
                    VALUES(?,?,?,?,?,?,?)""",
                    (
                        str(uuid4()), alert_id, finding.get("rule", "rule_engine"),
                        finding.get("reason", "Detection rule alert"),
                        _json(finding.get("observed")), _json(finding.get("expected")),
                        _json(finding),
                    ),
                )
        return {"result": result, "alerts": alerts}

    add = create

    def list(self, limit: int = 100) -> list[dict]:
        with self.database.connect() as db:
            return [_decode(row) for row in db.execute(
                "SELECT * FROM anomaly_alerts ORDER BY alert_timestamp DESC LIMIT ?", (limit,)
            )]


RouteRepository = ActiveRouteRepository
ROARepository = RoaRepository
DetectionRepository = DetectionResultRepository
