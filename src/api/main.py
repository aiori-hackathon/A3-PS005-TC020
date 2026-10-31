"""FastAPI application for BGP anomaly detection."""

from contextlib import asynccontextmanager
import ipaddress
import logging
from pathlib import Path
import tempfile
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ..config import settings
from ..detection.hybrid_detector import detect_anomaly
from ..ingestion.bgp_parser import parse_bgp_update
from ..ingestion.inventory_loader import load_inventory
from ..ingestion.roa_loader import load_roas
from ..storage.database import get_database
from ..storage.repositories import (
    ActiveRouteRepository,
    DetectionResultRepository,
    EventRepository,
    InventoryRepository,
    RoaRepository,
    RouteHistoryRepository,
)
from ..ml.model import model_status, predict_anomaly

logger = logging.getLogger("bgp_sentinel.api")
MAX_REQUEST_BYTES = 2 * 1024 * 1024


def _ml_features(
    event: dict[str, Any],
    result: dict[str, Any],
    observed_routes: list[dict[str, Any]],
) -> dict[str, int]:
    """Build the feature vector in the trained model's expected format."""
    network = ipaddress.ip_network(event["prefix"], strict=True)
    findings = result.get("findings", [])
    rpki_state = str(result.get("rpki_state", "Unknown")).lower()
    origin_mismatch = any(
        finding.get("rule") == "origin_validation"
        and finding.get("alert", False)
        for finding in findings
        if isinstance(finding, dict)
    )
    max_length_exceeded = any(
        "max length" in str(finding).lower()
        for finding in findings
    )
    parent_prefix = False
    more_specific = False
    for route in observed_routes:
        if route.get("prefix") == event["prefix"]:
            continue
        other = ipaddress.ip_network(route["prefix"], strict=True)
        if other.version != network.version:
            continue
        parent_prefix |= network.subnet_of(other)
        more_specific |= other.subnet_of(network)

    return {
        "prefix_length": network.prefixlen,
        "ip_version": network.version,
        "rov_valid": int(rpki_state == "valid"),
        "rov_invalid": int(rpki_state == "invalid"),
        "rov_notfound": int(rpki_state == "notfound"),
        "origin_mismatch": int(origin_mismatch),
        "max_length_exceeded": int(max_length_exceeded),
        "has_observed_parent_prefix": int(parent_prefix),
        "has_observed_more_specific": int(more_specific),
    }


def _apply_ml_confidence(
    event: dict[str, Any],
    result: dict[str, Any],
    observed_routes: list[dict[str, Any]],
) -> dict[str, Any]:
    """Use the model probability as confidence when the optional model is ready."""
    try:
        prediction = predict_anomaly(
            _ml_features(event, result, observed_routes)
        )
    except (FileNotFoundError, ImportError, OSError, ValueError) as exc:
        logger.warning("ML confidence unavailable: %s", exc)
        result["ml_score"] = None
        result["ml_prediction"] = None
        return result

    result["ml_score"] = prediction["anomaly_probability"]
    result["ml_prediction"] = prediction["prediction"]
    result["confidence_score"] = prediction["anomaly_probability"]
    return result


database = get_database()
events = EventRepository(database)
routes = ActiveRouteRepository(database)
history = RouteHistoryRepository(database)
roas = RoaRepository(database)
inventory = InventoryRepository(database)


def _load_configured_data() -> None:
    if settings.inventory_path:
        inventory.replace_all(load_inventory(settings.inventory_path))
    if settings.roa_path:
        roas.replace_all(load_roas(settings.roa_path))


@asynccontextmanager
async def lifespan(_: FastAPI):
    database.initialize()
    _load_configured_data()
    yield


app = FastAPI(title="BGP Anomaly Monitor", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=(
        ["*"] if settings.cors_origins == "*"
        else [origin.strip() for origin in settings.cors_origins.split(",")]
    ),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class EventPayload(BaseModel):
    """Validated request envelope for a normalized BGP event."""

    timestamp: float | str | None = None
    event_type: str
    prefix: str
    origin_as: int | str | None = None
    as_path: list[int | str] = Field(default_factory=list)
    peer_as: int | str | None = None
    source: str | None = None

    class Config:
        extra = "allow"


@app.middleware("http")
async def request_guard(request: Request, call_next):
    """Support Vercel's /api prefix and reject oversized JSON requests."""
    if request.url.path.startswith("/api/"):
        request.scope["path"] = request.url.path[4:]
    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > MAX_REQUEST_BYTES:
        return JSONResponse(
            status_code=413,
            content={"detail": "Request body is too large"},
        )
    logger.info("%s %s", request.method, request.url.path)
    return await call_next(request)


@app.get("/health")
def health() -> dict[str, str]:
    try:
        with database.connect() as connection:
            connection.execute("SELECT 1").fetchone()
        return {"status": "ok"}
    except Exception as exc:
        logger.exception("Database health check failed")
        raise HTTPException(
            status_code=503,
            detail="Database is unavailable",
        ) from exc


def _detect(event: dict[str, Any]) -> dict:
    normalized = parse_bgp_update(event)
    event_record = events.create(normalized)
    previous = routes.get(normalized["prefix"])
    observed_routes = routes.list()
    route_result = routes.upsert({
        "prefix": normalized["prefix"],
        "origin_as": normalized["origin_as"],
        "as_path": normalized["as_path"],
        "timestamp": normalized["timestamp"],
    }) if normalized["event_type"] == "announcement" else None
    if normalized["event_type"] == "withdrawal":
        routes.delete(normalized["prefix"])
        route_result = {"previous_route": previous}

    result = detect_anomaly(normalized, inventory.as_dict(), roas.list())
    if normalized["event_type"] == "announcement":
        result = _apply_ml_confidence(normalized, result, observed_routes)
    route_entry = {
        "timestamp": normalized["timestamp"],
        "event_type": normalized["event_type"],
        "prefix": normalized["prefix"],
        "origin_as": normalized["origin_as"],
        "action": "route_added_or_updated" if route_result and normalized["event_type"] == "announcement"
                  else ("route_removed" if route_result and route_result.get("previous_route") else "route_not_found"),
        "previous_route": previous,
    }
    history.create(route_entry, event_record["id"])
    DetectionResultRepository(database).create(result, event_record["id"])
    return result


def _event_dict(event: EventPayload) -> dict[str, Any]:
    return event.dict(exclude_none=True)


@app.post("/detect")
@app.post("/analyze")
@app.post("/ingest")
def detect(event: EventPayload) -> dict:
    try:
        return _detect(_event_dict(event))
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/detect/batch")
@app.post("/replay")
def detect_batch(payload: list[EventPayload]) -> dict[str, Any]:
    if len(payload) > 1000:
        raise HTTPException(status_code=413, detail="A maximum of 1000 events is allowed")
    results = []
    for event in payload:
        try:
            results.append(_detect(_event_dict(event)))
        except (ValueError, KeyError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"results": results, "count": len(results)}


@app.post("/upload-mrt")
async def upload_mrt(request: Request) -> dict[str, Any]:
    """Replay a bounded MRT upload without creating a persistent server file."""
    body = await request.body()
    if len(body) > MAX_REQUEST_BYTES:
        raise HTTPException(status_code=413, detail="MRT upload is too large")

    from ..ingestion.mrt_parser import replay_mrt_events

    suffix = ".gz" if request.headers.get("content-type") == "application/gzip" else ""
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as handle:
        handle.write(body)
        path = Path(handle.name)

    results: list[dict] = []
    try:
        for index, event in enumerate(replay_mrt_events(str(path))):
            if index >= 1000:
                raise HTTPException(
                    status_code=413,
                    detail="MRT replay is limited to 1000 events per request",
                )
            results.append(_detect(event))
    except (ValueError, KeyError, RuntimeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        path.unlink(missing_ok=True)
    return {"results": results, "count": len(results)}


@app.get("/routes")
def get_routes() -> list[dict]:
    return routes.list()


@app.get("/history")
def get_history(
    prefix: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[dict]:
    return history.list(prefix=prefix, limit=limit)


@app.post("/roas")
@app.post("/upload-roa")
def replace_roas(payload: list[dict[str, Any]]) -> dict[str, int]:
    try:
        from ..ingestion.roa_loader import validate_roa_record
        normalized = [validate_roa_record(record) for record in payload]
        roas.replace_all(normalized)
        return {"count": len(normalized)}
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/inventory")
@app.post("/upload-inventory")
def replace_inventory(payload: list[dict[str, Any]]) -> dict[str, int]:
    try:
        from ..ingestion.inventory_loader import validate_inventory_record
        normalized = [validate_inventory_record(record) for record in payload]
        values: dict[str, list[int]] = {}
        for record in normalized:
            if record["prefix"] in values:
                raise ValueError(f"Duplicate prefix: {record['prefix']}")
            values[record["prefix"]] = record["origin_as"]
        inventory.replace_all(values)
        return {"count": len(values)}
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/model/status")
@app.get("/ml/status")
def get_model_status() -> dict:
    return model_status()