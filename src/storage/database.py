"""SQLite and PostgreSQL database connection and schema management."""

from pathlib import Path
import sqlite3
from typing import Iterator

from ..config import ensure_database_parent, settings

SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS bgp_events (
 id TEXT PRIMARY KEY, event_timestamp TEXT NOT NULL, peer_asn INTEGER,
 prefix TEXT NOT NULL, origin_asn INTEGER, event_type TEXT NOT NULL
   CHECK (event_type IN ('announcement', 'withdrawal')),
 raw_event TEXT NOT NULL DEFAULT '{}', ingestion_source TEXT NOT NULL DEFAULT 'api',
 fingerprint TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_bgp_events_prefix_time
 ON bgp_events(prefix, event_timestamp DESC);
CREATE TABLE IF NOT EXISTS roa_records (
 id TEXT PRIMARY KEY, prefix TEXT NOT NULL, origin_asn INTEGER NOT NULL,
 max_length INTEGER NOT NULL CHECK (max_length BETWEEN 0 AND 128),
 trust_anchor TEXT, not_before TEXT, not_after TEXT,
 last_updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(prefix, origin_asn, max_length, not_before, not_after)
);
CREATE TABLE IF NOT EXISTS prefix_inventory (
 id TEXT PRIMARY KEY, prefix TEXT NOT NULL, expected_origin_asn INTEGER NOT NULL,
 max_length INTEGER, organization TEXT, description TEXT,
 status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(prefix, expected_origin_asn)
);
CREATE TABLE IF NOT EXISTS routing_state (
 id TEXT PRIMARY KEY, prefix TEXT NOT NULL UNIQUE, origin_asn INTEGER NOT NULL,
 as_path TEXT NOT NULL DEFAULT '[]', next_hop TEXT, last_seen TEXT NOT NULL,
 active INTEGER NOT NULL DEFAULT 1, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS anomaly_alerts (
 id TEXT PRIMARY KEY, event_id TEXT REFERENCES bgp_events(id) ON DELETE SET NULL,
 prefix TEXT NOT NULL, observed_origin_asn INTEGER, expected_origin_asn INTEGER,
 anomaly_type TEXT NOT NULL, severity TEXT NOT NULL,
 explanation TEXT NOT NULL, detection_source TEXT NOT NULL, ml_score REAL,
 alert_timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 status TEXT NOT NULL DEFAULT 'open'
   CHECK (status IN ('open', 'acknowledged', 'resolved', 'false_positive'))
);
CREATE INDEX IF NOT EXISTS idx_alerts_time_status
 ON anomaly_alerts(alert_timestamp DESC, status);
CREATE TABLE IF NOT EXISTS detection_evidence (
 id TEXT PRIMARY KEY, alert_id TEXT NOT NULL REFERENCES anomaly_alerts(id) ON DELETE CASCADE,
 rule_name TEXT NOT NULL, evidence_description TEXT NOT NULL,
 observed_value TEXT, expected_value TEXT, additional_evidence TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS ml_predictions (
 id TEXT PRIMARY KEY, event_id TEXT REFERENCES bgp_events(id) ON DELETE SET NULL,
 model_name TEXT NOT NULL, model_version TEXT, feature_values TEXT NOT NULL,
 prediction INTEGER NOT NULL, score REAL,
 prediction_timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS system_logs (
 id TEXT PRIMARY KEY, log_timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 component TEXT NOT NULL, log_level TEXT NOT NULL, message TEXT NOT NULL,
 metadata TEXT NOT NULL DEFAULT '{}'
);
"""

POSTGRES_SCHEMA = """
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS bgp_events (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), event_timestamp timestamptz NOT NULL,
 peer_asn bigint, prefix cidr NOT NULL, origin_asn bigint,
 event_type text NOT NULL CHECK (event_type IN ('announcement', 'withdrawal')),
 raw_event jsonb NOT NULL DEFAULT '{}'::jsonb, ingestion_source text NOT NULL DEFAULT 'api',
 fingerprint text NOT NULL UNIQUE, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_bgp_events_prefix_time
 ON bgp_events(prefix, event_timestamp DESC);
CREATE TABLE IF NOT EXISTS roa_records (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), prefix cidr NOT NULL,
 origin_asn bigint NOT NULL, max_length integer NOT NULL CHECK (max_length BETWEEN 0 AND 128),
 trust_anchor text, not_before timestamptz, not_after timestamptz,
 last_updated timestamptz NOT NULL DEFAULT now(),
 UNIQUE(prefix, origin_asn, max_length, not_before, not_after)
);
CREATE TABLE IF NOT EXISTS prefix_inventory (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), prefix cidr NOT NULL,
 expected_origin_asn bigint NOT NULL, max_length integer,
 organization text, description text, status text NOT NULL DEFAULT 'active'
 CHECK (status IN ('active', 'disabled')), created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(), UNIQUE(prefix, expected_origin_asn)
);
CREATE TABLE IF NOT EXISTS routing_state (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), prefix cidr NOT NULL UNIQUE,
 origin_asn bigint NOT NULL, as_path jsonb NOT NULL DEFAULT '[]'::jsonb,
 next_hop inet, last_seen timestamptz NOT NULL, active boolean NOT NULL DEFAULT true,
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS anomaly_alerts (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), event_id uuid REFERENCES bgp_events(id) ON DELETE SET NULL,
 prefix cidr NOT NULL, observed_origin_asn bigint, expected_origin_asn bigint,
 anomaly_type text NOT NULL, severity text NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
 explanation text NOT NULL, detection_source text NOT NULL, ml_score double precision,
 alert_timestamp timestamptz NOT NULL DEFAULT now(),
 status text NOT NULL DEFAULT 'open'
 CHECK (status IN ('open', 'acknowledged', 'resolved', 'false_positive'))
);
CREATE INDEX IF NOT EXISTS idx_alerts_time_status ON anomaly_alerts(alert_timestamp DESC, status);
CREATE TABLE IF NOT EXISTS detection_evidence (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), alert_id uuid NOT NULL REFERENCES anomaly_alerts(id) ON DELETE CASCADE,
 rule_name text NOT NULL, evidence_description text NOT NULL, observed_value jsonb,
 expected_value jsonb, additional_evidence jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE TABLE IF NOT EXISTS ml_predictions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), event_id uuid REFERENCES bgp_events(id) ON DELETE SET NULL,
 model_name text NOT NULL, model_version text, feature_values jsonb NOT NULL,
 prediction integer NOT NULL, score double precision, prediction_timestamp timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS system_logs (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), log_timestamp timestamptz NOT NULL DEFAULT now(),
 component text NOT NULL, log_level text NOT NULL, message text NOT NULL,
 metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);
"""


class Database:
    def __init__(self, path: str | Path | None = None):
        self.path = str(path or settings.database_path)
        ensure_database_parent(self.path)
        self._memory_connection = sqlite3.connect(":memory:") if self.path == ":memory:" else None
        if self._memory_connection is not None:
            self._memory_connection.row_factory = sqlite3.Row

    def connect(self) -> sqlite3.Connection:
        connection = self._memory_connection or sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript(SQLITE_SCHEMA)

    def connection(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            yield connection
        finally:
            connection.close()


def get_database(path: str | Path | None = None):
    if path is None and settings.database_url:
        return PostgresDatabase(settings.database_url)
    database = Database(path)
    database.initialize()
    return database


class PostgresDatabase:
    def __init__(self, url: str):
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:
            raise RuntimeError("DATABASE_URL requires psycopg") from exc
        self._psycopg = psycopg
        self._dict_row = dict_row
        self.url = url
        self.initialize()

    def connect(self):
        return PostgresConnection(self._psycopg.connect(self.url, row_factory=self._dict_row))

    def initialize(self) -> None:
        with self.connect() as connection:
            for statement in POSTGRES_SCHEMA.split(";"):
                if statement.strip():
                    connection.execute(statement)


class PostgresConnection:
    def __init__(self, connection):
        self._connection = connection

    def __enter__(self):
        self._connection.__enter__()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return self._connection.__exit__(exc_type, exc_value, traceback)

    def execute(self, query: str, params=()):
        return self._connection.execute(
            query.replace("?", "%s"),
            self._adapt_params(params, query),
        )

    def executemany(self, query: str, params):
        return self._connection.executemany(
            query.replace("?", "%s"),
            [self._adapt_params(row, query) for row in params],
        )

    @staticmethod
    def _adapt_params(params, query: str):
        from psycopg.types.json import Json
        import json
        json_query = any(
            column in query
            for column in (
                "raw_event",
                "as_path",
                "observed_value",
                "expected_value",
                "additional_evidence",
                "feature_values",
                "metadata",
            )
        )
        adapted = []
        for value in params:
            if json_query and isinstance(value, str):
                try:
                    decoded = json.loads(value)
                except json.JSONDecodeError:
                    decoded = None
                if isinstance(decoded, (dict, list)):
                    value = Json(decoded)
            adapted.append(value)
        return tuple(adapted)
