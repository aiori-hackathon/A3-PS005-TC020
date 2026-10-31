-- BGP Sentinel baseline schema for Supabase PostgreSQL.
-- Run this file in the Supabase SQL Editor. All timestamps are UTC.

create extension if not exists pgcrypto;

create table if not exists bgp_events (
    id uuid primary key default gen_random_uuid(),
    event_timestamp timestamptz not null,
    peer_asn bigint,
    prefix cidr not null,
    origin_asn bigint,
    event_type text not null check (event_type in ('announcement', 'withdrawal')),
    raw_event jsonb not null default '{}'::jsonb,
    ingestion_source text not null default 'api',
    fingerprint text not null unique,
    created_at timestamptz not null default now()
);

create table if not exists roa_records (
    id uuid primary key default gen_random_uuid(),
    prefix cidr not null,
    origin_asn bigint not null,
    max_length integer not null check (max_length between 0 and 128),
    trust_anchor text,
    not_before timestamptz,
    not_after timestamptz,
    last_updated timestamptz not null default now(),
    unique (prefix, origin_asn, max_length, not_before, not_after)
);

create table if not exists prefix_inventory (
    id uuid primary key default gen_random_uuid(),
    prefix cidr not null,
    expected_origin_asn bigint not null,
    max_length integer check (max_length between 0 and 128),
    organization text,
    description text,
    status text not null default 'active' check (status in ('active', 'disabled')),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (prefix, expected_origin_asn)
);

create table if not exists routing_state (
    id uuid primary key default gen_random_uuid(),
    prefix cidr not null unique,
    origin_asn bigint not null,
    as_path jsonb not null default '[]'::jsonb,
    next_hop inet,
    last_seen timestamptz not null,
    active boolean not null default true,
    updated_at timestamptz not null default now()
);

create table if not exists anomaly_alerts (
    id uuid primary key default gen_random_uuid(),
    event_id uuid references bgp_events(id) on delete set null,
    prefix cidr not null,
    observed_origin_asn bigint,
    expected_origin_asn bigint,
    anomaly_type text not null,
    severity text not null check (severity in ('low', 'medium', 'high', 'critical')),
    explanation text not null,
    detection_source text not null,
    ml_score double precision,
    alert_timestamp timestamptz not null default now(),
    status text not null default 'open' check (status in ('open', 'acknowledged', 'resolved', 'false_positive'))
);

create table if not exists detection_evidence (
    id uuid primary key default gen_random_uuid(),
    alert_id uuid not null references anomaly_alerts(id) on delete cascade,
    rule_name text not null,
    evidence_description text not null,
    observed_value jsonb,
    expected_value jsonb,
    additional_evidence jsonb not null default '{}'::jsonb
);

create table if not exists ml_predictions (
    id uuid primary key default gen_random_uuid(),
    event_id uuid references bgp_events(id) on delete set null,
    model_name text not null,
    model_version text,
    feature_values jsonb not null,
    prediction integer not null,
    score double precision,
    prediction_timestamp timestamptz not null default now()
);

create table if not exists system_logs (
    id uuid primary key default gen_random_uuid(),
    log_timestamp timestamptz not null default now(),
    component text not null,
    log_level text not null,
    message text not null,
    metadata jsonb not null default '{}'::jsonb
);

create index if not exists idx_bgp_events_prefix_time
    on bgp_events (prefix, event_timestamp desc);
create index if not exists idx_alerts_time_status
    on anomaly_alerts (alert_timestamp desc, status);
create index if not exists idx_alerts_prefix
    on anomaly_alerts (prefix);
create index if not exists idx_evidence_alert
    on detection_evidence (alert_id);
create index if not exists idx_ml_predictions_event
    on ml_predictions (event_id);

alter table bgp_events enable row level security;
alter table roa_records enable row level security;
alter table prefix_inventory enable row level security;
alter table routing_state enable row level security;
alter table anomaly_alerts enable row level security;
alter table detection_evidence enable row level security;
alter table ml_predictions enable row level security;
alter table system_logs enable row level security;
