-- Additive monitoring and ingestion migration. Existing Step 1 data is preserved.
ALTER TABLE deployments ADD COLUMN external_id VARCHAR(160);
ALTER TABLE deployments ADD COLUMN source VARCHAR(20) NOT NULL DEFAULT 'manual';
CREATE UNIQUE INDEX deployments_project_external_unique ON deployments(project_id, external_id) WHERE external_id IS NOT NULL;

CREATE TABLE monitors (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    environment_id UUID NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    url VARCHAR(1024) NOT NULL,
    method VARCHAR(8) NOT NULL DEFAULT 'GET' CHECK (method IN ('GET','HEAD')),
    expected_status INTEGER NOT NULL DEFAULT 200 CHECK (expected_status BETWEEN 100 AND 599),
    interval_seconds INTEGER NOT NULL DEFAULT 60 CHECK (interval_seconds BETWEEN 60 AND 3600),
    timeout_seconds INTEGER NOT NULL DEFAULT 10 CHECK (timeout_seconds BETWEEN 2 AND 20),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_status VARCHAR(12) NOT NULL DEFAULT 'unknown' CHECK (last_status IN ('unknown','up','down')),
    last_http_status INTEGER,
    last_latency_ms INTEGER,
    last_checked_at TIMESTAMPTZ,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    next_check_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claimed_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX monitors_due_idx ON monitors(next_check_at) WHERE enabled;
CREATE INDEX monitors_project_idx ON monitors(project_id);

CREATE TABLE monitor_checks (
    id BIGSERIAL PRIMARY KEY,
    monitor_id UUID NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
    status VARCHAR(8) NOT NULL CHECK (status IN ('up','down')),
    http_status INTEGER,
    latency_ms INTEGER,
    error_message VARCHAR(220),
    checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX monitor_checks_monitor_time_idx ON monitor_checks(monitor_id, checked_at DESC);
CREATE INDEX monitor_checks_time_idx ON monitor_checks(checked_at);

CREATE TABLE ingest_tokens (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    label VARCHAR(80) NOT NULL,
    token_prefix VARCHAR(20) NOT NULL,
    token_hash CHAR(64) NOT NULL UNIQUE,
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);
CREATE INDEX ingest_tokens_project_idx ON ingest_tokens(project_id, created_at DESC);

CREATE TABLE ingestion_events (
    id BIGSERIAL PRIMARY KEY,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    delivery_id VARCHAR(160) NOT NULL,
    deployment_id UUID NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    status VARCHAR(20) NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(project_id, delivery_id)
);
CREATE INDEX ingestion_events_received_idx ON ingestion_events(received_at);

CREATE TABLE api_samples (
    id BIGSERIAL PRIMARY KEY,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    environment_id UUID NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    route VARCHAR(160) NOT NULL,
    method VARCHAR(8) NOT NULL,
    status_code INTEGER NOT NULL CHECK (status_code BETWEEN 100 AND 599),
    latency_ms INTEGER NOT NULL CHECK (latency_ms BETWEEN 0 AND 600000),
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX api_samples_project_time_idx ON api_samples(project_id, observed_at DESC);
CREATE INDEX api_samples_time_idx ON api_samples(observed_at);
