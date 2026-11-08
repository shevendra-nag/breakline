-- Incident intelligence. Additive migration; no existing monitoring records are modified.
CREATE TABLE incident_rules (
    project_id UUID PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    monitor_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    deployment_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    metrics_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    failure_threshold INTEGER NOT NULL DEFAULT 3 CHECK (failure_threshold BETWEEN 2 AND 10),
    api_error_threshold INTEGER NOT NULL DEFAULT 15 CHECK (api_error_threshold BETWEEN 5 AND 80),
    minimum_samples INTEGER NOT NULL DEFAULT 30 CHECK (minimum_samples BETWEEN 20 AND 1000),
    notify_email BOOLEAN NOT NULL DEFAULT TRUE,
    notify_discord BOOLEAN NOT NULL DEFAULT TRUE,
    notify_webhook BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE incidents (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    environment_id UUID NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    monitor_id UUID REFERENCES monitors(id) ON DELETE SET NULL,
    trigger_deployment_id UUID REFERENCES deployments(id) ON DELETE SET NULL,
    suspected_deployment_id UUID REFERENCES deployments(id) ON DELETE SET NULL,
    fingerprint VARCHAR(160) NOT NULL,
    source VARCHAR(16) NOT NULL CHECK (source IN ('monitor','deployment','metrics')),
    status VARCHAR(16) NOT NULL DEFAULT 'open' CHECK (status IN ('open','acknowledged','resolved')),
    severity VARCHAR(16) NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    title VARCHAR(180) NOT NULL,
    summary VARCHAR(600) NOT NULL,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by UUID REFERENCES users(id) ON DELETE SET NULL,
    resolved_at TIMESTAMPTZ,
    resolved_by UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX incidents_open_fingerprint ON incidents(project_id,fingerprint) WHERE status IN ('open','acknowledged');
CREATE INDEX incidents_project_created ON incidents(project_id,detected_at DESC);
CREATE INDEX incidents_status_created ON incidents(status,detected_at DESC);
CREATE INDEX incidents_environment_created ON incidents(environment_id,detected_at DESC);
CREATE INDEX incidents_monitor_idx ON incidents(monitor_id) WHERE monitor_id IS NOT NULL;

CREATE TABLE incident_events (
    id BIGSERIAL PRIMARY KEY,
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    actor_id UUID REFERENCES users(id) ON DELETE SET NULL,
    kind VARCHAR(16) NOT NULL CHECK (kind IN ('opened','acknowledged','resolved','comment')),
    message VARCHAR(1000) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX incident_events_incident_time ON incident_events(incident_id,created_at,id);

CREATE TABLE alert_deliveries (
    id BIGSERIAL PRIMARY KEY,
    incident_event_id BIGINT NOT NULL REFERENCES incident_events(id) ON DELETE CASCADE,
    channel VARCHAR(12) NOT NULL CHECK (channel IN ('email','discord','webhook')),
    status VARCHAR(12) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','leased','delivered','failed')),
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    leased_until TIMESTAMPTZ,
    last_http_status INTEGER,
    last_error VARCHAR(220),
    delivered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(incident_event_id,channel)
);
CREATE INDEX alert_deliveries_due ON alert_deliveries(next_attempt_at) WHERE status IN ('pending','leased');
CREATE INDEX alert_deliveries_event ON alert_deliveries(incident_event_id);
