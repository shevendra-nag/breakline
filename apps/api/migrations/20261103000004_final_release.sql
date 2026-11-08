-- Final release: additive audit history, sign-in throttling and alert silence controls.
-- Keep audit records after project deletion so administrative actions remain traceable.
CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    actor_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(80) NOT NULL,
    resource_type VARCHAR(40) NOT NULL,
    resource_id UUID,
    project_id UUID,
    detail VARCHAR(350) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX audit_log_created_idx ON audit_log(created_at DESC, id DESC);
CREATE INDEX audit_log_project_created_idx ON audit_log(project_id, created_at DESC);
CREATE INDEX audit_log_actor_created_idx ON audit_log(actor_id, created_at DESC);
-- Preserve the meaningful activity history already recorded by earlier releases.
INSERT INTO audit_log(actor_id,action,resource_type,resource_id,detail,created_at)
SELECT actor_id,action,entity_type,entity_id,detail,created_at FROM activities ORDER BY id;

CREATE TABLE login_rate_limits (
    identifier_hash CHAR(64) PRIMARY KEY,
    attempts INTEGER NOT NULL DEFAULT 0,
    window_started_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX login_rate_limits_window_idx ON login_rate_limits(window_started_at);

CREATE TABLE alert_silences (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    channel VARCHAR(12) NOT NULL CHECK (channel IN ('all','email','discord','webhook')),
    reason VARCHAR(250) NOT NULL,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ends_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    CHECK (ends_at > created_at)
);
CREATE INDEX alert_silences_lookup_idx ON alert_silences(project_id, ends_at DESC) WHERE revoked_at IS NULL;
ALTER TABLE alert_deliveries DROP CONSTRAINT IF EXISTS alert_deliveries_status_check;
ALTER TABLE alert_deliveries ADD CONSTRAINT alert_deliveries_status_check
    CHECK (status IN ('pending','leased','delivered','failed','suppressed'));
CREATE INDEX alert_deliveries_status_time_idx ON alert_deliveries(status,next_attempt_at,id);
