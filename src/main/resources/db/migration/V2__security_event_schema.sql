CREATE TABLE IF NOT EXISTS security_event (
    id BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    actor_user_id UUID,
    subject_type VARCHAR(50),
    subject_id VARCHAR(100),
    request_id VARCHAR(100) NOT NULL,
    ip_hash VARCHAR(64) NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    prev_hash VARCHAR(64),
    hash VARCHAR(64)
);

CREATE INDEX IF NOT EXISTS idx_security_event_occurred ON security_event(occurred_at);
CREATE INDEX IF NOT EXISTS idx_security_event_type ON security_event(event_type);
