CREATE TABLE user_session_meta (
    id UUID PRIMARY KEY,
    session_id VARCHAR(128) NOT NULL,
    user_id UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    ip_hash VARCHAR(64) NOT NULL,
    user_agent_summary VARCHAR(120),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_accessed_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT uq_user_session_id UNIQUE (session_id)
);

CREATE INDEX idx_user_session_user ON user_session_meta(user_id);
CREATE INDEX idx_user_session_accessed ON user_session_meta(last_accessed_at);
