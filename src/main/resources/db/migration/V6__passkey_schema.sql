CREATE TABLE passkey_credential (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL,
    public_key BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    transports VARCHAR(128),
    label VARCHAR(100) NOT NULL,
    state VARCHAR(32) NOT NULL,
    activates_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_used_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT uq_passkey_credential_id UNIQUE (credential_id)
);

CREATE INDEX idx_passkey_user ON passkey_credential(user_id);
CREATE INDEX idx_passkey_state ON passkey_credential(state);
