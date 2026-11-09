CREATE TABLE IF NOT EXISTS secret (
    id UUID PRIMARY KEY,
    owner_user_id UUID,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    ciphertext BYTEA,
    nonce BYTEA,
    wrapped_dek BYTEA,
    key_version INT NOT NULL,
    format_version INT NOT NULL DEFAULT 1,
    passphrase_salt BYTEA,
    passphrase_protected BOOLEAN NOT NULL DEFAULT FALSE,
    max_views INT NOT NULL DEFAULT 1,
    views INT NOT NULL DEFAULT 0,
    state VARCHAR(30) NOT NULL DEFAULT 'ACTIVE',
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    failed_attempts INT NOT NULL DEFAULT 0,
    recipient_email VARCHAR(255),
    label VARCHAR(100),
    CONSTRAINT chk_views_max_views CHECK (views <= max_views),
    CONSTRAINT chk_active_content CHECK (
        (state = 'ACTIVE' AND ciphertext IS NOT NULL AND wrapped_dek IS NOT NULL AND nonce IS NOT NULL) OR
        (state <> 'ACTIVE' AND ciphertext IS NULL AND wrapped_dek IS NULL AND passphrase_salt IS NULL AND recipient_email IS NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_secret_token_hash ON secret(token_hash);
CREATE INDEX IF NOT EXISTS idx_secret_expires_state ON secret(expires_at, state);
CREATE INDEX IF NOT EXISTS idx_secret_owner ON secret(owner_user_id);
