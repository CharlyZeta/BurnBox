CREATE TABLE IF NOT EXISTS app_user (
    id UUID PRIMARY KEY,
    display_name VARCHAR(255),
    primary_email VARCHAR(255),
    primary_email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    status VARCHAR(30) NOT NULL DEFAULT 'ACTIVE',
    deletion_scheduled_at TIMESTAMPTZ,
    locale VARCHAR(10) NOT NULL DEFAULT 'es',
    created_at TIMESTAMPTZ NOT NULL,
    last_login_at TIMESTAMPTZ,
    CONSTRAINT chk_deletion_scheduled CHECK (
        (status = 'PENDING_DELETION' AND deletion_scheduled_at IS NOT NULL) OR
        (status <> 'PENDING_DELETION')
    )
);

CREATE TABLE IF NOT EXISTS linked_identity (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    provider VARCHAR(30) NOT NULL,
    issuer VARCHAR(255) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    email_at_link VARCHAR(255),
    email_verified_at_link BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    CONSTRAINT uk_issuer_subject UNIQUE (issuer, subject)
);

CREATE INDEX IF NOT EXISTS idx_linked_identity_user_id ON linked_identity(user_id);
CREATE INDEX IF NOT EXISTS idx_app_user_primary_email ON app_user(primary_email);
