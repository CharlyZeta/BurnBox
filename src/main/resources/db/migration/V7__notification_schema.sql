CREATE TABLE notification_delivery (
    id UUID PRIMARY KEY,
    source_event_id VARCHAR(64) NOT NULL,
    user_id UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    template VARCHAR(64) NOT NULL,
    recipient_email VARCHAR(255) NOT NULL,
    channel VARCHAR(32) NOT NULL DEFAULT 'EMAIL',
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    attempts INT NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMP WITH TIME ZONE,
    last_error TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    sent_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT uq_notification_delivery UNIQUE (source_event_id, template, user_id)
);

CREATE INDEX idx_notification_user ON notification_delivery(user_id);
CREATE INDEX idx_notification_status_attempt ON notification_delivery(status, next_attempt_at);
