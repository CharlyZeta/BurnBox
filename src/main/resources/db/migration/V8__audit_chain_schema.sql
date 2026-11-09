-- Enforce unique prev_hash to prevent forks in the audit chain (BR-002)
ALTER TABLE security_event ADD CONSTRAINT uq_security_event_prev_hash UNIQUE (prev_hash);

-- Enforce strict append-only immutability via trigger (BR-003)
CREATE OR REPLACE FUNCTION trg_func_security_event_append_only()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'security_event is strictly append-only; updates and deletes are forbidden';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_security_event_append_only ON security_event;
CREATE TRIGGER trg_security_event_append_only
BEFORE UPDATE OR DELETE ON security_event
FOR EACH ROW
EXECUTE FUNCTION trg_func_security_event_append_only();
