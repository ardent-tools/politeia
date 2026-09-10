-- Preserve the exact canonical receipt bytes whose digest marks completion.
ALTER TABLE operation_attempts
    ADD COLUMN receipt_payload BYTEA;

ALTER TABLE operation_attempts
    ADD CONSTRAINT completed_attempt_has_receipt_bytes
    CHECK (
        (status <> 'completed')
        OR (receipt_digest IS NOT NULL AND receipt_payload IS NOT NULL AND completed_at IS NOT NULL)
    );
