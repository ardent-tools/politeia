-- Preserve the exact canonical receipt bytes whose digest marks completion.
ALTER TABLE operation_attempts
    ADD COLUMN receipt_payload BYTEA;

ALTER TABLE operation_attempts
    ADD CONSTRAINT completed_attempt_has_receipt_bytes
    CHECK (
        (status <> 'completed')
        OR (receipt_digest IS NOT NULL AND receipt_payload IS NOT NULL AND completed_at IS NOT NULL)
    ) NOT VALID;

-- Existing digest-only receipts remain historical records. Their bytes cannot
-- be reconstructed from a hash. NOT VALID preserves those rows while enforcing
-- the complete receipt contract on every newly inserted or updated attempt.
-- They retain replay protection and are exposed without retained receipt bytes.
