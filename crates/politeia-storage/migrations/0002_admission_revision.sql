-- Old reservations have no observed revision and are intentionally unclaimable.
-- A new reservation records the revision under the same workspace-row lock
-- used to compare its generation. Claiming after activation or an approved
-- state change therefore requires fresh authorization, including after rollback.
ALTER TABLE operation_attempts
    ADD COLUMN admission_revision BIGINT CHECK (admission_revision >= 0);
