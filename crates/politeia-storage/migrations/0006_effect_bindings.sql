-- New reservations retain the canonical read/write classification and, for a
-- productive effect, its exact identity plus conservative overlap projection.
-- NULL is reserved for attempts created before this migration. A legacy
-- claimed NULL cannot prove disjointness and therefore blocks new mutating
-- work in its workspace until explicit outcome evidence completes it.
ALTER TABLE operation_attempts
    ADD COLUMN effect_binding BYTEA;

-- PostgreSQL SERIALIZABLE snapshots do not refresh merely because a statement
-- waited for a row lock. Incrementing this shared internal coordination fence
-- as the first statement of an authority or productive-effect admission makes
-- an older waiter abort and retry with a snapshot that sees the preceding
-- admission. This value is neither the public workspace revision nor product
-- authority.
ALTER TABLE institution_workspaces
    ADD COLUMN admission_epoch BIGINT NOT NULL DEFAULT 0
    CHECK (admission_epoch >= 0);

CREATE INDEX operation_attempts_claimed_effect_bindings
    ON operation_attempts (institution_id, workspace_id)
    WHERE status = 'claimed';
