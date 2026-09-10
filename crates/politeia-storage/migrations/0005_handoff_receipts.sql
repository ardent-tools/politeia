CREATE TABLE handoff_receipts (
    institution_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    generation_digest TEXT NOT NULL,
    commissioning_record_id UUID NOT NULL,
    continuity_reservation_id UUID NOT NULL,
    continuity_receipt_digest TEXT NOT NULL,
    handoff_receipt_digest TEXT NOT NULL,
    payload BYTEA NOT NULL,
    transition_digest TEXT NOT NULL,
    workspace_revision BIGINT NOT NULL CHECK (workspace_revision > 0),
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (institution_id, workspace_id, generation_digest),
    FOREIGN KEY (institution_id, workspace_id, generation_digest)
        REFERENCES runtime_generations (institution_id, workspace_id, generation_digest),
    FOREIGN KEY (institution_id, workspace_id, commissioning_record_id)
        REFERENCES commissioning_receipts (institution_id, workspace_id, record_id),
    FOREIGN KEY (institution_id, workspace_id, continuity_reservation_id)
        REFERENCES operation_attempts (institution_id, workspace_id, reservation_id),
    FOREIGN KEY (institution_id, workspace_id, workspace_revision)
        REFERENCES workspace_revisions (institution_id, workspace_id, revision)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (institution_id, workspace_id, transition_digest)
        REFERENCES transition_journal (institution_id, workspace_id, transition_digest)
        DEFERRABLE INITIALLY DEFERRED,
    UNIQUE (institution_id, workspace_id, commissioning_record_id),
    UNIQUE (institution_id, workspace_id, continuity_reservation_id),
    UNIQUE (institution_id, workspace_id, handoff_receipt_digest),
    CHECK (octet_length(generation_digest) = 64),
    CHECK (octet_length(continuity_receipt_digest) = 64),
    CHECK (octet_length(handoff_receipt_digest) = 64),
    CHECK (octet_length(transition_digest) = 64)
);

CREATE TRIGGER handoff_receipts_immutable
    BEFORE UPDATE OR DELETE ON handoff_receipts
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
