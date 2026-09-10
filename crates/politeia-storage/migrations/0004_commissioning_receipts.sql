CREATE TABLE commissioning_receipts (
    institution_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    record_id UUID NOT NULL,
    record_digest TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    payload BYTEA NOT NULL,
    admitted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (institution_id, workspace_id, record_id),
    FOREIGN KEY (institution_id, workspace_id)
        REFERENCES institution_workspaces (institution_id, workspace_id),
    UNIQUE (institution_id, workspace_id, record_digest),
    CHECK (octet_length(record_digest) = 64),
    CHECK (octet_length(payload_digest) = 64)
);

CREATE TRIGGER commissioning_receipts_immutable
    BEFORE UPDATE OR DELETE ON commissioning_receipts
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
