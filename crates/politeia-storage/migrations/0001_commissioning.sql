CREATE TABLE institution_workspaces (
    institution_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    trust_domain TEXT NOT NULL,
    owner_principal_id UUID NOT NULL,
    owner_delegation_id UUID NOT NULL,
    model_digest TEXT NOT NULL,
    model_payload BYTEA NOT NULL,
    model_signature BYTEA NOT NULL,
    model_signer_id UUID NOT NULL,
    revision BIGINT NOT NULL DEFAULT 0 CHECK (revision >= 0),
    active_generation_digest TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (institution_id, workspace_id),
    UNIQUE (workspace_id),
    CHECK (octet_length(model_digest) = 64)
);

CREATE TABLE state_entries (
    institution_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    state_key TEXT NOT NULL,
    value_digest TEXT NOT NULL,
    value_payload BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (institution_id, workspace_id, state_key),
    FOREIGN KEY (institution_id, workspace_id)
        REFERENCES institution_workspaces (institution_id, workspace_id),
    CHECK (octet_length(value_digest) = 64)
);

CREATE TABLE workspace_revisions (
    institution_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    revision BIGINT NOT NULL CHECK (revision >= 0),
    record_kind TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    payload BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    signer_id UUID NOT NULL,
    admitted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (institution_id, workspace_id, revision),
    FOREIGN KEY (institution_id, workspace_id)
        REFERENCES institution_workspaces (institution_id, workspace_id),
    CHECK (octet_length(content_digest) = 64)
);

CREATE TABLE admitted_records (
    institution_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    record_id UUID NOT NULL,
    record_kind TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    payload BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    signer_id UUID NOT NULL,
    admitted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (institution_id, workspace_id, record_id),
    FOREIGN KEY (institution_id, workspace_id)
        REFERENCES institution_workspaces (institution_id, workspace_id),
    CHECK (octet_length(content_digest) = 64)
);

CREATE TABLE delegations (
    institution_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    delegation_id UUID NOT NULL,
    delegation_digest TEXT NOT NULL,
    payload BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    signer_id UUID NOT NULL,
    admitted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (institution_id, workspace_id, delegation_id),
    FOREIGN KEY (institution_id, workspace_id)
        REFERENCES institution_workspaces (institution_id, workspace_id),
    UNIQUE (institution_id, workspace_id, delegation_digest),
    CHECK (octet_length(delegation_digest) = 64)
);

CREATE TABLE delegation_revocations (
    institution_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    delegation_id UUID NOT NULL,
    revocation_digest TEXT NOT NULL,
    evidence_record_id UUID NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (institution_id, workspace_id, delegation_id),
    FOREIGN KEY (institution_id, workspace_id, delegation_id)
        REFERENCES delegations (institution_id, workspace_id, delegation_id),
    CHECK (octet_length(revocation_digest) = 64)
);

CREATE TABLE transition_journal (
    institution_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    sequence BIGINT GENERATED ALWAYS AS IDENTITY,
    transition_digest TEXT NOT NULL,
    previous_digest TEXT,
    payload BYTEA NOT NULL,
    admitted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (institution_id, workspace_id, sequence),
    FOREIGN KEY (institution_id, workspace_id)
        REFERENCES institution_workspaces (institution_id, workspace_id),
    UNIQUE (institution_id, workspace_id, transition_digest),
    CHECK (octet_length(transition_digest) = 64),
    CHECK (previous_digest IS NULL OR octet_length(previous_digest) = 64)
);

CREATE TABLE evidence_journal (
    institution_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    evidence_id UUID NOT NULL,
    evidence_digest TEXT NOT NULL,
    payload BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    signer_id UUID NOT NULL,
    admitted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (institution_id, workspace_id, evidence_id),
    FOREIGN KEY (institution_id, workspace_id)
        REFERENCES institution_workspaces (institution_id, workspace_id),
    UNIQUE (institution_id, workspace_id, evidence_digest),
    CHECK (octet_length(evidence_digest) = 64)
);

CREATE TABLE runtime_generations (
    institution_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    generation_digest TEXT NOT NULL,
    input_digest TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    manifest BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    signer_id UUID NOT NULL,
    admitted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (institution_id, workspace_id, generation_digest),
    FOREIGN KEY (institution_id, workspace_id)
        REFERENCES institution_workspaces (institution_id, workspace_id),
    CHECK (octet_length(generation_digest) = 64),
    CHECK (octet_length(input_digest) = 64),
    CHECK (octet_length(artifact_digest) = 64)
);

ALTER TABLE institution_workspaces
    ADD CONSTRAINT active_generation_is_scoped
    FOREIGN KEY (institution_id, workspace_id, active_generation_digest)
    REFERENCES runtime_generations (institution_id, workspace_id, generation_digest)
    DEFERRABLE INITIALLY DEFERRED;

CREATE TYPE operation_attempt_status AS ENUM ('reserved', 'claimed', 'completed');

CREATE TABLE operation_attempts (
    institution_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    reservation_id UUID NOT NULL,
    replay_domain TEXT NOT NULL,
    replay_key TEXT NOT NULL,
    claims_digest TEXT NOT NULL,
    retain_replay BOOLEAN NOT NULL,
    request_payload BYTEA NOT NULL,
    status operation_attempt_status NOT NULL DEFAULT 'reserved',
    receipt_digest TEXT,
    completed_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (institution_id, workspace_id, reservation_id),
    FOREIGN KEY (institution_id, workspace_id)
        REFERENCES institution_workspaces (institution_id, workspace_id),
    UNIQUE (institution_id, workspace_id, replay_domain, replay_key),
    CHECK (octet_length(replay_key) = 64),
    CHECK (octet_length(claims_digest) = 64),
    CHECK (receipt_digest IS NULL OR octet_length(receipt_digest) = 64),
    CHECK ((status <> 'completed') OR (receipt_digest IS NOT NULL AND completed_at IS NOT NULL))
);

CREATE TABLE delegation_budget_accounts (
    institution_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    replay_domain TEXT NOT NULL,
    delegation_id UUID NOT NULL,
    delegation_digest TEXT NOT NULL,
    wall_ms_limit NUMERIC(20, 0),
    cpu_ms_limit NUMERIC(20, 0),
    memory_bytes_limit NUMERIC(20, 0),
    io_bytes_limit NUMERIC(20, 0),
    network_bytes_limit NUMERIC(20, 0),
    external_cost_microunits_limit NUMERIC(20, 0),
    wall_ms_committed NUMERIC(20, 0) NOT NULL DEFAULT 0,
    cpu_ms_committed NUMERIC(20, 0) NOT NULL DEFAULT 0,
    memory_bytes_committed NUMERIC(20, 0) NOT NULL DEFAULT 0,
    io_bytes_committed NUMERIC(20, 0) NOT NULL DEFAULT 0,
    network_bytes_committed NUMERIC(20, 0) NOT NULL DEFAULT 0,
    external_cost_microunits_committed NUMERIC(20, 0) NOT NULL DEFAULT 0,
    PRIMARY KEY (institution_id, workspace_id, replay_domain, delegation_id),
    FOREIGN KEY (institution_id, workspace_id, delegation_id)
        REFERENCES delegations (institution_id, workspace_id, delegation_id),
    CHECK (octet_length(delegation_digest) = 64)
);

CREATE TABLE attempt_budget_scopes (
    institution_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    reservation_id UUID NOT NULL,
    replay_domain TEXT NOT NULL,
    delegation_id UUID NOT NULL,
    wall_ms NUMERIC(20, 0) NOT NULL,
    cpu_ms NUMERIC(20, 0) NOT NULL,
    memory_bytes NUMERIC(20, 0) NOT NULL,
    io_bytes NUMERIC(20, 0) NOT NULL,
    network_bytes NUMERIC(20, 0) NOT NULL,
    external_cost_microunits NUMERIC(20, 0) NOT NULL,
    PRIMARY KEY (institution_id, workspace_id, reservation_id, delegation_id),
    FOREIGN KEY (institution_id, workspace_id, reservation_id)
        REFERENCES operation_attempts (institution_id, workspace_id, reservation_id) ON DELETE CASCADE
);

CREATE TABLE transactional_outbox (
    institution_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    outbox_id UUID NOT NULL,
    topic TEXT NOT NULL,
    payload BYTEA NOT NULL,
    payload_digest TEXT NOT NULL,
    available_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    delivered_at TIMESTAMPTZ,
    PRIMARY KEY (institution_id, workspace_id, outbox_id),
    FOREIGN KEY (institution_id, workspace_id)
        REFERENCES institution_workspaces (institution_id, workspace_id),
    CHECK (octet_length(payload_digest) = 64)
);

CREATE OR REPLACE FUNCTION reject_immutable_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'immutable journal rows cannot be updated or deleted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER transition_journal_immutable
    BEFORE UPDATE OR DELETE ON transition_journal
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
CREATE TRIGGER evidence_journal_immutable
    BEFORE UPDATE OR DELETE ON evidence_journal
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
CREATE TRIGGER workspace_revisions_immutable
    BEFORE UPDATE OR DELETE ON workspace_revisions
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
CREATE TRIGGER admitted_records_immutable
    BEFORE UPDATE OR DELETE ON admitted_records
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
