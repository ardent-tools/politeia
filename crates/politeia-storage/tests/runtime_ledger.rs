//! PostgreSQL admission exercised through the real dispatcher and effect port.
//!
//! This fixture isolates durable admission; it deliberately uses a trivial
//! policy and does not count as control activation or daemon acceptance.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use ed25519_dalek::SigningKey;
use jiff::{SignedDuration, Timestamp};
use politeia_core::{
    AdapterId, DataClass, Delegation, DelegationId, Digest, Effect, EvidenceId, InstitutionId,
    InstitutionWorkspaceId, OperationId, OperationSpec, PolicyBundleId, PrincipalId,
    ResourceBudget, RuntimeGenerationId,
    commissioning::{
        COMMISSION_ACTION, commissioning_institution_audience, commissioning_workspace_resource,
    },
    trust::{
        AdmissionKind, Admitted, InstitutionTrustAnchors, SignedAdmissionWire, TrustedSigningKey,
    },
};
use politeia_policy::{
    PolicyDecision,
    evaluate::{EvaluationEvidence, EvaluationSubject, evaluate},
};
use politeia_runtime::{
    AuthorizedEffect, Dispatcher, DispatcherConfig, EffectPort, OperationIntent,
    PolicyDecisionPoint, RuntimeError,
};
use politeia_storage::{
    ActivationCommit, AttemptStatus, CanonicalPayload, CommissioningReceipt, EvidenceAdmission,
    HandoffCommit, PostgresAuthorizationLedger, PostgresStorage, Scope, ScopedCommit, SignedRecord,
    StateMutation, StorageError, WorkspaceBootstrap,
};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;
type TestDispatcher = Dispatcher<LedgerFixturePolicy, CountingPort, PostgresAuthorizationLedger>;

async fn revoke_fixture_authority(fixture: &Fixture, delegation: &Delegation) -> TestResult {
    let record = fixture.signed_fixture_record_for(
        AdmissionKind::Revocation,
        serde_json::json!({"fixture_revocation": delegation.id}),
    )?;
    fixture
        .storage
        .revoke_with_record(
            &fixture.scope,
            &delegation.id,
            &Digest::blake3(&politeia_core::canonical::to_canonical_bytes(delegation)?),
            &EvidenceAdmission {
                id: EvidenceId::new(),
                record,
            },
        )
        .await?;
    Ok(())
}

fn admit_fixture_authority(
    fixture: &Fixture,
    grant: Delegation,
) -> TestResult<(Admitted<Delegation>, SignedAdmissionWire<Delegation>)> {
    let wire = SignedAdmissionWire::sign(
        AdmissionKind::Delegation,
        fixture.scope.institution().clone(),
        fixture.scope.workspace().clone(),
        fixture.intent.principal.clone(),
        grant,
        &SigningKey::from_bytes(&[0x37; 32]),
    )?;
    Ok((
        fixture
            .anchors
            .admit_expected(AdmissionKind::Delegation, wire.clone())?,
        wire,
    ))
}

async fn wait_for_workspace_lock_waiters(
    observer: &tokio_postgres::Client,
    blocker_pid: i32,
    expected: i64,
) -> TestResult {
    for _ in 0..100 {
        let row = observer
            .query_one(
                "WITH RECURSIVE waiters AS (SELECT pid FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)) UNION SELECT a.pid FROM pg_stat_activity a JOIN waiters w ON w.pid = ANY(pg_blocking_pids(a.pid))) SELECT count(DISTINCT pid) FROM waiters",
                &[&blocker_pid],
            )
            .await?;
        let observed: i64 = row.get(0);
        if observed >= expected {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err(format!(
        "expected at least {expected} workspace-lock waiters; the admission did not share handoff serialization"
    )
    .into())
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL instance; the package CI runs this explicitly"]
async fn stale_policy_snapshot_cannot_reserve_after_an_independent_grant_revoke() -> TestResult {
    let fixture = Fixture::new(&database_url()?, 8).await?;
    // This independent grant is deliberately absent from the operation's
    // delegation chain. Checking only that chain cannot detect this race.
    let mut verifier = fixture.authority.payload().clone();
    verifier.id = DelegationId::new();
    let (verifier, wire) = admit_fixture_authority(&fixture, verifier)?;
    fixture
        .storage
        .admit_delegation(&fixture.scope, &verifier, &wire)
        .await?;
    let evaluated = fixture.storage.load_workspace(&fixture.scope).await?;
    let dispatcher_at = |revision| -> TestResult<TestDispatcher> {
        let config = DispatcherConfig::new(
            fixture.policy.clone(),
            fixture.policy_digest.clone(),
            fixture.generation.clone(),
            "fixture:snapshot-replay".to_owned(),
            SignedDuration::from_mins(1),
            fixture.intent.delegation_chain.clone(),
            [fixture.intent.operation.clone()],
        )?;
        Ok(Dispatcher::new(
            LedgerFixturePolicy {
                bundle: fixture.policy.clone(),
                digest: fixture.policy_digest.clone(),
            },
            CountingPort {
                adapter: fixture.adapter.clone(),
                calls: fixture.calls.clone(),
            },
            PostgresAuthorizationLedger::for_bootstrap(
                fixture.storage.clone(),
                fixture.scope.clone(),
                fixture.bootstrap_digest.clone(),
            )
            .with_workspace_revision(revision),
            config,
        ))
    };
    let stale = dispatcher_at(evaluated.revision)?;
    revoke_fixture_authority(&fixture, verifier.payload()).await?;
    let refusal = stale.authorize(&fixture.intent).await;
    assert!(
        matches!(refusal, Err(RuntimeError::AuthorizationState { source, .. })
        if matches!(source.downcast_ref::<StorageError>(), Some(StorageError::RevisionConflict)))
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);

    // A fresh evaluation can reserve the same replay key: the refused stale
    // evaluation neither claimed an effect nor spent its budget.
    let current = fixture.storage.load_workspace(&fixture.scope).await?;
    let fresh = dispatcher_at(current.revision)?;
    let lease = fresh.authorize(&fixture.intent).await?;
    fresh.execute(&lease).await?;
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL instance; the package CI runs this explicitly"]
async fn delegated_commits_recheck_current_exact_authority_and_all_ancestors() -> TestResult {
    let fixture = Fixture::new(&database_url()?, 8).await?;
    let parent = fixture.authority.clone();
    let mut child = parent.payload().clone();
    child.id = DelegationId::new();
    child.parent = Some(parent.payload().id.clone());
    let (child, wire) = admit_fixture_authority(&fixture, child)?;
    fixture
        .storage
        .admit_delegation(&fixture.scope, &child, &wire)
        .await?;
    let initial = fixture.storage.load_workspace(&fixture.scope).await?;
    let mut commit = ScopedCommit {
        scope: fixture.scope.clone(),
        expected_revision: initial.revision,
        model: initial.model,
        model_kind: "fixture_delegated_change".to_owned(),
        transition: fixture.signed_fixture_record(serde_json::json!({"change": "first"}))?,
        state: vec![StateMutation {
            key: "fixture.authorized".to_owned(),
            value: CanonicalPayload::from_serializable(&serde_json::json!({"value": "admitted"}))?,
        }],
        evidence: vec![],
        outbox: vec![],
    };
    assert!(matches!(
        fixture.storage.commit_authorized(&commit, &[]).await,
        Err(StorageError::AdmissionMismatch)
    ));
    assert!(
        matches!(
            fixture
                .storage
                .commit_authorized(&commit, std::slice::from_ref(&child))
                .await,
            Err(StorageError::AdmissionMismatch)
        ),
        "a caller cannot omit a live ancestor from the transaction check"
    );
    let mut forged = parent.payload().clone();
    forged.actions.insert("write".to_owned());
    let (forged, _) = admit_fixture_authority(&fixture, forged)?;
    assert!(
        matches!(
            fixture.storage.commit_authorized(&commit, &[forged]).await,
            Err(StorageError::AdmissionMismatch)
        ),
        "a valid new signature cannot replace the already admitted grant's bytes"
    );
    let chain = [parent.clone(), child];
    let accepted = fixture.storage.commit_authorized(&commit, &chain).await?;
    assert_eq!(accepted.revision, 1);

    // Reproduce stale grant snapshot A followed by workspace snapshot B after
    // revocation. CAS alone would accept B; the in-transaction check must not.
    revoke_fixture_authority(&fixture, parent.payload()).await?;
    let after_revocation = fixture.storage.load_workspace(&fixture.scope).await?;
    commit.expected_revision = after_revocation.revision;
    commit.transition =
        fixture.signed_fixture_record(serde_json::json!({"change": "after-revoke"}))?;
    commit.state[0].value =
        CanonicalPayload::from_serializable(&serde_json::json!({"value": "forbidden"}))?;
    assert!(
        matches!(
            fixture.storage.commit_authorized(&commit, &chain).await,
            Err(StorageError::AdmissionMismatch)
        ),
        "a current workspace revision cannot revive a revoked ancestor"
    );
    let after_refusal = fixture.storage.load_workspace(&fixture.scope).await?;
    assert_eq!(after_refusal.revision, after_revocation.revision);
    assert_eq!(
        after_refusal.state["fixture.authorized"].digest,
        after_revocation.state["fixture.authorized"].digest
    );

    let mut expired = parent.payload().clone();
    expired.id = DelegationId::new();
    expired.expires_at = Timestamp::now() - SignedDuration::from_secs(1);
    let (expired, wire) = admit_fixture_authority(&fixture, expired)?;
    fixture
        .storage
        .admit_delegation(&fixture.scope, &expired, &wire)
        .await?;
    assert!(
        matches!(
            fixture.storage.commit_authorized(&commit, &[expired]).await,
            Err(StorageError::AdmissionMismatch)
        ),
        "durable existence cannot substitute for live authority"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL instance; the package CI runs this explicitly"]
async fn completion_and_outbox_commit_together_and_preserve_scope() -> TestResult {
    let fixture = Fixture::new(&database_url()?, 8).await?;
    let dispatcher = fixture.dispatcher(fixture.storage.clone(), SignedDuration::from_secs(30))?;
    let first = dispatcher.authorize(&fixture.intent).await?;
    let result = dispatcher.execute(&first).await?;
    let receipt = CanonicalPayload::from_json(&serde_json::json!({
        "result": result,
        "reservation": first.reservation_id(),
        "intent": fixture.intent.digest()?,
    }))?;
    let message = politeia_storage::OperationOutboxMessage {
        id: uuid::Uuid::now_v7(),
        topic: "fixture.completed".to_owned(),
        payload: receipt.clone(),
    };
    let wrong_domain = Scope::new(
        fixture.scope.institution().clone(),
        fixture.scope.workspace().clone(),
        "foreign.local".parse()?,
    );
    assert!(matches!(
        fixture
            .storage
            .record_completion_with_outbox(
                &wrong_domain,
                first.reservation_id(),
                &receipt,
                std::slice::from_ref(&message),
            )
            .await,
        Err(StorageError::AttemptUnavailable)
    ));
    fixture
        .storage
        .record_completion_with_outbox(
            &fixture.scope,
            first.reservation_id(),
            &receipt,
            std::slice::from_ref(&message),
        )
        .await?;
    let completed = fixture
        .storage
        .load_attempt(&fixture.scope, first.reservation_id())
        .await?;
    assert_eq!(completed.status, AttemptStatus::Completed);
    assert_eq!(completed.receipt_digest.as_ref(), Some(receipt.digest()));
    assert_eq!(completed.receipt_payload.as_deref(), Some(receipt.bytes()));
    assert!(
        fixture
            .storage
            .take_outbox(&wrong_domain, 10)
            .await?
            .is_empty()
    );
    assert!(matches!(
        fixture
            .storage
            .mark_outbox_delivered(&wrong_domain, message.id)
            .await,
        Err(StorageError::NotFound)
    ));
    assert_eq!(
        fixture.storage.take_outbox(&fixture.scope, 10).await?.len(),
        1
    );

    let mut next = fixture.intent.clone();
    next.idempotency_key = Some("outbox-collision".to_owned());
    let second = dispatcher.authorize(&next).await?;
    dispatcher.execute(&second).await?;
    let refusal = fixture
        .storage
        .record_completion_with_outbox(
            &fixture.scope,
            second.reservation_id(),
            &receipt,
            &[message],
        )
        .await;
    assert!(
        matches!(refusal, Err(StorageError::Database(ref error))
        if error.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION)),
        "the deliberate existing outbox identity must fail inside the completion transaction"
    );
    let unresolved = fixture
        .storage
        .load_attempt(&fixture.scope, second.reservation_id())
        .await?;
    assert_eq!(unresolved.status, AttemptStatus::Claimed);
    assert!(unresolved.receipt_digest.is_none());
    assert!(unresolved.receipt_payload.is_none());
    assert_eq!(
        fixture.storage.take_outbox(&fixture.scope, 10).await?.len(),
        1
    );
    assert!(dispatcher.execute(&second).await.is_err());
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 2);
    Ok(())
}

struct LedgerFixturePolicy {
    bundle: PolicyBundleId,
    digest: Digest,
}

impl PolicyDecisionPoint for LedgerFixturePolicy {
    type Error = RuntimeError;

    async fn decide(&self, intent: &OperationIntent) -> Result<PolicyDecision, Self::Error> {
        let intent_digest = intent.digest()?;
        let subject = EvaluationSubject {
            institution: InstitutionId::new(),
            workspace: InstitutionWorkspaceId::new(),
            bundle: self.bundle.clone(),
            policy_digest: self.digest.clone(),
            intent_digest: intent_digest.clone(),
            subject: intent_digest,
            population: Digest::blake3(b"ledger fixture population"),
            principal: intent.principal.clone(),
            scopes: BTreeSet::new(),
            at: Timestamp::now(),
        };
        evaluate(
            &subject,
            &[],
            &BTreeMap::new(),
            &EvaluationEvidence::new(&[], &[], &[]),
        )
        .map_err(|source| RuntimeError::PolicyEvaluation {
            source: Box::new(source),
        })
    }
}

struct CountingPort {
    adapter: AdapterId,
    calls: Arc<AtomicUsize>,
}

impl EffectPort for CountingPort {
    type Output = Digest;
    type Error = std::convert::Infallible;

    fn adapter(&self) -> &AdapterId {
        &self.adapter
    }
    fn audience(&self) -> &'static str {
        "fixture:effect-port"
    }

    async fn execute<'lease>(
        &'lease self,
        invocation: AuthorizedEffect<'lease>,
    ) -> Result<Self::Output, Self::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(invocation.lease().policy_digest().clone())
    }
}

struct Fixture {
    anchors: InstitutionTrustAnchors,
    authority: Admitted<Delegation>,
    storage: PostgresStorage,
    scope: Scope,
    intent: OperationIntent,
    policy: PolicyBundleId,
    policy_digest: Digest,
    generation: RuntimeGenerationId,
    bootstrap_digest: Digest,
    adapter: AdapterId,
    calls: Arc<AtomicUsize>,
}

fn budget(wall_ms: u64) -> ResourceBudget {
    ResourceBudget {
        wall_ms: Some(wall_ms),
        cpu_ms: Some(0),
        memory_bytes: Some(0),
        io_bytes: Some(0),
        network_bytes: Some(0),
        external_cost_microunits: Some(0),
    }
}

impl Fixture {
    async fn new(database_url: &str, capacity: u64) -> TestResult<Self> {
        Self::new_with_contract(
            database_url,
            capacity,
            BTreeSet::from(["fixture:document".to_owned()]),
            BTreeSet::from([Effect::ReadExternalSystem]),
            true,
            true,
        )
        .await
    }

    async fn new_productive(database_url: &str, capacity: u64) -> TestResult<Self> {
        Self::new_with_contract(
            database_url,
            capacity,
            BTreeSet::from([
                "fixture:artifact:a".to_owned(),
                "fixture:artifact:b".to_owned(),
                "fixture:artifact:c".to_owned(),
            ]),
            BTreeSet::from([Effect::CreateArtifact]),
            false,
            false,
        )
        .await
    }

    async fn new_with_contract(
        database_url: &str,
        capacity: u64,
        resources: BTreeSet<String>,
        effects: BTreeSet<Effect>,
        retryable: bool,
        requires_idempotency: bool,
    ) -> TestResult<Self> {
        let storage = PostgresStorage::connect(database_url).await?;
        storage.migrate().await?;
        let institution = InstitutionId::new();
        let workspace = InstitutionWorkspaceId::new();
        let owner = PrincipalId::new();
        let scope = Scope::new(
            institution.clone(),
            workspace.clone(),
            "fixture.local".parse()?,
        );
        let key = SigningKey::from_bytes(&[0x37; 32]);
        let anchors = InstitutionTrustAnchors::from_trusted_bootstrap(
            institution.clone(),
            workspace.clone(),
            [TrustedSigningKey::new(
                owner.clone(),
                key.verifying_key().to_bytes(),
                BTreeSet::from([
                    AdmissionKind::Delegation,
                    AdmissionKind::Evidence,
                    AdmissionKind::Generation,
                    AdmissionKind::Revocation,
                ]),
            )?],
        )?;
        let delegation = Delegation {
            id: DelegationId::new(),
            issuer: owner.clone(),
            subject: owner.clone(),
            parent: None,
            actions: BTreeSet::from(["read".to_owned()]),
            resources: resources.clone(),
            effects: effects.clone(),
            data_classes: BTreeSet::from([DataClass::Public]),
            audience: BTreeSet::from(["fixture:effect-port".to_owned()]),
            expires_at: Timestamp::now() + SignedDuration::from_hours(1),
            budget: budget(capacity),
        };
        let model = SignedAdmissionWire::sign(
            AdmissionKind::Generation,
            institution.clone(),
            workspace.clone(),
            owner.clone(),
            serde_json::json!({"fixture": "durable-admission"}),
            &key,
        )?;
        anchors.admit_expected(AdmissionKind::Generation, model.clone())?;
        let model_record = SignedRecord::from_json(
            &serde_json::to_value(&model)?,
            owner.clone(),
            model.signature.clone(),
        )?;
        let bootstrap_digest = model_record.digest().clone();
        storage
            .bootstrap_workspace(&WorkspaceBootstrap {
                scope: scope.clone(),
                owner: owner.clone(),
                owner_delegation: delegation.id.clone(),
                model: model_record,
            })
            .await?;
        let signed = SignedAdmissionWire::sign(
            AdmissionKind::Delegation,
            institution,
            workspace,
            owner.clone(),
            delegation.clone(),
            &key,
        )?;
        let admitted = anchors.admit_expected(AdmissionKind::Delegation, signed.clone())?;
        storage.admit_delegation(&scope, &admitted, &signed).await?;
        let operation = OperationSpec {
            id: OperationId::new(),
            name: "durable_fixture_operation".to_owned(),
            actions: delegation.actions.clone(),
            effects: delegation.effects.clone(),
            data_classes: delegation.data_classes.clone(),
            evidence_obligations: vec![],
            execution_requirement: None,
            retryable,
            requires_idempotency,
        };
        Ok(Self {
            anchors,
            authority: admitted,
            storage,
            scope,
            intent: OperationIntent {
                principal: owner,
                input_digest: Digest::blake3(b"ledger-fixture-input"),
                delegation_chain: vec![delegation],
                operation,
                resources,
                budget: budget(1),
                idempotency_key: requires_idempotency.then(|| "fixture-attempt".to_owned()),
                execution: None,
            },
            policy: PolicyBundleId::new(),
            policy_digest: Digest::blake3(b"ledger-fixture-policy"),
            generation: RuntimeGenerationId::from_digest(bootstrap_digest.clone()),
            bootstrap_digest,
            adapter: AdapterId::new(),
            calls: Arc::new(AtomicUsize::new(0)),
        })
    }

    fn dispatcher(
        &self,
        storage: PostgresStorage,
        ttl: SignedDuration,
    ) -> TestResult<TestDispatcher> {
        self.dispatcher_for_generation(storage, ttl, self.generation.clone(), true)
    }

    fn dispatcher_for_intent(
        &self,
        storage: PostgresStorage,
        ttl: SignedDuration,
        intent: &OperationIntent,
    ) -> TestResult<TestDispatcher> {
        self.dispatcher_for_intent_in_domain(
            storage,
            ttl,
            intent,
            "fixture:durable-replay".to_owned(),
        )
    }

    fn dispatcher_for_intent_in_domain(
        &self,
        storage: PostgresStorage,
        ttl: SignedDuration,
        intent: &OperationIntent,
        replay_domain: String,
    ) -> TestResult<TestDispatcher> {
        let config = DispatcherConfig::new(
            self.policy.clone(),
            self.policy_digest.clone(),
            self.generation.clone(),
            replay_domain,
            ttl,
            intent.delegation_chain.clone(),
            [intent.operation.clone()],
        )?;
        Ok(Dispatcher::new(
            LedgerFixturePolicy {
                bundle: self.policy.clone(),
                digest: self.policy_digest.clone(),
            },
            CountingPort {
                adapter: self.adapter.clone(),
                calls: self.calls.clone(),
            },
            PostgresAuthorizationLedger::for_bootstrap(
                storage,
                self.scope.clone(),
                self.bootstrap_digest.clone(),
            ),
            config,
        ))
    }

    async fn fresh_intent(
        &self,
        resources: BTreeSet<String>,
        operation: OperationSpec,
        input: &[u8],
    ) -> TestResult<OperationIntent> {
        let mut grant = self.authority.payload().clone();
        grant.id = DelegationId::new();
        let (admitted, wire) = admit_fixture_authority(self, grant)?;
        self.storage
            .admit_delegation(&self.scope, &admitted, &wire)
            .await?;
        Ok(OperationIntent {
            principal: self.intent.principal.clone(),
            input_digest: Digest::blake3(input),
            delegation_chain: vec![admitted.into_payload()],
            operation,
            resources,
            budget: budget(1),
            idempotency_key: None,
            execution: None,
        })
    }

    fn dispatcher_for_generation(
        &self,
        storage: PostgresStorage,
        ttl: SignedDuration,
        generation: RuntimeGenerationId,
        bootstrap: bool,
    ) -> TestResult<TestDispatcher> {
        let config = DispatcherConfig::new(
            self.policy.clone(),
            self.policy_digest.clone(),
            generation,
            "fixture:durable-replay".to_owned(),
            ttl,
            self.intent.delegation_chain.clone(),
            [self.intent.operation.clone()],
        )?;
        Ok(Dispatcher::new(
            LedgerFixturePolicy {
                bundle: self.policy.clone(),
                digest: self.policy_digest.clone(),
            },
            CountingPort {
                adapter: self.adapter.clone(),
                calls: self.calls.clone(),
            },
            if bootstrap {
                PostgresAuthorizationLedger::for_bootstrap(
                    storage,
                    self.scope.clone(),
                    self.bootstrap_digest.clone(),
                )
            } else {
                PostgresAuthorizationLedger::new(storage, self.scope.clone())
            },
            config,
        ))
    }

    fn signed_fixture_record(&self, value: serde_json::Value) -> TestResult<SignedRecord> {
        self.signed_fixture_record_for(AdmissionKind::Generation, value)
    }

    fn signed_fixture_record_for(
        &self,
        kind: AdmissionKind,
        value: serde_json::Value,
    ) -> TestResult<SignedRecord> {
        let wire = SignedAdmissionWire::sign(
            kind,
            self.scope.institution().clone(),
            self.scope.workspace().clone(),
            self.intent.principal.clone(),
            value,
            &SigningKey::from_bytes(&[0x37; 32]),
        )?;
        self.anchors.admit_expected(kind, wire.clone())?;
        Ok(SignedRecord::from_json(
            &serde_json::to_value(&wire)?,
            wire.signer.clone(),
            wire.signature,
        )?)
    }

    async fn admit_fixture_generation(&self, label: &str) -> TestResult<RuntimeGenerationId> {
        let manifest =
            self.signed_fixture_record(serde_json::json!({"ledger_fixture_generation": label}))?;
        let digest = manifest.digest().clone();
        self.storage
            .admit_generation(&politeia_storage::RuntimeGeneration {
                scope: self.scope.clone(),
                generation_digest: digest.clone(),
                input_digest: digest.clone(),
                artifact_digest: digest.clone(),
                manifest,
            })
            .await?;
        Ok(RuntimeGenerationId::from_digest(digest))
    }

    async fn activate(&self, generation: &RuntimeGenerationId) -> TestResult {
        let snapshot = self.storage.load_workspace(&self.scope).await?;
        let transition = self.signed_fixture_record(serde_json::json!({
            "ledger_fixture_activation": generation,
            "previous": snapshot.active_generation, "revision": snapshot.revision,
        }))?;
        self.storage
            .activate_generation(&ActivationCommit {
                scope: self.scope.clone(),
                expected_revision: snapshot.revision,
                expected_active: snapshot.active_generation,
                generation: generation.digest().clone(),
                transition,
                evidence: Vec::new(),
                outbox: Vec::new(),
            })
            .await?;
        Ok(())
    }
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL instance; the package CI runs this explicitly"]
async fn handoff_atomically_requires_closed_authority_and_the_exact_completed_canary() -> TestResult
{
    let url = database_url()?;
    let fixture = Fixture::new(&url, 8).await?;
    let generation = fixture.admit_fixture_generation("handoff").await?;
    fixture.activate(&generation).await?;
    let commissioning_record = politeia_core::CommissioningRecordId::new();
    let commissioning_payload = br#"{"fixture":"handoff-commissioning"}"#.to_vec();
    fixture
        .storage
        .admit_commissioning_receipt(
            &fixture.scope,
            &CommissioningReceipt {
                record: commissioning_record.clone(),
                record_digest: Digest::blake3(b"handoff-commissioning-record"),
                payload_digest: Digest::blake3(&commissioning_payload),
                payload: commissioning_payload,
            },
        )
        .await?;

    let commissioner = PrincipalId::new();
    let mut commissioner_grant = fixture.authority.payload().clone();
    commissioner_grant.id = DelegationId::new();
    commissioner_grant.subject = commissioner.clone();
    commissioner_grant.actions = BTreeSet::from([COMMISSION_ACTION.to_owned()]);
    commissioner_grant.resources =
        BTreeSet::from([commissioning_workspace_resource(fixture.scope.workspace())]);
    commissioner_grant.audience = BTreeSet::from([commissioning_institution_audience(
        fixture.scope.institution(),
    )]);
    let (commissioner_authority, commissioner_wire) =
        admit_fixture_authority(&fixture, commissioner_grant.clone())?;
    fixture
        .storage
        .admit_delegation(&fixture.scope, &commissioner_authority, &commissioner_wire)
        .await?;

    let mut canary_intent = fixture.intent.clone();
    canary_intent.idempotency_key = Some("handoff-before-revocation".to_owned());
    let dispatcher = fixture.dispatcher_for_generation(
        fixture.storage.clone(),
        SignedDuration::from_secs(30),
        generation.clone(),
        false,
    )?;
    let early = dispatcher.authorize(&canary_intent).await?;
    dispatcher.execute(&early).await?;
    let early_receipt = CanonicalPayload::from_json(&serde_json::json!({
        "canary": "before-revocation"
    }))?;
    fixture
        .storage
        .record_completion(&fixture.scope, early.reservation_id(), &early_receipt)
        .await?;

    canary_intent.idempotency_key = Some("handoff-crosses-revocation".to_owned());
    let crossing = dispatcher.authorize(&canary_intent).await?;
    dispatcher.execute(&crossing).await?;

    let initial = fixture.storage.load_workspace(&fixture.scope).await?;
    let evidence_a = EvidenceAdmission {
        id: EvidenceId::new(),
        record: fixture.signed_fixture_record_for(
            AdmissionKind::Evidence,
            serde_json::json!({"handoff": "revocation"}),
        )?,
    };
    let evidence_b = EvidenceAdmission {
        id: EvidenceId::new(),
        record: fixture.signed_fixture_record_for(
            AdmissionKind::Evidence,
            serde_json::json!({"handoff": "continuity"}),
        )?,
    };
    let handoff = |snapshot: &politeia_storage::WorkspaceSnapshot,
                   reservation: politeia_core::BudgetReservationId,
                   canary: CanonicalPayload,
                   expected_authorities: BTreeSet<DelegationId>|
     -> TestResult<HandoffCommit> {
        Ok(HandoffCommit {
            transition: ScopedCommit {
                scope: fixture.scope.clone(),
                expected_revision: snapshot.revision,
                model: snapshot.model.clone(),
                model_kind: "handoff_receipt".to_owned(),
                transition: evidence_b.record.clone(),
                state: vec![],
                evidence: vec![evidence_a.clone(), evidence_b.clone()],
                outbox: vec![],
            },
            generation: generation.digest().clone(),
            commissioning_record: commissioning_record.clone(),
            commissioner: commissioner.clone(),
            expected_authorities,
            continuity_reservation: reservation,
            continuity_receipt: canary,
            handoff_receipt: CanonicalPayload::from_json(&serde_json::json!({
                "handoff": generation
            }))?,
        })
    };
    let still_active = handoff(
        &initial,
        early.reservation_id().clone(),
        early_receipt.clone(),
        BTreeSet::from([commissioner_grant.id.clone()]),
    )?;
    assert!(matches!(
        fixture
            .storage
            .commit_handoff_authorized(&still_active, std::slice::from_ref(&fixture.authority))
            .await,
        Err(StorageError::AdmissionMismatch)
    ));

    revoke_fixture_authority(&fixture, &commissioner_grant).await?;
    let crossing_receipt = CanonicalPayload::from_json(&serde_json::json!({
        "canary": "reserved-before-revocation-completed-after"
    }))?;
    fixture
        .storage
        .record_completion(&fixture.scope, crossing.reservation_id(), &crossing_receipt)
        .await?;
    let closed = fixture.storage.load_workspace(&fixture.scope).await?;
    let crossing_boundary = handoff(
        &closed,
        crossing.reservation_id().clone(),
        crossing_receipt,
        BTreeSet::from([commissioner_grant.id.clone()]),
    )?;
    assert!(matches!(
        fixture
            .storage
            .commit_handoff_authorized(&crossing_boundary, std::slice::from_ref(&fixture.authority))
            .await,
        Err(StorageError::AttemptUnavailable)
    ));

    canary_intent.idempotency_key = Some("handoff-after-revocation".to_owned());
    let dispatcher = fixture.dispatcher_for_generation(
        fixture.storage.clone(),
        SignedDuration::from_secs(30),
        generation.clone(),
        false,
    )?;
    let canary = dispatcher.authorize(&canary_intent).await?;
    dispatcher.execute(&canary).await?;
    let canary_receipt = CanonicalPayload::from_json(&serde_json::json!({
        "canary": "after-revocation"
    }))?;
    fixture
        .storage
        .record_completion(&fixture.scope, canary.reservation_id(), &canary_receipt)
        .await?;
    let closed = fixture.storage.load_workspace(&fixture.scope).await?;
    let wrong_canary = handoff(
        &closed,
        canary.reservation_id().clone(),
        CanonicalPayload::from_json(&serde_json::json!({"canary": "caller-asserted"}))?,
        BTreeSet::from([commissioner_grant.id.clone()]),
    )?;
    assert!(matches!(
        fixture
            .storage
            .commit_handoff_authorized(&wrong_canary, std::slice::from_ref(&fixture.authority))
            .await,
        Err(StorageError::AttemptUnavailable)
    ));

    let contested = handoff(
        &closed,
        canary.reservation_id().clone(),
        canary_receipt.clone(),
        BTreeSet::from([commissioner_grant.id.clone()]),
    )?;
    // Hold a non-key workspace update before either public storage operation
    // starts. It blocks handoff's UPDATE/FOR UPDATE and the corrected
    // admission UPDATE, but permits the old INSERT's foreign-key KEY SHARE.
    // The handoff must first become a visible waiter. The corrected admission
    // must then wait too; the old INSERT/EXISTS-only admission would commit
    // while the handoff retained its pre-admission snapshot.
    let (mut lock_client, lock_connection) =
        tokio_postgres::connect(&url, tokio_postgres::NoTls).await?;
    tokio::spawn(async move {
        let _ = lock_connection.await;
    });
    let blocker_pid: i32 = lock_client
        .query_one("SELECT pg_backend_pid()", &[])
        .await?
        .get(0);
    let lock = lock_client.build_transaction().start().await?;
    lock.query_one(
        "SELECT 1 FROM institution_workspaces WHERE institution_id = $1 AND workspace_id = $2 FOR NO KEY UPDATE",
        &[
            &fixture.scope.institution().0,
            &fixture.scope.workspace().0,
        ],
    )
    .await?;
    let (observer, observer_connection) =
        tokio_postgres::connect(&url, tokio_postgres::NoTls).await?;
    tokio::spawn(async move {
        let _ = observer_connection.await;
    });
    let handoff_storage = fixture.storage.clone();
    let handoff_owner = fixture.authority.clone();
    let expected_handoff_receipt = contested.handoff_receipt.clone();
    let blocked_handoff = contested.clone();
    let handoff_task = tokio::spawn(async move {
        handoff_storage
            .commit_handoff_authorized(&blocked_handoff, &[handoff_owner])
            .await
    });
    wait_for_workspace_lock_waiters(&observer, blocker_pid, 1).await?;

    let mut concurrent_grant = commissioner_grant.clone();
    concurrent_grant.id = DelegationId::new();
    concurrent_grant.subject = PrincipalId::new();
    let (concurrent_authority, concurrent_wire) =
        admit_fixture_authority(&fixture, concurrent_grant.clone())?;
    let admission_storage = fixture.storage.clone();
    let admission_scope = fixture.scope.clone();
    let admission_task = tokio::spawn(async move {
        admission_storage
            .admit_delegation(&admission_scope, &concurrent_authority, &concurrent_wire)
            .await
    });
    wait_for_workspace_lock_waiters(&observer, blocker_pid, 2).await?;
    lock.commit().await?;
    let committed = handoff_task.await??;
    admission_task.await??;
    let retained = fixture
        .storage
        .load_handoff_receipt(&fixture.scope, generation.digest())
        .await?;
    assert_eq!(retained.revision, committed.revision);
    assert_eq!(retained.payload, expected_handoff_receipt.bytes());
    assert_eq!(retained.continuity_receipt_digest, *canary_receipt.digest());
    assert_eq!(
        fixture
            .storage
            .load_workspace(&fixture.scope)
            .await?
            .revision,
        committed.revision
    );
    Ok(())
}

fn database_url() -> TestResult<String> {
    Ok(std::env::var("POLITEIA_STORAGE_TEST_DATABASE_URL")?)
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL instance; the package CI runs this explicitly"]
async fn activation_and_rollback_cannot_revive_reserved_authority() -> TestResult {
    let fixture = Fixture::new(&database_url()?, 10).await?;
    let bootstrap = fixture.dispatcher(fixture.storage.clone(), SignedDuration::from_secs(30))?;
    let initial_lease = bootstrap.authorize(&fixture.intent).await?;
    let first = fixture.admit_fixture_generation("first").await?;
    fixture.activate(&first).await?;
    assert!(bootstrap.execute(&initial_lease).await.is_err());
    let mut intent = fixture.intent.clone();
    intent.idempotency_key = Some("after-initial-activation".to_owned());
    assert!(bootstrap.authorize(&intent).await.is_err());

    let active = fixture.dispatcher_for_generation(
        fixture.storage.clone(),
        SignedDuration::from_secs(30),
        first.clone(),
        false,
    )?;
    let lease = active.authorize(&intent).await?;
    let next = fixture.admit_fixture_generation("next").await?;
    fixture.activate(&next).await?;
    assert!(active.execute(&lease).await.is_err());
    fixture.activate(&first).await?;
    assert!(
        active.execute(&lease).await.is_err(),
        "rollback must not revive a lease issued at an older revision"
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);

    intent.idempotency_key = Some("fresh-authority-after-rollback".to_owned());
    let lease = active.authorize(&intent).await?;
    active.execute(&lease).await?;
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL instance; the package CI runs this explicitly"]
async fn dispatcher_reopens_reservations_and_refuses_ambiguous_replay() -> TestResult {
    let url = database_url()?;
    let fixture = Fixture::new(&url, 2).await?;
    let snapshot = fixture.storage.load_workspace(&fixture.scope).await?;
    assert_eq!(snapshot.revision, 0);
    assert_eq!(snapshot.owner, fixture.intent.principal);
    assert_eq!(snapshot.delegations.len(), 1);
    let wrong_domain = Scope::new(
        fixture.scope.institution().clone(),
        fixture.scope.workspace().clone(),
        "fixture.wrong".parse()?,
    );
    assert!(matches!(
        fixture.storage.load_workspace(&wrong_domain).await,
        Err(StorageError::NotFound)
    ));
    let first = fixture.dispatcher(fixture.storage.clone(), SignedDuration::from_secs(30))?;
    let lease = first.authorize(&fixture.intent).await?;
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture
            .storage
            .load_attempt(&fixture.scope, lease.reservation_id())
            .await?
            .status,
        AttemptStatus::Reserved
    );
    drop(first);
    let reopened = PostgresStorage::connect(&url).await?;
    let replacement = fixture.dispatcher(reopened.clone(), SignedDuration::from_secs(30))?;
    replacement.execute(&lease).await?;
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    let incomplete = reopened
        .load_attempt(&fixture.scope, lease.reservation_id())
        .await?;
    assert!(matches!(
        reopened
            .load_attempt(&wrong_domain, lease.reservation_id())
            .await,
        Err(StorageError::NotFound)
    ));
    assert_eq!(incomplete.status, AttemptStatus::Claimed);
    assert!(incomplete.receipt_digest.is_none());
    drop(replacement);
    let restarted = fixture.dispatcher(
        PostgresStorage::connect(&url).await?,
        SignedDuration::from_secs(30),
    )?;
    assert!(
        restarted.execute(&lease).await.is_err(),
        "issued effect cannot be claimed twice"
    );
    assert!(
        restarted.authorize(&fixture.intent).await.is_err(),
        "fresh lease cannot erase semantic replay"
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    reopened
        .record_completion(
            &fixture.scope,
            lease.reservation_id(),
            &CanonicalPayload::from_json(&serde_json::json!({"returned_policy": fixture.policy_digest, "effect_calls": fixture.calls.load(Ordering::SeqCst)}))?,
        )
        .await?;
    assert_eq!(
        reopened
            .load_attempt(&fixture.scope, lease.reservation_id())
            .await?
            .status,
        AttemptStatus::Completed
    );
    assert!(
        restarted.authorize(&fixture.intent).await.is_err(),
        "completion does not release retained replay"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL instance; the package CI runs this explicitly"]
async fn fresh_grants_cannot_evade_claimed_effect_overlap_and_completion_releases_it() -> TestResult
{
    let url = database_url()?;
    let fixture = Fixture::new_productive(&url, 1).await?;
    let mut first_intent = fixture.intent.clone();
    first_intent.resources = BTreeSet::from(["fixture:artifact:a".to_owned()]);
    let first_dispatcher = fixture.dispatcher_for_intent(
        fixture.storage.clone(),
        SignedDuration::from_secs(30),
        &first_intent,
    )?;
    let first = first_dispatcher.authorize(&first_intent).await?;
    first_dispatcher.execute(&first).await?;
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture
            .storage
            .load_attempt(&fixture.scope, first.reservation_id())
            .await?
            .status,
        AttemptStatus::Claimed
    );

    let mut different_operation = first_intent.operation.clone();
    different_operation.id = OperationId::new();
    different_operation.name = "replace_durable_fixture_artifact".to_owned();
    let overlapping = fixture
        .fresh_intent(
            BTreeSet::from([
                "fixture:artifact:a".to_owned(),
                "fixture:artifact:b".to_owned(),
            ]),
            different_operation,
            b"fresh operation parameters",
        )
        .await?;
    let overlapping_dispatcher = fixture.dispatcher_for_intent_in_domain(
        PostgresStorage::connect(&url).await?,
        SignedDuration::from_secs(30),
        &overlapping,
        "fixture:fresh-runtime-domain".to_owned(),
    )?;
    let refusal = overlapping_dispatcher.authorize(&overlapping).await;
    assert!(
        matches!(refusal, Err(RuntimeError::AmbiguousEffect)),
        "a fresh one-call grant, replay domain, operation ID, parameters, lease, and intersecting resource set must receive the semantic ambiguity refusal"
    );
    assert_eq!(
        fixture.calls.load(Ordering::SeqCst),
        1,
        "the overlapping fresh grant must not reach the effect port"
    );

    let disjoint = fixture
        .fresh_intent(
            BTreeSet::from(["fixture:artifact:c".to_owned()]),
            first_intent.operation.clone(),
            b"disjoint operation parameters",
        )
        .await?;
    let disjoint_dispatcher = fixture.dispatcher_for_intent(
        PostgresStorage::connect(&url).await?,
        SignedDuration::from_secs(30),
        &disjoint,
    )?;
    let disjoint_lease = disjoint_dispatcher.authorize(&disjoint).await?;
    disjoint_dispatcher.execute(&disjoint_lease).await?;
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 2);

    fixture
        .storage
        .record_completion(
            &fixture.scope,
            first.reservation_id(),
            &CanonicalPayload::from_json(
                &serde_json::json!({"outcome": "first effect completed"}),
            )?,
        )
        .await?;
    let repeated = fixture
        .fresh_intent(
            BTreeSet::from(["fixture:artifact:a".to_owned()]),
            first_intent.operation,
            b"intentional post-completion operation",
        )
        .await?;
    let repeated_dispatcher = fixture.dispatcher_for_intent(
        PostgresStorage::connect(&url).await?,
        SignedDuration::from_secs(30),
        &repeated,
    )?;
    let repeated_lease = repeated_dispatcher.authorize(&repeated).await?;
    repeated_dispatcher.execute(&repeated_lease).await?;
    assert_eq!(
        fixture.calls.load(Ordering::SeqCst),
        3,
        "canonical completion evidence releases only the resolved overlap"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL instance; the package CI runs this explicitly"]
async fn workspace_lock_serializes_competing_overlap_claims_before_either_port_runs() -> TestResult
{
    let url = database_url()?;
    let fixture = Fixture::new_productive(&url, 1).await?;
    let left_intent = fixture
        .fresh_intent(
            BTreeSet::from(["fixture:artifact:a".to_owned()]),
            fixture.intent.operation.clone(),
            b"left parameters",
        )
        .await?;
    let mut right_operation = fixture.intent.operation.clone();
    right_operation.id = OperationId::new();
    right_operation.name = "competing_artifact_write".to_owned();
    let right_intent = fixture
        .fresh_intent(
            BTreeSet::from([
                "fixture:artifact:a".to_owned(),
                "fixture:artifact:b".to_owned(),
            ]),
            right_operation,
            b"right parameters",
        )
        .await?;
    let left_dispatcher = fixture.dispatcher_for_intent(
        PostgresStorage::connect(&url).await?,
        SignedDuration::from_secs(30),
        &left_intent,
    )?;
    let right_dispatcher = fixture.dispatcher_for_intent_in_domain(
        PostgresStorage::connect(&url).await?,
        SignedDuration::from_secs(30),
        &right_intent,
        "fixture:concurrent-fresh-runtime-domain".to_owned(),
    )?;
    let left = left_dispatcher.authorize(&left_intent).await?;
    let right = right_dispatcher.authorize(&right_intent).await?;

    let (left_result, right_result) = tokio::join!(
        left_dispatcher.execute(&left),
        right_dispatcher.execute(&right),
    );
    let successes = usize::from(left_result.is_ok()) + usize::from(right_result.is_ok());
    let ambiguities = usize::from(matches!(left_result, Err(RuntimeError::AmbiguousEffect)))
        + usize::from(matches!(right_result, Err(RuntimeError::AmbiguousEffect)));
    assert_eq!(successes, 1, "one workspace-serialized claim must win");
    assert_eq!(ambiguities, 1, "the intersecting claim must fail closed");
    assert_eq!(
        fixture.calls.load(Ordering::SeqCst),
        1,
        "the losing claim must be refused before its port"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL instance; the package CI runs this explicitly"]
async fn legacy_claimed_attempt_without_a_subject_blocks_new_mutating_work() -> TestResult {
    let url = database_url()?;
    let fixture = Fixture::new_productive(&url, 1).await?;
    let mut original = fixture.intent.clone();
    original.resources = BTreeSet::from(["fixture:artifact:a".to_owned()]);
    let dispatcher = fixture.dispatcher_for_intent(
        fixture.storage.clone(),
        SignedDuration::from_secs(30),
        &original,
    )?;
    let lease = dispatcher.authorize(&original).await?;
    dispatcher.execute(&lease).await?;
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
        .execute(
            "UPDATE operation_attempts SET effect_binding = NULL WHERE institution_id = $1 AND workspace_id = $2 AND reservation_id = $3 AND status = 'claimed'",
            &[
                &fixture.scope.institution().0,
                &fixture.scope.workspace().0,
                &lease.reservation_id().0,
            ],
        )
        .await?;

    let fresh = fixture
        .fresh_intent(
            BTreeSet::from(["fixture:artifact:c".to_owned()]),
            fixture.intent.operation.clone(),
            b"apparently disjoint but legacy-unknown",
        )
        .await?;
    let fresh_dispatcher = fixture.dispatcher_for_intent(
        PostgresStorage::connect(&url).await?,
        SignedDuration::from_secs(30),
        &fresh,
    )?;
    assert!(matches!(
        fresh_dispatcher.authorize(&fresh).await,
        Err(RuntimeError::AmbiguousEffect)
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL instance; the package CI runs this explicitly"]
async fn concurrent_dispatchers_share_budget_and_one_use_claim() -> TestResult {
    let url = database_url()?;
    let fixture = Fixture::new(&url, 1).await?;
    let first = fixture.dispatcher(fixture.storage.clone(), SignedDuration::from_secs(30))?;
    let second = fixture.dispatcher(
        PostgresStorage::connect(&url).await?,
        SignedDuration::from_secs(30),
    )?;
    let mut other = fixture.intent.clone();
    other.idempotency_key = Some("different-effect-same-budget".to_owned());
    let (left, right) = tokio::join!(first.authorize(&fixture.intent), second.authorize(&other));
    let lease = match (left, right) {
        (Ok(lease), Err(_)) | (Err(_), Ok(lease)) => lease,
        (left, right) => {
            return Err(format!(
                "exactly one budget reservation must win; failures: {:?}, {:?}",
                left.err(),
                right.err()
            )
            .into());
        }
    };
    let (left, right) = tokio::join!(first.execute(&lease), second.execute(&lease));
    assert_ne!(
        left.is_ok(),
        right.is_ok(),
        "exactly one claimant may reach the effect port"
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    let reopened = fixture.dispatcher(
        PostgresStorage::connect(&url).await?,
        SignedDuration::from_secs(30),
    )?;
    let mut third = fixture.intent.clone();
    third.idempotency_key = Some("fresh-key-after-spent-budget".to_owned());
    assert!(
        reopened.authorize(&third).await.is_err(),
        "restart cannot reset spent budget"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL instance; the package CI runs this explicitly"]
async fn revoke_between_reservation_and_claim_prevents_effect() -> TestResult {
    let fixture = Fixture::new(&database_url()?, 2).await?;
    let dispatcher = fixture.dispatcher(fixture.storage.clone(), SignedDuration::from_secs(30))?;
    let lease = dispatcher.authorize(&fixture.intent).await?;
    revoke_fixture_authority(&fixture, &fixture.intent.delegation_chain[0]).await?;
    assert!(
        fixture
            .storage
            .load_delegation(&fixture.scope, &fixture.intent.delegation_chain[0].id)
            .await?
            .revoked
    );
    assert!(
        dispatcher.execute(&lease).await.is_err(),
        "revoked authority cannot claim a pending lease"
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    let remaining = fixture
        .storage
        .load_attempt(&fixture.scope, lease.reservation_id())
        .await?;
    assert_eq!(
        remaining.status,
        AttemptStatus::Reserved,
        "failed claim cannot fabricate an attempt"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL instance; the package CI runs this explicitly"]
async fn expired_reservation_releases_budget_for_a_different_replay_key() -> TestResult {
    let url = database_url()?;
    let fixture = Fixture::new(&url, 1).await?;
    let dispatcher = fixture.dispatcher(fixture.storage.clone(), SignedDuration::from_secs(30))?;
    let expired = dispatcher
        .authorize(&fixture.intent)
        .await
        .map_err(|error| format!("initial reservation admission failed: {error}"))?;
    let mut fresh = fixture.intent.clone();
    fresh.idempotency_key = Some("different-key-after-expiry".to_owned());
    let blocked = dispatcher.authorize(&fresh).await;
    assert!(
        matches!(&blocked, Err(RuntimeError::AuthorizationState { source })
            if matches!(source.downcast_ref::<StorageError>(), Some(StorageError::AttemptUnavailable))),
        "a live reservation must retain the entire finite budget; got {blocked:?}"
    );

    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let expired_rows = client
        .execute(
            "UPDATE operation_attempts SET expires_at = clock_timestamp() - INTERVAL '1 second' WHERE institution_id = $1 AND workspace_id = $2 AND reservation_id = $3 AND status = 'reserved'",
            &[
                &fixture.scope.institution().0,
                &fixture.scope.workspace().0,
                &expired.reservation_id().0,
            ],
        )
        .await
        .map_err(|error| format!("expire the unclaimed reservation: {error}"))?;
    assert_eq!(
        expired_rows, 1,
        "the fixture must expire exactly its still-unclaimed reservation"
    );

    let lease = dispatcher
        .authorize(&fresh)
        .await
        .map_err(|error| format!("fresh admission after reservation expiry failed: {error}"))?;
    let stale_execution = dispatcher.execute(&expired).await;
    assert!(
        matches!(&stale_execution, Err(RuntimeError::AuthorizationState { source })
            if matches!(source.downcast_ref::<StorageError>(), Some(StorageError::AttemptUnavailable))),
        "the expired reservation must not reach the effect port; got {stale_execution:?}"
    );
    dispatcher
        .execute(&lease)
        .await
        .map_err(|error| format!("fresh reservation execution failed: {error}"))?;
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    let foreign = Scope::new(
        InstitutionId::new(),
        InstitutionWorkspaceId::new(),
        "fixture.other".parse()?,
    );
    assert!(matches!(
        fixture
            .storage
            .load_attempt(&foreign, lease.reservation_id())
            .await,
        Err(StorageError::NotFound)
    ));
    Ok(())
}
