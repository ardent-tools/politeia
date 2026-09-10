//! Signed runtime-generation lifecycle at the installed service boundary.
//!
//! This module coordinates existing core provenance, artifact, assurance, and
//! storage contracts. It does not make a build-reproducibility claim: it
//! verifies the signed input and every published artifact byte.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
};

use politeia_core::{
    AdapterId, Delegation, DelegationId, Digest, EvidenceId,
    commissioning::{
        CommissionerGrantRecord, CommissioningRecord, TrustedCommissionerGrantRegistry,
    },
    evidence::{EvidenceRequest, TrustedEvidenceRegistry},
    generation::RuntimeGenerationInputs,
    trust::{AdmissionKind, Admitted, SignedAdmissionWire},
};
use politeia_evidence::{
    assurance::{
        ActivationProof, AuthorizedControlRun, ControlRun, VerifiedActivation, clean_claim,
    },
    authority::AuthorityContext,
};
use politeia_runtime::AuthorizationLedger;
use politeia_storage::{
    ActivationCommit, EvidenceAdmission, PostgresAuthorizationLedger, RuntimeGeneration,
    SignedRecord,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    CoordinatorError, OperationResult,
    artifacts::{ArtifactSources, CommissioningProvenance, GenerationArtifactBuilder},
    service::PoliteiadService,
};

const ACTIVATE_CONTROL: &str = "generation:activate";
const ROLLBACK_CONTROL: &str = "generation:rollback";

/// Paths to complete artifact inputs, relative to the installed workspace.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSourcePaths {
    /// Public source archive.
    pub public_source: PathBuf,
    /// Policy bundle bytes.
    pub policy: PathBuf,
    /// Specializer configuration.
    pub specializer: PathBuf,
    /// Toolchain description.
    pub toolchain: PathBuf,
    /// Approved schemas.
    pub schemas: BTreeMap<String, PathBuf>,
    /// Approved adapters.
    pub adapters: BTreeMap<AdapterId, PathBuf>,
    /// Approved packs.
    pub packs: BTreeMap<String, PathBuf>,
    /// Complete remaining component set.
    pub components: BTreeMap<String, PathBuf>,
}

/// Inert selection of already-admitted commissioning facts.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommissioningSelection {
    /// Durable temporary commissioner grant used for this record.
    pub delegation: DelegationId,
    /// Discovery observations used by the record.
    pub observations: BTreeSet<EvidenceId>,
    /// Owner approvals used by the record.
    pub approvals: BTreeSet<EvidenceId>,
    /// Explicitly owner-approved open obligations.
    pub unresolved_obligations: BTreeSet<String>,
}

/// Typed assurance material required for activation and rollback.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationAssurance {
    /// Signed run of the exact lifecycle control.
    pub run: SignedAdmissionWire<ControlRun>,
    /// Signed direct grant for the control-run producer.
    pub run_authority: SignedAdmissionWire<Delegation>,
    /// Signed proof that the control fires on its mediation path.
    pub proof: SignedAdmissionWire<ActivationProof>,
    /// Signed direct grant for the independent activation verifier.
    pub proof_authority: SignedAdmissionWire<Delegation>,
}

/// Generation lifecycle requests carried by the commissioning transport.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GenerationRequest {
    /// Derive, publish, verify, and durably admit a complete generation.
    Publish {
        /// Exact signed specialization inputs.
        inputs: SignedAdmissionWire<RuntimeGenerationInputs>,
        /// Re-admitted commissioning selection.
        commissioning: CommissioningSelection,
        /// Workspace-confined bytes for every approved input.
        sources: ArtifactSourcePaths,
    },
    /// Re-admit stored signed inputs and verify every immutable artifact byte.
    Verify {
        /// Generation digest returned by publish.
        generation: Digest,
    },
    /// Compare-and-swap an admitted generation into the active slot.
    Activate {
        /// Target generation digest.
        generation: Digest,
        /// Durable workspace revision observed by the caller.
        expected_revision: i64,
        /// Active generation observed by the caller, including explicit empty.
        expected_active: Option<Digest>,
        /// Control run and independent activation proof.
        assurance: ActivationAssurance,
    },
    /// Compare-and-swap a previously admitted generation back into service.
    Rollback {
        /// Previously admitted target generation digest.
        generation: Digest,
        /// Durable workspace revision observed by the caller.
        expected_revision: i64,
        /// Active generation observed by the caller.
        expected_active: Option<Digest>,
        /// Control run and independent activation proof.
        assurance: ActivationAssurance,
    },
    /// Admit a fresh replacement-maintainer grant before further commissioning.
    Recommission {
        /// Fresh owner-rooted delegation for the replacement maintainer.
        delegation: SignedAdmissionWire<Delegation>,
    },
}

impl PoliteiadService {
    /// Execute one typed signed-generation lifecycle request.
    pub(crate) async fn handle_generation(
        &self,
        request: Value,
    ) -> Result<OperationResult, CoordinatorError> {
        let request: GenerationRequest = serde_json::from_value(request).map_err(|error| {
            CoordinatorError::Refused(format!("generation input is not typed JSON: {error}"))
        })?;
        match request {
            GenerationRequest::Publish {
                inputs,
                commissioning,
                sources,
            } => {
                self.publish_generation(inputs, commissioning, sources)
                    .await
            }
            GenerationRequest::Verify { generation } => self.verify_generation(generation).await,
            GenerationRequest::Activate {
                generation,
                expected_revision,
                expected_active,
                assurance,
            } => {
                self.activate_generation(
                    generation,
                    expected_revision,
                    expected_active,
                    assurance,
                    ACTIVATE_CONTROL,
                )
                .await
            }
            GenerationRequest::Rollback {
                generation,
                expected_revision,
                expected_active,
                assurance,
            } => {
                self.activate_generation(
                    generation,
                    expected_revision,
                    expected_active,
                    assurance,
                    ROLLBACK_CONTROL,
                )
                .await
            }
            GenerationRequest::Recommission { delegation } => self.recommission(delegation).await,
        }
    }

    async fn publish_generation(
        &self,
        inputs: SignedAdmissionWire<RuntimeGenerationInputs>,
        selection: CommissioningSelection,
        sources: ArtifactSourcePaths,
    ) -> Result<OperationResult, CoordinatorError> {
        let durable = self.durable_snapshot().await?;
        let admitted = self
            .anchors()
            .admit_expected(AdmissionKind::Generation, inputs.clone())
            .map_err(refusal)?;
        let commissioning = self
            .commissioning_record(
                &durable,
                admitted.signer(),
                &admitted.payload().commissioning_record,
                &admitted.payload().commissioning_record_digest,
                &selection,
                true,
            )
            .await?;
        let artifact = GenerationArtifactBuilder::new(self.layout().artifact_dir.clone())
            .publish_with_provenance(
                self.anchors(),
                inputs.clone(),
                self.workspace(),
                &commissioning,
                CommissioningProvenance {
                    delegation: selection.delegation,
                    observations: selection.observations,
                    approvals: selection.approvals,
                    unresolved_obligations: selection.unresolved_obligations,
                },
                &self.resolve_sources(sources)?,
            )
            .map_err(refusal)?;
        let generation = artifact.generation().id().digest().clone();
        let stored = RuntimeGeneration {
            scope: self.scope().clone(),
            generation_digest: generation.clone(),
            input_digest: generation_input_digest(admitted.payload())?,
            // The immutable manifest binds every exact component digest.
            artifact_digest: artifact.manifest_digest().clone(),
            manifest: signed_wire_record(&inputs)?,
        };
        self.storage()
            .admit_generation(&stored)
            .await
            .map_err(storage_refusal)?;
        let verified = GenerationArtifactBuilder::new(self.layout().artifact_dir.clone())
            .verify(
                self.anchors(),
                self.workspace(),
                &commissioning,
                &generation,
            )
            .map_err(refusal)?;
        Ok(OperationResult::Coordinated {
            result: json!({
                "generation": generation,
                "artifact_manifest": verified.manifest_digest(),
                "admitted": true,
            }),
            evidence_refs: Vec::new(),
        })
    }

    async fn verify_generation(
        &self,
        generation: Digest,
    ) -> Result<OperationResult, CoordinatorError> {
        let stored = self
            .storage()
            .load_generation(self.scope(), &generation)
            .await
            .map_err(storage_refusal)?;
        let inputs = stored_inputs(&stored)?;
        let admitted = self
            .anchors()
            .admit_expected(AdmissionKind::Generation, inputs)
            .map_err(refusal)?;
        if generation_input_digest(admitted.payload())? != stored.input_digest {
            return Err(CoordinatorError::Refused(
                "stored generation input digest differs from signed inputs".to_string(),
            ));
        }
        let builder = GenerationArtifactBuilder::new(self.layout().artifact_dir.clone());
        let provenance = builder
            .commissioning_provenance(&generation)
            .map_err(refusal)?;
        let durable = self.durable_snapshot().await?;
        let commissioning = self
            .commissioning_record(
                &durable,
                admitted.signer(),
                &admitted.payload().commissioning_record,
                &admitted.payload().commissioning_record_digest,
                &CommissioningSelection {
                    delegation: provenance.delegation,
                    observations: provenance.observations,
                    approvals: provenance.approvals,
                    unresolved_obligations: provenance.unresolved_obligations,
                },
                false,
            )
            .await?;
        let artifact = builder
            .verify(
                self.anchors(),
                self.workspace(),
                &commissioning,
                &generation,
            )
            .map_err(refusal)?;
        if artifact.manifest_digest() != &stored.artifact_digest {
            return Err(CoordinatorError::Refused(
                "stored artifact manifest differs from immutable artifact bytes".to_string(),
            ));
        }
        Ok(OperationResult::Coordinated {
            result: json!({
                "generation": generation,
                "artifact_manifest": artifact.manifest_digest(),
                "verified": true,
                "build_reproducibility": "not_claimed",
            }),
            evidence_refs: Vec::new(),
        })
    }

    async fn activate_generation(
        &self,
        generation: Digest,
        expected_revision: i64,
        expected_active: Option<Digest>,
        assurance: ActivationAssurance,
        control: &str,
    ) -> Result<OperationResult, CoordinatorError> {
        let durable = self.durable_snapshot().await?;
        if durable.revision != expected_revision || durable.active_generation != expected_active {
            return Err(CoordinatorError::Refused(
                "generation activation compare-and-swap is stale".to_string(),
            ));
        }
        let stored = self
            .storage()
            .load_generation(self.scope(), &generation)
            .await
            .map_err(storage_refusal)?;
        self.verify_generation(generation.clone()).await?;

        let now = self.observed_at().await?;
        let context = AuthorityContext::new(
            self.workspace().institution.clone(),
            self.workspace().id.clone(),
            durable.owner.clone(),
            now,
        );
        self.require_current_direct_grant(&durable, &assurance.run_authority)?;
        self.require_current_direct_grant(&durable, &assurance.proof_authority)?;
        let run = self
            .anchors()
            .admit_expected(AdmissionKind::ControlRun, assurance.run.clone())
            .map_err(refusal)?;
        let run_authority = self
            .anchors()
            .admit_expected(AdmissionKind::Delegation, assurance.run_authority.clone())
            .map_err(refusal)?;
        let proof = self
            .anchors()
            .admit_expected(AdmissionKind::ActivationProof, assurance.proof.clone())
            .map_err(refusal)?;
        let proof_authority = self
            .anchors()
            .admit_expected(AdmissionKind::Delegation, assurance.proof_authority.clone())
            .map_err(refusal)?;
        let authorized =
            AuthorizedControlRun::admit(&run, &run_authority, &context).map_err(refusal)?;
        let verified =
            VerifiedActivation::admit(&proof, &proof_authority, &context).map_err(refusal)?;
        let artifact = stored.artifact_digest.clone();
        let run_value = authorized.run();
        if run_value.control != control
            || run_value.input_digest != generation
            || run_value.subject != generation
            || run_value.population != generation
            || run_value.configuration_digest != artifact
            || run_value.policy != self.workspace().policy_bundle
            || run_value.policy_digest != self.workspace().policy_digest
        {
            return Err(CoordinatorError::Refused(
                "control run does not bind the exact generation and installed policy".to_string(),
            ));
        }
        clean_claim(&[authorized], control, &generation, &verified).map_err(refusal)?;
        let evidence = vec![
            EvidenceAdmission {
                id: assurance.run.payload.id.clone(),
                record: signed_wire_record(&assurance.run)?,
            },
            EvidenceAdmission {
                id: assurance.proof.payload.id.clone(),
                record: signed_wire_record(&assurance.proof)?,
            },
        ];
        let transition = signed_wire_record(&assurance.run)?;
        let receipt = self
            .storage()
            .activate_generation(&ActivationCommit {
                scope: self.scope().clone(),
                expected_revision,
                expected_active,
                generation: generation.clone(),
                transition,
                evidence,
                outbox: Vec::new(),
            })
            .await
            .map_err(storage_refusal)?;
        Ok(OperationResult::Coordinated {
            result: json!({
                "generation": generation,
                "active_generation": generation,
                "revision": receipt.revision,
                "transition": receipt.transition_digest,
                "control": control,
            }),
            evidence_refs: vec![
                assurance.run.payload.id.0.to_string(),
                assurance.proof.payload.id.0.to_string(),
            ],
        })
    }

    async fn recommission(
        &self,
        delegation: SignedAdmissionWire<Delegation>,
    ) -> Result<OperationResult, CoordinatorError> {
        let durable = self.durable_snapshot().await?;
        let admitted = self
            .anchors()
            .admit_expected(AdmissionKind::Delegation, delegation.clone())
            .map_err(refusal)?;
        self.validate_generation_delegation(&durable, &admitted)?;
        self.storage()
            .admit_delegation(self.scope(), &admitted, &delegation)
            .await
            .map_err(storage_refusal)?;
        Ok(OperationResult::Coordinated {
            result: json!({ "delegation": admitted.payload().id, "recommissioned": true }),
            evidence_refs: Vec::new(),
        })
    }

    async fn commissioning_record(
        &self,
        durable: &politeia_storage::WorkspaceSnapshot,
        signer: &politeia_core::PrincipalId,
        record_id: &politeia_core::CommissioningRecordId,
        expected_digest: &Digest,
        selection: &CommissioningSelection,
        require_current: bool,
    ) -> Result<CommissioningRecord, CoordinatorError> {
        let persisted = durable
            .delegations
            .get(&selection.delegation)
            .ok_or_else(|| {
                CoordinatorError::Refused(
                    "commissioner delegation is not durably admitted".to_string(),
                )
            })?;
        if require_current && persisted.revoked {
            return Err(CoordinatorError::Refused(
                "commissioner delegation is revoked".to_string(),
            ));
        }
        let delegation = self
            .anchors()
            .admit_expected(AdmissionKind::Delegation, persisted.wire.clone())
            .map_err(refusal)?;
        if delegation.signer() != &delegation.payload().issuer
            || delegation.payload().subject != *signer
        {
            return Err(CoordinatorError::Refused(
                "generation signer does not hold the selected commissioner delegation".to_string(),
            ));
        }
        if require_current {
            self.validate_generation_delegation(durable, &delegation)?;
        }
        let evidence_wires = selection
            .observations
            .iter()
            .chain(selection.approvals.iter())
            .map(|id| {
                durable.evidence.get(id).ok_or_else(|| {
                    CoordinatorError::Refused(
                        "commissioning evidence is not durably admitted".to_string(),
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(evidence_wire)
            .collect::<Result<Vec<_>, _>>()?;
        let evidence = TrustedEvidenceRegistry::admit_signed(self.anchors(), evidence_wires)
            .map_err(refusal)?;
        let as_of = if require_current {
            self.observed_at().await?
        } else {
            selection
                .observations
                .iter()
                .chain(selection.approvals.iter())
                .filter_map(|id| durable.evidence.get(id))
                .map(evidence_wire)
                .collect::<Result<Vec<_>, _>>()?
                .iter()
                .map(|wire| wire.payload.observed_at)
                .max()
                .ok_or_else(|| {
                    CoordinatorError::Refused("commissioning needs admitted evidence".to_string())
                })?
        };
        let grants = TrustedCommissionerGrantRegistry::from_trusted_bootstrap(
            as_of,
            [CommissionerGrantRecord {
                institution: self.workspace().institution.clone(),
                workspace: self.workspace().id.clone(),
                valid_from: persisted.admitted_at,
                // Historical reconstruction preserves the prior grant; current
                // authority was checked above for publication.
                revoked_at: None,
                delegation: delegation.into_payload(),
            }],
        )
        .map_err(refusal)?;
        let record = CommissioningRecord::rebuild(
            record_id.clone(),
            self.workspace(),
            &grants,
            &evidence,
            &selection.observations,
            &selection.approvals,
            selection.unresolved_obligations.clone(),
        )
        .map_err(refusal)?;
        if record.digest().map_err(refusal)? != *expected_digest {
            return Err(CoordinatorError::Refused(
                "re-admitted commissioning provenance differs from signed generation inputs"
                    .to_string(),
            ));
        }
        Ok(record)
    }

    fn resolve_sources(
        &self,
        sources: ArtifactSourcePaths,
    ) -> Result<ArtifactSources, CoordinatorError> {
        let root = &self.layout().workspace_dir;
        Ok(ArtifactSources {
            public_source: confined(root, &sources.public_source)?,
            policy: confined(root, &sources.policy)?,
            specializer: confined(root, &sources.specializer)?,
            toolchain: confined(root, &sources.toolchain)?,
            schemas: resolve_map(root, sources.schemas)?,
            adapters: resolve_map(root, sources.adapters)?,
            packs: resolve_map(root, sources.packs)?,
            components: resolve_map(root, sources.components)?,
        })
    }

    async fn observed_at(&self) -> Result<jiff::Timestamp, CoordinatorError> {
        PostgresAuthorizationLedger::new(self.storage().clone(), self.scope().clone())
            .observed_at()
            .await
            .map_err(|error| {
                CoordinatorError::Refused(format!(
                    "durable authorization clock refused operation: {error}"
                ))
            })
    }

    fn require_current_direct_grant(
        &self,
        durable: &politeia_storage::WorkspaceSnapshot,
        wire: &SignedAdmissionWire<Delegation>,
    ) -> Result<(), CoordinatorError> {
        if durable.owner != self.workspace().owner
            || durable.owner_delegation != self.workspace().owner_delegation
        {
            return Err(CoordinatorError::Refused(
                "durable workspace owner differs from installed workspace skeleton".to_string(),
            ));
        }
        let persisted = durable.delegations.get(&wire.payload.id).ok_or_else(|| {
            CoordinatorError::Refused("assurance delegation is not durably admitted".to_string())
        })?;
        if persisted.revoked || persisted.wire != *wire {
            return Err(CoordinatorError::Refused(
                "assurance delegation is revoked or differs from its durable admission".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_generation_delegation(
        &self,
        durable: &politeia_storage::WorkspaceSnapshot,
        admitted: &Admitted<Delegation>,
    ) -> Result<(), CoordinatorError> {
        let delegation = admitted.payload();
        if admitted.signer() != &delegation.issuer
            || durable.owner != self.workspace().owner
            || durable.owner_delegation != self.workspace().owner_delegation
        {
            return Err(CoordinatorError::Refused(
                "delegation authority does not match the installed owner chain".to_string(),
            ));
        }
        let mut current = delegation.clone();
        let mut visited = BTreeSet::new();
        loop {
            if !visited.insert(current.id.clone()) {
                return Err(CoordinatorError::Refused(
                    "delegation authority chain contains a cycle".to_string(),
                ));
            }
            match current.parent.as_ref() {
                None if current.id == self.workspace().owner_delegation
                    && current.issuer == self.workspace().owner =>
                {
                    return Ok(());
                }
                None => {
                    return Err(CoordinatorError::Refused(
                        "delegation chain is not rooted in the installed owner grant".to_string(),
                    ));
                }
                Some(parent_id) => {
                    let parent = durable.delegations.get(parent_id).ok_or_else(|| {
                        CoordinatorError::Refused(
                            "delegation parent is not durably admitted".to_string(),
                        )
                    })?;
                    if parent.revoked {
                        return Err(CoordinatorError::Refused(
                            "delegation parent is revoked".to_string(),
                        ));
                    }
                    let parent = self
                        .anchors()
                        .admit_expected(AdmissionKind::Delegation, parent.wire.clone())
                        .map_err(refusal)?;
                    if parent.signer() != &parent.payload().issuer
                        || current.issuer != parent.payload().subject
                        || !current.is_attenuation_of(parent.payload())
                    {
                        return Err(CoordinatorError::Refused(
                            "delegation does not attenuate a signed durable parent".to_string(),
                        ));
                    }
                    current = parent.into_payload();
                }
            }
        }
    }
}

fn confined(root: &Path, path: &Path) -> Result<PathBuf, CoordinatorError> {
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(CoordinatorError::Refused(
            "artifact source path escapes the installed workspace".to_string(),
        ));
    }
    Ok(root.join(path))
}

fn resolve_map<K: Ord>(
    root: &Path,
    paths: BTreeMap<K, PathBuf>,
) -> Result<BTreeMap<K, PathBuf>, CoordinatorError> {
    paths
        .into_iter()
        .map(|(key, path)| confined(root, &path).map(|path| (key, path)))
        .collect()
}

fn evidence_wire(
    record: &SignedRecord,
) -> Result<SignedAdmissionWire<EvidenceRequest>, CoordinatorError> {
    let wire: SignedAdmissionWire<EvidenceRequest> = serde_json::from_slice(record.payload())
        .map_err(|error| {
            CoordinatorError::Refused(format!("stored evidence wire is malformed: {error}"))
        })?;
    if wire.signer != *record.signer() || wire.signature != record.signature() {
        return Err(CoordinatorError::Refused(
            "stored evidence wire differs from its durable signature".to_string(),
        ));
    }
    Ok(wire)
}

fn stored_inputs(
    stored: &RuntimeGeneration,
) -> Result<SignedAdmissionWire<RuntimeGenerationInputs>, CoordinatorError> {
    let wire: SignedAdmissionWire<RuntimeGenerationInputs> =
        serde_json::from_slice(stored.manifest.payload()).map_err(|error| {
            CoordinatorError::Refused(format!("stored generation wire is malformed: {error}"))
        })?;
    if wire.signer != *stored.manifest.signer() || wire.signature != stored.manifest.signature() {
        return Err(CoordinatorError::Refused(
            "stored generation wire differs from its durable signature".to_string(),
        ));
    }
    Ok(wire)
}

fn signed_wire_record<T: serde::Serialize>(
    wire: &SignedAdmissionWire<T>,
) -> Result<SignedRecord, CoordinatorError> {
    let value = serde_json::to_value(wire).map_err(|error| {
        CoordinatorError::Refused(format!("signed wire encoding failed: {error}"))
    })?;
    SignedRecord::from_json(&value, wire.signer.clone(), wire.signature.clone())
        .map_err(storage_refusal)
}

fn refusal(error: impl std::fmt::Display) -> CoordinatorError {
    CoordinatorError::Refused(error.to_string())
}

fn storage_refusal(error: politeia_storage::StorageError) -> CoordinatorError {
    CoordinatorError::Refused(format!("durable authority refused operation: {error}"))
}

fn generation_input_digest(inputs: &RuntimeGenerationInputs) -> Result<Digest, CoordinatorError> {
    politeia_core::canonical::to_canonical_bytes(inputs)
        .map(|bytes| Digest::blake3(&bytes))
        .map_err(refusal)
}
