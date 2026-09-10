//! Synthetic, process-bound inputs for the commissioning-package acceptance test.
//!
//! This module deliberately returns inert host configuration, files, and
//! signing identities. It never creates a service, coordinator, dispatcher, or
//! storage handle, so the acceptance test must cross the installed daemon's
//! Unix socket for every semantic transition.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use ed25519_dalek::SigningKey;
use jiff::{SignedDuration, Timestamp};
use politeia_core::{
    AdapterId, DataClass, Delegation, DelegationId, Digest, Effect, InstitutionId,
    InstitutionWorkspaceId, PolicyBundleId, PrincipalId, ResourceBudget,
    generation::{ApprovedGenerationInputs, ReproducibilityContract},
    institution::{InstitutionWorkspace, TrustDomainId},
    lifecycle::{DeploymentTopology, LifecycleProfile},
    reconnaissance::RECONNOITRE_ACTION,
    trust::{AdmissionKind, SignedAdmissionWire, WorkspaceBootstrapRequest},
};
use politeiad::config::{HostTrustConfiguration, InstalledTrustAnchor};

/// The two intentionally disjoint reference institutions exercised by the package.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ReferenceInstitutionKind {
    /// A synthetic software-development institution.
    SoftwareDevelopment,
    /// A synthetic analytics institution.
    Analytics,
}

impl ReferenceInstitutionKind {
    /// Stable public fixture directory name.
    pub(crate) const fn directory(self) -> &'static str {
        match self {
            Self::SoftwareDevelopment => "software-development",
            Self::Analytics => "analytics",
        }
    }

    /// A compact filesystem label that keeps the Unix socket beneath its length limit.
    const fn short_label(self) -> &'static str {
        match self {
            Self::SoftwareDevelopment => "software",
            Self::Analytics => "analytics",
        }
    }

    /// A distinct trust-domain label for the synthetic institution.
    fn trust_domain(self) -> &'static str {
        match self {
            Self::SoftwareDevelopment => "reference.software-development.local",
            Self::Analytics => "reference.analytics.local",
        }
    }
}

/// Four separate identities installed into one reference institution.
pub(crate) struct SigningIdentities {
    /// Institutional owner who may approve exact constitutional subjects.
    pub(crate) owner: PrincipalId,
    /// Temporary commissioning identity.
    pub(crate) commissioner: PrincipalId,
    /// Operational canary identity.
    pub(crate) worker: PrincipalId,
    /// Independent verification identity.
    pub(crate) verifier: PrincipalId,
    /// Fresh handoff identity, deliberately distinct from the commissioner.
    pub(crate) replacement: PrincipalId,
    owner_key: SigningKey,
    commissioner_key: SigningKey,
    worker_key: SigningKey,
    verifier_key: SigningKey,
    replacement_key: SigningKey,
}

impl SigningIdentities {
    /// Return the owner signing key only to construct a raw signed document.
    pub(crate) fn owner_key(&self) -> &SigningKey {
        &self.owner_key
    }

    /// Return the commissioner signing key only to construct a raw signed document.
    pub(crate) fn commissioner_key(&self) -> &SigningKey {
        &self.commissioner_key
    }

    /// Return the worker signing key only to construct a raw signed document.
    pub(crate) fn worker_key(&self) -> &SigningKey {
        &self.worker_key
    }

    /// Return the verifier signing key only to construct a raw signed document.
    pub(crate) fn verifier_key(&self) -> &SigningKey {
        &self.verifier_key
    }

    /// Return the replacement signing key only to construct a raw signed document.
    pub(crate) fn replacement_key(&self) -> &SigningKey {
        &self.replacement_key
    }
}

/// One installed fixture with real public source member files copied into a private test root.
pub(crate) struct ReferenceFixture {
    /// Which public reference corpus supplies the source facts.
    pub(crate) kind: ReferenceInstitutionKind,
    /// Institution-owned temporary root used as a process prefix and source root.
    pub(crate) root: PathBuf,
    /// Actual checked-in synthetic source document copied into the source root.
    pub(crate) source_document: PathBuf,
    /// Inert host configuration passed to `politeiad initialize`.
    pub(crate) host_trust: HostTrustConfiguration,
    /// Separate signing material retained by the test process, never written to the host config.
    pub(crate) identities: SigningIdentities,
}

impl ReferenceFixture {
    /// Create one synthetic institution fixture under a fresh temporary directory.
    ///
    /// The approved generation binds the exact source, schema, migration, and
    /// public metadata files materialized by the acceptance test. This helper
    /// only lays out the disjoint identity and installation boundary.
    #[expect(
        clippy::expect_used,
        reason = "the acceptance fixture must fail loudly when public test inputs are absent"
    )]
    pub(crate) fn new(kind: ReferenceInstitutionKind) -> Self {
        let root = std::env::temp_dir().join(format!(
            "plp-{}-{}",
            kind.short_label(),
            uuid::Uuid::now_v7()
        ));
        fs::create_dir(&root).expect("fresh package fixture root creates");
        let source_root = root.join("selected-public-source");
        fs::create_dir(&source_root).expect("selected source root creates");
        let source_document = source_root.join("institution.md");
        fs::copy(
            repository_root()
                .join("examples/reference-institutions")
                .join(kind.directory())
                .join("README.md"),
            &source_document,
        )
        .expect("public synthetic fixture source copies");

        let identities = SigningIdentities {
            owner: PrincipalId::new(),
            commissioner: PrincipalId::new(),
            worker: PrincipalId::new(),
            verifier: PrincipalId::new(),
            replacement: PrincipalId::new(),
            owner_key: SigningKey::from_bytes(&[0x11; 32]),
            commissioner_key: SigningKey::from_bytes(&[0x22; 32]),
            worker_key: SigningKey::from_bytes(&[0x33; 32]),
            verifier_key: SigningKey::from_bytes(&[0x44; 32]),
            replacement_key: SigningKey::from_bytes(&[0x55; 32]),
        };
        let institution = InstitutionId::new();
        let workspace_id = InstitutionWorkspaceId::new();
        let approved_generation = ApprovedGenerationInputs {
            source_digest: Digest::blake3(
                &fs::read(&source_document).expect("copied source is readable"),
            ),
            lifecycle: LifecycleProfile::Commissioning,
            topology: DeploymentTopology::ClientControlledSingleTenant,
            schema_digests: BTreeMap::from([(
                "public-contract".to_owned(),
                Digest::blake3(
                    &fs::read(repository_root().join("spec/semantic-operation.schema.json"))
                        .expect("public protocol schema is readable"),
                ),
            )]),
            adapter_digests: BTreeMap::from([(
                AdapterId::new(),
                Digest::blake3(
                    &fs::read(repository_root().join("crates/politeiad/src/source.rs"))
                        .expect("public source adapter is readable"),
                ),
            )]),
            pack_digests: BTreeMap::from([(
                "reference-institution".to_owned(),
                Digest::blake3(&fs::read(&source_document).expect("source remains readable")),
            )]),
            component_digests: BTreeMap::new(),
            excluded_commissioning_capabilities: BTreeSet::new(),
            specializer_digest: Digest::blake3(
                &fs::read(repository_root().join("crates/politeiad/src/artifacts.rs"))
                    .expect("public artifact specializer is readable"),
            ),
            toolchain_digest: Digest::blake3(
                &fs::read(repository_root().join("rust-toolchain.toml"))
                    .expect("public toolchain declaration is readable"),
            ),
            reproducibility: ReproducibilityContract::Deterministic,
        };
        let workspace = InstitutionWorkspace {
            id: workspace_id,
            institution,
            trust_domain: kind
                .trust_domain()
                .parse::<TrustDomainId>()
                .expect("fixture trust domain is canonical"),
            owner: identities.owner.clone(),
            owner_delegation: DelegationId::new(),
            approved_model_digest: Digest::blake3(b"synthetic broad institutional model"),
            policy_bundle: PolicyBundleId::new(),
            policy_digest: Digest::blake3(b"synthetic owner-approved policy"),
            approved_generation,
            secret_references: BTreeSet::new(),
        };
        let anchors = vec![
            anchor(
                &identities.owner,
                identities.owner_key(),
                [
                    AdmissionKind::WorkspaceBootstrap,
                    AdmissionKind::FactApproval,
                    AdmissionKind::Delegation,
                    AdmissionKind::Generation,
                    AdmissionKind::Revocation,
                ],
            ),
            anchor(
                &identities.commissioner,
                identities.commissioner_key(),
                [
                    AdmissionKind::SourceCapture,
                    AdmissionKind::Evidence,
                    AdmissionKind::Observation,
                    AdmissionKind::Delegation,
                ],
            ),
            anchor(
                &identities.worker,
                identities.worker_key(),
                [AdmissionKind::Delegation],
            ),
            anchor(
                &identities.verifier,
                identities.verifier_key(),
                [AdmissionKind::Verification],
            ),
            anchor(
                &identities.replacement,
                identities.replacement_key(),
                [AdmissionKind::Delegation, AdmissionKind::Generation],
            ),
        ];
        let bootstrap = SignedAdmissionWire::sign(
            AdmissionKind::WorkspaceBootstrap,
            workspace.institution.clone(),
            workspace.id.clone(),
            workspace.owner.clone(),
            WorkspaceBootstrapRequest {
                workspace: workspace.clone(),
            },
            identities.owner_key(),
        )
        .expect("owner signs matching workspace bootstrap");
        Self {
            kind,
            root,
            source_document,
            host_trust: HostTrustConfiguration {
                workspace,
                anchors,
                bootstrap,
            },
            identities,
        }
    }

    /// Return this installation's private prefix.
    pub(crate) fn prefix(&self) -> PathBuf {
        self.root.join("installation")
    }

    /// Produce the temporary, read-only delegation required before source capture.
    pub(crate) fn commissioner_delegation(&self) -> Delegation {
        Delegation {
            id: DelegationId::new(),
            issuer: self.identities.owner.clone(),
            subject: self.identities.commissioner.clone(),
            parent: None,
            actions: BTreeSet::from([RECONNOITRE_ACTION.to_owned()]),
            resources: BTreeSet::from([format!("reference:{}:source", self.kind.directory())]),
            effects: BTreeSet::from([Effect::ReadExternalSystem]),
            data_classes: BTreeSet::from([DataClass::Internal]),
            audience: BTreeSet::from(["commissioning".to_owned()]),
            expires_at: Timestamp::now() + SignedDuration::from_hours(1),
            budget: ResourceBudget {
                wall_ms: Some(60_000),
                cpu_ms: Some(10_000),
                memory_bytes: Some(64 * 1024 * 1024),
                io_bytes: Some(1024 * 1024),
                network_bytes: Some(1024 * 1024),
                external_cost_microunits: Some(0),
            },
        }
    }

    /// Sign the temporary delegation as raw input to the commissioning socket operation.
    pub(crate) fn signed_commissioner_delegation(
        &self,
        delegation: Delegation,
    ) -> SignedAdmissionWire<Delegation> {
        SignedAdmissionWire::sign(
            AdmissionKind::Delegation,
            self.host_trust.workspace.institution.clone(),
            self.host_trust.workspace.id.clone(),
            self.identities.owner.clone(),
            delegation,
            self.identities.owner_key(),
        )
        .expect("owner signs temporary commissioner delegation")
    }

    /// Write inert installed public-key configuration for the administrative CLI.
    pub(crate) fn write_host_trust(&self) -> PathBuf {
        let path = self.root.join("host-trust.json");
        fs::write(
            &path,
            serde_json::to_vec_pretty(&self.host_trust)
                .expect("host trust configuration serializes"),
        )
        .expect("host trust configuration writes");
        path
    }
}

impl Drop for ReferenceFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn anchor(
    principal: &PrincipalId,
    key: &SigningKey,
    permitted: impl IntoIterator<Item = AdmissionKind>,
) -> InstalledTrustAnchor {
    InstalledTrustAnchor {
        principal: principal.clone(),
        public_key: key.verifying_key().to_bytes(),
        permitted: permitted.into_iter().collect(),
    }
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("politeiad manifest is nested below repository root")
        .to_path_buf()
}
