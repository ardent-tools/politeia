//! Canonical evidence records and trusted admission boundaries.

use std::collections::BTreeMap;

use jiff::Timestamp;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::canonical::CanonicalError;
use crate::trust::{AdmissionError, AdmissionKind, InstitutionTrustAnchors, SignedAdmissionWire};
use crate::{
    DelegationId, Digest, DigestDomain, EvidenceId, InstitutionId, InstitutionWorkspaceId,
    PrincipalId,
};

/// How independent the evidence producer is from the actor being judged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum IndependenceClass {
    /// The actor reports on itself (weakest; never satisfies an
    /// independent-verification obligation).
    SelfReported,
    /// Same actor, separate process.
    SameActorDifferentProcess,
    /// A different agent produced the evidence.
    IndependentAgent,
    /// A separate service produced the evidence.
    IndependentService,
    /// A human authority produced or approved the evidence.
    HumanAuthority,
}

/// A provenance-bearing evidence record admitted for an exact subject.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
pub struct EvidenceRecord {
    /// This record's identity.
    pub id: EvidenceId,
    /// Digest of the exact subject the evidence is about.
    pub subject: Digest,
    /// The principal that produced the evidence.
    pub producer: PrincipalId,
    /// Exact delegation under which the producer emitted the record.
    pub producer_delegation: DelegationId,
    /// The collection method (how the evidence was produced).
    pub method: String,
    /// Digest of the evidence payload.
    pub payload_digest: Digest,
    /// Trusted observation time assigned by the admitting evidence store.
    pub observed_at: Timestamp,
    /// The producer's independence from the actor being judged.
    pub independence: IndependenceClass,
}

/// Inert received evidence data before installed-key admission.
///
/// The sender cannot choose the resulting [`EvidenceRecord::producer`]: the
/// trusted registry derives it from the verified signer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRequest {
    /// Stable identity of the evidence record.
    pub id: EvidenceId,
    /// Digest of the exact subject the evidence concerns.
    pub subject: Digest,
    /// Delegation under which the authenticated producer emitted it.
    pub producer_delegation: DelegationId,
    /// Collection method.
    pub method: String,
    /// Digest of the payload retained in the institution's evidence store.
    pub payload_digest: Digest,
    /// Observation time asserted by the signed producer.
    pub observed_at: Timestamp,
    /// Claimed independence class; consumers must independently resolve any
    /// required verifier authority rather than trusting this label alone.
    pub independence: IndependenceClass,
}

impl EvidenceRecord {
    /// Digest the full admitted evidence record.
    ///
    /// # Errors
    ///
    /// Returns the JSON encoding failure if the record cannot be represented.
    pub fn digest(&self) -> Result<Digest, CanonicalError> {
        Digest::of(DigestDomain::EvidenceRecord, self)
    }
}

/// Exact evidence records already admitted by the institution's trusted host.
///
/// Constructing this value is a host-bootstrap authority action: the host
/// restores an already authenticated, integrity-protected evidence snapshot
/// from its institution-controlled store. It is not a received-wire API.
/// Consumers resolve exact records from it; they never treat a bare evidence
/// identifier or caller-authored subject as proof. New received evidence must
/// cross a signed admission boundary before host code can include it here.
#[derive(Clone, Debug, Default)]
pub struct TrustedEvidenceRegistry {
    institution: Option<InstitutionId>,
    workspace: Option<InstitutionWorkspaceId>,
    records: BTreeMap<EvidenceId, EvidenceRecord>,
}

impl TrustedEvidenceRegistry {
    /// Admit received evidence statements signed by installed principals.
    ///
    /// The anchors select the exact institution/workspace scope and resolve
    /// the verification key. The evidence producer is derived from the
    /// verified signer; a wire payload cannot label another principal as its
    /// producer. Permission to submit `Evidence` only controls admission
    /// ingress, not whether the producer satisfies an assurance obligation.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceAdmissionError`] when authentication fails or record
    /// identities repeat in this exact admitted snapshot.
    pub fn admit_signed(
        anchors: &InstitutionTrustAnchors,
        statements: impl IntoIterator<Item = SignedAdmissionWire<EvidenceRequest>>,
    ) -> Result<Self, EvidenceAdmissionError> {
        let mut registry = BTreeMap::new();
        for statement in statements {
            let admitted = anchors
                .admit_expected(AdmissionKind::Evidence, statement)
                .map_err(EvidenceAdmissionError::Authentication)?;
            let request = admitted.payload();
            let record = EvidenceRecord {
                id: request.id.clone(),
                subject: request.subject.clone(),
                producer: admitted.signer().clone(),
                producer_delegation: request.producer_delegation.clone(),
                method: request.method.clone(),
                payload_digest: request.payload_digest.clone(),
                observed_at: request.observed_at,
                independence: request.independence.clone(),
            };
            if registry.insert(record.id.clone(), record).is_some() {
                return Err(EvidenceAdmissionError::DuplicateIdentity);
            }
        }
        Ok(Self {
            institution: Some(anchors.institution().clone()),
            workspace: Some(anchors.workspace().clone()),
            records: registry,
        })
    }

    /// Restore exact records supplied by the trusted host bootstrap.
    ///
    /// # Errors
    ///
    /// The caller is the installed host recovery path, not a transport adapter.
    /// `EvidenceRecord` deliberately has no deserializer, so wire input cannot
    /// manufacture this admitted value before reaching that boundary.
    ///
    /// Returns [`EvidenceRegistryError`] when the iterator repeats an identity.
    ///
    /// Time: O(n log n). Space: O(n), where n is the admitted record count.
    pub fn from_trusted_bootstrap(
        records: impl IntoIterator<Item = EvidenceRecord>,
    ) -> Result<Self, EvidenceRegistryError> {
        let mut registry = BTreeMap::new();
        for record in records {
            if registry.insert(record.id.clone(), record).is_some() {
                return Err(EvidenceRegistryError::DuplicateIdentity);
            }
        }
        Ok(Self {
            institution: None,
            workspace: None,
            records: registry,
        })
    }

    /// Resolve one exact admitted record by identity.
    pub fn resolve(&self, id: &EvidenceId) -> Option<&EvidenceRecord> {
        self.records.get(id)
    }

    /// The installed institution scope of signed admission, if any.
    pub(crate) fn institution(&self) -> Option<&InstitutionId> {
        self.institution.as_ref()
    }

    /// The installed workspace scope of signed admission, if any.
    pub(crate) fn workspace(&self) -> Option<&InstitutionWorkspaceId> {
        self.workspace.as_ref()
    }
}

/// A trusted evidence registry contained duplicate identities.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EvidenceRegistryError {
    /// One evidence identity appeared more than once.
    DuplicateIdentity,
}

/// Why received evidence did not become an admitted registry record.
#[derive(Debug)]
#[non_exhaustive]
pub enum EvidenceAdmissionError {
    /// Installed-key or exact-scope verification failed.
    Authentication(AdmissionError),
    /// More than one signed statement used one evidence identity.
    DuplicateIdentity,
}

impl std::fmt::Display for EvidenceAdmissionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Authentication(error) => {
                write!(formatter, "evidence authentication failed: {error}")
            }
            Self::DuplicateIdentity => formatter.write_str("signed evidence repeats an identity"),
        }
    }
}

impl std::error::Error for EvidenceAdmissionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Authentication(error) => Some(error),
            Self::DuplicateIdentity => None,
        }
    }
}

impl std::fmt::Display for EvidenceRegistryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("duplicate evidence identity in trusted registry")
    }
}

impl std::error::Error for EvidenceRegistryError {}
