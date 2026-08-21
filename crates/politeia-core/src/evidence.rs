//! Canonical evidence records and trusted admission boundaries.

use std::collections::BTreeMap;

use jiff::Timestamp;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::canonical::CanonicalError;
use crate::{DelegationId, Digest, DigestDomain, EvidenceId, PrincipalId};

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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
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

/// Exact evidence records already admitted by the institution's trusted store.
///
/// Constructing this value is a host-bootstrap authority action. Consumers
/// resolve exact records from it; they never treat a bare evidence identifier
/// or caller-authored subject as proof.
#[derive(Clone, Debug, Default)]
pub struct TrustedEvidenceRegistry {
    records: BTreeMap<EvidenceId, EvidenceRecord>,
}

impl TrustedEvidenceRegistry {
    /// Admit exact records supplied by the trusted host bootstrap.
    ///
    /// # Errors
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
        Ok(Self { records: registry })
    }

    /// Resolve one exact admitted record by identity.
    pub fn resolve(&self, id: &EvidenceId) -> Option<&EvidenceRecord> {
        self.records.get(id)
    }
}

/// A trusted evidence registry contained duplicate identities.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EvidenceRegistryError {
    /// One evidence identity appeared more than once.
    DuplicateIdentity,
}

impl std::fmt::Display for EvidenceRegistryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("duplicate evidence identity in trusted registry")
    }
}

impl std::error::Error for EvidenceRegistryError {}
