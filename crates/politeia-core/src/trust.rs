//! Authenticated admission at an institution's installed trust boundary.
//!
//! A signature proves only that an installed key made a statement.  It does
//! not make the signer an owner, a commissioner, or an independent evidence
//! producer.  Those semantic checks remain with the bounded consumer.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::canonical::{CanonicalError, to_canonical_bytes};
use crate::{InstitutionId, InstitutionWorkspaceId, PrincipalId};

/// The semantic statement class an installed principal may sign.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum AdmissionKind {
    /// A sourced observation presented to the institution.
    Observation,
    /// A provenance-bearing evidence record.
    Evidence,
    /// An owner approval of an institutional claim.
    FactApproval,
    /// A temporary commissioning grant.
    CommissionerGrant,
    /// A delegation whose semantic scope is resolved by its consumer.
    Delegation,
    /// A revocation of a previously admitted authority.
    Revocation,
    /// A scoped exception whose authority is resolved by its consumer.
    Waiver,
    /// A concrete control execution record.
    ControlRun,
    /// Evidence that an exact control was activated on its mediation path.
    ActivationProof,
    /// An independent verification statement.
    Verification,
    /// Inputs that identify an operational generation.
    Generation,
}

/// One public key installed by the institution, together with its narrow use.
#[derive(Clone, Debug)]
pub struct TrustedSigningKey {
    principal: PrincipalId,
    verifying_key: VerifyingKey,
    permitted: BTreeSet<AdmissionKind>,
}

impl TrustedSigningKey {
    /// Install an Ed25519 verification key for one principal's declared uses.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::MalformedKey`] for invalid key bytes or
    /// [`AdmissionError::EmptyPermissionSet`] when no admission is permitted.
    pub fn new(
        principal: PrincipalId,
        public_key: [u8; 32],
        permitted: BTreeSet<AdmissionKind>,
    ) -> Result<Self, AdmissionError> {
        if permitted.is_empty() {
            return Err(AdmissionError::EmptyPermissionSet);
        }
        let verifying_key =
            VerifyingKey::from_bytes(&public_key).map_err(|_| AdmissionError::MalformedKey)?;
        Ok(Self {
            principal,
            verifying_key,
            permitted,
        })
    }

    /// The principal whose signature this key can authenticate.
    pub fn principal(&self) -> &PrincipalId {
        &self.principal
    }
}

/// Installed institution and workspace trust anchors.
///
/// This is bootstrap configuration, not a wire type or a database record.
/// Its key material is deliberately not serializable; a received payload can
/// name a signer but cannot choose the key used to verify that name.
#[derive(Clone, Debug)]
pub struct InstitutionTrustAnchors {
    institution: InstitutionId,
    workspace: InstitutionWorkspaceId,
    keys: BTreeMap<PrincipalId, TrustedSigningKey>,
}

impl InstitutionTrustAnchors {
    /// Construct an exact installed-key snapshot for one workspace.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::DuplicatePrincipal`] when bootstrap provides
    /// multiple keys for one principal.
    pub fn from_trusted_bootstrap(
        institution: InstitutionId,
        workspace: InstitutionWorkspaceId,
        keys: impl IntoIterator<Item = TrustedSigningKey>,
    ) -> Result<Self, AdmissionError> {
        let mut installed = BTreeMap::new();
        for key in keys {
            if installed.insert(key.principal.clone(), key).is_some() {
                return Err(AdmissionError::DuplicatePrincipal);
            }
        }
        Ok(Self {
            institution,
            workspace,
            keys: installed,
        })
    }

    /// The institution whose statements these anchors can admit.
    pub fn institution(&self) -> &InstitutionId {
        &self.institution
    }

    /// The workspace whose statements these anchors can admit.
    pub fn workspace(&self) -> &InstitutionWorkspaceId {
        &self.workspace
    }

    /// Verify a received statement for one expected semantic use and scope.
    ///
    /// The expected kind is chosen by the consumer, never trusted from the
    /// received envelope.  A verified [`Admitted`] value is the only output
    /// that exposes its payload as authenticated.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] when scope, requested use, installed signer,
    /// canonical encoding, or signature verification fails.
    pub fn admit_expected<T: Serialize>(
        &self,
        expected: AdmissionKind,
        statement: SignedAdmissionWire<T>,
    ) -> Result<Admitted<T>, AdmissionError> {
        if statement.kind != expected {
            return Err(AdmissionError::UnexpectedKind {
                expected,
                found: statement.kind,
            });
        }
        if statement.institution != self.institution {
            return Err(AdmissionError::ForeignInstitution);
        }
        if statement.workspace != self.workspace {
            return Err(AdmissionError::ForeignWorkspace);
        }
        let installed = self
            .keys
            .get(&statement.signer)
            .ok_or(AdmissionError::UnknownSigner)?;
        if !installed.permitted.contains(&expected) {
            return Err(AdmissionError::UnauthorizedKind { expected });
        }
        let signature = Signature::from_slice(&statement.signature)
            .map_err(|_| AdmissionError::MalformedSignature)?;
        installed
            .verifying_key
            .verify(
                &statement_bytes(
                    statement.kind,
                    &statement.institution,
                    &statement.workspace,
                    &statement.signer,
                    &statement.payload,
                )?,
                &signature,
            )
            .map_err(|_| AdmissionError::InvalidSignature)?;

        Ok(Admitted {
            kind: expected,
            institution: self.institution.clone(),
            workspace: self.workspace.clone(),
            signer: statement.signer,
            payload: statement.payload,
        })
    }
}

/// An inert, received signed statement.
///
/// Deserialization produces this raw envelope only.  It must be passed to the
/// installed [`InstitutionTrustAnchors`] before its payload has authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedAdmissionWire<T> {
    /// Semantic statement class claimed by the sender.
    pub kind: AdmissionKind,
    /// Institution the sender claims this statement concerns.
    pub institution: InstitutionId,
    /// Workspace the sender claims this statement concerns.
    pub workspace: InstitutionWorkspaceId,
    /// Principal the sender claims signed the statement.
    pub signer: PrincipalId,
    /// Inert received payload.
    pub payload: T,
    /// Detached Ed25519 signature over canonical domain-separated bytes.
    pub signature: Vec<u8>,
}

impl<T: Serialize> SignedAdmissionWire<T> {
    /// Sign one exact statement for transport to its installed trust boundary.
    ///
    /// Signing does not admit the statement: even a locally produced envelope
    /// remains raw until a matching anchor verifies it.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::Encoding`] if the statement cannot be
    /// encoded canonically.
    pub fn sign(
        kind: AdmissionKind,
        institution: InstitutionId,
        workspace: InstitutionWorkspaceId,
        signer: PrincipalId,
        payload: T,
        key: &SigningKey,
    ) -> Result<Self, AdmissionError> {
        let signature = key
            .sign(&statement_bytes(
                kind,
                &institution,
                &workspace,
                &signer,
                &payload,
            )?)
            .to_bytes()
            .to_vec();
        Ok(Self {
            kind,
            institution,
            workspace,
            signer,
            payload,
            signature,
        })
    }
}

/// A payload authenticated by installed anchors for one exact use and scope.
#[derive(Clone, Debug)]
pub struct Admitted<T> {
    kind: AdmissionKind,
    institution: InstitutionId,
    workspace: InstitutionWorkspaceId,
    signer: PrincipalId,
    payload: T,
}

impl<T> Admitted<T> {
    /// The consumer-selected semantic statement class.
    pub fn kind(&self) -> AdmissionKind {
        self.kind
    }

    /// The installed institution scope.
    pub fn institution(&self) -> &InstitutionId {
        &self.institution
    }

    /// The installed workspace scope.
    pub fn workspace(&self) -> &InstitutionWorkspaceId {
        &self.workspace
    }

    /// The installed principal that signed this statement.
    pub fn signer(&self) -> &PrincipalId {
        &self.signer
    }

    /// The authenticated payload.
    pub fn payload(&self) -> &T {
        &self.payload
    }

    /// Consume the authenticated envelope and return its payload.
    pub fn into_payload(self) -> T {
        self.payload
    }
}

/// Why a statement could not cross the trust boundary.
#[derive(Debug)]
#[non_exhaustive]
pub enum AdmissionError {
    /// Bootstrap provided multiple keys for one principal.
    DuplicatePrincipal,
    /// A key was not a valid Ed25519 public key.
    MalformedKey,
    /// A key authorized no statement class.
    EmptyPermissionSet,
    /// The received institution differs from the installed scope.
    ForeignInstitution,
    /// The received workspace differs from the installed scope.
    ForeignWorkspace,
    /// The envelope's class differs from the consumer's expected class.
    UnexpectedKind {
        /// Class the consumer accepts here.
        expected: AdmissionKind,
        /// Class named by the received envelope.
        found: AdmissionKind,
    },
    /// No installed key belongs to the claimed signer.
    UnknownSigner,
    /// The installed signer is not permitted to sign this statement class.
    UnauthorizedKind {
        /// Class the signer attempted to use.
        expected: AdmissionKind,
    },
    /// The detached signature did not have Ed25519's exact length.
    MalformedSignature,
    /// The installed key did not verify the canonical statement bytes.
    InvalidSignature,
    /// The statement had no canonical representation.
    Encoding(CanonicalError),
}

impl std::fmt::Display for AdmissionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicatePrincipal => {
                formatter.write_str("duplicate installed signing principal")
            }
            Self::MalformedKey => formatter.write_str("installed Ed25519 key is malformed"),
            Self::EmptyPermissionSet => {
                formatter.write_str("installed signing key permits no admission class")
            }
            Self::ForeignInstitution => formatter.write_str("statement names another institution"),
            Self::ForeignWorkspace => formatter.write_str("statement names another workspace"),
            Self::UnexpectedKind { expected, found } => write!(
                formatter,
                "expected {expected:?} statement, received {found:?}"
            ),
            Self::UnknownSigner => formatter.write_str("statement signer is not installed"),
            Self::UnauthorizedKind { expected } => write!(
                formatter,
                "installed signer cannot admit {expected:?} statements"
            ),
            Self::MalformedSignature => formatter.write_str("Ed25519 signature is malformed"),
            Self::InvalidSignature => formatter.write_str("Ed25519 signature does not verify"),
            Self::Encoding(error) => write!(
                formatter,
                "statement cannot be canonically encoded: {error}"
            ),
        }
    }
}

impl std::error::Error for AdmissionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Encoding(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CanonicalError> for AdmissionError {
    fn from(error: CanonicalError) -> Self {
        Self::Encoding(error)
    }
}

#[derive(Serialize)]
struct SigningStatement<'a, T> {
    kind: &'static str,
    admission: AdmissionKind,
    institution: &'a InstitutionId,
    workspace: &'a InstitutionWorkspaceId,
    signer: &'a PrincipalId,
    payload: &'a T,
}

fn statement_bytes<T: Serialize>(
    kind: AdmissionKind,
    institution: &InstitutionId,
    workspace: &InstitutionWorkspaceId,
    signer: &PrincipalId,
    payload: &T,
) -> Result<Vec<u8>, AdmissionError> {
    Ok(to_canonical_bytes(&SigningStatement {
        kind: "politeia_signed_admission_v1",
        admission: kind,
        institution,
        workspace,
        signer,
        payload,
    })?)
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "fixed keys and canonical fixture statements must fail loudly when they drift"
    )]

    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn anchors(
        institution: InstitutionId,
        workspace: InstitutionWorkspaceId,
        principal: PrincipalId,
        key: &SigningKey,
    ) -> InstitutionTrustAnchors {
        InstitutionTrustAnchors::from_trusted_bootstrap(
            institution,
            workspace,
            [TrustedSigningKey::new(
                principal,
                key.verifying_key().to_bytes(),
                BTreeSet::from([AdmissionKind::FactApproval]),
            )
            .expect("fixture key is valid")],
        )
        .expect("fixture contains one principal")
    }

    #[test]
    fn only_installed_scope_and_expected_use_cross_the_boundary() {
        let institution = InstitutionId::new();
        let workspace = InstitutionWorkspaceId::new();
        let principal = PrincipalId::new();
        let signing = key(7);
        let anchors = anchors(
            institution.clone(),
            workspace.clone(),
            principal.clone(),
            &signing,
        );
        let wire = SignedAdmissionWire::sign(
            AdmissionKind::FactApproval,
            institution,
            workspace,
            principal,
            "accepted".to_string(),
            &signing,
        )
        .expect("fixture statement encodes");

        assert_eq!(
            anchors
                .admit_expected(AdmissionKind::FactApproval, wire)
                .expect("installed signer and exact scope verify")
                .payload(),
            "accepted"
        );
    }

    #[test]
    fn a_signature_for_another_scope_or_kind_is_not_repurposed() {
        let institution = InstitutionId::new();
        let workspace = InstitutionWorkspaceId::new();
        let principal = PrincipalId::new();
        let signing = key(9);
        let anchors = anchors(
            institution.clone(),
            workspace.clone(),
            principal.clone(),
            &signing,
        );
        let wire = SignedAdmissionWire::sign(
            AdmissionKind::FactApproval,
            institution,
            InstitutionWorkspaceId::new(),
            principal,
            "accepted".to_string(),
            &signing,
        )
        .expect("fixture statement encodes");
        assert!(matches!(
            anchors.admit_expected(AdmissionKind::FactApproval, wire),
            Err(AdmissionError::ForeignWorkspace)
        ));
    }

    #[test]
    fn a_valid_signature_does_not_grant_an_uninstalled_permission() {
        let institution = InstitutionId::new();
        let workspace = InstitutionWorkspaceId::new();
        let principal = PrincipalId::new();
        let signing = key(11);
        let anchors = anchors(
            institution.clone(),
            workspace.clone(),
            principal.clone(),
            &signing,
        );
        let wire = SignedAdmissionWire::sign(
            AdmissionKind::Evidence,
            institution,
            workspace,
            principal,
            "evidence".to_string(),
            &signing,
        )
        .expect("fixture statement encodes");
        assert!(matches!(
            anchors.admit_expected(AdmissionKind::Evidence, wire),
            Err(AdmissionError::UnauthorizedKind { .. })
        ));
    }
}
