//! politeia-protocol: the transport-independent semantic protocol envelope.
//!
//! MCP, A2A, HTTP/gRPC, CLI, and embedded use are transports over the same
//! operation model. No transport may reinterpret semantic operation meaning.

#![deny(missing_docs)]

use politeia_core::PrincipalId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The semantic protocol major version this crate speaks.
pub const SEMANTIC_PROTOCOL_MAJOR: u16 = 1;
/// The semantic protocol minor version this crate speaks.
pub const SEMANTIC_PROTOCOL_MINOR: u16 = 0;

/// A protocol version (major.minor).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProtocolVersion {
    /// Major version; peers must match.
    pub major: u16,
    /// Backwards-compatible feature level negotiated down within one major.
    pub minor: u16,
}

/// The semantic protocol version implemented by this crate.
pub const CURRENT_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion {
    major: SEMANTIC_PROTOCOL_MAJOR,
    minor: SEMANTIC_PROTOCOL_MINOR,
};

/// A fail-closed compatibility requirement declared by an extension or peer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProtocolRequirement {
    /// Required protocol major version.
    pub major: u16,
    /// Oldest protocol minor version that satisfies the requirement.
    pub minimum_minor: u16,
}

impl ProtocolRequirement {
    /// True when `version` has the required major and a sufficient minor.
    pub fn is_satisfied_by(&self, version: &ProtocolVersion) -> bool {
        version.major == self.major && version.minor >= self.minimum_minor
    }
}

/// A semantic request envelope.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SemanticRequest {
    /// The protocol version the caller speaks.
    pub version: ProtocolVersion,
    /// The principal issuing the request.
    pub principal: PrincipalId,
    /// The semantic operation name (see docs/05-SEMANTIC_PROTOCOL.md).
    pub operation: String,
    /// The operation payload.
    pub payload: serde_json::Value,
}

/// A semantic response envelope.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SemanticResponse {
    /// The negotiated protocol version.
    pub version: ProtocolVersion,
    /// The operation result.
    pub result: serde_json::Value,
    /// References to evidence produced while serving the request.
    pub evidence_refs: Vec<String>,
}

/// Negotiate a protocol version with a peer.
///
/// The peers must speak the same major version. Within that major, the result
/// is the lower feature level so neither side claims support it does not have.
pub fn negotiate(peer: &ProtocolVersion) -> Option<ProtocolVersion> {
    negotiate_against(&CURRENT_PROTOCOL_VERSION, peer)
}

fn negotiate_against(local: &ProtocolVersion, peer: &ProtocolVersion) -> Option<ProtocolVersion> {
    (peer.major == local.major).then_some(ProtocolVersion {
        major: local.major,
        minor: local.minor.min(peer.minor),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compatibility_requires_exact_major_and_sufficient_minor() {
        let current = ProtocolRequirement {
            major: SEMANTIC_PROTOCOL_MAJOR,
            minimum_minor: SEMANTIC_PROTOCOL_MINOR,
        };
        assert!(
            current.is_satisfied_by(&CURRENT_PROTOCOL_VERSION),
            "the current protocol must satisfy its own requirement"
        );

        let future_major = ProtocolRequirement {
            major: SEMANTIC_PROTOCOL_MAJOR + 1,
            minimum_minor: 0,
        };
        assert!(
            !future_major.is_satisfied_by(&CURRENT_PROTOCOL_VERSION),
            "a different protocol major must fail closed"
        );

        let future_minor = ProtocolRequirement {
            major: SEMANTIC_PROTOCOL_MAJOR,
            minimum_minor: SEMANTIC_PROTOCOL_MINOR + 1,
        };
        assert!(
            !future_minor.is_satisfied_by(&CURRENT_PROTOCOL_VERSION),
            "an unavailable protocol minor must fail closed"
        );
    }

    #[test]
    fn protocol_requirement_rejects_unknown_fields() {
        let encoded = serde_json::json!({
            "major": SEMANTIC_PROTOCOL_MAJOR,
            "minimum_minor": SEMANTIC_PROTOCOL_MINOR,
            "ambient_compatibility": true,
        });
        let result = serde_json::from_value::<ProtocolRequirement>(encoded);
        assert!(
            result.is_err(),
            "unknown compatibility fields must fail closed"
        );
    }

    #[test]
    fn negotiation_selects_the_lower_same_major_feature_level() {
        let local = ProtocolVersion { major: 1, minor: 3 };

        assert_eq!(
            negotiate_against(&local, &ProtocolVersion { major: 1, minor: 1 }),
            Some(ProtocolVersion { major: 1, minor: 1 }),
            "an older peer must negotiate to the peer's feature level"
        );
        assert_eq!(
            negotiate_against(&local, &ProtocolVersion { major: 1, minor: 3 }),
            Some(local.clone()),
            "equal feature levels must remain unchanged"
        );
        assert_eq!(
            negotiate_against(&local, &ProtocolVersion { major: 1, minor: 5 }),
            Some(local),
            "a newer peer must negotiate down to the local feature level"
        );
        assert_eq!(
            negotiate_against(
                &ProtocolVersion { major: 1, minor: 3 },
                &ProtocolVersion { major: 2, minor: 0 },
            ),
            None,
            "a major mismatch must fail closed"
        );
    }
}
