//! The outbox: where institution material leaves, and what has to be true first.
//!
//! `docs/16-DATA_GOVERNANCE.md` sets two requirements that shape everything
//! here. One is what a crossing has to record:
//!
//! > Every allowed or denied boundary crossing records purpose, source,
//! > transformation, sink, locality, retention/deletion policy, execution
//! > resource, routing decision, and authority.
//!
//! The other is what happens when something is not known:
//!
//! > An unknown sink, locality, purpose, retention rule, or institution
//! > boundary fails closed.
//!
//! WHY a denial produces a record too, and not just a refusal: the same
//! document says the product must be able to answer *which classified data was
//! allowed **or denied** at which boundary, under what authority, for what
//! purpose*. A boundary that logs only what it let through cannot answer the
//! second half, and its log looks complete either way -- every entry in it is
//! true, and the absent ones are the interesting ones. [`adjudicate`] therefore
//! returns an [`Adjudication`] rather than a `Result`: the record exists in
//! both outcomes and the decision is a field on it.

use std::collections::{BTreeMap, BTreeSet};

use jiff::Timestamp;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    DataClass, DelegationId, Digest, ExecutionLocality, ExecutionResourceId,
    InstitutionWorkspaceId, PrincipalId, RoutingDecisionId,
};

/// A class of destination that data can reach.
///
/// These are the sinks `docs/16-DATA_GOVERNANCE.md` names. The list is closed
/// because a destination nobody has classified is an unknown sink, and an
/// unknown sink fails closed rather than acquiring a default class.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum SinkKind {
    /// Context made visible to an agent.
    AgentContext,
    /// Output returned from a tool.
    ToolOutput,
    /// An operational log.
    Log,
    /// A telemetry stream.
    Telemetry,
    /// A model runtime inside the client's control.
    ClientLocalModelRuntime,
    /// A remote inference provider.
    ///
    /// Each provider is a distinct sink, which is why a sink carries an
    /// identity as well as a kind.
    RemoteInferenceProvider,
    /// Any other external system.
    ExternalSystem,
}

/// One destination the workspace has classified.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Sink {
    /// What kind of destination it is.
    pub kind: SinkKind,
    /// Which one, as the institution names it.
    pub identity: String,
    /// Where it sits relative to the client trust domain.
    pub locality: ExecutionLocality,
}

/// What one workspace has declared about its own boundary.
///
/// Everything not named here is unknown, and unknown fails closed. That is the
/// whole reason this is a declaration rather than a set of defaults: a default
/// is an answer nobody gave.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeclaredBoundary {
    /// The workspace this boundary belongs to.
    pub workspace: InstitutionWorkspaceId,
    /// Classified destinations, by identity.
    pub sinks: BTreeMap<String, Sink>,
    /// Purposes the institution has approved.
    pub purposes: BTreeSet<String>,
    /// Retention rules the institution has approved, by name.
    ///
    /// Names rather than a modelled policy: `docs/16-DATA_GOVERNANCE.md`
    /// requires a crossing to record its retention/deletion policy and does not
    /// enumerate the policies, and `docs/03-ONTOLOGY.md` forbids minting a
    /// second concept for semantics that already live somewhere. What this
    /// enforces is that the rule was *declared*, which is the part that fails
    /// closed.
    pub retention_rules: BTreeSet<String>,
    /// Data classes explicitly authorized to reach commissioner-controlled
    /// infrastructure.
    ///
    /// Empty by default, because the document is explicit that secret values,
    /// private facts, operational logs, evidence and prompts *do not move to a
    /// commissioner-controlled machine by default*. "By default" is a statement
    /// about what happens when nobody decided, so the field that records the
    /// decision starts empty.
    pub commissioner_export: BTreeSet<DataClass>,
}

/// One attempt to move material across the boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoundaryCrossing {
    /// The workspace whose material is moving.
    pub workspace: InstitutionWorkspaceId,
    /// Why it is moving.
    pub purpose: String,
    /// Where it came from.
    pub source: String,
    /// What was done to it on the way.
    pub transformation: String,
    /// The destination, by identity.
    pub sink: String,
    /// What is moving.
    pub data_classes: BTreeSet<DataClass>,
    /// The retention rule that will govern it.
    pub retention_rule: String,
    /// The execution resource involved, where one was.
    pub execution_resource: Option<ExecutionResourceId>,
    /// The routing decision that selected it, where one did.
    pub routing_decision: Option<RoutingDecisionId>,
    /// The principal answering for the crossing.
    pub authority: PrincipalId,
    /// The exact delegation carrying that authority.
    pub authority_delegation: DelegationId,
    /// Digest of the exact material.
    pub subject: Digest,
    /// When it was attempted.
    pub at: Timestamp,
}

/// Why a crossing was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum DenialReason {
    /// The material belongs to another workspace.
    ForeignWorkspace,
    /// The destination is not one this workspace has classified.
    UnknownSink {
        /// The destination named.
        sink: String,
    },
    /// The purpose is not one this institution has approved.
    UnknownPurpose {
        /// The purpose named.
        purpose: String,
    },
    /// The retention rule is not one this institution has approved.
    UnknownRetentionRule {
        /// The rule named.
        rule: String,
    },
    /// Material moving to commissioner-controlled infrastructure that nobody
    /// authorized to go there.
    UnauthorizedCommissionerExport {
        /// The classes without an export authorization.
        classes: BTreeSet<DataClass>,
    },
}

impl std::fmt::Display for DenialReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DenialReason::ForeignWorkspace => {
                formatter.write_str("the material belongs to another workspace")
            }
            DenialReason::UnknownSink { sink } => {
                write!(formatter, "sink {sink} is not classified by this workspace")
            }
            DenialReason::UnknownPurpose { purpose } => {
                write!(formatter, "purpose {purpose} is not approved")
            }
            DenialReason::UnknownRetentionRule { rule } => {
                write!(formatter, "retention rule {rule} is not approved")
            }
            DenialReason::UnauthorizedCommissionerExport { classes } => write!(
                formatter,
                "{classes:?} are not authorized to reach commissioner-controlled infrastructure"
            ),
        }
    }
}

/// What was decided, and the record of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Adjudication {
    /// The crossing exactly as attempted.
    pub crossing: BoundaryCrossing,
    /// Why it was refused, if it was.
    ///
    /// `None` is the allowed case. Reading the decision off the reason rather
    /// than off a separate boolean means the two cannot disagree.
    pub denied: Option<DenialReason>,
}

impl Adjudication {
    /// Whether the crossing was permitted.
    pub fn allowed(&self) -> bool {
        self.denied.is_none()
    }
}

/// Decide one crossing, and record it either way.
///
/// Never returns a `Result`: a refusal is an outcome to be recorded, not an
/// error to be propagated and possibly swallowed. The caller that ignores the
/// returned [`Adjudication`] has dropped an audit record, which is a different
/// and more visible mistake than ignoring an error.
///
/// Time: O(c log c) for c data classes. Space: O(c).
pub fn adjudicate(boundary: &DeclaredBoundary, crossing: &BoundaryCrossing) -> Adjudication {
    let record = |denied| Adjudication {
        crossing: crossing.clone(),
        denied,
    };

    if crossing.workspace != boundary.workspace {
        return record(Some(DenialReason::ForeignWorkspace));
    }
    let Some(sink) = boundary.sinks.get(&crossing.sink) else {
        return record(Some(DenialReason::UnknownSink {
            sink: crossing.sink.clone(),
        }));
    };
    if !boundary.purposes.contains(&crossing.purpose) {
        return record(Some(DenialReason::UnknownPurpose {
            purpose: crossing.purpose.clone(),
        }));
    }
    if !boundary.retention_rules.contains(&crossing.retention_rule) {
        return record(Some(DenialReason::UnknownRetentionRule {
            rule: crossing.retention_rule.clone(),
        }));
    }

    if sink.locality == ExecutionLocality::CommissionerLocal {
        let unauthorized: BTreeSet<DataClass> = crossing
            .data_classes
            .iter()
            .filter(|class| {
                **class != DataClass::Public && !boundary.commissioner_export.contains(class)
            })
            .cloned()
            .collect();
        if !unauthorized.is_empty() {
            return record(Some(DenialReason::UnauthorizedCommissionerExport {
                classes: unauthorized,
            }));
        }
    }

    record(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[expect(
        clippy::expect_used,
        reason = "a fixture whose fixed timestamp cannot parse is a broken test, not a finding"
    )]
    fn now() -> Timestamp {
        "2026-08-21T00:00:00Z"
            .parse()
            .expect("the fixture timestamp is valid RFC 3339")
    }

    const PROVIDER: &str = "inference:acme";
    const COMMISSIONER: &str = "workstation:commissioner";

    fn boundary() -> DeclaredBoundary {
        DeclaredBoundary {
            workspace: InstitutionWorkspaceId::new(),
            sinks: BTreeMap::from([
                (
                    PROVIDER.to_string(),
                    Sink {
                        kind: SinkKind::RemoteInferenceProvider,
                        identity: PROVIDER.to_string(),
                        locality: ExecutionLocality::ProviderRemote,
                    },
                ),
                (
                    COMMISSIONER.to_string(),
                    Sink {
                        kind: SinkKind::ExternalSystem,
                        identity: COMMISSIONER.to_string(),
                        locality: ExecutionLocality::CommissionerLocal,
                    },
                ),
            ]),
            purposes: BTreeSet::from(["answer a support question".to_string()]),
            retention_rules: BTreeSet::from(["delete-after-30-days".to_string()]),
            commissioner_export: BTreeSet::new(),
        }
    }

    fn crossing(
        boundary: &DeclaredBoundary,
        sink: &str,
        classes: &[DataClass],
    ) -> BoundaryCrossing {
        BoundaryCrossing {
            workspace: boundary.workspace.clone(),
            purpose: "answer a support question".to_string(),
            source: "crm:contacts".to_string(),
            transformation: "summarised".to_string(),
            sink: sink.to_string(),
            data_classes: classes.iter().cloned().collect(),
            retention_rule: "delete-after-30-days".to_string(),
            execution_resource: None,
            routing_decision: None,
            authority: PrincipalId::new(),
            authority_delegation: DelegationId::new(),
            subject: Digest::blake3(b"the material"),
            at: now(),
        }
    }

    #[test]
    fn a_fully_declared_crossing_is_allowed() {
        let b = boundary();
        let c = crossing(&b, PROVIDER, &[DataClass::Internal]);
        let adjudication = adjudicate(&b, &c);
        assert!(adjudication.allowed());
        assert_eq!(adjudication.denied, None);
    }

    #[test]
    fn every_denial_still_produces_the_record() {
        // The property the whole module is shaped around. A boundary that logs
        // only what it let through cannot answer "which classified data was
        // denied at which boundary", and its log looks complete either way --
        // every entry in it is true and the absent ones are the interesting
        // ones.
        let b = boundary();
        let refused = [
            {
                let mut c = crossing(&b, PROVIDER, &[DataClass::Internal]);
                c.workspace = InstitutionWorkspaceId::new();
                c
            },
            crossing(&b, "inference:nobody-declared", &[DataClass::Internal]),
            {
                let mut c = crossing(&b, PROVIDER, &[DataClass::Internal]);
                c.purpose = "curiosity".to_string();
                c
            },
            {
                let mut c = crossing(&b, PROVIDER, &[DataClass::Internal]);
                c.retention_rule = "forever".to_string();
                c
            },
            crossing(&b, COMMISSIONER, &[DataClass::Confidential]),
        ];

        for attempted in refused {
            let adjudication = adjudicate(&b, &attempted);
            assert!(
                !adjudication.allowed(),
                "this fixture must be refused: {attempted:?}"
            );
            assert_eq!(
                adjudication.crossing, attempted,
                "a refused crossing must be recorded exactly as attempted"
            );
        }
    }

    #[test]
    fn material_from_another_workspace_is_refused() {
        let b = boundary();
        let mut c = crossing(&b, PROVIDER, &[DataClass::Internal]);
        c.workspace = InstitutionWorkspaceId::new();
        assert_eq!(
            adjudicate(&b, &c).denied,
            Some(DenialReason::ForeignWorkspace)
        );
    }

    #[test]
    fn an_unclassified_sink_is_refused_rather_than_treated_as_external() {
        // The tempting default is "it is some external system", which is a
        // class nobody assigned. An unknown sink has an unknown locality, and
        // locality is what the commissioner-export rule turns on.
        let b = boundary();
        let c = crossing(&b, "inference:someone-else", &[DataClass::Public]);
        assert_eq!(
            adjudicate(&b, &c).denied,
            Some(DenialReason::UnknownSink {
                sink: "inference:someone-else".to_string(),
            })
        );
    }

    #[test]
    fn an_unapproved_purpose_is_refused() {
        let b = boundary();
        let mut c = crossing(&b, PROVIDER, &[DataClass::Public]);
        c.purpose = "curiosity".to_string();
        assert_eq!(
            adjudicate(&b, &c).denied,
            Some(DenialReason::UnknownPurpose {
                purpose: "curiosity".to_string(),
            })
        );
    }

    #[test]
    fn an_unapproved_retention_rule_is_refused() {
        let b = boundary();
        let mut c = crossing(&b, PROVIDER, &[DataClass::Public]);
        c.retention_rule = "forever".to_string();
        assert_eq!(
            adjudicate(&b, &c).denied,
            Some(DenialReason::UnknownRetentionRule {
                rule: "forever".to_string(),
            })
        );
    }

    #[test]
    fn private_material_does_not_reach_a_commissioner_machine_by_default() {
        // `docs/16-DATA_GOVERNANCE.md`: secret values, private facts,
        // operational logs, evidence and prompts do not move to a
        // commissioner-controlled machine *by default*. "By default" is what
        // happens when nobody decided, so the field recording the decision
        // starts empty and this is what that emptiness means.
        let b = boundary();
        assert!(b.commissioner_export.is_empty());
        let c = crossing(
            &b,
            COMMISSIONER,
            &[DataClass::Confidential, DataClass::Secret],
        );
        assert_eq!(
            adjudicate(&b, &c).denied,
            Some(DenialReason::UnauthorizedCommissionerExport {
                classes: BTreeSet::from([DataClass::Confidential, DataClass::Secret]),
            }),
            "the refusal names every unauthorized class, not the first one found"
        );
    }

    #[test]
    fn an_explicit_export_authorization_permits_exactly_what_it_names() {
        let mut b = boundary();
        b.commissioner_export = BTreeSet::from([DataClass::Confidential]);

        assert!(
            adjudicate(&b, &crossing(&b, COMMISSIONER, &[DataClass::Confidential])).allowed(),
            "the authorized class may go"
        );
        assert_eq!(
            adjudicate(&b, &crossing(&b, COMMISSIONER, &[DataClass::Secret])).denied,
            Some(DenialReason::UnauthorizedCommissionerExport {
                classes: BTreeSet::from([DataClass::Secret]),
            }),
            "authorizing one class must not authorize its neighbours"
        );
    }

    #[test]
    fn public_material_reaches_a_commissioner_machine_without_an_authorization() {
        // The rule is about private material. Requiring an export authorization
        // for public data would make the list a general allowlist, and a list
        // that has to name everything gets filled in wholesale.
        let b = boundary();
        assert!(adjudicate(&b, &crossing(&b, COMMISSIONER, &[DataClass::Public])).allowed());
    }

    #[test]
    fn the_commissioner_rule_applies_to_locality_rather_than_to_a_named_sink() {
        // A second commissioner-controlled destination is covered without being
        // listed anywhere, because the rule turns on where the sink sits.
        let mut b = boundary();
        b.sinks.insert(
            "log:commissioner-laptop".to_string(),
            Sink {
                kind: SinkKind::Log,
                identity: "log:commissioner-laptop".to_string(),
                locality: ExecutionLocality::CommissionerLocal,
            },
        );
        let c = crossing(&b, "log:commissioner-laptop", &[DataClass::Internal]);
        assert!(matches!(
            adjudicate(&b, &c).denied,
            Some(DenialReason::UnauthorizedCommissionerExport { .. })
        ));
    }

    #[test]
    fn every_denial_reason_names_the_test_that_reaches_it() {
        // A reason nothing can produce is a branch documenting a check rather
        // than performing one. The exhaustive match stops the build when a
        // reason is added, which forces naming the test that reaches it -- and
        // noticing when there is none.
        let reached_by = |reason: &DenialReason| -> &'static str {
            match reason {
                DenialReason::ForeignWorkspace => "material_from_another_workspace_is_refused",
                DenialReason::UnknownSink { .. } => {
                    "an_unclassified_sink_is_refused_rather_than_treated_as_external"
                }
                DenialReason::UnknownPurpose { .. } => "an_unapproved_purpose_is_refused",
                DenialReason::UnknownRetentionRule { .. } => {
                    "an_unapproved_retention_rule_is_refused"
                }
                DenialReason::UnauthorizedCommissionerExport { .. } => {
                    "private_material_does_not_reach_a_commissioner_machine_by_default"
                }
            }
        };
        assert_eq!(
            reached_by(&DenialReason::ForeignWorkspace),
            "material_from_another_workspace_is_refused"
        );
    }
}
