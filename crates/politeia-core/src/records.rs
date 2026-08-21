//! Versioned persistent records: what a stored record says about itself, and
//! what happens when it says something this build does not understand.
//!
//! A record outlives the code that wrote it. `docs/09-PERSISTENCE.md` requires
//! delivered bytes to stay immutable and `docs/02-CONSTITUTION.md` law 12
//! requires corrections to append rather than rewrite, so a build that meets a
//! record it cannot read has exactly two honest options: migrate it forward, or
//! set it aside intact. Deleting it and coercing it are both rewrites.
//!
//! WHY the stored form is bytes rather than a parsed value: what was persisted
//! is bytes, and a quarantined record must be preserved as what it actually
//! was. Round-tripping through a value first would quarantine this build's
//! reading of the record rather than the record.
//!
//! The version lives in one place. A record's `kind` is the digest-domain tag
//! that already identifies it -- `operation_intent_v1` -- so the version a
//! record was written under and the version its digest was computed under
//! cannot disagree. [`split_kind`] is the only parser of that form, and
//! `every_digest_domain_tag_splits` holds the two together.

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::canonical::{CanonicalError, to_canonical_bytes};

/// Split a versioned kind into its class and version.
///
/// Returns `None` when the text does not end in `_v<digits>`, which is the
/// shape every digest-domain tag has.
pub fn split_kind(kind: &str) -> Option<(&str, u32)> {
    let (class, version) = kind.rsplit_once("_v")?;
    if class.is_empty() {
        return None;
    }
    // Parsed rather than pattern-matched so `_v01` and `_v1` cannot both be
    // accepted as version 1: two spellings of one version are two identities
    // for one record class.
    if version.is_empty() || version.starts_with('0') && version != "0" {
        return None;
    }
    version.parse().ok().map(|version| (class, version))
}

/// A persisted record as it was written: its kind, and its exact bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredRecord {
    /// The versioned kind the writer stamped, e.g. `operation_intent_v1`.
    pub kind: String,
    /// The canonical bytes the writer produced.
    pub body: Vec<u8>,
}

/// A record class this build can read, and how far back it can read it.
pub trait VersionedRecord: Sized {
    /// The class name, without a version suffix.
    const CLASS: &'static str;
    /// The version this build writes.
    const CURRENT_VERSION: u32;
    /// The oldest version this build can still read.
    ///
    /// Retiring a version is a deliberate act that makes older records
    /// unreadable, so it is declared rather than inferred from whichever
    /// migrations happen to exist.
    const OLDEST_READABLE_VERSION: u32;

    /// Migrate a decoded body one version forward.
    ///
    /// Called repeatedly, from `version` toward [`Self::CURRENT_VERSION`], so
    /// each implementation handles a single step. A step that would drop
    /// information returns [`RecordRefusal::Lossy`] rather than performing it.
    ///
    /// # Errors
    ///
    /// Returns [`RecordRefusal`] when this build has no step from `version`, or
    /// when the body does not hold what that step needs.
    fn migrate_one(
        version: u32,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, RecordRefusal>;
}

/// Why a stored record cannot be read.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecordRefusal {
    /// The kind does not carry a parseable version.
    UnversionedKind {
        /// The kind as stored.
        kind: String,
    },
    /// The kind names a different record class.
    ClassMismatch {
        /// The class this reader handles.
        expected: &'static str,
        /// The class the record claims.
        found: String,
    },
    /// The record was written by a newer build.
    ///
    /// Fails closed rather than attempting a best-effort read: a newer version
    /// exists precisely because something changed, and this build cannot know
    /// what.
    FutureVersion {
        /// The version stored.
        found: u32,
        /// The newest version this build writes.
        current: u32,
    },
    /// The record predates the oldest version this build reads.
    RetiredVersion {
        /// The version stored.
        found: u32,
        /// The oldest version still readable.
        oldest: u32,
    },
    /// No migration step exists from this version.
    NoMigration {
        /// The version reached with nowhere to go.
        from: u32,
    },
    /// The bytes are not the JSON the version claims.
    Malformed {
        /// The version being read when it failed.
        at_version: u32,
        /// What the decoder said.
        message: String,
    },
    /// A migration step would have dropped information.
    ///
    /// A record that cannot move forward without loss is quarantined rather
    /// than migrated, because the loss is invisible afterwards: the migrated
    /// record decodes cleanly and is simply missing something.
    Lossy {
        /// The version being migrated from.
        from: u32,
        /// What the step would have dropped.
        field: String,
    },
}

impl std::fmt::Display for RecordRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordRefusal::UnversionedKind { kind } => {
                write!(formatter, "kind {kind} carries no version")
            }
            RecordRefusal::ClassMismatch { expected, found } => {
                write!(formatter, "expected class {expected}, found {found}")
            }
            RecordRefusal::FutureVersion { found, current } => write!(
                formatter,
                "record is version {found}; this build writes {current} and cannot know what changed"
            ),
            RecordRefusal::RetiredVersion { found, oldest } => write!(
                formatter,
                "record is version {found}; this build reads back only to {oldest}"
            ),
            RecordRefusal::NoMigration { from } => {
                write!(formatter, "no migration step exists from version {from}")
            }
            RecordRefusal::Malformed {
                at_version,
                message,
            } => write!(
                formatter,
                "record is not valid at version {at_version}: {message}"
            ),
            RecordRefusal::Lossy { from, field } => write!(
                formatter,
                "migrating from version {from} would drop {field}"
            ),
        }
    }
}

impl std::error::Error for RecordRefusal {}

/// A record set aside intact because it could not be read.
///
/// WHY the original travels with the reason: a refusal that discards the bytes
/// turns an unreadable record into a lost one, and the two are different
/// outcomes. A quarantined record can be read by a later build, migrated by a
/// tool, or inspected by a person; a dropped one cannot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Quarantined {
    /// Why it could not be read.
    pub reason: RecordRefusal,
    /// The record exactly as it was stored.
    pub original: StoredRecord,
}

impl std::fmt::Display for Quarantined {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "quarantined {}: {}",
            self.original.kind, self.reason
        )
    }
}

impl std::error::Error for Quarantined {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.reason)
    }
}

/// Store a record under the version this build writes.
///
/// # Errors
///
/// Returns the canonical-encoding failure if the record cannot be represented.
pub fn write<T: VersionedRecord + Serialize>(record: &T) -> Result<StoredRecord, CanonicalError> {
    Ok(StoredRecord {
        kind: format!("{}_v{}", T::CLASS, T::CURRENT_VERSION),
        body: to_canonical_bytes(record)?,
    })
}

/// Read a stored record, migrating it forward if this build can.
///
/// # Errors
///
/// Returns [`Quarantined`], carrying the original bytes, for every record this
/// build cannot read: an unversioned or foreign kind, a version from the future
/// or from before the supported floor, a missing migration step, a step that
/// would lose information, and bytes that do not decode at the version they
/// claim.
///
/// Time: O(v) migration steps for a record v versions behind, plus decoding.
/// Space: O(n) in the record size.
pub fn read<T: VersionedRecord + DeserializeOwned>(
    stored: &StoredRecord,
) -> Result<T, Quarantined> {
    let quarantine = |reason| Quarantined {
        reason,
        original: stored.clone(),
    };

    let Some((class, mut version)) = split_kind(&stored.kind) else {
        return Err(quarantine(RecordRefusal::UnversionedKind {
            kind: stored.kind.clone(),
        }));
    };
    if class != T::CLASS {
        return Err(quarantine(RecordRefusal::ClassMismatch {
            expected: T::CLASS,
            found: class.to_string(),
        }));
    }
    if version > T::CURRENT_VERSION {
        return Err(quarantine(RecordRefusal::FutureVersion {
            found: version,
            current: T::CURRENT_VERSION,
        }));
    }
    if version < T::OLDEST_READABLE_VERSION {
        return Err(quarantine(RecordRefusal::RetiredVersion {
            found: version,
            oldest: T::OLDEST_READABLE_VERSION,
        }));
    }

    let mut body: serde_json::Value = serde_json::from_slice(&stored.body).map_err(|error| {
        quarantine(RecordRefusal::Malformed {
            at_version: version,
            message: error.to_string(),
        })
    })?;

    while version < T::CURRENT_VERSION {
        body = T::migrate_one(version, body).map_err(&quarantine)?;
        version += 1;
    }

    serde_json::from_value(body).map_err(|error| {
        quarantine(RecordRefusal::Malformed {
            at_version: T::CURRENT_VERSION,
            message: error.to_string(),
        })
    })
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;
    use crate::DigestDomain;

    #[test]
    fn every_digest_domain_tag_splits_into_a_class_and_a_version() {
        // The link that keeps the version in one place. A record's kind is the
        // digest-domain tag, so if a tag ever stopped carrying a parseable
        // version, records written under it would become unreadable -- and the
        // failure would appear at read time, on stored data, rather than here.
        for domain in DigestDomain::all() {
            let tag = domain.tag();
            let split = split_kind(tag);
            assert!(
                split.is_some(),
                "digest domain tag {tag} does not carry a parseable version"
            );
        }
    }

    #[test]
    fn a_kind_without_a_well_formed_version_is_not_split() {
        for kind in [
            "operation_intent",
            "_v1",
            "note_v",
            "note_v01",
            "note_vx",
            "",
        ] {
            assert_eq!(split_kind(kind), None, "{kind} must not split");
        }
    }

    #[test]
    fn a_zero_padded_version_is_refused_rather_than_normalised() {
        // `note_v01` and `note_v1` would otherwise be two spellings of one
        // version, which is two identities for one record class.
        assert_eq!(split_kind("note_v01"), None);
        assert_eq!(split_kind("note_v1"), Some(("note", 1)));
    }

    /// A record class with three versions, so migration is exercised over more
    /// than one step.
    ///
    /// WHY a fixture rather than a shipped class: every real record class is at
    /// version 1, so none of them has a migration to perform. The mechanism is
    /// what this proves, and the day a shipped class gains a second version the
    /// path is already here and already tested.
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Note {
        title: String,
        tags: Vec<String>,
    }

    impl VersionedRecord for Note {
        const CLASS: &'static str = "note";
        const CURRENT_VERSION: u32 = 3;
        const OLDEST_READABLE_VERSION: u32 = 1;

        fn migrate_one(
            version: u32,
            mut body: serde_json::Value,
        ) -> Result<serde_json::Value, RecordRefusal> {
            let object = body.as_object_mut().ok_or(RecordRefusal::Malformed {
                at_version: version,
                message: "record is not an object".to_string(),
            })?;
            match version {
                // v1 had no tag at all.
                1 => {
                    object.insert("tag".to_string(), serde_json::Value::String(String::new()));
                    Ok(body)
                }
                // v2 carried one tag; v3 carries a list.
                2 => {
                    let tag = object
                        .remove("tag")
                        .and_then(|tag| tag.as_str().map(str::to_owned))
                        .unwrap_or_default();
                    let tags = if tag.is_empty() {
                        Vec::new()
                    } else {
                        vec![serde_json::Value::String(tag)]
                    };
                    object.insert("tags".to_string(), serde_json::Value::Array(tags));
                    Ok(body)
                }
                other => Err(RecordRefusal::NoMigration { from: other }),
            }
        }
    }

    /// A class whose forward step drops a field, so the refusal has something
    /// real to refuse.
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Ticket {
        summary: String,
    }

    impl VersionedRecord for Ticket {
        const CLASS: &'static str = "ticket";
        const CURRENT_VERSION: u32 = 2;
        const OLDEST_READABLE_VERSION: u32 = 1;

        fn migrate_one(
            version: u32,
            mut body: serde_json::Value,
        ) -> Result<serde_json::Value, RecordRefusal> {
            let object = body.as_object_mut().ok_or(RecordRefusal::Malformed {
                at_version: version,
                message: "record is not an object".to_string(),
            })?;
            match version {
                1 => {
                    // Dropping an empty field is not loss; dropping a populated
                    // one is, and the record is set aside rather than trimmed.
                    match object.remove("assignee") {
                        Some(serde_json::Value::String(who)) if !who.is_empty() => {
                            Err(RecordRefusal::Lossy {
                                from: 1,
                                field: "assignee".to_string(),
                            })
                        }
                        _ => Ok(body),
                    }
                }
                other => Err(RecordRefusal::NoMigration { from: other }),
            }
        }
    }

    fn stored(kind: &str, body: &str) -> StoredRecord {
        StoredRecord {
            kind: kind.to_string(),
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "a fixture that cannot be written is a broken test, not a finding"
    )]
    fn a_record_written_now_reads_back_unchanged() {
        let note = Note {
            title: "canonical bytes".to_string(),
            tags: vec!["protocol".to_string()],
        };
        let written = write(&note).expect("the fixture note encodes");
        assert_eq!(written.kind, "note_v3");
        assert_eq!(read::<Note>(&written), Ok(note));
    }

    #[test]
    fn an_old_record_migrates_forward_through_every_step() {
        let v1 = stored("note_v1", r#"{"title":"first"}"#);
        assert_eq!(
            read::<Note>(&v1),
            Ok(Note {
                title: "first".to_string(),
                tags: Vec::new(),
            }),
            "a v1 record must reach the current shape through both steps"
        );

        let v2 = stored("note_v2", r#"{"tag":"protocol","title":"second"}"#);
        assert_eq!(
            read::<Note>(&v2),
            Ok(Note {
                title: "second".to_string(),
                tags: vec!["protocol".to_string()],
            })
        );
    }

    #[test]
    fn migration_is_deterministic() {
        // Same bytes, same result, every time. Stated because a migration that
        // consulted a clock, a map iteration order, or anything else outside
        // its input would still pass a single-run test.
        let v1 = stored("note_v1", r#"{"title":"first"}"#);
        let once = read::<Note>(&v1);
        for _ in 0..8 {
            assert_eq!(read::<Note>(&v1), once);
        }
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "a fixture that does not refuse is a broken test, not a finding"
    )]
    fn a_record_from_the_future_is_quarantined_rather_than_guessed_at() {
        let ahead = stored("note_v4", r#"{"title":"later","tags":[]}"#);
        let refused = read::<Note>(&ahead).expect_err("a future version must not be read");
        assert_eq!(
            refused.reason,
            RecordRefusal::FutureVersion {
                found: 4,
                current: 3,
            }
        );
        assert_eq!(
            refused.original, ahead,
            "the quarantined record must be preserved exactly as stored"
        );
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "a fixture that does not refuse is a broken test, not a finding"
    )]
    fn a_retired_version_is_quarantined() {
        struct Recent;
        impl VersionedRecord for Recent {
            const CLASS: &'static str = "note";
            const CURRENT_VERSION: u32 = 3;
            const OLDEST_READABLE_VERSION: u32 = 3;
            fn migrate_one(
                version: u32,
                _body: serde_json::Value,
            ) -> Result<serde_json::Value, RecordRefusal> {
                Err(RecordRefusal::NoMigration { from: version })
            }
        }
        impl<'de> Deserialize<'de> for Recent {
            fn deserialize<D: serde::Deserializer<'de>>(_: D) -> Result<Self, D::Error> {
                Ok(Recent)
            }
        }

        let old = stored("note_v1", r#"{"title":"ancient"}"#);
        let refused = read::<Recent>(&old).expect_err("a retired version must not be read");
        assert_eq!(
            refused.reason,
            RecordRefusal::RetiredVersion {
                found: 1,
                oldest: 3,
            }
        );
        assert_eq!(refused.original, old);
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "a fixture that does not refuse is a broken test, not a finding"
    )]
    fn a_lossy_step_quarantines_instead_of_trimming() {
        // The refusal that matters most, because its alternative is invisible:
        // a trimmed record decodes cleanly and is simply missing something.
        let assigned = stored("ticket_v1", r#"{"assignee":"someone","summary":"a bug"}"#);
        let refused = read::<Ticket>(&assigned).expect_err("a lossy step must not run");
        assert_eq!(
            refused.reason,
            RecordRefusal::Lossy {
                from: 1,
                field: "assignee".to_string(),
            }
        );
        assert_eq!(refused.original, assigned);
    }

    #[test]
    fn a_step_that_drops_nothing_is_not_lossy() {
        // The other side of the same rule, so `Lossy` is a judgement about the
        // record rather than about the shape of the migration.
        let unassigned = stored("ticket_v1", r#"{"assignee":"","summary":"a bug"}"#);
        assert_eq!(
            read::<Ticket>(&unassigned),
            Ok(Ticket {
                summary: "a bug".to_string(),
            })
        );
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "a fixture that does not refuse is a broken test, not a finding"
    )]
    fn a_foreign_class_is_quarantined() {
        let other = stored("ticket_v1", r#"{"summary":"a bug"}"#);
        let refused = read::<Note>(&other).expect_err("a foreign class must not be read");
        assert_eq!(
            refused.reason,
            RecordRefusal::ClassMismatch {
                expected: "note",
                found: "ticket".to_string(),
            }
        );
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "a fixture that does not refuse is a broken test, not a finding"
    )]
    fn an_unversioned_kind_is_quarantined() {
        let bare = stored("note", r#"{"title":"x","tags":[]}"#);
        let refused = read::<Note>(&bare).expect_err("an unversioned kind must not be read");
        assert_eq!(
            refused.reason,
            RecordRefusal::UnversionedKind {
                kind: "note".to_string(),
            }
        );
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "a fixture that does not refuse is a broken test, not a finding"
    )]
    fn bytes_that_are_not_the_record_are_quarantined_with_the_version_that_failed() {
        let broken = stored("note_v3", "{not json");
        let refused = read::<Note>(&broken).expect_err("malformed bytes must not be read");
        assert!(
            matches!(
                refused.reason,
                RecordRefusal::Malformed { at_version: 3, .. }
            ),
            "got {:?}",
            refused.reason
        );
        assert_eq!(refused.original, broken);
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "a fixture that does not refuse is a broken test, not a finding"
    )]
    fn a_record_that_decodes_only_after_migration_reports_the_current_version() {
        // A v1 body missing its own required field fails at v3, after both
        // steps ran -- so the reported version is where decoding was attempted,
        // not where the record came from.
        let missing = stored("note_v1", r#"{}"#);
        let refused = read::<Note>(&missing).expect_err("a note needs a title");
        assert!(
            matches!(
                refused.reason,
                RecordRefusal::Malformed { at_version: 3, .. }
            ),
            "got {:?}",
            refused.reason
        );
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "a fixture that does not refuse is a broken test, not a finding"
    )]
    fn every_refusal_preserves_the_record_exactly() {
        // The property that separates quarantine from loss, checked over every
        // refusing input at once rather than once per case.
        let refusals = [
            stored("note_v4", r#"{"title":"later","tags":[]}"#),
            stored("note", r#"{"title":"x","tags":[]}"#),
            stored("ticket_v1", r#"{"summary":"a bug"}"#),
            stored("note_v3", "{not json"),
        ];
        for original in refusals {
            let refused = read::<Note>(&original).expect_err("each of these must refuse");
            assert_eq!(
                refused.original, original,
                "a quarantined record must be byte-identical to what was stored"
            );
        }
    }
}
