//! Read-only source capture with explicit membership.

use std::{
    collections::BTreeSet,
    fs, io,
    path::{Component, Path, PathBuf},
};

use politeia_core::Digest;
use serde::{Deserialize, Serialize};

/// An explicit source membership selection. Directories are never swept.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSnapshotRequest {
    /// Root that contains every selected source member.
    pub root: PathBuf,
    /// Repository-relative paths selected by the authoritative manifest.
    pub members: BTreeSet<PathBuf>,
}

/// One exact source object captured from the explicit manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceMember {
    /// Slash-separated path relative to the request root.
    pub path: String,
    /// Content digest of the read bytes.
    pub content_digest: Digest,
    /// Exact byte count of the read object.
    pub byte_len: u64,
}

/// A read-only source capture awaiting signed admission by the coordinator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSnapshot {
    /// Canonical root path at capture time.
    pub root: PathBuf,
    /// Complete selected membership, including every exclusion by omission.
    pub members: Vec<SourceMember>,
    /// Digest of the ordered source member records.
    pub manifest_digest: Digest,
}

/// A source capture refusal.
#[derive(Debug)]
#[non_exhaustive]
pub enum SourceSnapshotError {
    /// The manifest did not select any source object.
    EmptyMembership,
    /// A member was absolute or escaped its selected root.
    MemberOutsideRoot(PathBuf),
    /// A manifest member did not resolve to one regular file.
    NotRegularFile(PathBuf),
    /// The filesystem could not be read.
    Io(io::Error),
    /// The explicit member record could not be canonicalized.
    Encoding(String),
}

impl std::fmt::Display for SourceSnapshotError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyMembership => {
                formatter.write_str("source membership must name at least one regular file")
            }
            Self::MemberOutsideRoot(path) => write!(
                formatter,
                "source member is outside the selected root: {}",
                path.display()
            ),
            Self::NotRegularFile(path) => write!(
                formatter,
                "source member is not one regular file: {}",
                path.display()
            ),
            Self::Io(error) => write!(formatter, "source capture failed: {error}"),
            Self::Encoding(error) => {
                write!(formatter, "source manifest could not be encoded: {error}")
            }
        }
    }
}

impl std::error::Error for SourceSnapshotError {}

impl From<io::Error> for SourceSnapshotError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Capture exactly the selected, regular files without following an implicit tree.
pub fn snapshot(request: SourceSnapshotRequest) -> Result<SourceSnapshot, SourceSnapshotError> {
    if request.members.is_empty() {
        return Err(SourceSnapshotError::EmptyMembership);
    }
    let root = fs::canonicalize(request.root)?;
    let mut members = Vec::with_capacity(request.members.len());
    for relative in request.members {
        if relative.is_absolute()
            || relative.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            return Err(SourceSnapshotError::MemberOutsideRoot(relative));
        }
        let joined = root.join(&relative);
        let resolved = fs::canonicalize(&joined)?;
        if !resolved.starts_with(&root) {
            return Err(SourceSnapshotError::MemberOutsideRoot(relative));
        }
        if !resolved.metadata()?.is_file() {
            return Err(SourceSnapshotError::NotRegularFile(relative));
        }
        let bytes = fs::read(resolved)?;
        let path = normalized_member_path(&relative)?;
        members.push(SourceMember {
            path,
            content_digest: Digest::blake3(&bytes),
            byte_len: u64::try_from(bytes.len())
                .map_err(|error| SourceSnapshotError::Encoding(error.to_string()))?,
        });
    }
    members.sort_by(|left, right| left.path.cmp(&right.path));
    let bytes = serde_json::to_vec(&members)
        .map_err(|error| SourceSnapshotError::Encoding(error.to_string()))?;
    Ok(SourceSnapshot {
        root,
        members,
        manifest_digest: Digest::blake3(&bytes),
    })
}

fn normalized_member_path(path: &Path) -> Result<String, SourceSnapshotError> {
    let text = path
        .to_str()
        .ok_or_else(|| SourceSnapshotError::Encoding("source member is not UTF-8".to_string()))?;
    if text.is_empty()
        || text.starts_with('/')
        || text
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(SourceSnapshotError::MemberOutsideRoot(path.to_path_buf()));
    }
    Ok(text.to_string())
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, fs};

    use super::*;

    #[test]
    fn snapshot_captures_only_explicit_members() {
        let root = std::env::temp_dir().join(format!("politeiad-source-{}", std::process::id()));
        fs::create_dir_all(&root).expect("fixture directory is creatable");
        fs::write(root.join("selected.txt"), b"selected").expect("fixture is writable");
        fs::write(root.join("unselected.txt"), b"unselected").expect("fixture is writable");
        let result = snapshot(SourceSnapshotRequest {
            root: root.clone(),
            members: BTreeSet::from([PathBuf::from("selected.txt")]),
        })
        .expect("the explicit regular file is capturable");
        assert_eq!(result.members.len(), 1);
        assert_eq!(result.members[0].path, "selected.txt");
        fs::remove_dir_all(root).expect("fixture is removable");
    }

    #[test]
    fn snapshot_refuses_parent_escape() {
        let result = snapshot(SourceSnapshotRequest {
            root: std::env::temp_dir(),
            members: BTreeSet::from([PathBuf::from("../outside")]),
        });
        assert!(matches!(
            result,
            Err(SourceSnapshotError::MemberOutsideRoot(_))
        ));
    }
}
