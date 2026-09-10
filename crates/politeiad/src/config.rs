//! Institution-owned installation layout and local socket configuration.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use politeia_core::{InstitutionId, InstitutionWorkspaceId};
use serde::{Deserialize, Serialize};

/// Persistent local paths for one single-tenant Politeia installation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationLayout {
    /// Institution this host serves.
    pub institution: InstitutionId,
    /// Institution-owned workspace selected during initialization.
    pub workspace: InstitutionWorkspaceId,
    /// The installation prefix, owned by the institution.
    pub prefix: PathBuf,
    /// Local daemon socket. Its filesystem permissions are part of auth.
    pub socket: PathBuf,
    /// Key material directory, deliberately outside PostgreSQL.
    pub key_dir: PathBuf,
    /// Institution-owned immutable artifacts and generation manifests.
    pub artifact_dir: PathBuf,
    /// Writable working directory for explicit source snapshots.
    pub workspace_dir: PathBuf,
}

/// Why an installation layout could not be initialized safely.
#[derive(Debug)]
#[non_exhaustive]
pub enum InstallationError {
    /// The requested prefix already exists, so initialization could overwrite custody state.
    AlreadyInitialized(PathBuf),
    /// Stored configuration directed an owned path outside its declared prefix.
    InvalidLayout,
    /// Filesystem setup failed.
    Io(io::Error),
}

impl std::fmt::Display for InstallationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyInitialized(path) => write!(
                formatter,
                "installation prefix already exists: {}",
                path.display()
            ),
            Self::InvalidLayout => {
                formatter.write_str("installation layout does not match its owned prefix")
            }
            Self::Io(error) => write!(
                formatter,
                "installation filesystem operation failed: {error}"
            ),
        }
    }
}

impl std::error::Error for InstallationError {}

impl From<io::Error> for InstallationError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl InstallationLayout {
    /// Derive all locations from one institution-owned prefix.
    pub fn new(
        institution: InstitutionId,
        workspace: InstitutionWorkspaceId,
        prefix: PathBuf,
    ) -> Self {
        Self {
            institution,
            workspace,
            socket: prefix.join("run/politeiad.sock"),
            key_dir: prefix.join("keys"),
            artifact_dir: prefix.join("artifacts"),
            workspace_dir: prefix.join("workspace"),
            prefix,
        }
    }

    /// Create the layout without generating a key or silently replacing state.
    ///
    /// The caller must first authenticate an owner-signed initialization request
    /// and install its trust anchors in `key_dir`; this method only establishes
    /// private filesystem ownership for that explicit host action.
    pub fn initialize_filesystem(&self) -> Result<(), InstallationError> {
        if self.prefix.exists() {
            return Err(InstallationError::AlreadyInitialized(self.prefix.clone()));
        }
        fs::create_dir_all(&self.key_dir)?;
        fs::create_dir_all(&self.artifact_dir)?;
        fs::create_dir_all(&self.workspace_dir)?;
        fs::create_dir_all(self.socket.parent().unwrap_or(&self.prefix))?;
        set_private_directory(&self.key_dir)?;
        set_private_directory(&self.artifact_dir)?;
        set_private_directory(&self.workspace_dir)?;
        set_private_directory(self.socket.parent().unwrap_or(&self.prefix))?;
        let config = self.config_path();
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| InstallationError::Io(io::Error::other(error)))?;
        fs::write(&config, bytes)?;
        set_private_file(&config)?;
        Ok(())
    }

    /// Return the immutable configuration location inside the prefix.
    pub fn config_path(&self) -> PathBuf {
        self.prefix.join("politeiad-installation.json")
    }

    /// Load an existing layout without inferring alternate locations.
    pub fn load(prefix: &Path) -> Result<Self, InstallationError> {
        let config = prefix.join("politeiad-installation.json");
        let bytes = fs::read(config)?;
        let layout: Self = serde_json::from_slice(&bytes)
            .map_err(|error| InstallationError::Io(io::Error::other(error)))?;
        if layout.prefix != prefix
            || layout.socket != prefix.join("run/politeiad.sock")
            || layout.key_dir != prefix.join("keys")
            || layout.artifact_dir != prefix.join("artifacts")
            || layout.workspace_dir != prefix.join("workspace")
        {
            return Err(InstallationError::InvalidLayout);
        }
        Ok(layout)
    }
}

#[cfg(unix)]
fn set_private_directory(path: &Path) -> Result<(), io::Error> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_private_directory(_path: &Path) -> Result<(), io::Error> {
    Err(io::Error::other(
        "Politeiad's local authenticated socket requires Unix",
    ))
}

#[cfg(unix)]
fn set_private_file(path: &Path) -> Result<(), io::Error> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_private_file(_path: &Path) -> Result<(), io::Error> {
    Err(io::Error::other(
        "Politeiad's local authenticated socket requires Unix",
    ))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn initialization_creates_private_owned_paths_and_refuses_replacement() {
        let prefix =
            std::env::temp_dir().join(format!("politeiad-install-{}", uuid::Uuid::now_v7()));
        let layout = InstallationLayout::new(
            InstitutionId::new(),
            InstitutionWorkspaceId::new(),
            prefix.clone(),
        );
        layout
            .initialize_filesystem()
            .expect("a fresh prefix initializes without replacing state");
        assert_eq!(
            InstallationLayout::load(&prefix).expect("layout reloads"),
            layout
        );
        assert!(matches!(
            layout.initialize_filesystem(),
            Err(InstallationError::AlreadyInitialized(_))
        ));
        fs::remove_dir_all(prefix).expect("fixture is removable");
    }
}
