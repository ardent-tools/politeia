//! Institution-owned installation layout and local socket configuration.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use politeia_core::{
    InstitutionId, InstitutionWorkspaceId, PrincipalId,
    institution::InstitutionWorkspace,
    trust::{AdmissionKind, InstitutionTrustAnchors, TrustedSigningKey},
};
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

/// One public verification key installed by the explicit host action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledTrustAnchor {
    /// Institution principal whose statements this key can authenticate.
    pub principal: PrincipalId,
    /// Ed25519 public key bytes. Private keys never enter this configuration.
    pub public_key: [u8; 32],
    /// The exact signed statement kinds this principal may submit.
    pub permitted: std::collections::BTreeSet<AdmissionKind>,
}

/// The non-secret, host-installed trust configuration for one workspace.
///
/// Supplying this document to the local initialization command is an explicit
/// host-custody action. It is not accepted by the daemon transport.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostTrustConfiguration {
    /// Client-owned workspace that the host will serve.
    pub workspace: InstitutionWorkspace,
    /// Installed public verification keys for the exact workspace.
    pub anchors: Vec<InstalledTrustAnchor>,
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
    /// The requested public-key trust configuration was not valid.
    InvalidTrust(String),
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
            Self::InvalidTrust(reason) => {
                write!(
                    formatter,
                    "installed trust configuration is invalid: {reason}"
                )
            }
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

impl HostTrustConfiguration {
    /// Install this public-key configuration under a fresh institution prefix.
    pub fn install(&self, prefix: PathBuf) -> Result<InstallationLayout, InstallationError> {
        let layout = InstallationLayout::new(
            self.workspace.institution.clone(),
            self.workspace.id.clone(),
            prefix,
        );
        let _anchors = self.anchors()?;
        layout.initialize_filesystem()?;
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| InstallationError::Io(io::Error::other(error)))?;
        let path = layout.trust_configuration_path();
        fs::write(&path, bytes)?;
        set_private_file(&path)?;
        Ok(layout)
    }

    /// Load public trust configuration from an already-installed layout.
    pub fn load(layout: &InstallationLayout) -> Result<Self, InstallationError> {
        let bytes = fs::read(layout.trust_configuration_path())?;
        let configuration: Self = serde_json::from_slice(&bytes)
            .map_err(|error| InstallationError::Io(io::Error::other(error)))?;
        if configuration.workspace.institution != layout.institution
            || configuration.workspace.id != layout.workspace
        {
            return Err(InstallationError::InvalidLayout);
        }
        let _anchors = configuration.anchors()?;
        Ok(configuration)
    }

    /// Reconstruct the non-serializable core trust boundary from installed keys.
    pub fn anchors(&self) -> Result<InstitutionTrustAnchors, InstallationError> {
        let keys = self
            .anchors
            .iter()
            .cloned()
            .map(|anchor| {
                TrustedSigningKey::new(anchor.principal, anchor.public_key, anchor.permitted)
                    .map_err(|error| InstallationError::InvalidTrust(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        InstitutionTrustAnchors::from_trusted_bootstrap(
            self.workspace.institution.clone(),
            self.workspace.id.clone(),
            keys,
        )
        .map_err(|error| InstallationError::InvalidTrust(error.to_string()))
    }
}

impl InstallationLayout {
    /// Return the fixed location of the installed non-secret public key set.
    pub fn trust_configuration_path(&self) -> PathBuf {
        self.key_dir.join("trust-anchors.json")
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
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
    };

    use politeia_core::{
        DelegationId, Digest, PolicyBundleId, PrincipalId,
        generation::{ApprovedGenerationInputs, CommissioningCapability, ReproducibilityContract},
        institution::{InstitutionWorkspace, TrustDomainId},
        lifecycle::{DeploymentTopology, LifecycleProfile},
        trust::AdmissionKind,
    };

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

    #[test]
    fn host_initialization_installs_only_public_workspace_trust() {
        let prefix =
            std::env::temp_dir().join(format!("politeiad-host-install-{}", uuid::Uuid::now_v7()));
        let institution = InstitutionId::new();
        let workspace = InstitutionWorkspace {
            id: InstitutionWorkspaceId::new(),
            institution: institution.clone(),
            trust_domain: "client-a:production"
                .parse::<TrustDomainId>()
                .expect("fixture trust domain is canonical"),
            owner: PrincipalId::new(),
            owner_delegation: DelegationId::new(),
            approved_model_digest: Digest::blake3(b"installed-skeleton"),
            policy_bundle: PolicyBundleId::new(),
            policy_digest: Digest::blake3(b"installed-policy"),
            approved_generation: ApprovedGenerationInputs {
                source_digest: Digest::blake3(b"source"),
                lifecycle: LifecycleProfile::Operational,
                topology: DeploymentTopology::ClientControlledSingleTenant,
                schema_digests: BTreeMap::new(),
                adapter_digests: BTreeMap::new(),
                pack_digests: BTreeMap::new(),
                component_digests: BTreeMap::new(),
                excluded_commissioning_capabilities: BTreeSet::from([
                    CommissioningCapability::GenericReconnaissance,
                    CommissioningCapability::InstitutionAuthoring,
                    CommissioningCapability::AdapterDevelopment,
                    CommissioningCapability::PolicyAuthoring,
                    CommissioningCapability::GenerationDerivation,
                ]),
                specializer_digest: Digest::blake3(b"specializer"),
                toolchain_digest: Digest::blake3(b"toolchain"),
                reproducibility: ReproducibilityContract::Deterministic,
            },
            secret_references: BTreeSet::new(),
        };
        let configuration = HostTrustConfiguration {
            anchors: vec![InstalledTrustAnchor {
                principal: workspace.owner.clone(),
                public_key: [42; 32],
                permitted: BTreeSet::from([AdmissionKind::FactApproval]),
            }],
            workspace,
        };
        let layout = configuration
            .install(prefix.clone())
            .expect("fresh host trust action succeeds");
        let restored = HostTrustConfiguration::load(&layout)
            .expect("installed public trust configuration reloads");
        let anchors = restored
            .anchors()
            .expect("installed public key reconstructs trust anchors");
        assert_eq!(anchors.institution(), &institution);
        assert_eq!(anchors.workspace(), &layout.workspace);
        fs::remove_dir_all(prefix).expect("fixture is removable");
    }
}
