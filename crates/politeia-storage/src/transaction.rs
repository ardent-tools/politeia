//! Bounded retries of transactions PostgreSQL explicitly reports as aborted.

use std::{future::Future, time::Duration};

use crate::StorageError;

/// Never wrap an effect port or retry an ambiguous connection/commit failure.
/// This helper covers only database transactions whose effects are known to
/// have rolled back. Backoff prevents concurrent workspaces from immediately
/// repeating the same serializable predicate conflicts.
pub(super) async fn retry<T, F, Fut>(mut run: F) -> Result<T, StorageError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, StorageError>>,
{
    const DELAYS_MS: [u64; 8] = [0, 5, 10, 20, 40, 80, 160, 320];
    for delay in DELAYS_MS {
        if delay != 0 {
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
        match run().await {
            Err(StorageError::Database(error))
                if matches!(
                    error.code(),
                    Some(code) if *code == tokio_postgres::error::SqlState::T_R_SERIALIZATION_FAILURE
                        || *code == tokio_postgres::error::SqlState::T_R_DEADLOCK_DETECTED
                ) => {}
            outcome => return outcome,
        }
    }
    Err(StorageError::SerializationExhausted)
}
