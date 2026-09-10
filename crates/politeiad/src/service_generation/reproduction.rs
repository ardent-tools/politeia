//! Public generation reproduction without an original commissioner's key.

use super::{
    CoordinatorError, Digest, GenerationArtifactBuilder, OperationResult, PoliteiadService, json,
    refusal,
};

impl PoliteiadService {
    pub(super) async fn reproduce_generation(
        &self,
        generation: Digest,
    ) -> Result<OperationResult, CoordinatorError> {
        // This verification binds the signed inputs and the on-disk manifest
        // to the immutable PostgreSQL record, not just to one another.
        let original = self.verified_generation(&generation).await?;
        let durable = self.durable_snapshot().await?;
        let inputs = original.generation().inputs();
        let receipt = self
            .load_commissioning_receipt(&durable, &inputs.commissioning_record)
            .await?;
        let commissioning = self
            .commissioning_record(
                &durable,
                &inputs.commissioning_record,
                &inputs.commissioning_record_digest,
                &receipt,
            )
            .await?;
        let result = GenerationArtifactBuilder::new(self.layout().artifact_dir.clone())
            .reproduce(
                self.anchors(),
                self.workspace(),
                &commissioning,
                &generation,
            )
            .map_err(refusal)?;
        if &result.artifact_manifest != original.manifest_digest() {
            return Err(CoordinatorError::Refused(
                "reproduced artifact differs from durable generation".to_owned(),
            ));
        }
        Ok(OperationResult::Coordinated {
            result: json!({
                "generation": result.generation,
                "artifact_manifest": result.artifact_manifest,
                "components_compared": result.components_compared,
                "generation_reproduced": true,
                "compiler_rebuild": "not_performed",
            }),
            evidence_refs: Vec::new(),
        })
    }
}
