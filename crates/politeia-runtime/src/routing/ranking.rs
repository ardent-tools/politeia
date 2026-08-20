use std::cmp::Ordering;

use super::{ExecutionLocality, ExecutionResource, SoftPreference};

pub(super) fn compare_resources(
    left: &ExecutionResource,
    right: &ExecutionResource,
    preferences: &[SoftPreference],
) -> Ordering {
    for preference in preferences {
        let ordering = match preference {
            SoftPreference::PreferLocal => {
                locality_rank(&left.locality).cmp(&locality_rank(&right.locality))
            }
            SoftPreference::MinimizeCost => left
                .estimated_cost_microunits
                .cmp(&right.estimated_cost_microunits),
            SoftPreference::MinimizeLatency => {
                left.estimated_latency_ms.cmp(&right.estimated_latency_ms)
            }
        };
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    left.id.cmp(&right.id)
}

fn locality_rank(locality: &ExecutionLocality) -> u8 {
    match locality {
        ExecutionLocality::ClientLocal => 0,
        ExecutionLocality::ClientRemote => 1,
        ExecutionLocality::ProviderRemote => 2,
        ExecutionLocality::CommissionerLocal => 3,
        ExecutionLocality::Other => 4,
    }
}
