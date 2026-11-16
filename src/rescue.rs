//! Transaction model for Rescue Mode. This module is simulation-only: it never writes cgroups or controls processes.
use crate::linux::Snapshot;
use crate::policy;
use serde::Serialize;
use std::path::{Component, Path};

const MIB: u64 = 1024 * 1024;
const MIN_TTL_SECONDS: u64 = 30;
const MAX_TTL_SECONDS: u64 = 900;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum TransactionPhase {
    Proposed,
    AwaitingSave,
    AwaitingApproval,
    DryRunReady,
    Declined,
    Expired,
    NoRescueRequired,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum SaveVerification {
    NotRequested,
    AwaitingUser,
    UserAttested,
    AdapterVerified,
    Unverified,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum CandidateDisposition {
    Pause,
    CloseGracefully,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct ReclaimMeasurement {
    pub(crate) baseline_memory_current_bytes: u64,
    pub(crate) observed_memory_current_bytes: u64,
    pub(crate) observed_reduction_bytes: u64,
    pub(crate) observed_increase_bytes: u64,
    pub(crate) interpretation: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RescueCandidateAction {
    pub(crate) workload: String,
    pub(crate) cgroup_path: String,
    pub(crate) baseline_memory_current_bytes: u64,
    pub(crate) estimated_reclaimable_bytes: Option<u64>,
    pub(crate) selected_action: Option<CandidateDisposition>,
    pub(crate) save_verification: SaveVerification,
    pub(crate) adapter_id: Option<String>,
    pub(crate) action_approved: bool,
    pub(crate) measurement: Option<ReclaimMeasurement>,
    pub(crate) restore: RestorePlan,
    pub(crate) pause_note: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RestorePlan {
    pub(crate) restore_memory_high_to: Option<String>,
    pub(crate) preserve_memory_max_at: Option<String>,
    pub(crate) restore_values_captured: bool,
    pub(crate) status: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct TemporaryBudgetOverride {
    pub(crate) requested_headroom_bytes: u64,
    pub(crate) ttl_seconds: u64,
    pub(crate) expires_at_unix_secs: u64,
    pub(crate) previous_memory_high: Option<String>,
    pub(crate) previous_memory_max: Option<String>,
    pub(crate) proposed_memory_high_bytes: Option<u64>,
    pub(crate) proposed_memory_high_note: &'static str,
    pub(crate) memory_max_change: &'static str,
    pub(crate) applied: bool,
    pub(crate) restore: RestorePlan,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct CgroupCoordinationPlan {
    pub(crate) memory_controller_available: bool,
    pub(crate) memory_controller_enabled_for_children: bool,
    pub(crate) current_cgroup_subtree_write_open_probe: bool,
    pub(crate) target_write_access_revalidated: bool,
    pub(crate) ancestor_limits_validated: bool,
    pub(crate) enforcement_enabled: bool,
    pub(crate) note: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RescueTransaction {
    pub(crate) schema_version: u32,
    pub(crate) transaction_id: String,
    pub(crate) phase: TransactionPhase,
    pub(crate) target: String,
    pub(crate) target_cgroup_path: String,
    pub(crate) target_current_bytes: u64,
    pub(crate) requested_extra_bytes: u64,
    pub(crate) estimated_shortfall_bytes: u64,
    pub(crate) reserve_target_bytes: u64,
    pub(crate) system_available_bytes: Option<u64>,
    pub(crate) temporary_budget: TemporaryBudgetOverride,
    pub(crate) cgroup: CgroupCoordinationPlan,
    pub(crate) candidates: Vec<RescueCandidateAction>,
    pub(crate) dry_run_user_approval: bool,
    pub(crate) dry_run_only: bool,
    pub(crate) enforcement_allowed: bool,
    pub(crate) save_adapter_status: &'static str,
    pub(crate) warning: &'static str,
    pub(crate) next_step: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlanError {
    InvalidHeadroom,
    InvalidTtl,
    ExpiryOverflow,
    TargetNotFound,
    ProtectedTarget,
    UnsafeTargetPath,
    TargetMemoryUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransitionError {
    CandidateNotFound,
    InvalidPhase,
    CandidateNotSelected,
    SaveNotRequested,
    SaveNotVerified,
    ActionNotApproved,
    RollbackNotReady,
    NoCandidateSelected,
    InvalidAdapterId,
    Expired,
}

impl RescueTransaction {
    pub(crate) fn select_candidate(
        &mut self,
        workload: &str,
        action: CandidateDisposition,
        now_unix_secs: u64,
    ) -> Result<(), TransitionError> {
        self.ensure_not_expired(now_unix_secs)?;
        if !matches!(
            self.phase,
            TransactionPhase::Proposed
                | TransactionPhase::AwaitingSave
                | TransactionPhase::AwaitingApproval
        ) {
            return Err(TransitionError::InvalidPhase);
        }
        let candidate = self
            .candidates
            .iter_mut()
            .find(|candidate| candidate.workload == workload)
            .ok_or(TransitionError::CandidateNotFound)?;
        candidate.selected_action = Some(action);
        candidate.save_verification = SaveVerification::NotRequested;
        candidate.adapter_id = None;
        candidate.action_approved = false;
        candidate.measurement = None;
        self.refresh_phase();
        Ok(())
    }

    pub(crate) fn request_save(
        &mut self,
        workload: &str,
        now_unix_secs: u64,
    ) -> Result<(), TransitionError> {
        self.ensure_not_expired(now_unix_secs)?;
        if !matches!(
            self.phase,
            TransactionPhase::Proposed
                | TransactionPhase::AwaitingSave
                | TransactionPhase::AwaitingApproval
        ) {
            return Err(TransitionError::InvalidPhase);
        }
        let candidate = self
            .candidates
            .iter_mut()
            .find(|candidate| candidate.workload == workload)
            .ok_or(TransitionError::CandidateNotFound)?;
        if candidate.selected_action.is_none() {
            return Err(TransitionError::CandidateNotSelected);
        }
        candidate.save_verification = SaveVerification::AwaitingUser;
        candidate.action_approved = false;
        self.refresh_phase();
        Ok(())
    }

    /// A user attestation is not application-level verification.
    pub(crate) fn confirm_user_saved(
        &mut self,
        workload: &str,
        now_unix_secs: u64,
    ) -> Result<(), TransitionError> {
        self.ensure_not_expired(now_unix_secs)?;
        if !matches!(
            self.phase,
            TransactionPhase::AwaitingSave | TransactionPhase::AwaitingApproval
        ) {
            return Err(TransitionError::InvalidPhase);
        }
        let candidate = self
            .candidates
            .iter_mut()
            .find(|candidate| candidate.workload == workload)
            .ok_or(TransitionError::CandidateNotFound)?;
        if candidate.save_verification != SaveVerification::AwaitingUser {
            return Err(TransitionError::SaveNotRequested);
        }
        candidate.save_verification = SaveVerification::UserAttested;
        self.refresh_phase();
        Ok(())
    }

    /// The adapter contract may advance only on an explicit positive application result.
    pub(crate) fn record_adapter_save_result(
        &mut self,
        workload: &str,
        adapter_id: &str,
        verified: bool,
        now_unix_secs: u64,
    ) -> Result<(), TransitionError> {
        self.ensure_not_expired(now_unix_secs)?;
        if !matches!(
            self.phase,
            TransactionPhase::AwaitingSave | TransactionPhase::AwaitingApproval
        ) {
            return Err(TransitionError::InvalidPhase);
        }
        if adapter_id.trim().is_empty() {
            return Err(TransitionError::InvalidAdapterId);
        }
        let candidate = self
            .candidates
            .iter_mut()
            .find(|candidate| candidate.workload == workload)
            .ok_or(TransitionError::CandidateNotFound)?;
        if candidate.save_verification != SaveVerification::AwaitingUser {
            return Err(TransitionError::SaveNotRequested);
        }
        candidate.adapter_id = Some(adapter_id.trim().to_owned());
        candidate.save_verification = if verified {
            SaveVerification::AdapterVerified
        } else {
            SaveVerification::Unverified
        };
        self.refresh_phase();
        Ok(())
    }

    /// Pause/close consent is separate from the save confirmation.
    pub(crate) fn approve_candidate_action(
        &mut self,
        workload: &str,
        approved: bool,
        now_unix_secs: u64,
    ) -> Result<(), TransitionError> {
        self.ensure_not_expired(now_unix_secs)?;
        if !matches!(
            self.phase,
            TransactionPhase::Proposed
                | TransactionPhase::AwaitingSave
                | TransactionPhase::AwaitingApproval
        ) {
            return Err(TransitionError::InvalidPhase);
        }
        let candidate = self
            .candidates
            .iter_mut()
            .find(|candidate| candidate.workload == workload)
            .ok_or(TransitionError::CandidateNotFound)?;
        if candidate.selected_action.is_none() {
            return Err(TransitionError::CandidateNotSelected);
        }
        if !matches!(
            candidate.save_verification,
            SaveVerification::UserAttested | SaveVerification::AdapterVerified
        ) {
            return Err(TransitionError::SaveNotVerified);
        }
        candidate.action_approved = approved;
        self.refresh_phase();
        Ok(())
    }

    fn ensure_not_expired(&mut self, now_unix_secs: u64) -> Result<(), TransitionError> {
        if matches!(
            self.phase,
            TransactionPhase::Declined
                | TransactionPhase::Expired
                | TransactionPhase::NoRescueRequired
        ) {
            return Err(TransitionError::InvalidPhase);
        }
        if now_unix_secs >= self.temporary_budget.expires_at_unix_secs {
            self.expire(now_unix_secs);
            return Err(TransitionError::Expired);
        }
        Ok(())
    }

    fn refresh_phase(&mut self) {
        if !matches!(
            self.phase,
            TransactionPhase::Proposed
                | TransactionPhase::AwaitingSave
                | TransactionPhase::AwaitingApproval
        ) {
            return;
        }
        let selected: Vec<_> = self
            .candidates
            .iter()
            .filter(|candidate| candidate.selected_action.is_some())
            .collect();
        self.phase = if selected.is_empty() {
            TransactionPhase::Proposed
        } else if selected.iter().any(|candidate| {
            !matches!(
                candidate.save_verification,
                SaveVerification::UserAttested | SaveVerification::AdapterVerified
            )
        }) {
            TransactionPhase::AwaitingSave
        } else {
            TransactionPhase::AwaitingApproval
        };
    }

    /// This approves only the dry-run plan, never cgroup enforcement.
    pub(crate) fn approve_dry_run(
        &mut self,
        now_unix_secs: u64,
        approved: bool,
    ) -> Result<(), TransitionError> {
        self.ensure_not_expired(now_unix_secs)?;
        if !approved {
            self.dry_run_user_approval = false;
            self.phase = TransactionPhase::Declined;
            return Ok(());
        }
        if !matches!(
            self.phase,
            TransactionPhase::Proposed
                | TransactionPhase::AwaitingSave
                | TransactionPhase::AwaitingApproval
        ) {
            return Err(TransitionError::InvalidPhase);
        }
        let selected: Vec<_> = self
            .candidates
            .iter()
            .filter(|candidate| candidate.selected_action.is_some())
            .collect();
        if selected.is_empty() {
            return Err(TransitionError::NoCandidateSelected);
        }
        if selected.iter().any(|candidate| {
            !matches!(
                candidate.save_verification,
                SaveVerification::UserAttested | SaveVerification::AdapterVerified
            )
        }) {
            return Err(TransitionError::SaveNotVerified);
        }
        if selected.iter().any(|candidate| !candidate.action_approved) {
            return Err(TransitionError::ActionNotApproved);
        }
        if !self.temporary_budget.restore.restore_values_captured
            || selected
                .iter()
                .any(|candidate| !candidate.restore.restore_values_captured)
        {
            return Err(TransitionError::RollbackNotReady);
        }
        self.dry_run_user_approval = true;
        self.phase = TransactionPhase::DryRunReady;
        Ok(())
    }

    pub(crate) fn expire(&mut self, now_unix_secs: u64) {
        if now_unix_secs >= self.temporary_budget.expires_at_unix_secs
            && !matches!(
                self.phase,
                TransactionPhase::Declined
                    | TransactionPhase::Expired
                    | TransactionPhase::NoRescueRequired
            )
        {
            self.phase = TransactionPhase::Expired;
            self.dry_run_user_approval = false;
        }
    }

    /// Records a before/after cgroup memory.current delta; it does not attribute causality.
    pub(crate) fn record_measurement(
        &mut self,
        workload: &str,
        observed_after_bytes: u64,
        now_unix_secs: u64,
    ) -> Result<(), TransitionError> {
        self.ensure_not_expired(now_unix_secs)?;
        if self.phase != TransactionPhase::DryRunReady {
            return Err(TransitionError::InvalidPhase);
        }
        let candidate = self
            .candidates
            .iter_mut()
            .find(|candidate| candidate.workload == workload)
            .ok_or(TransitionError::CandidateNotFound)?;
        if !candidate.action_approved {
            return Err(TransitionError::ActionNotApproved);
        }
        let before = candidate.baseline_memory_current_bytes;
        candidate.measurement = Some(ReclaimMeasurement {
            baseline_memory_current_bytes: before,
            observed_memory_current_bytes: observed_after_bytes,
            observed_reduction_bytes: before.saturating_sub(observed_after_bytes),
            observed_increase_bytes: observed_after_bytes.saturating_sub(before),
            interpretation: "observed memory.current delta only; concurrent activity means this is not causal proof of reclaimed memory",
        });
        Ok(())
    }
}

pub(crate) fn build_transaction(
    snapshot: &Snapshot,
    target_query: &str,
    extra_mib: u64,
    ttl_seconds: u64,
    now_unix_secs: u64,
) -> Result<RescueTransaction, PlanError> {
    if extra_mib == 0 {
        return Err(PlanError::InvalidHeadroom);
    }
    if !(MIN_TTL_SECONDS..=MAX_TTL_SECONDS).contains(&ttl_seconds) {
        return Err(PlanError::InvalidTtl);
    }
    let requested_headroom_bytes = extra_mib
        .checked_mul(MIB)
        .ok_or(PlanError::InvalidHeadroom)?;
    let expires_at_unix_secs = now_unix_secs
        .checked_add(ttl_seconds)
        .ok_or(PlanError::ExpiryOverflow)?;
    let query = target_query.trim().to_ascii_lowercase();
    if query.is_empty() {
        return Err(PlanError::TargetNotFound);
    }
    let target = snapshot
        .workloads
        .iter()
        .find(|workload| {
            workload.slice == "app.slice" && workload.name.to_ascii_lowercase().contains(&query)
        })
        .ok_or(PlanError::TargetNotFound)?;
    if is_protected_target(&target.name) {
        return Err(PlanError::ProtectedTarget);
    }
    if !safe_workload_path(&target.path) {
        return Err(PlanError::UnsafeTargetPath);
    }
    let target_current_bytes = target
        .memory_current_bytes
        .ok_or(PlanError::TargetMemoryUnavailable)?;
    let policy_plan = policy::rescue_plan(snapshot, &target.name, extra_mib);
    let (proposed_memory_high_bytes, proposed_memory_high_note) =
        if policy_plan.estimated_shortfall_bytes == 0 {
            (
                None,
                "no memory shortfall; no temporary cgroup budget is proposed",
            )
        } else {
            propose_memory_high(
                target.memory_high_limit.as_deref(),
                target.memory_max_limit.as_deref(),
                target_current_bytes,
                requested_headroom_bytes,
            )
        };
    let restore_values_captured = limits_captured(
        target.memory_high_limit.as_deref(),
        target.memory_max_limit.as_deref(),
    );
    let restore = RestorePlan {
        restore_memory_high_to: target.memory_high_limit.clone(),
        preserve_memory_max_at: target.memory_max_limit.clone(),
        restore_values_captured,
        status: "NOT_APPLIED_DRY_RUN; captured values are a restore plan, not proof rollback is executable",
    };
    let candidates = policy_plan
        .candidates
        .iter()
        .filter(|_| policy_plan.estimated_shortfall_bytes > 0)
        .filter_map(|planned| {
            let workload = snapshot.workloads.iter().find(|workload| {
                workload.slice == planned.slice && workload.name == planned.workload
            })?;
            if !safe_workload_path(&workload.path) {
                return None;
            }
            Some(RescueCandidateAction {
                workload: workload.name.clone(),
                cgroup_path: workload.path.clone(),
                baseline_memory_current_bytes: workload.memory_current_bytes?,
                estimated_reclaimable_bytes: None,
                selected_action: None,
                save_verification: SaveVerification::NotRequested,
                adapter_id: None,
                action_approved: false,
                measurement: None,
                restore: RestorePlan {
                    restore_memory_high_to: workload.memory_high_limit.clone(),
                    preserve_memory_max_at: workload.memory_max_limit.clone(),
                    restore_values_captured: limits_captured(
                        workload.memory_high_limit.as_deref(),
                        workload.memory_max_limit.as_deref(),
                    ),
                    status: "NOT_APPLIED_DRY_RUN; captured values are a restore plan, not proof rollback is executable",
                },
                pause_note: "pausing stops execution but does not itself release resident memory; graceful close may release memory only after the process exits",
            })
        })
        .collect();
    let slug: String = target
        .name
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-')
        .take(32)
        .collect::<String>()
        .trim_matches('-')
        .to_ascii_lowercase();
    Ok(RescueTransaction {
        schema_version: 1,
        transaction_id: format!("rescue-{now_unix_secs}-{slug}"),
        phase: if policy_plan.estimated_shortfall_bytes == 0 {
            TransactionPhase::NoRescueRequired
        } else {
            TransactionPhase::Proposed
        },
        target: target.name.clone(),
        target_cgroup_path: target.path.clone(),
        target_current_bytes,
        requested_extra_bytes: requested_headroom_bytes,
        estimated_shortfall_bytes: policy_plan.estimated_shortfall_bytes,
        reserve_target_bytes: policy_plan.reserve_target_bytes,
        system_available_bytes: policy_plan.system_available_bytes,
        temporary_budget: TemporaryBudgetOverride {
            requested_headroom_bytes,
            ttl_seconds,
            expires_at_unix_secs,
            previous_memory_high: target.memory_high_limit.clone(),
            previous_memory_max: target.memory_max_limit.clone(),
            proposed_memory_high_bytes,
            proposed_memory_high_note,
            memory_max_change: "PROHIBITED; memory.max is captured and left unchanged",
            applied: false,
            restore,
        },
        cgroup: CgroupCoordinationPlan {
            memory_controller_available: snapshot.cgroup_capabilities.memory_accounting_available
                || snapshot
                    .cgroup_capabilities
                    .controllers_available_to_children
                    .iter()
                    .any(|controller| controller == "memory"),
            memory_controller_enabled_for_children: snapshot
                .cgroup_capabilities
                .memory_controller_enabled_for_children,
            current_cgroup_subtree_write_open_probe: snapshot
                .cgroup_capabilities
                .subtree_control_write_open,
            target_write_access_revalidated: false,
            ancestor_limits_validated: false,
            enforcement_enabled: false,
            note: "controller visibility and the current-cgroup write-open probe do not prove target delegation or ancestor headroom; revalidate both before any future enforcement",
        },
        candidates,
        dry_run_user_approval: false,
        dry_run_only: true,
        enforcement_allowed: false,
        save_adapter_status: "NO_APPLICATION_ADAPTERS_REGISTERED; user attestation is not application verification",
        warning: "memory.current is an accounting charge, not guaranteed reclaimable memory. A before/after decrease is observational and may include unrelated activity. No process is paused or closed by this plan.",
        next_step: if policy_plan.estimated_shortfall_bytes == 0 {
            "No rescue action is currently required; continue monitoring and do not pause or close candidates."
        } else {
            "Select a candidate, request that the user save work, verify through a compatible adapter or record a clearly labeled user attestation, obtain separate pause/close consent, then approve the dry-run plan. Enforcement remains disabled."
        },
    })
}

fn propose_memory_high(
    previous_high: Option<&str>,
    previous_max: Option<&str>,
    current_bytes: u64,
    extra_bytes: u64,
) -> (Option<u64>, &'static str) {
    let Some(previous_high) = previous_high else {
        return (
            None,
            "memory.high is unavailable; no control change is proposed",
        );
    };
    if previous_high == "max" {
        return (
            None,
            "memory.high is already unlimited; no soft-limit change is needed",
        );
    }
    let Ok(previous_high_bytes) = previous_high.parse::<u64>() else {
        return (
            None,
            "memory.high could not be parsed; no control change is proposed",
        );
    };
    let Some(previous_max) = previous_max else {
        return (
            None,
            "memory.max is unavailable; the proposed soft limit cannot be bounded safely",
        );
    };
    let maximum_bytes = if previous_max == "max" {
        None
    } else {
        match previous_max.parse::<u64>() {
            Ok(value) => Some(value),
            Err(_) => {
                return (
                    None,
                    "memory.max could not be parsed; no control change is proposed",
                );
            }
        }
    };
    let Some(proposed) = current_bytes
        .max(previous_high_bytes)
        .checked_add(extra_bytes)
    else {
        return (
            None,
            "proposed memory.high would overflow; no control change is proposed",
        );
    };
    if maximum_bytes.is_some_and(|maximum| proposed > maximum) {
        return (
            None,
            "requested soft-limit extension exceeds the captured memory.max; no control change is proposed",
        );
    }
    (
        Some(proposed),
        "illustrative soft-limit extension only; ancestor headroom and target delegation are not validated",
    )
}

fn limits_captured(memory_high: Option<&str>, memory_max: Option<&str>) -> bool {
    fn valid_limit(value: &str) -> bool {
        value == "max" || value.parse::<u64>().is_ok()
    }
    memory_high.is_some_and(valid_limit) && memory_max.is_some_and(valid_limit)
}

fn safe_workload_path(path: &str) -> bool {
    let path = Path::new(path);
    path.is_absolute()
        && path.starts_with("/sys/fs/cgroup")
        && path != Path::new("/sys/fs/cgroup")
        && !path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
}

fn is_protected_target(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "remote-desktop-commander",
        "chatgpt",
        "openai",
        "codex",
        "agy",
        "alacritty",
        "konsole",
        "kwin",
        "plasma",
        "pipewire",
        "wireplumber",
        "dbus",
        "polkit",
        "scrcnexus",
        "nrg-agent",
    ]
    .iter()
    .any(|protected| name.contains(protected))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::{CgroupCapabilities, Memory, Pressure, PsiLine, WorkloadSnapshot};

    const GIB: u64 = 1024 * MIB;

    fn workload(name: &str, current: u64, high: &str, max: &str) -> WorkloadSnapshot {
        WorkloadSnapshot {
            slice: "app.slice".to_owned(),
            name: name.to_owned(),
            path: format!("/sys/fs/cgroup/user.slice/user-1000.slice/app.slice/{name}"),
            memory_current_bytes: Some(current),
            memory_high_limit: Some(high.to_owned()),
            memory_max_limit: Some(max.to_owned()),
            memory_anon_bytes: None,
            memory_file_bytes: None,
            cpu_usage_usec: None,
            pids_current: Some(10),
            io_read_bytes: 0,
            io_write_bytes: 0,
            memory_events: Default::default(),
            process_count_observed: 0,
            top_processes: Vec::new(),
            process_tree: Vec::new(),
            process_tree_truncated: false,
            executable_hints: Vec::new(),
        }
    }

    fn fixture() -> Snapshot {
        Snapshot {
            schema_version: 14,
            timestamp_unix_ms: 0,
            platform: "linux",
            process_details_collected: false,
            memory: Memory {
                total_bytes: Some(8 * GIB),
                available_bytes: Some(GIB),
                free_bytes: None,
                buffers_bytes: None,
                cached_bytes: None,
                reclaimable_slab_bytes: None,
                unreclaimable_slab_bytes: None,
                swap_total_bytes: Some(4 * GIB),
                swap_free_bytes: Some(2 * GIB),
                swap_used_bytes: Some(2 * GIB),
                committed_bytes: None,
                commit_limit_bytes: None,
                overcommit_mode: Some(0),
            },
            pressure: Pressure {
                some: Some(PsiLine {
                    avg10: Some(0.0),
                    avg60: Some(0.0),
                    avg300: Some(0.0),
                    total_us: Some(0),
                }),
                full: Some(PsiLine {
                    avg10: Some(0.0),
                    avg60: Some(0.0),
                    avg300: Some(0.0),
                    total_us: Some(0),
                }),
            },
            cpu_pressure: Pressure {
                some: None,
                full: None,
            },
            io_pressure: Pressure {
                some: None,
                full: None,
            },
            interrupts: Vec::new(),
            graphics: Vec::new(),
            display_connectors: Vec::new(),
            thermal_zones: Vec::new(),
            cpu_thermal_throttle: None,
            zram: None,
            vmstat: Default::default(),
            cgroup_v2: None,
            cgroup_capabilities: CgroupCapabilities {
                mount_detected: true,
                current_path: Some("/user.slice/user-1000.slice".to_owned()),
                controllers_available_to_children: vec!["memory".to_owned()],
                controllers_enabled_for_children: vec!["memory".to_owned()],
                memory_accounting_available: true,
                memory_controller_enabled_for_children: true,
                subtree_control_write_open: false,
            },
            workloads: vec![
                workload("app-game.service", 900 * MIB, "1073741824", "2147483648"),
                workload("app-editor.service", 600 * MIB, "max", "max"),
            ],
        }
    }

    fn transaction() -> RescueTransaction {
        build_transaction(&fixture(), "game", 256, 300, 1_000).unwrap()
    }

    #[test]
    fn transaction_captures_previous_limits_and_never_proposes_memory_max() {
        let tx = transaction();
        assert!(tx.dry_run_only);
        assert!(!tx.enforcement_allowed);
        assert!(!tx.temporary_budget.applied);
        assert_eq!(tx.temporary_budget.expires_at_unix_secs, 1_300);
        assert_eq!(
            tx.temporary_budget.previous_memory_high.as_deref(),
            Some("1073741824")
        );
        assert_eq!(
            tx.temporary_budget.previous_memory_max.as_deref(),
            Some("2147483648")
        );
        assert_eq!(
            tx.temporary_budget.proposed_memory_high_bytes,
            Some(1_342_177_280)
        );
        assert!(tx.temporary_budget.memory_max_change.contains("PROHIBITED"));
        assert!(tx.temporary_budget.restore.restore_values_captured);
        assert_eq!(
            tx.temporary_budget
                .restore
                .restore_memory_high_to
                .as_deref(),
            Some("1073741824")
        );
        assert!(tx.candidates[0].restore.restore_values_captured);
        assert_eq!(
            tx.candidates[0].restore.preserve_memory_max_at.as_deref(),
            Some("max")
        );
    }

    #[test]
    fn transaction_requires_save_and_separate_action_approval_before_dry_run() {
        let mut tx = transaction();
        tx.select_candidate(
            "app-editor.service",
            CandidateDisposition::CloseGracefully,
            1_001,
        )
        .unwrap();
        tx.request_save("app-editor.service", 1_001).unwrap();
        assert_eq!(
            tx.approve_dry_run(1_001, true),
            Err(TransitionError::SaveNotVerified)
        );
        tx.confirm_user_saved("app-editor.service", 1_001).unwrap();
        assert_eq!(
            tx.approve_dry_run(1_001, true),
            Err(TransitionError::ActionNotApproved)
        );
        tx.approve_candidate_action("app-editor.service", true, 1_001)
            .unwrap();
        tx.approve_dry_run(1_001, true).unwrap();
        assert_eq!(tx.phase, TransactionPhase::DryRunReady);
        assert!(tx.dry_run_user_approval);
        assert!(!tx.enforcement_allowed);
    }

    #[test]
    fn adapter_result_must_be_positive_and_named_to_verify_save() {
        let mut tx = transaction();
        tx.select_candidate("app-editor.service", CandidateDisposition::Pause, 1_001)
            .unwrap();
        tx.request_save("app-editor.service", 1_001).unwrap();
        tx.record_adapter_save_result("app-editor.service", "editor-api", false, 1_001)
            .unwrap();
        assert_eq!(
            tx.candidates[0].save_verification,
            SaveVerification::Unverified
        );
        assert_eq!(
            tx.approve_candidate_action("app-editor.service", true, 1_001),
            Err(TransitionError::SaveNotVerified)
        );
        tx.request_save("app-editor.service", 1_001).unwrap();
        tx.record_adapter_save_result("app-editor.service", "editor-api", true, 1_001)
            .unwrap();
        tx.approve_candidate_action("app-editor.service", true, 1_001)
            .unwrap();
        tx.approve_dry_run(1_001, true).unwrap();
        assert_eq!(
            tx.candidates[0].save_verification,
            SaveVerification::AdapterVerified
        );
    }

    #[test]
    fn expired_transaction_cannot_be_approved() {
        let mut tx = transaction();
        tx.select_candidate(
            "app-editor.service",
            CandidateDisposition::CloseGracefully,
            1_001,
        )
        .unwrap();
        tx.request_save("app-editor.service", 1_001).unwrap();
        tx.confirm_user_saved("app-editor.service", 1_001).unwrap();
        tx.approve_candidate_action("app-editor.service", true, 1_001)
            .unwrap();
        assert_eq!(
            tx.approve_dry_run(1_300, true),
            Err(TransitionError::Expired)
        );
        assert_eq!(tx.phase, TransactionPhase::Expired);
        assert!(!tx.dry_run_user_approval);
    }

    #[test]
    fn every_transition_rejects_an_expired_transaction() {
        let mut tx = transaction();
        assert_eq!(
            tx.select_candidate("app-editor.service", CandidateDisposition::Pause, 1_300),
            Err(TransitionError::Expired)
        );
        assert_eq!(tx.phase, TransactionPhase::Expired);

        let mut tx = transaction();
        tx.select_candidate("app-editor.service", CandidateDisposition::Pause, 1_001)
            .unwrap();
        tx.request_save("app-editor.service", 1_001).unwrap();
        tx.confirm_user_saved("app-editor.service", 1_001).unwrap();
        tx.approve_candidate_action("app-editor.service", true, 1_001)
            .unwrap();
        tx.approve_dry_run(1_001, true).unwrap();
        assert_eq!(
            tx.record_measurement("app-editor.service", 300 * MIB, 1_300),
            Err(TransitionError::Expired)
        );
        assert_eq!(tx.phase, TransactionPhase::Expired);
    }

    #[test]
    fn user_can_decline_before_saving_or_approving_any_action() {
        let mut tx = transaction();
        tx.approve_dry_run(1_001, false).unwrap();
        assert_eq!(tx.phase, TransactionPhase::Declined);
        assert!(!tx.dry_run_user_approval);
    }

    #[test]
    fn observed_memory_delta_is_not_misrepresented_as_causal_reclaim() {
        let mut tx = transaction();
        tx.select_candidate("app-editor.service", CandidateDisposition::Pause, 1_001)
            .unwrap();
        tx.request_save("app-editor.service", 1_001).unwrap();
        tx.confirm_user_saved("app-editor.service", 1_001).unwrap();
        tx.approve_candidate_action("app-editor.service", true, 1_001)
            .unwrap();
        tx.approve_dry_run(1_001, true).unwrap();
        tx.record_measurement("app-editor.service", 300 * MIB, 1_002)
            .unwrap();
        let measurement = tx.candidates[0].measurement.as_ref().unwrap();
        assert_eq!(measurement.observed_reduction_bytes, 300 * MIB);
        assert_eq!(measurement.observed_increase_bytes, 0);
        assert!(measurement.interpretation.contains("not causal proof"));
    }

    #[test]
    fn unlimited_memory_high_does_not_create_a_new_soft_limit() {
        let mut snapshot = fixture();
        snapshot.workloads[0].memory_high_limit = Some("max".to_owned());
        let tx = build_transaction(&snapshot, "game", 256, 300, 1_000).unwrap();
        assert_eq!(tx.temporary_budget.proposed_memory_high_bytes, None);
        assert!(
            tx.temporary_budget
                .proposed_memory_high_note
                .contains("already unlimited")
        );
    }

    #[test]
    fn proposed_soft_limit_never_exceeds_the_captured_hard_limit() {
        let mut snapshot = fixture();
        snapshot.workloads[0].memory_max_limit = Some("1200000000".to_owned());
        let tx = build_transaction(&snapshot, "game", 256, 300, 1_000).unwrap();
        assert_eq!(tx.temporary_budget.proposed_memory_high_bytes, None);
        assert!(
            tx.temporary_budget
                .proposed_memory_high_note
                .contains("exceeds the captured memory.max")
        );
    }

    #[test]
    fn no_shortfall_produces_no_candidates_or_rescue_actions() {
        let mut snapshot = fixture();
        snapshot.memory.available_bytes = Some(6 * GIB);
        let tx = build_transaction(&snapshot, "game", 256, 300, 1_000).unwrap();
        assert_eq!(tx.phase, TransactionPhase::NoRescueRequired);
        assert!(tx.candidates.is_empty());
        assert_eq!(tx.temporary_budget.proposed_memory_high_bytes, None);
        assert!(tx.next_step.contains("No rescue action"));
    }

    #[test]
    fn missing_candidate_restore_values_block_dry_run_approval() {
        let mut snapshot = fixture();
        snapshot.workloads[1].memory_high_limit = None;
        let mut tx = build_transaction(&snapshot, "game", 256, 300, 1_000).unwrap();
        tx.select_candidate(
            "app-editor.service",
            CandidateDisposition::CloseGracefully,
            1_001,
        )
        .unwrap();
        tx.request_save("app-editor.service", 1_001).unwrap();
        tx.confirm_user_saved("app-editor.service", 1_001).unwrap();
        tx.approve_candidate_action("app-editor.service", true, 1_001)
            .unwrap();
        assert_eq!(
            tx.approve_dry_run(1_001, true),
            Err(TransitionError::RollbackNotReady)
        );
        assert!(!tx.enforcement_allowed);
    }

    #[test]
    fn invalid_limit_contents_do_not_claim_restore_values_were_captured() {
        let mut snapshot = fixture();
        snapshot.workloads[0].memory_high_limit = Some("not-a-limit".to_owned());
        let mut tx = build_transaction(&snapshot, "game", 256, 300, 1_000).unwrap();
        tx.select_candidate(
            "app-editor.service",
            CandidateDisposition::CloseGracefully,
            1_001,
        )
        .unwrap();
        tx.request_save("app-editor.service", 1_001).unwrap();
        tx.confirm_user_saved("app-editor.service", 1_001).unwrap();
        tx.approve_candidate_action("app-editor.service", true, 1_001)
            .unwrap();
        assert_eq!(
            tx.approve_dry_run(1_001, true),
            Err(TransitionError::RollbackNotReady)
        );
    }

    #[test]
    fn unsafe_targets_and_invalid_ttls_are_rejected() {
        let mut snapshot = fixture();
        snapshot.workloads[0].path = "/sys/fs/cgroup/../../etc".to_owned();
        assert!(matches!(
            build_transaction(&snapshot, "game", 256, 300, 1_000),
            Err(PlanError::UnsafeTargetPath)
        ));
        assert!(matches!(
            build_transaction(&fixture(), "game", 256, 29, 1_000),
            Err(PlanError::InvalidTtl)
        ));
    }
}
