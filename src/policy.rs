//! Deterministic, read-only policy evaluation. This module never changes cgroups or processes.
use crate::linux::Snapshot;
use serde::Serialize;

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum PressureState {
    Normal,
    Watch,
    Pressure,
    Critical,
}

#[derive(Debug, Serialize)]
pub(crate) struct OomGuard {
    pub(crate) state: PressureState,
    pub(crate) available_bytes: Option<u64>,
    pub(crate) reserve_target_bytes: u64,
    pub(crate) psi_some_avg10: Option<f64>,
    pub(crate) psi_full_avg10: Option<f64>,
    pub(crate) recommended_response: &'static str,
    pub(crate) automatic_termination_allowed: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct RescueCandidate {
    pub(crate) workload: String,
    pub(crate) slice: String,
    pub(crate) current_bytes: u64,
    pub(crate) estimated_upper_bound_bytes: u64,
    pub(crate) action: &'static str,
    pub(crate) reason: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct RescuePlan {
    pub(crate) mode: &'static str,
    pub(crate) target: String,
    pub(crate) target_current_bytes: Option<u64>,
    pub(crate) requested_extra_bytes: u64,
    pub(crate) system_available_bytes: Option<u64>,
    pub(crate) reserve_target_bytes: u64,
    pub(crate) estimated_shortfall_bytes: u64,
    pub(crate) candidates: Vec<RescueCandidate>,
    pub(crate) execution: &'static str,
    pub(crate) warning: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct PolicyReport {
    pub(crate) oom_guard: OomGuard,
    pub(crate) rescue_guidance: &'static str,
}

pub(crate) fn evaluate(snapshot: &Snapshot) -> PolicyReport {
    let total = snapshot.memory.total_bytes.unwrap_or(8 * GIB);
    let available = snapshot.memory.available_bytes;
    let reserve = (total / 4).clamp(512 * MIB, 2 * GIB);
    let some = snapshot.pressure.some.as_ref().and_then(|p| p.avg10);
    let full = snapshot.pressure.full.as_ref().and_then(|p| p.avg10);
    let state = if available.is_some_and(|v| v < 384 * MIB) || full.is_some_and(|v| v >= 2.0) {
        PressureState::Critical
    } else if available.is_some_and(|v| v < reserve / 2) || full.is_some_and(|v| v >= 0.5) {
        PressureState::Pressure
    } else if available.is_some_and(|v| v < reserve) || some.is_some_and(|v| v >= 2.0) {
        PressureState::Watch
    } else {
        PressureState::Normal
    };
    let response = match state {
        PressureState::Normal => "observe; keep adaptive reserve available to workloads",
        PressureState::Watch => "warn and identify high-memory workloads; do not throttle yet",
        PressureState::Pressure => {
            "offer Rescue Mode; ask the user to save before closing or pausing an app"
        }
        PressureState::Critical => {
            "emergency warning; prioritize user-approved save/close actions; never silently kill"
        }
    };
    PolicyReport {
        oom_guard: OomGuard {
            state,
            available_bytes: available,
            reserve_target_bytes: reserve,
            psi_some_avg10: some,
            psi_full_avg10: full,
            recommended_response: response,
            automatic_termination_allowed: false,
        },
        rescue_guidance: "Use a temporary, expiring budget override only after a user-approved workload handoff; restore prior budgets afterward.",
    }
}

pub(crate) fn rescue_plan(snapshot: &Snapshot, target_query: &str, extra_mib: u64) -> RescuePlan {
    let target = snapshot
        .workloads
        .iter()
        .find(|w| w.name.to_lowercase().contains(&target_query.to_lowercase()));
    let target_name = target
        .map(|w| w.name.clone())
        .unwrap_or_else(|| target_query.to_owned());
    let target_current = target.and_then(|w| w.memory_current_bytes);
    let total = snapshot.memory.total_bytes.unwrap_or(8 * GIB);
    let reserve = (total / 4).clamp(512 * MIB, 2 * GIB);
    let available = snapshot.memory.available_bytes;
    let requested = extra_mib.saturating_mul(MIB);
    let shortfall = available
        .map(|v| reserve.saturating_add(requested).saturating_sub(v))
        .unwrap_or(requested);
    let current_cgroup_path = snapshot
        .cgroup_v2
        .as_ref()
        .map(|c| format!("/sys/fs/cgroup{}", c.path));
    let mut candidates: Vec<_> = snapshot.workloads.iter().filter(|w| {
        if w.name == target_name || w.slice != "app.slice" { return false; }
        if current_cgroup_path.as_deref() == Some(w.path.as_str()) { return false; }
        let n = w.name.to_lowercase();
        // Protect desktop/session infrastructure and the governor itself.
        !["remote-desktop-commander", "kwin", "plasma", "pipewire", "wireplumber", "dbus", "polkit", "scrcnexus", "nrg-agent"]
            .iter().any(|protected| n.contains(protected))
    }).filter_map(|w| {
        let current = w.memory_current_bytes?;
        if current < 128 * MIB { return None; }
        Some(RescueCandidate { workload: w.name.clone(), slice: w.slice.clone(), current_bytes: current,
            estimated_upper_bound_bytes: current, action: "ask_user_to_save_then_close_or_pause",
            reason: "user application; reclaim is only an upper bound and requires explicit user action" })
    }).collect();
    candidates.sort_by_key(|w| std::cmp::Reverse(w.current_bytes));
    RescuePlan {
        mode: "DRY_RUN_ONLY",
        target: target_name,
        target_current_bytes: target_current,
        requested_extra_bytes: requested,
        system_available_bytes: available,
        reserve_target_bytes: reserve,
        estimated_shortfall_bytes: shortfall,
        candidates,
        execution: "no process or memory limit was changed",
        warning: "A cgroup memory.current value is not guaranteed reclaimable memory. NRG cannot save arbitrary app state; save must be confirmed by the application or user.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reserve_is_adaptive_and_bounded() {
        assert_eq!((8 * GIB / 4).clamp(512 * MIB, 2 * GIB), 2 * GIB);
        assert_eq!((2 * GIB / 4).clamp(512 * MIB, 2 * GIB), 512 * MIB);
    }
    fn fixture(available: u64) -> Snapshot {
        use crate::linux::{Memory, Pressure, PsiLine};
        Snapshot {
            schema_version: 2,
            timestamp_unix_ms: 0,
            platform: "linux",
            memory: Memory {
                total_bytes: Some(8 * GIB),
                available_bytes: Some(available),
                free_bytes: None,
                buffers_bytes: None,
                cached_bytes: None,
                reclaimable_slab_bytes: None,
                unreclaimable_slab_bytes: None,
                swap_total_bytes: None,
                swap_free_bytes: None,
                swap_used_bytes: None,
                committed_bytes: None,
                commit_limit_bytes: None,
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
            zram: None,
            vmstat: Default::default(),
            cgroup_v2: None,
            cgroup_capabilities: crate::linux::CgroupCapabilities {
                mount_detected: false,
                current_path: None,
                controllers_available_to_children: vec![],
                controllers_enabled_for_children: vec![],
                memory_accounting_available: false,
                memory_controller_enabled_for_children: false,
                subtree_control_write_open: false,
            },
            workloads: vec![],
        }
    }

    #[test]
    fn oom_guard_never_terminates_automatically() {
        let report = evaluate(&fixture(128 * MIB));
        assert_eq!(report.oom_guard.state, PressureState::Critical);
        assert!(!report.oom_guard.automatic_termination_allowed);
    }

    #[test]
    fn rescue_plan_excludes_decoded_protected_workloads() {
        use crate::linux::WorkloadSnapshot;
        let mut snapshot = fixture(3 * GIB);
        let workload = |slice: &str, name: &str, memory: u64| WorkloadSnapshot {
            slice: slice.to_owned(),
            name: name.to_owned(),
            path: format!("/sys/fs/cgroup/user.slice/{slice}/{name}"),
            memory_current_bytes: Some(memory),
            memory_anon_bytes: None,
            memory_file_bytes: None,
            cpu_usage_usec: None,
            pids_current: Some(10),
            io_read_bytes: 0,
            io_write_bytes: 0,
            memory_events: Default::default(),
            process_count_observed: 0,
            top_processes: Vec::new(),
        };
        snapshot.workloads = vec![
            workload(
                "app.slice",
                "app-Remote-Desktop-Commander@session.service",
                600 * MIB,
            ),
            workload("session.slice", "plasma-kwin_wayland.service", 500 * MIB),
            workload("app.slice", "app-editor.service", 400 * MIB),
        ];
        let plan = rescue_plan(&snapshot, "editor", 512);
        assert_eq!(plan.candidates.len(), 0);
        assert!(
            !plan
                .candidates
                .iter()
                .any(|candidate| candidate.workload.contains("Remote-Desktop-Commander"))
        );
    }

    #[test]
    fn normal_memory_does_not_trigger_pressure() {
        assert_eq!(
            evaluate(&fixture(3 * GIB)).oom_guard.state,
            PressureState::Normal
        );
    }
}
