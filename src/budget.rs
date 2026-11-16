//! Deterministic adaptive memory-budget planner. It only emits proposals; it never writes cgroups.
use crate::linux::{Snapshot, WorkloadSnapshot};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::path::PathBuf;

const MIB: u64 = 1024 * 1024;
const MIN_APP_BYTES: u64 = 16 * MIB;
const MAX_HISTORY_BYTES: u64 = 8 * 1024 * 1024;
const MAX_SAMPLES_PER_APP: usize = 1_000;

#[derive(Debug, Deserialize)]
struct HistorySample {
    workloads: Vec<HistoryWorkload>,
}

#[derive(Debug, Deserialize)]
struct HistoryWorkload {
    name: String,
    memory_current_bytes: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct UserProfileFile {
    profiles: BTreeMap<String, UserProfile>,
}

#[derive(Debug, Deserialize)]
struct UserProfile {
    priorities: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct BudgetPlan {
    pub(crate) schema_version: u32,
    pub(crate) profile: String,
    pub(crate) physical_ram_total_bytes: Option<u64>,
    pub(crate) system_reserve_target_bytes: Option<u64>,
    pub(crate) allocatable_app_budget_bytes: Option<u64>,
    pub(crate) history_samples_loaded: usize,
    pub(crate) status: &'static str,
    pub(crate) enforcement_enabled: bool,
    pub(crate) workloads: Vec<WorkloadBudget>,
    pub(crate) explanation: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct WorkloadBudget {
    pub(crate) workload: String,
    pub(crate) application_key: String,
    pub(crate) current_bytes: u64,
    pub(crate) historical_samples: usize,
    pub(crate) historical_p95_bytes: Option<u64>,
    pub(crate) estimated_demand_bytes: u64,
    pub(crate) priority_rank: u8,
    pub(crate) priority: &'static str,
    pub(crate) previous_memory_high: Option<String>,
    pub(crate) proposed_memory_high_bytes: Option<u64>,
    pub(crate) preserved_memory_max: Option<String>,
    pub(crate) decision: &'static str,
}

struct Candidate {
    output: WorkloadBudget,
    floor_bytes: u64,
    desired_bytes: u64,
    hard_max_bytes: Option<u64>,
    hard_max_unlimited: bool,
}

pub(crate) fn build_plan(snapshot: &Snapshot, requested_profile: &str) -> BudgetPlan {
    let (history, history_samples_loaded) = load_history();
    build_plan_with_history(
        snapshot,
        requested_profile,
        &history,
        history_samples_loaded,
    )
}

fn build_plan_with_history(
    snapshot: &Snapshot,
    requested_profile: &str,
    history: &BTreeMap<String, VecDeque<u64>>,
    history_samples_loaded: usize,
) -> BudgetPlan {
    let profile = normalize_profile(requested_profile);
    let custom_priorities = load_custom_priorities(&profile);
    let total = snapshot.memory.total_bytes;
    let reserve = total.map(|bytes| (bytes / 4).clamp(512 * MIB, 2 * 1024 * MIB));
    let allocatable = total
        .zip(reserve)
        .map(|(total, reserve)| total.saturating_sub(reserve));

    let mut candidates = Vec::new();
    for workload in snapshot
        .workloads
        .iter()
        .filter(|workload| is_application(workload))
    {
        let current = workload.memory_current_bytes.unwrap_or(0);
        let key = application_key(&workload.name);
        let samples = history.get(&key);
        let sample_count = samples.map_or(0, VecDeque::len);
        let p95 = samples.and_then(percentile_95);
        // Until enough observations exist, use a larger bootstrap margin.
        let demand_basis = p95.unwrap_or(current);
        let margin_percent = if sample_count >= 5 { 110 } else { 135 };
        let estimated = demand_basis
            .saturating_mul(margin_percent)
            .saturating_div(100)
            .max(current);
        // Keep a small safety gap above current usage so a new soft limit does not
        // immediately force reclaim just because the plan was calculated.
        let floor = current.saturating_add((current / 20).max(64 * MIB));
        let desired = estimated.max(floor);
        let (rank, priority) = priority_for(&profile, &key, custom_priorities.as_deref());
        let (hard_max_bytes, hard_max_unlimited) = match workload.memory_max_limit.as_deref() {
            Some("max") => (None, true),
            Some(value) => (value.parse::<u64>().ok(), false),
            None => (None, false),
        };
        let decision = if sample_count >= 5 {
            "history_based_estimate"
        } else {
            "bootstrap_estimate_needs_more_samples"
        };
        candidates.push(Candidate {
            output: WorkloadBudget {
                workload: workload.name.clone(),
                application_key: key,
                current_bytes: current,
                historical_samples: sample_count,
                historical_p95_bytes: p95,
                estimated_demand_bytes: estimated,
                priority_rank: rank,
                priority,
                previous_memory_high: workload.memory_high_limit.clone(),
                proposed_memory_high_bytes: None,
                preserved_memory_max: workload.memory_max_limit.clone(),
                decision,
            },
            floor_bytes: floor,
            desired_bytes: desired,
            hard_max_bytes,
            hard_max_unlimited,
        });
    }

    candidates.sort_by(|a, b| {
        a.output
            .priority_rank
            .cmp(&b.output.priority_rank)
            .then_with(|| a.output.application_key.cmp(&b.output.application_key))
    });

    let floor_total = candidates
        .iter()
        .fold(0_u64, |sum, item| sum.saturating_add(item.floor_bytes));
    let hard_limit_conflict = candidates.iter().any(|item| {
        !item.hard_max_unlimited
            && item
                .hard_max_bytes
                .is_none_or(|maximum| maximum < item.floor_bytes)
    });

    let status = match allocatable {
        None => "INSUFFICIENT_TELEMETRY_NO_PROPOSALS",
        Some(_capacity) if hard_limit_conflict => "EXISTING_HARD_LIMIT_CONFLICT_NO_PROPOSALS",
        Some(capacity) if floor_total > capacity => "OVERCOMMITTED_NO_SAFE_SOFT_LIMITS",
        Some(capacity) => {
            let mut remaining = capacity.saturating_sub(floor_total);
            for item in &mut candidates {
                let extra = item
                    .desired_bytes
                    .saturating_sub(item.floor_bytes)
                    .min(remaining);
                remaining = remaining.saturating_sub(extra);
                let mut proposed = item.floor_bytes.saturating_add(extra);
                if let Some(maximum) = item.hard_max_bytes {
                    proposed = proposed.min(maximum);
                }
                item.output.proposed_memory_high_bytes = Some(proposed);
                if proposed < item.desired_bytes {
                    item.output.decision = "constrained_by_profile_priority_and_system_reserve";
                }
            }
            if candidates.iter().any(|item| {
                item.output.decision == "constrained_by_profile_priority_and_system_reserve"
            }) {
                "PRIORITY_CONSTRAINED_WITHIN_RESERVE"
            } else {
                "ALL_ESTIMATED_DEMAND_FITS_WITHIN_RESERVE"
            }
        }
    };

    if !matches!(
        status,
        "ALL_ESTIMATED_DEMAND_FITS_WITHIN_RESERVE" | "PRIORITY_CONSTRAINED_WITHIN_RESERVE"
    ) {
        for item in &mut candidates {
            item.output.proposed_memory_high_bytes = None;
            item.output.decision = "no_safe_proposal";
        }
    }

    BudgetPlan {
        schema_version: 1,
        profile,
        physical_ram_total_bytes: total,
        system_reserve_target_bytes: reserve,
        allocatable_app_budget_bytes: allocatable,
        history_samples_loaded,
        status,
        enforcement_enabled: false,
        workloads: candidates.into_iter().map(|item| item.output).collect(),
        explanation: "memory.high values are dry-run soft-limit proposals only. memory.max is never changed. Current usage plus a safety gap is protected; if those floors cannot fit inside the system reserve, NRG refuses to propose limits.",
    }
}

fn normalize_profile(profile: &str) -> String {
    let normalized = profile.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "gaming" | "game" => "gaming".to_owned(),
        "study" | "school" => "study".to_owned(),
        "work" => "work".to_owned(),
        "development" | "dev" | "coding" => "development".to_owned(),
        "balanced" => "balanced".to_owned(),
        _ if !normalized.is_empty()
            && normalized.len() <= 32
            && normalized
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') =>
        {
            normalized
        }
        _ => "balanced".to_owned(),
    }
}

fn load_custom_priorities(profile: &str) -> Option<Vec<String>> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
    let path = base.join("nrg").join("profiles.json");
    let raw = fs::read_to_string(path).ok()?;
    let config: UserProfileFile = serde_json::from_str(&raw).ok()?;
    let entry = config
        .profiles
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(profile))
        .map(|(_, entry)| entry)?;
    if entry.priorities.len() > 64 {
        return None;
    }
    let values: Vec<String> = entry
        .priorities
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 80
                && value
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
        })
        .take(64)
        .collect();
    Some(values)
}

fn priority_for(profile: &str, key: &str, custom: Option<&[String]>) -> (u8, &'static str) {
    if let Some(patterns) = custom {
        if let Some(index) = patterns.iter().position(|pattern| key.contains(pattern)) {
            return (
                index.saturating_add(1).min(u8::MAX as usize) as u8,
                "CUSTOM",
            );
        }
        return (100, "NORMAL");
    }
    let patterns: &[&str] = match profile {
        "gaming" => &["geforcenow", "geometry", "steam", "gamescope", "bottles"],
        "study" => &[
            "wordcraft",
            "libreoffice",
            "onlyoffice",
            "chatgpt",
            "openai",
            "firefox",
            "chromium",
            "brave",
        ],
        "work" => &[
            "chatgpt",
            "wordcraft",
            "libreoffice",
            "onlyoffice",
            "firefox",
            "chromium",
            "brave",
            "spotify",
        ],
        "development" => &[
            "codium",
            "code",
            "jetbrains",
            "alacritty",
            "konsole",
            "terminal",
            "codex",
            "agy",
            "chatgpt",
            "openai",
            "chromium",
            "firefox",
        ],
        _ => &[
            "chatgpt",
            "openai",
            "wordcraft",
            "geforcenow",
            "geometry",
            "chromium",
            "firefox",
            "brave",
        ],
    };
    patterns
        .iter()
        .position(|pattern| key.contains(pattern))
        .map(|index| (index.saturating_add(1) as u8, "HIGHER"))
        .unwrap_or((100, "NORMAL"))
}

fn is_application(workload: &WorkloadSnapshot) -> bool {
    if workload.slice != "app.slice"
        || !workload.name.starts_with("app-")
        || workload.memory_current_bytes.unwrap_or(0) < MIN_APP_BYTES
    {
        return false;
    }
    let name = workload.name.to_ascii_lowercase();
    ![
        "remote-desktop-commander",
        "nrg-monitor",
        "dbus",
        "kwin",
        "plasma",
        "pipewire",
        "wireplumber",
        "portal",
        "polkit",
        "discover",
        "baloo",
        "kded",
        "kscreen",
        "kwallet",
        "autostart",
        "xdg-",
    ]
    .iter()
    .any(|excluded| name.contains(excluded))
}

fn application_key(name: &str) -> String {
    let mut key = name.strip_prefix("app-").unwrap_or(name).to_owned();
    if let Some((prefix, _)) = key.split_once('@') {
        key = prefix.to_owned();
    }
    if let Some(scope) = key.strip_suffix(".scope") {
        key = scope.to_owned();
        if let Some((prefix, suffix)) = key.rsplit_once('-') {
            if !suffix.is_empty() && suffix.chars().all(|ch| ch.is_ascii_digit()) {
                key = prefix.to_owned();
            }
        }
    }
    if let Some(service) = key.strip_suffix(".service") {
        key = service.to_owned();
    }
    key.to_ascii_lowercase()
}

fn percentile_95(samples: &VecDeque<u64>) -> Option<u64> {
    if samples.is_empty() {
        return None;
    }
    let mut sorted: Vec<u64> = samples.iter().copied().collect();
    sorted.sort_unstable();
    let index = (sorted.len() * 95).div_ceil(100).saturating_sub(1);
    sorted.get(index).copied()
}

fn load_history() -> (BTreeMap<String, VecDeque<u64>>, usize) {
    let root = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")));
    let Some(root) = root else {
        return (BTreeMap::new(), 0);
    };
    let directory = root.join("nrg");
    let mut history = BTreeMap::<String, VecDeque<u64>>::new();
    let mut valid_samples = 0usize;
    for path in [
        directory.join("telemetry.jsonl.1"),
        directory.join("telemetry.jsonl"),
    ] {
        let Ok(metadata) = fs::metadata(&path) else {
            continue;
        };
        if metadata.len() > MAX_HISTORY_BYTES {
            continue;
        }
        let Ok(contents) = fs::read_to_string(path) else {
            continue;
        };
        for line in contents.lines() {
            let Ok(sample) = serde_json::from_str::<HistorySample>(line) else {
                continue;
            };
            valid_samples = valid_samples.saturating_add(1);
            for workload in sample.workloads {
                let Some(memory) = workload.memory_current_bytes else {
                    continue;
                };
                let key = application_key(&workload.name);
                if key.is_empty() {
                    continue;
                }
                let values = history.entry(key).or_default();
                values.push_back(memory);
                if values.len() > MAX_SAMPLES_PER_APP {
                    values.pop_front();
                }
            }
        }
    }
    (history, valid_samples)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn application_identity_normalizes_systemd_instance_suffixes() {
        assert_eq!(
            application_key("app-org.chromium.Chromium-1484.scope"),
            "org.chromium.chromium"
        );
        assert_eq!(application_key("app-chatgpt@instance.service"), "chatgpt");
    }

    #[test]
    fn profile_priorities_change_by_context() {
        assert!(
            priority_for("gaming", "com.nvidia.geforcenow", None).0
                < priority_for("study", "com.nvidia.geforcenow", None).0
        );
        assert!(
            priority_for("study", "chatgpt", None).0 < priority_for("gaming", "chatgpt", None).0
        );
    }

    #[test]
    fn work_profile_prioritizes_productivity_apps_over_browser_extras() {
        let (chatgpt_rank, _) = priority_for("work", "chatgpt", None);
        let (libreoffice_rank, _) = priority_for("work", "libreoffice", None);
        let (firefox_rank, _) = priority_for("work", "firefox", None);
        let (spotify_rank, _) = priority_for("work", "spotify", None);
        assert!(chatgpt_rank < firefox_rank);
        assert!(libreoffice_rank < spotify_rank);
    }

    #[test]
    fn custom_profile_priorities_override_builtin_order() {
        let custom = vec!["browser".to_owned(), "geforcenow".to_owned()];
        assert_eq!(
            priority_for("custom", "com.nvidia.geforcenow", Some(&custom)).0,
            2
        );
        assert_eq!(priority_for("custom", "org.browser", Some(&custom)).0, 1);
        assert_eq!(priority_for("custom", "chatgpt", Some(&custom)).0, 100);
    }

    #[test]
    fn percentile_uses_nearest_rank_p95() {
        let samples = VecDeque::from([100, 200, 300, 400, 500]);
        assert_eq!(percentile_95(&samples), Some(500));
    }

    #[test]
    fn planner_allocates_remaining_headroom_by_active_profile_priority() {
        let mut snapshot = fixture();
        snapshot.workloads = vec![
            workload("app-chatgpt.service", 1_700 * MIB),
            workload("app-browser.service", 1_700 * MIB),
            workload("app-com.nvidia.geforcenow.service", 1_700 * MIB),
        ];
        let plan = build_plan_with_history(&snapshot, "gaming", &BTreeMap::new(), 0);
        assert_eq!(plan.status, "PRIORITY_CONSTRAINED_WITHIN_RESERVE");
        let game = plan
            .workloads
            .iter()
            .find(|item| item.application_key.contains("geforcenow"))
            .unwrap();
        let browser = plan
            .workloads
            .iter()
            .find(|item| item.application_key == "browser")
            .unwrap();
        let chat = plan
            .workloads
            .iter()
            .find(|item| item.application_key == "chatgpt")
            .unwrap();
        assert!(game.proposed_memory_high_bytes > browser.proposed_memory_high_bytes);
        assert!(browser.proposed_memory_high_bytes > chat.proposed_memory_high_bytes);
        assert!(!plan.enforcement_enabled);
    }

    #[test]
    fn planner_refuses_limits_when_current_usage_floors_exceed_capacity() {
        let mut snapshot = fixture();
        snapshot.workloads = vec![
            workload("app-game.service", 4 * 1024 * MIB),
            workload("app-browser.service", 3 * 1024 * MIB),
        ];
        let plan = build_plan_with_history(&snapshot, "gaming", &BTreeMap::new(), 0);
        assert_eq!(plan.status, "OVERCOMMITTED_NO_SAFE_SOFT_LIMITS");
        assert!(
            plan.workloads
                .iter()
                .all(|item| item.proposed_memory_high_bytes.is_none())
        );
    }

    #[test]
    fn planner_preserves_hard_limits_and_prioritizes_active_profile() {
        let mut snapshot = fixture();
        snapshot.workloads = vec![
            workload("app-browser.service", 512 * MIB),
            workload("app-com.nvidia.geforcenow.service", 1024 * MIB),
        ];
        let plan = build_plan_with_history(&snapshot, "gaming", &BTreeMap::new(), 0);
        assert_eq!(plan.status, "ALL_ESTIMATED_DEMAND_FITS_WITHIN_RESERVE");
        assert!(plan.workloads[0].application_key.contains("geforcenow"));
        assert_eq!(plan.workloads[0].priority, "HIGHER");
        assert!(
            plan.workloads
                .iter()
                .all(|item| item.preserved_memory_max.as_deref() == Some("max"))
        );
        assert!(!plan.enforcement_enabled);
    }

    fn fixture() -> Snapshot {
        use crate::linux::{CgroupCapabilities, Memory, Pressure};
        Snapshot {
            schema_version: 14,
            timestamp_unix_ms: 0,
            platform: "linux",
            process_details_collected: false,
            memory: Memory {
                total_bytes: Some(8 * 1024 * MIB),
                available_bytes: Some(4 * 1024 * MIB),
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
                overcommit_mode: Some(0),
            },
            pressure: Pressure {
                some: None,
                full: None,
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
                mount_detected: false,
                current_path: None,
                controllers_available_to_children: vec![],
                controllers_enabled_for_children: vec![],
                memory_accounting_available: false,
                memory_controller_enabled_for_children: false,
                subtree_control_write_open: false,
            },
            workloads: Vec::new(),
        }
    }

    fn workload(name: &str, memory: u64) -> WorkloadSnapshot {
        WorkloadSnapshot {
            slice: "app.slice".to_owned(),
            name: name.to_owned(),
            path: format!("/test/{name}"),
            memory_current_bytes: Some(memory),
            memory_high_limit: Some("max".to_owned()),
            memory_max_limit: Some("max".to_owned()),
            memory_anon_bytes: None,
            memory_file_bytes: None,
            cpu_usage_usec: None,
            pids_current: Some(1),
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
}
