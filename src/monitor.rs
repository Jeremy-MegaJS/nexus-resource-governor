//! Lightweight, notification-only monitor state. No resource controls are applied.
use crate::linux::{Snapshot, WorkloadSnapshot};
use crate::policy::{self, PressureState};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

const MIB: u64 = 1024 * 1024;
const MIN_APP_BYTES: u64 = 16 * MIB;

#[derive(Debug, Clone)]
pub(crate) struct Notification {
    pub(crate) title: String,
    pub(crate) body: String,
    pub(crate) critical: bool,
}

#[derive(Debug, Clone, Copy)]
struct Budget {
    warning_bytes: u64,
    critical_bytes: u64,
}

#[derive(Debug)]
struct Budgets {
    default: Budget,
    per_app: BTreeMap<String, Budget>,
}

impl Budgets {
    fn load(total_bytes: Option<u64>) -> Self {
        let total = total_bytes.unwrap_or(8 * 1024 * MIB);
        let default = Budget {
            warning_bytes: (total / 5).max(1024 * MIB),
            critical_bytes: (total * 35 / 100).max(2 * 1024 * MIB),
        };
        let mut budgets = Self {
            default,
            per_app: BTreeMap::new(),
        };
        let Some(home) = std::env::var_os("HOME") else {
            return budgets;
        };
        let path = PathBuf::from(home).join(".config/nrg/budgets.conf");
        let Ok(contents) = fs::read_to_string(path) else {
            return budgets;
        };
        for line in contents.lines().take(128).map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((name, values)) = line.split_once('=') else {
                continue;
            };
            let Some((warning, critical)) = values.split_once(',') else {
                continue;
            };
            let (Ok(warning), Ok(critical)) = (
                warning.trim().parse::<u64>(),
                critical.trim().parse::<u64>(),
            ) else {
                continue;
            };
            if warning == 0 || critical <= warning {
                continue;
            }
            let budget = Budget {
                warning_bytes: warning.saturating_mul(MIB),
                critical_bytes: critical.saturating_mul(MIB),
            };
            let key = name.trim().to_ascii_lowercase();
            if key == "default" {
                budgets.default = budget;
            } else if !key.is_empty() {
                budgets.per_app.insert(key, budget);
            }
        }
        budgets
    }

    fn for_workload(&self, workload: &WorkloadSnapshot) -> Budget {
        let key = application_key(&workload.name);
        self.per_app
            .iter()
            .filter(|(name, _)| key == name.as_str() || key.starts_with(&format!("{}-", name)))
            .max_by_key(|(name, _)| name.len())
            .map(|(_, budget)| *budget)
            .unwrap_or(self.default)
    }
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

fn is_user_application(workload: &WorkloadSnapshot) -> bool {
    if workload.slice != "app.slice"
        || !workload.name.starts_with("app-")
        || workload.memory_current_bytes.unwrap_or(0) < MIN_APP_BYTES
    {
        return false;
    }
    let name = workload.name.to_ascii_lowercase();
    ![
        "remote-desktop-commander",
        "dbus",
        "kde.",
        "kwallet",
        "portal",
        "pipewire",
        "wireplumber",
        "autostart",
        "discover",
        "baloo",
        "xdg-",
        "klauncher",
        "kded",
        "kscreen",
        "plasma",
        "polkit",
        "ibus",
        "fcitx",
    ]
    .iter()
    .any(|excluded| name.contains(excluded))
}

fn format_mib(bytes: u64) -> String {
    format!("{:.0} MiB", bytes as f64 / MIB as f64)
}

#[derive(Debug, Default)]
pub(crate) struct MonitorState {
    initialized: bool,
    known_workloads: BTreeSet<String>,
    workload_severity: BTreeMap<String, u8>,
    workload_memory_events: BTreeMap<String, BTreeMap<String, u64>>,
    kernel_oom_kills: Option<u64>,
    vmstat_counters: BTreeMap<String, u64>,
    reclaim_cooldown_samples: u8,
    cpu_core_throttle_total_ms: Option<u64>,
    cpu_package_throttle_total_ms: Option<u64>,
    thermal_throttle_cooldown_samples: u8,
    pressure_state: Option<PressureState>,
    normal_samples: u8,
    budgets: Option<Budgets>,
}

impl MonitorState {
    pub(crate) fn update(&mut self, snapshot: &Snapshot) -> Vec<Notification> {
        if self.budgets.is_none() {
            self.budgets = Some(Budgets::load(snapshot.memory.total_bytes));
        }
        let budgets = self.budgets.as_ref().expect("budgets initialized");
        let mut notifications = Vec::new();
        let active_workloads: BTreeSet<String> = snapshot
            .workloads
            .iter()
            .filter(|workload| is_user_application(workload))
            .map(|workload| workload.path.clone())
            .collect();
        self.known_workloads
            .retain(|path| active_workloads.contains(path));
        self.workload_severity
            .retain(|path, _| active_workloads.contains(path));
        self.workload_memory_events
            .retain(|path, _| active_workloads.contains(path));

        for workload in snapshot.workloads.iter().filter(|w| is_user_application(w)) {
            let current = workload.memory_current_bytes.unwrap_or(0);
            let budget = budgets.for_workload(workload);
            let previous_severity = self
                .workload_severity
                .get(&workload.path)
                .copied()
                .unwrap_or(0);
            let severity = if current >= budget.critical_bytes {
                2
            } else if current >= budget.warning_bytes {
                1
            } else {
                0
            };
            let was_known = self.known_workloads.contains(&workload.path);
            let is_new = self.initialized && !was_known;
            self.known_workloads.insert(workload.path.clone());
            let previous_events = self
                .workload_memory_events
                .insert(workload.path.clone(), workload.memory_events.clone());
            let mut new_events = Vec::new();
            if let Some(previous) = previous_events {
                for (event, label) in [
                    ("high", "memory.high pressure"),
                    ("max", "memory.max boundary"),
                    ("oom", "cgroup OOM condition"),
                    ("oom_kill", "OOM kill"),
                ] {
                    let current = workload.memory_events.get(event).copied().unwrap_or(0);
                    let old = previous.get(event).copied().unwrap_or(0);
                    if current > old {
                        new_events.push(format!("{} new {label} event(s)", current - old));
                    }
                }
            }
            if !new_events.is_empty() {
                let critical = new_events
                    .iter()
                    .any(|event| event.contains("memory.max") || event.contains("OOM"));
                notifications.push(Notification {
                    title: format!("NRG memory event: {}", application_key(&workload.name)),
                    body: new_events.join("; "),
                    critical,
                });
            }

            let app_label = application_key(&workload.name);
            if severity > previous_severity {
                let threshold = if severity == 2 {
                    budget.critical_bytes
                } else {
                    budget.warning_bytes
                };
                let level = if severity == 2 {
                    "critical ceiling"
                } else {
                    "warning budget"
                };
                let opened = if is_new {
                    "New application detected. "
                } else {
                    ""
                };
                notifications.push(Notification {
                    title: format!("NRG: {} memory warning", app_label),
                    body: format!(
                        "{opened}Usage {} has reached {} ({}) for this application.",
                        format_mib(current),
                        level,
                        format_mib(threshold)
                    ),
                    critical: severity == 2,
                });
            } else if is_new && severity == 0 {
                notifications.push(Notification {
                    title: format!("NRG: application opened — {app_label}"),
                    body: format!(
                        "Detected a new application workload using {} RAM.",
                        format_mib(current)
                    ),
                    critical: false,
                });
            }

            if severity == 0 {
                if current < budget.warning_bytes.saturating_mul(90) / 100 {
                    self.workload_severity.remove(&workload.path);
                }
            } else {
                self.workload_severity
                    .insert(workload.path.clone(), severity);
            }
        }

        let global_oom = snapshot.vmstat.get("oom_kill").copied();
        if let (Some(previous), Some(current)) = (self.kernel_oom_kills, global_oom) {
            if current > previous {
                let already_attributed = notifications.iter().any(|notification| {
                    notification.title.starts_with("NRG memory event:")
                        && notification.body.contains("OOM kill")
                });
                if !already_attributed {
                    notifications.push(Notification {
                        title: "Kernel OOM event detected".to_owned(),
                        body: format!(
                            "{} new OOM kill event(s) have occurred since the previous sample.",
                            current - previous
                        ),
                        critical: true,
                    });
                }
            }
        }
        self.kernel_oom_kills = global_oom;

        let allocstall = snapshot.vmstat.get("allocstall").copied().unwrap_or(0);
        let direct_throttle = snapshot
            .vmstat
            .get("pgscan_direct_throttle")
            .copied()
            .unwrap_or(0);
        let previous_allocstall = self
            .vmstat_counters
            .insert("allocstall".to_owned(), allocstall);
        let previous_direct_throttle = self
            .vmstat_counters
            .insert("pgscan_direct_throttle".to_owned(), direct_throttle);
        let reclaim_stalls = previous_allocstall.is_some_and(|old| allocstall > old)
            || previous_direct_throttle.is_some_and(|old| direct_throttle > old);
        if reclaim_stalls && self.reclaim_cooldown_samples == 0 {
            notifications.push(Notification {
                title: "NRG: direct memory reclaim activity".to_owned(),
                body: "The kernel entered direct reclaim or throttled direct reclaim since the previous sample. Correlate with memory PSI and per-app growth.".to_owned(),
                critical: false,
            });
            self.reclaim_cooldown_samples = 30;
        } else if self.reclaim_cooldown_samples > 0 {
            self.reclaim_cooldown_samples -= 1;
        }

        let core_throttle_ms = snapshot
            .cpu_thermal_throttle
            .as_ref()
            .and_then(|throttle| throttle.core_throttle_total_time_ms);
        let package_throttle_ms = snapshot
            .cpu_thermal_throttle
            .as_ref()
            .and_then(|throttle| throttle.package_throttle_total_time_ms);
        let core_delta = self
            .cpu_core_throttle_total_ms
            .zip(core_throttle_ms)
            .map(|(previous, current)| current.saturating_sub(previous))
            .unwrap_or(0);
        let package_delta = self
            .cpu_package_throttle_total_ms
            .zip(package_throttle_ms)
            .map(|(previous, current)| current.saturating_sub(previous))
            .unwrap_or(0);
        self.cpu_core_throttle_total_ms = core_throttle_ms;
        self.cpu_package_throttle_total_ms = package_throttle_ms;
        if self.thermal_throttle_cooldown_samples > 0 {
            self.thermal_throttle_cooldown_samples -= 1;
        } else if core_delta >= 250 || package_delta >= 250 {
            notifications.push(Notification {
                title: "NRG: CPU thermal throttling detected".to_owned(),
                body: format!(
                    "CPU0 throttle counters increased during the last sample: core +{core_delta} ms, package +{package_delta} ms. Check temperatures and cooling; these are counter deltas, not a diagnosis of the cause."
                ),
                critical: false,
            });
            self.thermal_throttle_cooldown_samples = 30;
        }

        let state = policy::evaluate(snapshot).oom_guard.state;
        let previous = self.pressure_state.unwrap_or(PressureState::Normal);
        if state > previous {
            notifications.push(Notification {
                title: format!("NRG system pressure: {state:?}"),
                body: format!(
                    "Available RAM: {}. Memory PSI full avg10: {}%. Recommended action: {}.",
                    snapshot
                        .memory
                        .available_bytes
                        .map(format_mib)
                        .unwrap_or_else(|| "unknown".to_owned()),
                    snapshot
                        .pressure
                        .full
                        .as_ref()
                        .and_then(|p| p.avg10)
                        .map(|v| format!("{v:.2}"))
                        .unwrap_or_else(|| "unknown".to_owned()),
                    policy::evaluate(snapshot).oom_guard.recommended_response
                ),
                critical: state == PressureState::Critical,
            });
            self.normal_samples = 0;
            self.pressure_state = Some(state);
        } else if state == PressureState::Normal {
            self.normal_samples = self.normal_samples.saturating_add(1);
            if self.normal_samples >= 5 {
                self.pressure_state = Some(PressureState::Normal);
            }
        } else {
            self.normal_samples = 0;
            if self.pressure_state.is_none() {
                self.pressure_state = Some(state);
            }
        }

        self.initialized = true;
        notifications
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_systemd_workload_names_for_budget_matching() {
        assert_eq!(
            application_key("app-brave-browser@abc123.service"),
            "brave-browser"
        );
        assert_eq!(
            application_key("app-org.chromium.Chromium-1484.scope"),
            "org.chromium.chromium"
        );
        assert_eq!(application_key("app-chatgpt@abc.service"), "chatgpt");
    }

    #[test]
    fn workload_budget_crossings_escalate_once_and_reset_with_hysteresis() {
        let mut state = MonitorState {
            budgets: Some(Budgets {
                default: Budget {
                    warning_bytes: 1536 * MIB,
                    critical_bytes: 2560 * MIB,
                },
                per_app: BTreeMap::new(),
            }),
            ..MonitorState::default()
        };
        let mut snapshot =
            test_snapshot(test_workload("app-brave-browser@abc.service", 1700 * MIB));
        let first = state.update(&snapshot);
        assert_eq!(first.len(), 1);
        assert!(!first[0].critical);
        snapshot.workloads[0].memory_current_bytes = Some(2700 * MIB);
        let escalation = state.update(&snapshot);
        assert_eq!(escalation.len(), 1);
        assert!(escalation[0].critical);
        snapshot.workloads[0].memory_current_bytes = Some(2500 * MIB);
        assert!(state.update(&snapshot).is_empty());
        snapshot.workloads[0].memory_current_bytes = Some(1300 * MIB);
        assert!(state.update(&snapshot).is_empty());
        snapshot.workloads[0].memory_current_bytes = Some(1700 * MIB);
        assert_eq!(state.update(&snapshot).len(), 1);
    }

    #[test]
    fn detects_new_app_workload_after_initial_baseline() {
        let mut state = MonitorState {
            budgets: Some(Budgets {
                default: Budget {
                    warning_bytes: 2 * 1024 * MIB,
                    critical_bytes: 3 * 1024 * MIB,
                },
                per_app: BTreeMap::new(),
            }),
            ..MonitorState::default()
        };
        let first = test_snapshot(test_workload("app-brave-browser@abc.service", 500 * MIB));
        assert!(state.update(&first).is_empty());
        let mut second = first;
        second
            .workloads
            .push(test_workload("app-chatgpt@def.service", 600 * MIB));
        let alerts = state.update(&second);
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].title.contains("chatgpt"));
        assert!(
            alerts[0]
                .body
                .contains("Detected a new application workload")
        );
    }

    #[test]
    fn reports_sustained_cpu_thermal_throttle_counter_deltas() {
        use crate::linux::CpuThermalThrottle;
        let mut state = MonitorState {
            budgets: Some(Budgets {
                default: Budget {
                    warning_bytes: 2 * 1024 * MIB,
                    critical_bytes: 3 * 1024 * MIB,
                },
                per_app: BTreeMap::new(),
            }),
            ..MonitorState::default()
        };
        let mut snapshot = test_snapshot(test_workload("app-browser.service", 500 * MIB));
        snapshot.cpu_thermal_throttle = Some(CpuThermalThrottle {
            cpu: "cpu0".to_owned(),
            core_throttle_count: Some(10),
            core_throttle_max_time_ms: Some(50),
            core_throttle_total_time_ms: Some(1_000),
            package_throttle_count: Some(20),
            package_throttle_max_time_ms: Some(80),
            package_throttle_total_time_ms: Some(2_000),
        });
        state.update(&snapshot);
        snapshot
            .cpu_thermal_throttle
            .as_mut()
            .unwrap()
            .core_throttle_total_time_ms = Some(1_400);
        snapshot
            .cpu_thermal_throttle
            .as_mut()
            .unwrap()
            .package_throttle_total_time_ms = Some(2_350);
        let alerts = state.update(&snapshot);
        assert!(
            alerts
                .iter()
                .any(|alert| alert.title.contains("thermal throttling"))
        );
        assert!(
            alerts
                .iter()
                .any(|alert| alert.body.contains("core +400 ms"))
        );
    }

    #[test]
    fn reports_new_per_workload_oom_kill_events() {
        let mut state = MonitorState {
            budgets: Some(Budgets {
                default: Budget {
                    warning_bytes: 2 * 1024 * MIB,
                    critical_bytes: 3 * 1024 * MIB,
                },
                per_app: BTreeMap::new(),
            }),
            ..MonitorState::default()
        };
        let mut snapshot = test_snapshot(test_workload("app-brave-browser@abc.service", 500 * MIB));
        state.update(&snapshot);
        snapshot.workloads[0]
            .memory_events
            .insert("oom_kill".to_owned(), 1);
        let alerts = state.update(&snapshot);
        assert!(alerts.iter().any(|alert| alert.body.contains("OOM kill")));
    }

    #[test]
    fn excludes_desktop_infrastructure_from_app_open_alerts() {
        let mut workload = test_workload("app-Remote-Desktop-Commander@abc.service", 512 * MIB);
        assert!(!is_user_application(&workload));
        workload.name = "app-brave-browser@abc.service".to_owned();
        assert!(is_user_application(&workload));
    }

    fn test_snapshot(workload: WorkloadSnapshot) -> Snapshot {
        use crate::linux::{CgroupCapabilities, Memory, Pressure, PsiLine};
        let zero_pressure = || Pressure {
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
        };
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
                swap_total_bytes: Some(4 * 1024 * MIB),
                swap_free_bytes: Some(4 * 1024 * MIB),
                swap_used_bytes: Some(0),
                committed_bytes: None,
                commit_limit_bytes: None,
                overcommit_mode: Some(0),
            },
            pressure: zero_pressure(),
            cpu_pressure: zero_pressure(),
            io_pressure: zero_pressure(),
            interrupts: Vec::new(),
            graphics: Vec::new(),
            display_connectors: Vec::new(),
            thermal_zones: Vec::new(),
            cpu_thermal_throttle: None,
            zram: None,
            vmstat: BTreeMap::from([("oom_kill".to_owned(), 0)]),
            cgroup_v2: None,
            cgroup_capabilities: CgroupCapabilities {
                mount_detected: false,
                current_path: None,
                controllers_available_to_children: Vec::new(),
                controllers_enabled_for_children: Vec::new(),
                memory_accounting_available: false,
                memory_controller_enabled_for_children: false,
                subtree_control_write_open: false,
            },
            workloads: vec![workload],
        }
    }

    fn test_workload(name: &str, memory: u64) -> WorkloadSnapshot {
        WorkloadSnapshot {
            slice: "app.slice".to_owned(),
            name: name.to_owned(),
            path: format!("/cgroup/{name}"),
            memory_current_bytes: Some(memory),
            memory_high_limit: Some("max".to_owned()),
            memory_max_limit: Some("max".to_owned()),
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
}
