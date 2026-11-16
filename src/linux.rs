use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const MEMINFO: &str = "/proc/meminfo";
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

#[derive(Debug, Serialize)]
pub(crate) struct Snapshot {
    pub(crate) schema_version: u32,
    pub(crate) timestamp_unix_ms: u128,
    pub(crate) platform: &'static str,
    pub(crate) process_details_collected: bool,
    pub(crate) memory: Memory,
    pub(crate) pressure: Pressure,
    pub(crate) cpu_pressure: Pressure,
    pub(crate) io_pressure: Pressure,
    pub(crate) interrupts: Vec<InterruptSnapshot>,
    pub(crate) graphics: Vec<GraphicsDevice>,
    pub(crate) display_connectors: Vec<DisplayConnector>,
    pub(crate) thermal_zones: Vec<ThermalZone>,
    pub(crate) cpu_thermal_throttle: Option<CpuThermalThrottle>,
    pub(crate) zram: Option<Zram>,
    pub(crate) vmstat: BTreeMap<String, u64>,
    pub(crate) cgroup_v2: Option<CgroupSnapshot>,
    pub(crate) cgroup_capabilities: CgroupCapabilities,
    pub(crate) workloads: Vec<WorkloadSnapshot>,
}

#[derive(Debug, Serialize)]
pub(crate) struct Memory {
    pub(crate) total_bytes: Option<u64>,
    pub(crate) available_bytes: Option<u64>,
    pub(crate) free_bytes: Option<u64>,
    pub(crate) buffers_bytes: Option<u64>,
    pub(crate) cached_bytes: Option<u64>,
    pub(crate) reclaimable_slab_bytes: Option<u64>,
    pub(crate) unreclaimable_slab_bytes: Option<u64>,
    pub(crate) swap_total_bytes: Option<u64>,
    pub(crate) swap_free_bytes: Option<u64>,
    pub(crate) swap_used_bytes: Option<u64>,
    pub(crate) committed_bytes: Option<u64>,
    pub(crate) commit_limit_bytes: Option<u64>,
    pub(crate) overcommit_mode: Option<u64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct Pressure {
    pub(crate) some: Option<PsiLine>,
    pub(crate) full: Option<PsiLine>,
}

#[derive(Debug, Serialize)]
pub(crate) struct InterruptSnapshot {
    pub(crate) irq: String,
    pub(crate) cpu_counts: Vec<u64>,
    pub(crate) detail: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct GraphicsDevice {
    pub(crate) card: String,
    pub(crate) driver: Option<String>,
    pub(crate) vendor: Option<String>,
    pub(crate) device: Option<String>,
    pub(crate) boot_vga: Option<bool>,
}

#[derive(Debug)]
struct KScreenOutput {
    name: String,
    connected: bool,
    enabled: bool,
    mode: String,
    width: u64,
    height: u64,
    x: i64,
    y: i64,
}

#[derive(Debug, Serialize)]
pub(crate) struct DisplayConnector {
    pub(crate) name: String,
    pub(crate) status: Option<String>,
    pub(crate) enabled: Option<String>,
    pub(crate) mode_count: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct ThermalZone {
    pub(crate) zone: String,
    pub(crate) kind: Option<String>,
    pub(crate) temperature_millicelsius: Option<i64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CpuThermalThrottle {
    pub(crate) cpu: String,
    pub(crate) core_throttle_count: Option<u64>,
    pub(crate) core_throttle_max_time_ms: Option<u64>,
    pub(crate) core_throttle_total_time_ms: Option<u64>,
    pub(crate) package_throttle_count: Option<u64>,
    pub(crate) package_throttle_max_time_ms: Option<u64>,
    pub(crate) package_throttle_total_time_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct PsiLine {
    pub(crate) avg10: Option<f64>,
    pub(crate) avg60: Option<f64>,
    pub(crate) avg300: Option<f64>,
    pub(crate) total_us: Option<u64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct Zram {
    pub(crate) device: String,
    pub(crate) disk_size_bytes: Option<u64>,
    pub(crate) original_data_bytes: Option<u64>,
    pub(crate) compressed_data_bytes: Option<u64>,
    pub(crate) memory_used_bytes: Option<u64>,
    pub(crate) payload_compression_ratio: Option<f64>,
    pub(crate) effective_compression_ratio: Option<f64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CgroupSnapshot {
    pub(crate) path: String,
    pub(crate) memory_current_bytes: Option<u64>,
    pub(crate) memory_high_limit: Option<String>,
    pub(crate) memory_max_limit: Option<String>,
    pub(crate) memory_swap_current_bytes: Option<u64>,
    pub(crate) memory_swap_max_limit: Option<String>,
    pub(crate) memory_events: BTreeMap<String, u64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CgroupCapabilities {
    pub(crate) mount_detected: bool,
    pub(crate) current_path: Option<String>,
    pub(crate) controllers_available_to_children: Vec<String>,
    pub(crate) controllers_enabled_for_children: Vec<String>,
    pub(crate) memory_accounting_available: bool,
    pub(crate) memory_controller_enabled_for_children: bool,
    pub(crate) subtree_control_write_open: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct WorkloadSnapshot {
    pub(crate) slice: String,
    pub(crate) name: String,
    pub(crate) path: String,
    pub(crate) memory_current_bytes: Option<u64>,
    pub(crate) memory_high_limit: Option<String>,
    pub(crate) memory_max_limit: Option<String>,
    pub(crate) memory_anon_bytes: Option<u64>,
    pub(crate) memory_file_bytes: Option<u64>,
    pub(crate) cpu_usage_usec: Option<u64>,
    pub(crate) pids_current: Option<u64>,
    pub(crate) io_read_bytes: u64,
    pub(crate) io_write_bytes: u64,
    pub(crate) memory_events: BTreeMap<String, u64>,
    pub(crate) process_count_observed: u64,
    pub(crate) top_processes: Vec<ProcessSnapshot>,
    pub(crate) process_tree: Vec<ProcessSnapshot>,
    pub(crate) process_tree_truncated: bool,
    pub(crate) executable_hints: Vec<ExecutableHint>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ExecutableHint {
    pub(crate) path: String,
    pub(crate) basename: String,
    pub(crate) observed_processes: usize,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ProcessSnapshot {
    pub(crate) pid: u32,
    pub(crate) comm: String,
    pub(crate) executable: Option<String>,
    pub(crate) executable_path: Option<String>,
    pub(crate) parent_pid: Option<u32>,
    pub(crate) parent_comm: Option<String>,
    pub(crate) parent_in_workload: Option<bool>,
    pub(crate) parent_in_tree: Option<bool>,
    pub(crate) rss_estimate_bytes: Option<u64>,
}

impl Snapshot {
    pub fn to_human(&self) -> String {
        let mut out = String::new();
        out.push_str("Nexus Resource Governor — read-only Linux snapshot\n");
        out.push_str("No resource controls were changed.\n");
        out.push_str(&format!(
            "Per-process attribution: {}\n",
            if self.process_details_collected {
                "enabled"
            } else {
                "skipped (lightweight sample)"
            }
        ));
        out.push_str(&format!(
            "cgroup v2: mount={} memory_accounting={} memory_for_children={} subtree_control_write_open={}\n",
            self.cgroup_capabilities.mount_detected,
            self.cgroup_capabilities.memory_accounting_available,
            self.cgroup_capabilities.memory_controller_enabled_for_children,
            self.cgroup_capabilities.subtree_control_write_open
        ));
        if !self
            .cgroup_capabilities
            .controllers_available_to_children
            .is_empty()
        {
            out.push_str(&format!(
                "cgroup controllers available to children: {}\n",
                self.cgroup_capabilities
                    .controllers_available_to_children
                    .join(" ")
            ));
        }
        out.push_str(&format!(
            "cgroup controllers enabled for children: {}\n",
            if self
                .cgroup_capabilities
                .controllers_enabled_for_children
                .is_empty()
            {
                "none".to_owned()
            } else {
                self.cgroup_capabilities
                    .controllers_enabled_for_children
                    .join(" ")
            }
        ));
        out.push('\n');
        push_metric(&mut out, "Physical RAM total", self.memory.total_bytes);
        push_metric(
            &mut out,
            "Physical RAM available",
            self.memory.available_bytes,
        );
        push_metric(&mut out, "Physical RAM free", self.memory.free_bytes);
        push_metric(&mut out, "Swap used", self.memory.swap_used_bytes);
        push_metric(
            &mut out,
            "Committed virtual memory",
            self.memory.committed_bytes,
        );
        push_metric(&mut out, "Commit limit", self.memory.commit_limit_bytes);
        out.push_str(&format!(
            "VM overcommit mode: {}\n",
            self.memory
                .overcommit_mode
                .map(|mode| mode.to_string())
                .unwrap_or_else(|| "unavailable".to_owned())
        ));
        for key in [
            "oom_kill",
            "compact_stall",
            "pgscan_direct_throttle",
            "allocstall",
        ] {
            if let Some(value) = self.vmstat.get(key) {
                out.push_str(&format!("Kernel {key} (since boot): {value}\n"));
            }
        }
        if let Some(zram) = &self.zram {
            push_metric(
                &mut out,
                &format!("{} compressed data", zram.device),
                zram.compressed_data_bytes,
            );
            push_metric(
                &mut out,
                &format!("{} physical memory used", zram.device),
                zram.memory_used_bytes,
            );
            if let Some(ratio) = zram.payload_compression_ratio {
                out.push_str(&format!(
                    "{} payload compression: {:.2}:1\n",
                    zram.device, ratio
                ));
            }
            if let Some(ratio) = zram.effective_compression_ratio {
                out.push_str(&format!(
                    "{} effective compression: {:.2}:1\n",
                    zram.device, ratio
                ));
            }
        } else {
            out.push_str("ZRAM: not detected or unavailable\n");
        }
        if let Some(some) = &self.pressure.some {
            out.push_str(&format!(
                "Memory PSI some: avg10={:.2}% avg60={:.2}% avg300={:.2}%\n",
                some.avg10.unwrap_or(0.0),
                some.avg60.unwrap_or(0.0),
                some.avg300.unwrap_or(0.0)
            ));
        }
        if let Some(full) = &self.pressure.full {
            out.push_str(&format!(
                "Memory PSI full: avg10={:.2}% avg60={:.2}% avg300={:.2}%\n",
                full.avg10.unwrap_or(0.0),
                full.avg60.unwrap_or(0.0),
                full.avg300.unwrap_or(0.0)
            ));
        }
        for (label, pressure) in [("CPU", &self.cpu_pressure), ("I/O", &self.io_pressure)] {
            if let Some(some) = &pressure.some {
                out.push_str(&format!(
                    "{label} PSI some: avg10={:.2}% avg60={:.2}% avg300={:.2}%\n",
                    some.avg10.unwrap_or(0.0),
                    some.avg60.unwrap_or(0.0),
                    some.avg300.unwrap_or(0.0)
                ));
            }
            if let Some(full) = &pressure.full {
                out.push_str(&format!(
                    "{label} PSI full: avg10={:.2}% avg60={:.2}% avg300={:.2}%\n",
                    full.avg10.unwrap_or(0.0),
                    full.avg60.unwrap_or(0.0),
                    full.avg300.unwrap_or(0.0)
                ));
            }
        }
        if !self.graphics.is_empty() {
            out.push_str("Graphics devices (sysfs identity; not GPU utilization):\n");
            for gpu in &self.graphics {
                out.push_str(&format!(
                    "  {} driver={} vendor={} device={} boot_vga={}\n",
                    gpu.card,
                    gpu.driver.as_deref().unwrap_or("unknown"),
                    gpu.vendor.as_deref().unwrap_or("unknown"),
                    gpu.device.as_deref().unwrap_or("unknown"),
                    gpu.boot_vga
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "unknown".to_owned())
                ));
            }
        }
        if !self.display_connectors.is_empty() {
            out.push_str("DRM display connectors (sample-time state):\n");
            for connector in &self.display_connectors {
                out.push_str(&format!(
                    "  {} status={} enabled={} modes={}\n",
                    connector.name,
                    connector.status.as_deref().unwrap_or("unknown"),
                    connector.enabled.as_deref().unwrap_or("unknown"),
                    connector.mode_count
                ));
            }
        }
        if !self.thermal_zones.is_empty() {
            out.push_str("Thermal zones (millidegree sysfs readings):\n");
            for zone in &self.thermal_zones {
                let temp = zone
                    .temperature_millicelsius
                    .map(|v| format!("{:.1} °C", v as f64 / 1000.0))
                    .unwrap_or_else(|| "unavailable".to_owned());
                out.push_str(&format!(
                    "  {} type={} temperature={}\n",
                    zone.zone,
                    zone.kind.as_deref().unwrap_or("unknown"),
                    temp
                ));
            }
        }
        if let Some(throttle) = &self.cpu_thermal_throttle {
            out.push_str("CPU thermal-throttle counters (CPU0 sysfs; cumulative):\n");
            for (label, value) in [
                ("core count", throttle.core_throttle_count),
                ("core max ms", throttle.core_throttle_max_time_ms),
                ("core total ms", throttle.core_throttle_total_time_ms),
                ("package count", throttle.package_throttle_count),
                ("package max ms", throttle.package_throttle_max_time_ms),
                ("package total ms", throttle.package_throttle_total_time_ms),
            ] {
                if let Some(value) = value {
                    out.push_str(&format!("  {label}: {value}\n"));
                }
            }
        } else {
            out.push_str("CPU thermal-throttle counters: unavailable\n");
        }
        if !self.interrupts.is_empty() {
            out.push_str(
                "Selected interrupt counters (cumulative; IRQ 27 and relevant device handlers):\n",
            );
            for irq in &self.interrupts {
                out.push_str(&format!(
                    "  IRQ {} counts={:?} detail={}\n",
                    irq.irq, irq.cpu_counts, irq.detail
                ));
            }
        }
        if let Some(cgroup) = &self.cgroup_v2 {
            out.push_str(&format!("Current cgroup: {}\n", cgroup.path));
            push_metric(
                &mut out,
                "Cgroup memory.current",
                cgroup.memory_current_bytes,
            );
            out.push_str(&format!(
                "Cgroup memory.high: {}\n",
                cgroup.memory_high_limit.as_deref().unwrap_or("unavailable")
            ));
        } else {
            out.push_str("Current cgroup: unavailable (not cgroup v2 or inaccessible)\n");
        }
        if !self.workloads.is_empty() {
            out.push_str("Top user workloads (cgroup memory; aggregate source):\n");
            for workload in self.workloads.iter().take(8) {
                let memory_gib =
                    workload.memory_current_bytes.unwrap_or(0) as f64 / 1_073_741_824.0;
                out.push_str(&format!(
                    "  {}/{}: {:.2} GiB, {} tasks, {} processes observed\n",
                    workload.slice,
                    workload.name,
                    memory_gib,
                    workload.pids_current.unwrap_or(0),
                    workload.process_count_observed
                ));
                let oom = workload.memory_events.get("oom").copied().unwrap_or(0);
                let oom_kill = workload.memory_events.get("oom_kill").copied().unwrap_or(0);
                let high = workload.memory_events.get("high").copied().unwrap_or(0);
                if oom > 0 || oom_kill > 0 || high > 0 {
                    out.push_str(&format!(
                        "    cgroup memory events: high={high} oom={oom} oom_kill={oom_kill} (cumulative)\n"
                    ));
                }
                for process in workload.top_processes.iter().take(3) {
                    let rss = process
                        .rss_estimate_bytes
                        .map(|bytes| format!("{:.0} MiB RSS estimate", bytes as f64 / 1_048_576.0))
                        .unwrap_or_else(|| "RSS unavailable".to_owned());
                    let parent = process
                        .parent_pid
                        .map(|pid| format!("parent PID {pid}"))
                        .unwrap_or_else(|| "parent unknown".to_owned());
                    let relation = match process.parent_in_workload {
                        Some(true) => "same workload",
                        Some(false) => "outside workload",
                        None => "parent unavailable",
                    };
                    out.push_str(&format!(
                        "    PID {} {} ({}, {}; {})\n",
                        process.pid, process.comm, rss, parent, relation
                    ));
                }
                if !workload.process_tree.is_empty() {
                    out.push_str(&format!(
                        "    Parent-linked process sample: {} nodes{} (showing up to 8)\n",
                        workload.process_tree.len(),
                        if workload.process_tree_truncated {
                            ", truncated"
                        } else {
                            ""
                        }
                    ));
                    for process in workload.process_tree.iter().take(8) {
                        let parent = process
                            .parent_pid
                            .map(|pid| format!(" <- {pid}"))
                            .unwrap_or_default();
                        let edge = match process.parent_in_tree {
                            Some(true) => "parent included",
                            Some(false) => "parent outside sample",
                            None => "parent unknown",
                        };
                        out.push_str(&format!(
                            "      PID {} {}{} [{}]\n",
                            process.pid, process.comm, parent, edge
                        ));
                    }
                }
            }
            out.push_str("Process RSS values are per-process estimates and must not be summed; shared pages can be counted more than once.\n");
        }
        out
    }

    pub fn to_diagnostic(&self) -> String {
        let mut out = self.to_human();
        out.push_str("\nFreeze triage (signals, not root-cause claims):\n");
        let memory_full = self.pressure.full.as_ref().and_then(|p| p.avg10);
        let cpu_full = self.cpu_pressure.full.as_ref().and_then(|p| p.avg10);
        let io_full = self.io_pressure.full.as_ref().and_then(|p| p.avg10);
        let available = self.memory.available_bytes;
        let swap_used = self.memory.swap_used_bytes;
        let swap_total = self.memory.swap_total_bytes;
        if available.is_some_and(|v| v < 512 * 1024 * 1024) || memory_full.is_some_and(|v| v >= 0.5)
        {
            out.push_str("  MEMORY: active pressure signal; correlate with pgscan/allocstall and workload growth.\n");
        } else {
            out.push_str("  MEMORY: no strong sustained pressure signal in this sample.\n");
        }
        if cpu_full.is_some_and(|v| v >= 0.5) {
            out.push_str("  CPU: runnable tasks are experiencing measurable stall pressure.\n");
        } else {
            out.push_str("  CPU: no strong CPU PSI full-stall signal in this sample.\n");
        }
        let cpu_temperature = self
            .thermal_zones
            .iter()
            .filter(|zone| {
                zone.kind.as_deref().is_some_and(|kind| {
                    kind.eq_ignore_ascii_case("TCPU") || kind.eq_ignore_ascii_case("x86_pkg_temp")
                })
            })
            .filter_map(|zone| zone.temperature_millicelsius)
            .max();
        if let Some(temperature) = cpu_temperature {
            if temperature >= 90_000 {
                out.push_str(&format!(
                    "  THERMAL WARNING: CPU/package sensor is currently {:.1} °C; correlate with thermal-throttle counter deltas.\n",
                    temperature as f64 / 1000.0
                ));
            }
        }
        if let Some(throttle) = &self.cpu_thermal_throttle {
            let core_ms = throttle.core_throttle_total_time_ms.unwrap_or(0);
            let package_ms = throttle.package_throttle_total_time_ms.unwrap_or(0);
            if core_ms > 0 || package_ms > 0 {
                out.push_str(&format!(
                    "  THERMAL: cumulative CPU0 throttling is core={} ms, package={} ms since boot; use monitor deltas to identify active throttling.\n",
                    core_ms, package_ms
                ));
            }
        }
        let unavailable_thermal_sensors = self
            .thermal_zones
            .iter()
            .filter(|zone| zone.temperature_millicelsius.is_none())
            .count();
        if unavailable_thermal_sensors > 0 {
            out.push_str(&format!(
                "  THERMAL: {unavailable_thermal_sensors} thermal-zone sensor(s) returned no temperature; inspect ACPI/firmware logs before trusting missing readings.\n"
            ));
        }
        if io_full.is_some_and(|v| v >= 0.5) {
            out.push_str("  STORAGE: I/O PSI indicates tasks stalled on I/O; inspect device latency and kernel logs.\n");
        } else {
            out.push_str("  STORAGE: no strong I/O PSI full-stall signal in this sample.\n");
        }
        if let (Some(used), Some(total)) = (swap_used, swap_total) {
            if total > 0 && used.saturating_mul(100) / total >= 85 {
                out.push_str("  SWAP: usage is at least 85%; this alone does not prove active memory pressure.\n");
            }
        }
        if self.interrupts.iter().any(|irq| irq.irq == "27") {
            out.push_str("  IRQ 27: counters/handler captured; a disabled IRQ must be confirmed from kernel journal messages, not inferred from counters alone.\n");
        } else {
            out.push_str("  IRQ 27: no matching /proc/interrupts row was available.\n");
        }
        out.push_str("  GRAPHICS: driver identity is reported where sysfs exposes it; this build does not yet measure GPU engine hangs or resets.\n");
        match read_kscreen_outputs() {
            Ok(outputs) if !outputs.is_empty() => {
                out.push_str("KScreen runtime outputs (userspace state):\n");
                for output in &outputs {
                    out.push_str(&format!(
                        "  {} connected={} enabled={} mode={} geometry={}x{} at {},{}\n",
                        output.name,
                        output.connected,
                        output.enabled,
                        output.mode,
                        output.width,
                        output.height,
                        output.x,
                        output.y
                    ));
                }
                let drm_connected = self
                    .display_connectors
                    .iter()
                    .any(|connector| connector.status.as_deref() == Some("connected"));
                let kscreen_connected = outputs.iter().any(|output| output.connected);
                if drm_connected && !kscreen_connected {
                    out.push_str("DISPLAY MISMATCH: sysfs/DRM reports a connected connector, but KScreen reports none.\n");
                } else if !drm_connected && kscreen_connected {
                    out.push_str("DISPLAY MISMATCH: KScreen reports a connected output, but sysfs/DRM reports none.\n");
                }
            }
            Ok(_) => {
                out.push_str("KScreen reports no outputs in its current userspace state.\n");
                if self
                    .display_connectors
                    .iter()
                    .any(|connector| connector.status.as_deref() == Some("connected"))
                {
                    out.push_str("DISPLAY MISMATCH: sysfs/DRM sees a connected connector while KScreen reports zero outputs.\n");
                }
            }
            Err(error) => out.push_str(&format!("KScreen runtime state unavailable: {error}\n")),
        }
        match read_kscreen_dpms() {
            Ok(state) => out.push_str(&format!("KScreen DPMS: {state}\n")),
            Err(error) => out.push_str(&format!("KScreen DPMS state unavailable: {error}\n")),
        }
        let mut desktop_reported_no_outputs = false;
        let mut swapchain_allocation_failures = false;
        let mut atomic_commit_failures = false;
        for (label, boot) in [
            ("current boot", "0"),
            ("previous boot", "-1"),
            ("two boots ago", "-2"),
            ("three boots ago", "-3"),
        ] {
            match read_kernel_events(boot) {
                Ok(events) if !events.is_empty() => {
                    out.push_str(&format!(
                        "\nRelevant kernel journal events ({label}; filtered and bounded):\n"
                    ));
                    for event in events {
                        out.push_str("  ");
                        out.push_str(&event);
                        out.push('\n');
                    }
                }
                Ok(_) => out.push_str(&format!(
                    "\nNo matching kernel journal events found for {label}.\n"
                )),
                Err(error) => out.push_str(&format!(
                    "\nKernel journal unavailable for {label}: {error}\n"
                )),
            }
            match read_graphics_session_events(boot) {
                Ok(events) if !events.is_empty() => {
                    for event in &events {
                        let lower = event.to_ascii_lowercase();
                        desktop_reported_no_outputs |= lower.contains("there are no outputs")
                            || lower.contains("placeholder screen")
                            || lower.contains("unexisting screen");
                        swapchain_allocation_failures |=
                            lower.contains("failed to allocate a graphics buffer for a swapchain");
                        atomic_commit_failures |= lower.contains("atomic commit failed");
                    }
                    out.push_str(&format!("\nRelevant desktop/graphics session events ({label}; filtered and bounded):\n"));
                    for event in events {
                        out.push_str("  ");
                        out.push_str(&event);
                        out.push('\n');
                    }
                }
                Ok(_) => out.push_str(&format!(
                    "\nNo matching desktop/graphics events found for {label}.\n"
                )),
                Err(error) => out.push_str(&format!(
                    "\nUser session journal unavailable for {label}: {error}\n"
                )),
            }
        }
        if desktop_reported_no_outputs {
            out.push_str("\nDISPLAY WARNING: the desktop journal reported that no display outputs were available. Correlate this with DRM connector status and the event timestamp.\n");
        }
        if swapchain_allocation_failures {
            out.push_str("GRAPHICS WARNING: KWin reported swapchain buffer allocation failures in the retained session journal. This can disrupt presentation but does not alone prove a full-system freeze.\n");
        }
        if atomic_commit_failures {
            out.push_str("DISPLAY WARNING: KWin reported a DRM atomic-commit failure in the retained session journal. Correlate it with connector hotplug/output-loss events.\n");
        }
        out.push_str("\nCORRELATION: capture JSONL during the next freeze and record its local timestamp; a single snapshot cannot identify the cause.\n");
        out
    }
}

fn push_metric(out: &mut String, label: &str, value: Option<u64>) {
    match value {
        Some(bytes) => out.push_str(&format!(
            "{label}: {} ({:.2} GiB)\n",
            bytes,
            bytes as f64 / 1_073_741_824.0
        )),
        None => out.push_str(&format!("{label}: unavailable\n")),
    }
}

pub fn collect_snapshot() -> io::Result<Snapshot> {
    collect_snapshot_with_process_details(true)
}

pub fn collect_monitor_snapshot() -> io::Result<Snapshot> {
    collect_snapshot_with_process_details(false)
}

fn collect_snapshot_with_process_details(include_process_details: bool) -> io::Result<Snapshot> {
    let mem = parse_meminfo(&fs::read_to_string(MEMINFO)?);
    let swap_total = mem.get("SwapTotal").copied();
    let swap_free = mem.get("SwapFree").copied();

    let memory = Memory {
        total_bytes: kib_to_bytes(mem.get("MemTotal").copied()),
        available_bytes: kib_to_bytes(mem.get("MemAvailable").copied()),
        free_bytes: kib_to_bytes(mem.get("MemFree").copied()),
        buffers_bytes: kib_to_bytes(mem.get("Buffers").copied()),
        cached_bytes: kib_to_bytes(mem.get("Cached").copied()),
        reclaimable_slab_bytes: kib_to_bytes(mem.get("SReclaimable").copied()),
        unreclaimable_slab_bytes: kib_to_bytes(mem.get("SUnreclaim").copied()),
        swap_total_bytes: kib_to_bytes(swap_total),
        swap_free_bytes: kib_to_bytes(swap_free),
        swap_used_bytes: match (swap_total, swap_free) {
            (Some(total), Some(free)) => Some(total.saturating_sub(free).saturating_mul(1024)),
            _ => None,
        },
        committed_bytes: kib_to_bytes(mem.get("Committed_AS").copied()),
        commit_limit_bytes: kib_to_bytes(mem.get("CommitLimit").copied()),
        overcommit_mode: fs::read_to_string("/proc/sys/vm/overcommit_memory")
            .ok()
            .and_then(|value| value.trim().parse().ok()),
    };

    let pressure = read_pressure("/proc/pressure/memory");
    let cpu_pressure = read_pressure("/proc/pressure/cpu");
    let io_pressure = read_pressure("/proc/pressure/io");

    let timestamp_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();

    Ok(Snapshot {
        schema_version: 14,
        timestamp_unix_ms,
        platform: "linux",
        process_details_collected: include_process_details,
        memory,
        pressure,
        cpu_pressure,
        io_pressure,
        interrupts: read_interrupts().unwrap_or_default(),
        graphics: read_graphics_devices(),
        display_connectors: read_display_connectors(),
        thermal_zones: read_thermal_zones(),
        cpu_thermal_throttle: read_cpu_thermal_throttle(),
        zram: read_zram("zram0").ok().flatten(),
        vmstat: read_vmstat()?,
        cgroup_v2: read_current_cgroup().ok().flatten(),
        cgroup_capabilities: read_cgroup_capabilities(),
        workloads: read_workloads(include_process_details).unwrap_or_default(),
    })
}

fn parse_meminfo(input: &str) -> BTreeMap<String, u64> {
    input
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            let number = value.split_whitespace().next()?.parse::<u64>().ok()?;
            Some((key.to_owned(), number))
        })
        .collect()
}

fn kib_to_bytes(value: Option<u64>) -> Option<u64> {
    value.map(|v| v.saturating_mul(1024))
}

fn is_relevant_kernel_event(line: &str) -> bool {
    const MARKERS: &[&str] = &[
        "nobody cared",
        "disabling irq",
        "irq 27",
        "idma64",
        "i2c_dw",
        "i915",
        "xe ",
        "drm",
        "gpu",
        "hang",
        "reset",
        "watchdog",
        "lockup",
        "nvme",
        "timeout",
        "i/o error",
        "thermal",
        "thrott",
        "acpi bios error",
        "acpi error",
        "firmware",
        "out of memory",
        "oom-kill",
        "killed process",
        "machine check",
        "mce:",
        "edac",
        "hardware error",
        "uncorrected",
    ];
    let lower = line.to_ascii_lowercase();
    MARKERS.iter().any(|marker| lower.contains(marker))
}

fn journal_message_signature(line: &str) -> &str {
    line.rsplit_once(": ")
        .map(|(_, message)| message)
        .unwrap_or(line)
}

fn parse_kernel_events(input: &str, max_events: usize) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut events: Vec<String> = input
        .lines()
        .filter(|line| is_relevant_kernel_event(line))
        .filter(|line| seen.insert(journal_message_signature(line).to_owned()))
        .map(|line| line.chars().take(420).collect())
        .collect();
    if events.len() > max_events {
        events = events.split_off(events.len() - max_events);
    }
    events
}

fn read_kernel_events(boot: &str) -> io::Result<Vec<String>> {
    const PATTERN: &str = "nobody cared|Disabling IRQ|irq 27|idma64|i2c_dw|i915|GPU HANG|drm|gpu|hang|reset|watchdog|lockup|nvme|timeout|I/O error|thermal|thrott|ACPI BIOS Error|ACPI Error|firmware|out of memory|oom-kill|killed process|machine check|MCE|EDAC|hardware error|uncorrected";
    let filtered = Command::new("journalctl")
        .args([
            "-k",
            "-b",
            boot,
            "--no-pager",
            "-o",
            "short-iso",
            "--grep",
            PATTERN,
            "--case-sensitive=no",
            "-n",
            "80",
        ])
        .output()?;
    if filtered.status.success() {
        return Ok(parse_kernel_events(
            &String::from_utf8_lossy(&filtered.stdout),
            40,
        ));
    }

    // Older systemd versions may not support --grep; fall back to a bounded tail.
    let fallback = Command::new("journalctl")
        .args([
            "-k",
            "-b",
            boot,
            "--no-pager",
            "-o",
            "short-iso",
            "-n",
            "2500",
        ])
        .output()?;
    if !fallback.status.success() {
        return Err(io::Error::other(format!(
            "journalctl exited with status {}",
            fallback.status
        )));
    }
    Ok(parse_kernel_events(
        &String::from_utf8_lossy(&fallback.stdout),
        40,
    ))
}

fn is_relevant_graphics_event(line: &str) -> bool {
    const MARKERS: &[&str] = &[
        "egl",
        "glx",
        "atomic commit",
        "failed to commit",
        "pageflip",
        "swapchain",
        "graphics buffer",
        "gpu process",
        "gpu reset",
        "main thread was hanging",
        "qsgtexture",
        "segfault",
        "core dumped",
        "drkonqi",
        "renderer process gone",
        "compositor",
        "no outputs",
        "placeholder screen",
        "unexisting screen",
        "org_kde_powerdevil",
        "i915 gmbus",
        "prop_subsystem:  drm",
    ];
    let lower = line.to_ascii_lowercase();
    MARKERS.iter().any(|marker| lower.contains(marker))
}

fn parse_graphics_events(input: &str, max_events: usize) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut critical = Vec::new();
    let mut routine = Vec::new();
    for (index, line) in input.lines().enumerate() {
        if !is_relevant_graphics_event(line)
            || !seen.insert(journal_message_signature(line).to_owned())
        {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        let is_critical = [
            "atomic commit failed",
            "failed to allocate a graphics buffer",
            "swapchain",
            "no outputs",
            "placeholder screen",
            "unexisting screen",
            "gpu reset",
            "main thread was hanging",
            "segfault",
            "core dumped",
        ]
        .iter()
        .any(|marker| lower.contains(marker));
        let event = (index, line.chars().take(420).collect::<String>());
        if is_critical {
            critical.push(event);
        } else {
            routine.push(event);
        }
    }

    let remaining = max_events.saturating_sub(critical.len());
    let mut selected = critical;
    selected.extend(routine.into_iter().rev().take(remaining));
    selected.sort_by_key(|(index, _)| *index);
    if selected.len() > max_events {
        selected = selected.split_off(selected.len() - max_events);
    }
    selected.into_iter().map(|(_, event)| event).collect()
}

fn parse_kscreen_outputs(input: &str) -> Result<Vec<KScreenOutput>, serde_json::Error> {
    let root: serde_json::Value = serde_json::from_str(input)?;
    let outputs = root
        .get("outputs")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    Ok(outputs
        .iter()
        .take(8)
        .map(|output| {
            let current_mode_id = output
                .get("currentModeId")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let mode = output
                .get("modes")
                .and_then(serde_json::Value::as_array)
                .and_then(|modes| {
                    modes.iter().find(|mode| {
                        mode.get("id").and_then(serde_json::Value::as_str) == Some(current_mode_id)
                    })
                })
                .and_then(|mode| mode.get("name"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown")
                .to_owned();
            let size = output.get("size");
            let position = output.get("pos");
            KScreenOutput {
                name: output
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned(),
                connected: output
                    .get("connected")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
                enabled: output
                    .get("enabled")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
                mode,
                width: size
                    .and_then(|value| value.get("width"))
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0),
                height: size
                    .and_then(|value| value.get("height"))
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0),
                x: position
                    .and_then(|value| value.get("x"))
                    .and_then(serde_json::Value::as_i64)
                    .unwrap_or(0),
                y: position
                    .and_then(|value| value.get("y"))
                    .and_then(serde_json::Value::as_i64)
                    .unwrap_or(0),
            }
        })
        .collect())
}

fn read_kscreen_outputs() -> io::Result<Vec<KScreenOutput>> {
    let output = Command::new("kscreen-doctor").arg("-j").output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "kscreen-doctor exited with status {}",
            output.status
        )));
    }
    parse_kscreen_outputs(&String::from_utf8_lossy(&output.stdout))
        .map_err(|error| io::Error::other(format!("invalid KScreen JSON: {error}")))
}

fn read_kscreen_dpms() -> io::Result<String> {
    let output = Command::new("kscreen-doctor")
        .args(["--dpms", "show"])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "kscreen-doctor --dpms show exited with status {}",
            output.status
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .take(8)
        .map(|line| line.chars().take(200).collect::<String>())
        .collect::<Vec<_>>()
        .join("; "))
}

fn read_graphics_session_events(boot: &str) -> io::Result<Vec<String>> {
    const CRITICAL_PATTERN: &str = "atomic commit failed|failed to allocate a graphics buffer|swapchain|no outputs|placeholder screen|GPU reset|main thread was hanging|segfault|core dumped";
    const ROUTINE_PATTERN: &str = "EGL|GLX|pageflip|compositor|unexisting screen|org_kde_powerdevil|i915 gmbus|prop_subsystem:  drm";

    let query = |pattern: &str, limit: &str| {
        Command::new("journalctl")
            .args([
                "--user",
                "-b",
                boot,
                "--no-pager",
                "-o",
                "short-iso",
                "--grep",
                pattern,
                "--case-sensitive=no",
                "-n",
                limit,
            ])
            .output()
    };

    let critical = query(CRITICAL_PATTERN, "80")?;
    let routine = query(ROUTINE_PATTERN, "12")?;
    if critical.status.success() || routine.status.success() {
        let mut combined = String::from_utf8_lossy(&critical.stdout).into_owned();
        combined.push('\n');
        combined.push_str(&String::from_utf8_lossy(&routine.stdout));
        return Ok(parse_graphics_events(&combined, 40));
    }

    // Older systemd versions may not support --grep; fall back to a bounded tail.
    let fallback = Command::new("journalctl")
        .args([
            "--user",
            "-b",
            boot,
            "--no-pager",
            "-o",
            "short-iso",
            "-n",
            "2500",
        ])
        .output()?;
    if !fallback.status.success() {
        return Err(io::Error::other(format!(
            "user journalctl exited with status {}",
            fallback.status
        )));
    }
    Ok(parse_graphics_events(
        &String::from_utf8_lossy(&fallback.stdout),
        40,
    ))
}

fn read_pressure(path: &str) -> Pressure {
    Pressure {
        some: read_psi_line(path, "some").ok().flatten(),
        full: read_psi_line(path, "full").ok().flatten(),
    }
}

fn parse_interrupts(input: &str, max_entries: usize) -> Vec<InterruptSnapshot> {
    const RELEVANT: &[&str] = &[
        "idma64", "i2c_dw", "i915", "xe", "nvme", "xhci", "iwlwifi", "pciehp", "snd",
    ];
    input
        .lines()
        .filter_map(|line| {
            let (irq, rest) = line.split_once(':')?;
            let irq = irq.trim();
            let mut fields = rest.split_whitespace().peekable();
            let mut cpu_counts = Vec::new();
            while let Some(value) = fields.peek() {
                if let Ok(count) = value.parse::<u64>() {
                    cpu_counts.push(count);
                    fields.next();
                } else {
                    break;
                }
            }
            let detail = fields.collect::<Vec<_>>().join(" ");
            let lower = detail.to_ascii_lowercase();
            if irq != "27" && !RELEVANT.iter().any(|needle| lower.contains(needle)) {
                return None;
            }
            Some(InterruptSnapshot {
                irq: irq.to_owned(),
                cpu_counts,
                detail: detail.chars().take(256).collect(),
            })
        })
        .take(max_entries)
        .collect()
}

fn read_interrupts() -> io::Result<Vec<InterruptSnapshot>> {
    Ok(parse_interrupts(
        &fs::read_to_string("/proc/interrupts")?,
        32,
    ))
}

fn read_graphics_devices() -> Vec<GraphicsDevice> {
    let Ok(entries) = fs::read_dir("/sys/class/drm") else {
        return Vec::new();
    };
    let mut entries: Vec<_> = entries
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .strip_prefix("card")
                .is_some_and(|suffix| {
                    !suffix.is_empty() && suffix.chars().all(|ch| ch.is_ascii_digit())
                })
        })
        .collect();
    entries.sort_by_key(|entry| entry.file_name());
    let mut devices = Vec::new();
    for entry in entries.into_iter().take(8) {
        let card = entry.file_name().to_string_lossy().into_owned();
        let base = entry.path().join("device");
        let driver = fs::read_link(base.join("driver")).ok().and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        });
        let read_text = |name: &str| {
            fs::read_to_string(base.join(name))
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        };
        let boot_vga = read_text("boot_vga").and_then(|value| match value.as_str() {
            "0" => Some(false),
            "1" => Some(true),
            _ => None,
        });
        devices.push(GraphicsDevice {
            card,
            driver,
            vendor: read_text("vendor"),
            device: read_text("device"),
            boot_vga,
        });
    }
    devices
}

fn is_drm_connector_name(name: &str) -> bool {
    let Some((card, connector)) = name.split_once('-') else {
        return false;
    };
    card.strip_prefix("card")
        .is_some_and(|suffix| !suffix.is_empty() && suffix.chars().all(|ch| ch.is_ascii_digit()))
        && !connector.is_empty()
}

fn read_display_connectors() -> Vec<DisplayConnector> {
    let Ok(entries) = fs::read_dir("/sys/class/drm") else {
        return Vec::new();
    };
    let mut entries: Vec<_> = entries
        .flatten()
        .filter(|entry| is_drm_connector_name(&entry.file_name().to_string_lossy()))
        .collect();
    entries.sort_by_key(|entry| entry.file_name());
    entries
        .into_iter()
        .take(16)
        .map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let base = entry.path();
            let read_text = |field: &str| {
                fs::read_to_string(base.join(field))
                    .ok()
                    .map(|value| value.trim().to_owned())
                    .filter(|value| !value.is_empty())
            };
            let mode_count = fs::read_to_string(base.join("modes"))
                .ok()
                .map(|value| value.lines().filter(|line| !line.trim().is_empty()).count())
                .unwrap_or(0);
            DisplayConnector {
                name,
                status: read_text("status"),
                enabled: read_text("enabled"),
                mode_count,
            }
        })
        .collect()
}

fn read_thermal_zones() -> Vec<ThermalZone> {
    let mut zones = Vec::new();
    for index in 0..16 {
        let zone = format!("thermal_zone{index}");
        let base = Path::new("/sys/class/thermal").join(&zone);
        if !base.is_dir() {
            continue;
        }
        let kind = fs::read_to_string(base.join("type"))
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        let temperature_millicelsius = fs::read_to_string(base.join("temp"))
            .ok()
            .and_then(|value| value.trim().parse::<i64>().ok());
        zones.push(ThermalZone {
            zone,
            kind,
            temperature_millicelsius,
        });
    }
    zones
}

fn parse_thermal_throttle_counter(input: &str) -> Option<u64> {
    input.trim().parse::<u64>().ok()
}

fn read_cpu_thermal_throttle() -> Option<CpuThermalThrottle> {
    // CPU0 provides one representative counter set. Do not sum package
    // counters across CPUs because package-level values may be duplicated.
    let base = Path::new("/sys/devices/system/cpu/cpu0/thermal_throttle");
    let read = |name: &str| {
        fs::read_to_string(base.join(name))
            .ok()
            .and_then(|value| parse_thermal_throttle_counter(&value))
    };
    let throttle = CpuThermalThrottle {
        cpu: "cpu0".to_owned(),
        core_throttle_count: read("core_throttle_count"),
        core_throttle_max_time_ms: read("core_throttle_max_time_ms"),
        core_throttle_total_time_ms: read("core_throttle_total_time_ms"),
        package_throttle_count: read("package_throttle_count"),
        package_throttle_max_time_ms: read("package_throttle_max_time_ms"),
        package_throttle_total_time_ms: read("package_throttle_total_time_ms"),
    };
    [
        throttle.core_throttle_count,
        throttle.core_throttle_max_time_ms,
        throttle.core_throttle_total_time_ms,
        throttle.package_throttle_count,
        throttle.package_throttle_max_time_ms,
        throttle.package_throttle_total_time_ms,
    ]
    .iter()
    .any(Option::is_some)
    .then_some(throttle)
}

fn read_psi_line(path: &str, wanted: &str) -> io::Result<Option<PsiLine>> {
    let contents = fs::read_to_string(path)?;
    for line in contents.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() != Some(wanted) {
            continue;
        }
        let mut values = BTreeMap::new();
        for part in parts {
            if let Some((key, value)) = part.split_once('=') {
                values.insert(key, value);
            }
        }
        return Ok(Some(PsiLine {
            avg10: values.get("avg10").and_then(|v| v.parse().ok()),
            avg60: values.get("avg60").and_then(|v| v.parse().ok()),
            avg300: values.get("avg300").and_then(|v| v.parse().ok()),
            total_us: values.get("total").and_then(|v| v.parse().ok()),
        }));
    }
    Ok(None)
}

fn read_zram(device: &str) -> io::Result<Option<Zram>> {
    let base = PathBuf::from("/sys/block").join(device);
    if !base.exists() {
        return Ok(None);
    }
    let stats = fs::read_to_string(base.join("mm_stat"))?;
    let values: Vec<u64> = stats
        .split_whitespace()
        .filter_map(|v| v.parse().ok())
        .collect();
    let original = values.first().copied();
    let compressed = values.get(1).copied();
    let memory_used = values.get(2).copied();
    let payload_ratio = match (original, compressed) {
        (Some(orig), Some(comp)) if comp > 0 => Some(orig as f64 / comp as f64),
        _ => None,
    };
    let effective_ratio = match (original, memory_used) {
        (Some(orig), Some(used)) if used > 0 => Some(orig as f64 / used as f64),
        _ => None,
    };
    Ok(Some(Zram {
        device: device.to_owned(),
        disk_size_bytes: read_u64(base.join("disksize")).ok(),
        original_data_bytes: original,
        compressed_data_bytes: compressed,
        memory_used_bytes: memory_used,
        payload_compression_ratio: payload_ratio,
        effective_compression_ratio: effective_ratio,
    }))
}

fn parse_vmstat(input: &str) -> BTreeMap<String, u64> {
    const SELECTED: &[&str] = &[
        "pgmajfault",
        "oom_kill",
        "compact_stall",
        "pgscan_direct_throttle",
        "pswpin",
        "pswpout",
        "pgscan_kswapd",
        "pgscan_direct",
        "pgsteal_kswapd",
        "pgsteal_direct",
    ];
    let mut counters = BTreeMap::new();
    let mut allocstall_total = 0u64;
    for line in input.lines() {
        let mut parts = line.split_whitespace();
        let Some(key) = parts.next() else { continue };
        let Some(value) = parts.next().and_then(|value| value.parse::<u64>().ok()) else {
            continue;
        };
        if SELECTED.contains(&key) {
            counters.insert(key.to_owned(), value);
        } else if key.starts_with("allocstall_") {
            allocstall_total = allocstall_total.saturating_add(value);
        }
    }
    counters.insert("allocstall".to_owned(), allocstall_total);
    counters
}

fn read_vmstat() -> io::Result<BTreeMap<String, u64>> {
    Ok(parse_vmstat(&fs::read_to_string("/proc/vmstat")?))
}

fn current_cgroup_relative_path() -> io::Result<Option<PathBuf>> {
    let contents = fs::read_to_string("/proc/self/cgroup")?;
    let relative = contents.lines().find_map(|line| {
        let mut parts = line.splitn(3, ':');
        if parts.next()? == "0" && parts.next()?.is_empty() {
            Some(parts.next()?.to_owned())
        } else {
            None
        }
    });
    Ok(relative.and_then(|path| safe_cgroup_relative_path(&path)))
}

fn parse_controller_list(input: &str) -> Vec<String> {
    input
        .split_whitespace()
        .map(|controller| controller.trim_start_matches(['+', '-']).to_owned())
        .filter(|controller| !controller.is_empty())
        .collect()
}

fn read_cgroup_capabilities() -> CgroupCapabilities {
    let current_path = current_cgroup_relative_path().ok().flatten();
    let base = current_path
        .as_ref()
        .map(|path| Path::new(CGROUP_ROOT).join(path))
        .unwrap_or_else(|| PathBuf::from(CGROUP_ROOT));
    let mount_detected = Path::new(CGROUP_ROOT).join("cgroup.controllers").is_file();
    let controllers_available_to_children = fs::read_to_string(base.join("cgroup.controllers"))
        .map(|contents| parse_controller_list(&contents))
        .unwrap_or_default();
    let controllers_enabled_for_children = fs::read_to_string(base.join("cgroup.subtree_control"))
        .map(|contents| parse_controller_list(&contents))
        .unwrap_or_default();
    let subtree_control_write_open = OpenOptions::new()
        .write(true)
        .open(base.join("cgroup.subtree_control"))
        .is_ok();

    CgroupCapabilities {
        mount_detected,
        current_path: current_path.map(|path| format!("/{}", path.display())),
        controllers_available_to_children,
        memory_controller_enabled_for_children: controllers_enabled_for_children
            .iter()
            .any(|controller| controller == "memory"),
        controllers_enabled_for_children,
        memory_accounting_available: base.join("memory.current").is_file(),
        subtree_control_write_open,
    }
}

fn read_current_cgroup() -> io::Result<Option<CgroupSnapshot>> {
    let Some(relative_path) = current_cgroup_relative_path()? else {
        return Ok(None);
    };
    let relative = format!("/{}", relative_path.display());
    let base = Path::new(CGROUP_ROOT).join(&relative_path);
    if !base.join("memory.current").exists() {
        return Ok(None);
    }

    let memory_events = fs::read_to_string(base.join("memory.events"))
        .map(|text| parse_key_values(&text))
        .unwrap_or_default();

    Ok(Some(CgroupSnapshot {
        path: relative,
        memory_current_bytes: read_u64(base.join("memory.current")).ok(),
        memory_high_limit: read_limit(base.join("memory.high")).ok(),
        memory_max_limit: read_limit(base.join("memory.max")).ok(),
        memory_swap_current_bytes: read_u64(base.join("memory.swap.current")).ok(),
        memory_swap_max_limit: read_limit(base.join("memory.swap.max")).ok(),
        memory_events,
    }))
}

fn user_manager_root(path: &Path) -> Option<PathBuf> {
    let components: Vec<_> = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_os_string()),
            _ => None,
        })
        .collect();
    let index = components
        .iter()
        .position(|part| {
            let name = part.to_string_lossy();
            name.starts_with("user@") && name.ends_with(".service")
        })
        .or_else(|| {
            components.iter().position(|part| {
                let name = part.to_string_lossy();
                name.starts_with("user-") && name.ends_with(".slice")
            })
        })?;
    Some(components[..=index].iter().collect())
}

fn decode_systemd_escape(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if index + 3 < bytes.len() && bytes[index] == b'\\' && bytes[index + 1] == b'x' {
            let hex = std::str::from_utf8(&bytes[index + 2..index + 4]).unwrap_or("");
            if let Ok(value) = u8::from_str_radix(hex, 16) {
                decoded.push(value);
                index += 4;
                continue;
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn read_workloads(include_process_details: bool) -> io::Result<Vec<WorkloadSnapshot>> {
    let Some(current_path) = current_cgroup_relative_path()? else {
        return Ok(Vec::new());
    };
    let Some(user_root) = user_manager_root(&current_path) else {
        return Ok(Vec::new());
    };
    let user_root = Path::new(CGROUP_ROOT).join(user_root);
    let mut workloads = Vec::new();

    for slice in ["app.slice", "session.slice", "background.slice"] {
        let slice_path = user_root.join(slice);
        if !slice_path.is_dir() {
            continue;
        }
        for entry in fs::read_dir(&slice_path)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let raw_name = entry.file_name().to_string_lossy().into_owned();
            let name = decode_systemd_escape(&raw_name);
            let path = entry.path();
            if !path.join("memory.current").exists() {
                continue;
            }
            let memory_stat = fs::read_to_string(path.join("memory.stat"))
                .map(|text| parse_key_values(&text))
                .unwrap_or_default();
            let cpu_stat = fs::read_to_string(path.join("cpu.stat"))
                .map(|text| parse_key_values(&text))
                .unwrap_or_default();
            let memory_events = fs::read_to_string(path.join("memory.events"))
                .map(|text| parse_key_values(&text))
                .unwrap_or_default();
            let (io_read_bytes, io_write_bytes) = fs::read_to_string(path.join("io.stat"))
                .map(|text| parse_io_stat(&text))
                .unwrap_or_default();

            workloads.push(WorkloadSnapshot {
                slice: slice.to_owned(),
                name,
                path: path.to_string_lossy().into_owned(),
                memory_current_bytes: read_u64(path.join("memory.current")).ok(),
                memory_high_limit: read_limit(path.join("memory.high")).ok(),
                memory_max_limit: read_limit(path.join("memory.max")).ok(),
                memory_anon_bytes: memory_stat.get("anon").copied(),
                memory_file_bytes: memory_stat.get("file").copied(),
                cpu_usage_usec: cpu_stat.get("usage_usec").copied(),
                pids_current: read_u64(path.join("pids.current")).ok(),
                io_read_bytes,
                io_write_bytes,
                memory_events,
                process_count_observed: 0,
                top_processes: Vec::new(),
                process_tree: Vec::new(),
                process_tree_truncated: false,
                executable_hints: Vec::new(),
            });
        }
    }

    if include_process_details {
        correlate_processes(&mut workloads);
    }
    workloads.sort_by_key(|item| std::cmp::Reverse(item.memory_current_bytes.unwrap_or(0)));
    Ok(workloads)
}

fn parse_unified_process_cgroup(input: &str) -> Option<PathBuf> {
    input.lines().find_map(|line| {
        let mut parts = line.splitn(3, ':');
        if parts.next()? == "0" && parts.next()?.is_empty() {
            safe_cgroup_relative_path(parts.next()?)
        } else {
            None
        }
    })
}

fn parse_process_parent_pid(stat: &str) -> Option<u32> {
    let (_, fields) = stat.rsplit_once(')')?;
    let mut fields = fields.split_whitespace();
    fields.next()?;
    fields.next()?.parse().ok()
}

fn parse_process_rss_bytes(status: &str) -> Option<u64> {
    status.lines().find_map(|line| {
        let value = line.strip_prefix("VmRSS:")?.split_whitespace().next()?;
        value
            .parse::<u64>()
            .ok()
            .map(|kib| kib.saturating_mul(1024))
    })
}

fn workload_for_cgroup(workloads: &[WorkloadSnapshot], process_cgroup: &Path) -> Option<usize> {
    workloads.iter().position(|workload| {
        let Ok(relative) = Path::new(&workload.path).strip_prefix(CGROUP_ROOT) else {
            return false;
        };
        process_cgroup == relative || process_cgroup.starts_with(relative)
    })
}

fn correlate_processes(workloads: &mut [WorkloadSnapshot]) {
    const TOP_PROCESSES: usize = 5;
    const MAX_PROCESS_TREE_NODES: usize = 32;
    let Ok(entries) = fs::read_dir("/proc") else {
        return;
    };
    let mut observed: Vec<Vec<ProcessSnapshot>> = vec![Vec::new(); workloads.len()];

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(pid) = file_name
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        let process_dir = entry.path();
        let Ok(cgroup_text) = fs::read_to_string(process_dir.join("cgroup")) else {
            continue;
        };
        let Some(cgroup) = parse_unified_process_cgroup(&cgroup_text) else {
            continue;
        };
        let Some(workload_index) = workload_for_cgroup(workloads, &cgroup) else {
            continue;
        };
        let comm = fs::read_to_string(process_dir.join("comm"))
            .map(|value| value.trim().to_owned())
            .unwrap_or_else(|_| "unknown".to_owned());
        let executable_link = fs::read_link(process_dir.join("exe")).ok();
        let executable = executable_link.as_ref().and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        });
        let executable_path = executable_link
            .map(|path| path.to_string_lossy().chars().take(512).collect::<String>());
        let rss_estimate_bytes = fs::read_to_string(process_dir.join("status"))
            .ok()
            .and_then(|status| parse_process_rss_bytes(&status));
        let parent_pid = fs::read_to_string(process_dir.join("stat"))
            .ok()
            .and_then(|stat| parse_process_parent_pid(&stat));
        let parent_dir = parent_pid.map(|parent| PathBuf::from(format!("/proc/{parent}")));
        let parent_comm = parent_dir.as_ref().and_then(|dir| {
            fs::read_to_string(dir.join("comm"))
                .ok()
                .map(|value| value.trim().to_owned())
        });
        let parent_in_workload = parent_dir.as_ref().and_then(|dir| {
            let cgroup_text = fs::read_to_string(dir.join("cgroup")).ok()?;
            let parent_cgroup = parse_unified_process_cgroup(&cgroup_text)?;
            Some(workload_for_cgroup(workloads, &parent_cgroup) == Some(workload_index))
        });

        if let Some(workload) = workloads.get_mut(workload_index) {
            workload.process_count_observed = workload.process_count_observed.saturating_add(1);
        }
        let sample = &mut observed[workload_index];
        sample.push(ProcessSnapshot {
            pid,
            comm,
            executable,
            executable_path,
            parent_pid,
            parent_comm,
            parent_in_workload,
            parent_in_tree: None,
            rss_estimate_bytes,
        });
        sample.sort_by(|a, b| {
            b.rss_estimate_bytes
                .unwrap_or(0)
                .cmp(&a.rss_estimate_bytes.unwrap_or(0))
                .then_with(|| a.pid.cmp(&b.pid))
        });
        sample.truncate(MAX_PROCESS_TREE_NODES);
    }

    for (workload_index, mut processes) in observed.into_iter().enumerate() {
        processes.sort_by(|a, b| {
            b.rss_estimate_bytes
                .unwrap_or(0)
                .cmp(&a.rss_estimate_bytes.unwrap_or(0))
                .then_with(|| a.pid.cmp(&b.pid))
        });
        let top_processes: Vec<ProcessSnapshot> =
            processes.iter().take(TOP_PROCESSES).cloned().collect();
        let (tree, mut truncated) = build_ancestor_closed_process_tree(
            top_processes.clone(),
            MAX_PROCESS_TREE_NODES,
            |pid| read_process_snapshot_for_workload(pid, workload_index, workloads),
        );
        truncated |= workloads[workload_index].process_count_observed > tree.len() as u64;
        let tree_pids: std::collections::BTreeSet<u32> =
            tree.iter().map(|process| process.pid).collect();
        let mut top_processes = top_processes;
        for process in &mut top_processes {
            process.parent_in_tree = process.parent_pid.map(|pid| tree_pids.contains(&pid));
        }
        if let Some(workload) = workloads.get_mut(workload_index) {
            workload.top_processes = top_processes;
            workload.executable_hints = build_executable_hints(&tree, 8);
            workload.process_tree = tree;
            workload.process_tree_truncated = truncated;
        }
    }
}

fn read_process_snapshot_for_workload(
    pid: u32,
    workload_index: usize,
    workloads: &[WorkloadSnapshot],
) -> Option<ProcessSnapshot> {
    let process_dir = PathBuf::from(format!("/proc/{pid}"));
    let cgroup_text = fs::read_to_string(process_dir.join("cgroup")).ok()?;
    let cgroup = parse_unified_process_cgroup(&cgroup_text)?;
    if workload_for_cgroup(workloads, &cgroup) != Some(workload_index) {
        return None;
    }

    let comm = fs::read_to_string(process_dir.join("comm"))
        .ok()
        .map(|value| value.trim().to_owned())?;
    let executable_link = fs::read_link(process_dir.join("exe")).ok();
    let executable = executable_link.as_ref().and_then(|path| {
        path.file_name()
            .map(|name| name.to_string_lossy().into_owned())
    });
    let executable_path =
        executable_link.map(|path| path.to_string_lossy().chars().take(512).collect::<String>());
    let rss_estimate_bytes = fs::read_to_string(process_dir.join("status"))
        .ok()
        .and_then(|status| parse_process_rss_bytes(&status));
    let parent_pid = fs::read_to_string(process_dir.join("stat"))
        .ok()
        .and_then(|stat| parse_process_parent_pid(&stat));
    let parent_dir = parent_pid.map(|parent| PathBuf::from(format!("/proc/{parent}")));
    let parent_comm = parent_dir.as_ref().and_then(|dir| {
        fs::read_to_string(dir.join("comm"))
            .ok()
            .map(|value| value.trim().to_owned())
    });
    let parent_in_workload = parent_dir.as_ref().and_then(|dir| {
        let cgroup_text = fs::read_to_string(dir.join("cgroup")).ok()?;
        let parent_cgroup = parse_unified_process_cgroup(&cgroup_text)?;
        Some(workload_for_cgroup(workloads, &parent_cgroup) == Some(workload_index))
    });

    Some(ProcessSnapshot {
        pid,
        comm,
        executable,
        executable_path,
        parent_pid,
        parent_comm,
        parent_in_workload,
        parent_in_tree: None,
        rss_estimate_bytes,
    })
}

fn build_executable_hints(processes: &[ProcessSnapshot], max_hints: usize) -> Vec<ExecutableHint> {
    let mut counts = BTreeMap::<String, (String, usize)>::new();
    for process in processes {
        let (Some(path), Some(basename)) = (
            process.executable_path.as_ref(),
            process.executable.as_ref(),
        ) else {
            continue;
        };
        let entry = counts
            .entry(path.clone())
            .or_insert_with(|| (basename.clone(), 0));
        entry.1 = entry.1.saturating_add(1);
    }
    let mut hints: Vec<_> = counts
        .into_iter()
        .map(|(path, (basename, observed_processes))| ExecutableHint {
            path,
            basename,
            observed_processes,
        })
        .collect();
    hints.sort_by(|a, b| {
        b.observed_processes
            .cmp(&a.observed_processes)
            .then_with(|| a.path.cmp(&b.path))
    });
    hints.truncate(max_hints);
    hints
}

fn build_ancestor_closed_process_tree(
    seeds: Vec<ProcessSnapshot>,
    max_nodes: usize,
    mut lookup_parent: impl FnMut(u32) -> Option<ProcessSnapshot>,
) -> (Vec<ProcessSnapshot>, bool) {
    let mut processes = Vec::with_capacity(max_nodes);
    let mut included_pids = std::collections::BTreeSet::new();
    let mut pending = std::collections::VecDeque::new();

    for mut seed in seeds {
        if processes.len() >= max_nodes {
            break;
        }
        if included_pids.insert(seed.pid) {
            seed.parent_in_tree = None;
            if seed.parent_in_workload == Some(true) {
                if let Some(parent_pid) = seed.parent_pid {
                    pending.push_back(parent_pid);
                }
            }
            processes.push(seed);
        }
    }

    while processes.len() < max_nodes {
        let Some(parent_pid) = pending.pop_front() else {
            break;
        };
        if included_pids.contains(&parent_pid) {
            continue;
        }
        let Some(parent) = lookup_parent(parent_pid) else {
            continue;
        };
        if parent.pid != parent_pid || !included_pids.insert(parent.pid) {
            continue;
        }
        if parent.parent_in_workload == Some(true) {
            if let Some(next_parent) = parent.parent_pid {
                pending.push_back(next_parent);
            }
        }
        processes.push(parent);
    }

    let included_pids: std::collections::BTreeSet<u32> =
        processes.iter().map(|process| process.pid).collect();
    for process in &mut processes {
        process.parent_in_tree = process.parent_pid.map(|pid| included_pids.contains(&pid));
    }
    processes.sort_by_key(|process| process.pid);
    let pending_unresolved = pending.iter().any(|pid| !included_pids.contains(pid));
    let truncated = pending_unresolved
        || processes.iter().any(|process| {
            process.parent_in_workload == Some(true)
                && process.parent_pid.is_some()
                && process.parent_in_tree != Some(true)
        });
    (processes, truncated)
}

fn read_u64(path: PathBuf) -> io::Result<u64> {
    fs::read_to_string(path)?
        .trim()
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid numeric value"))
}

fn read_limit(path: PathBuf) -> io::Result<String> {
    Ok(fs::read_to_string(path)?.trim().to_owned())
}

fn safe_cgroup_relative_path(path: &str) -> Option<PathBuf> {
    let relative = Path::new(path.trim_start_matches('/'));
    if relative.components().any(|part| {
        matches!(
            part,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        None
    } else {
        Some(relative.to_path_buf())
    }
}

fn parse_io_stat(input: &str) -> (u64, u64) {
    let mut read_bytes = 0_u64;
    let mut write_bytes = 0_u64;
    for line in input.lines() {
        for field in line.split_whitespace().skip(1) {
            if let Some(value) = field.strip_prefix("rbytes=") {
                read_bytes = read_bytes.saturating_add(value.parse().unwrap_or(0));
            } else if let Some(value) = field.strip_prefix("wbytes=") {
                write_bytes = write_bytes.saturating_add(value.parse().unwrap_or(0));
            }
        }
    }
    (read_bytes, write_bytes)
}

fn parse_key_values(input: &str) -> BTreeMap<String, u64> {
    input
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            Some((parts.next()?.to_owned(), parts.next()?.parse().ok()?))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process_fixture(pid: u32, parent_pid: Option<u32>, rss: Option<u64>) -> ProcessSnapshot {
        ProcessSnapshot {
            pid,
            comm: format!("process-{pid}"),
            executable: None,
            executable_path: None,
            parent_pid,
            parent_comm: None,
            parent_in_workload: parent_pid.map(|_| true),
            parent_in_tree: None,
            rss_estimate_bytes: rss,
        }
    }

    #[test]
    fn process_tree_is_deterministic_and_marks_missing_parent_edges() {
        let mut first = process_fixture(30, Some(10), Some(300));
        first.parent_in_workload = Some(true);
        let mut second = process_fixture(20, Some(99), Some(200));
        second.parent_in_workload = Some(true);

        let (tree, truncated) =
            build_ancestor_closed_process_tree(vec![first, second], 2, |_| None);

        assert!(truncated);
        assert_eq!(
            tree.iter().map(|process| process.pid).collect::<Vec<_>>(),
            vec![20, 30]
        );
        assert_eq!(tree[0].parent_in_tree, Some(false));
        assert_eq!(tree[1].parent_in_tree, Some(false));
    }

    #[test]
    fn process_tree_keeps_parent_edges_when_parent_is_in_sample() {
        let mut child = process_fixture(20, Some(10), Some(200));
        child.parent_in_workload = Some(true);
        let parent = process_fixture(10, None, Some(100));

        let (tree, truncated) =
            build_ancestor_closed_process_tree(vec![child, parent], 2, |_| None);

        assert!(!truncated);
        assert_eq!(
            tree.iter().map(|process| process.pid).collect::<Vec<_>>(),
            vec![10, 20]
        );
        assert_eq!(tree[0].parent_in_tree, None);
        assert_eq!(tree[1].parent_in_tree, Some(true));
    }

    #[test]
    fn bounded_process_tree_marks_unknown_parent_without_inventing_an_edge() {
        let (tree, truncated) =
            build_ancestor_closed_process_tree(vec![process_fixture(7, None, None)], 32, |_| None);

        assert!(!truncated);
        assert_eq!(tree[0].parent_pid, None);
        assert_eq!(tree[0].parent_in_tree, None);
    }

    #[test]
    fn process_tree_adds_ancestors_of_top_processes() {
        let seed = process_fixture(30, Some(20), Some(300));
        let parent = process_fixture(20, Some(10), Some(100));
        let grandparent = process_fixture(10, None, Some(50));

        let (tree, truncated) =
            build_ancestor_closed_process_tree(vec![seed], 32, |pid| match pid {
                20 => Some(parent.clone()),
                10 => Some(grandparent.clone()),
                _ => None,
            });

        assert!(!truncated);
        assert_eq!(
            tree.iter().map(|process| process.pid).collect::<Vec<_>>(),
            vec![10, 20, 30]
        );
        assert_eq!(
            tree.iter()
                .find(|process| process.pid == 30)
                .unwrap()
                .parent_in_tree,
            Some(true)
        );
        assert_eq!(
            tree.iter()
                .find(|process| process.pid == 20)
                .unwrap()
                .parent_in_tree,
            Some(true)
        );
    }

    #[test]
    fn process_tree_stops_at_node_cap_and_reports_truncation() {
        let seed = process_fixture(30, Some(20), Some(300));
        let parent = process_fixture(20, Some(10), Some(100));

        let (tree, truncated) =
            build_ancestor_closed_process_tree(vec![seed], 2, |pid| match pid {
                20 => Some(parent.clone()),
                10 => Some(process_fixture(10, None, Some(50))),
                _ => None,
            });

        assert!(truncated);
        assert_eq!(tree.len(), 2);
        assert_eq!(
            tree.iter().map(|process| process.pid).collect::<Vec<_>>(),
            vec![20, 30]
        );
    }

    #[test]
    fn process_tree_does_not_import_parent_from_another_workload() {
        let mut seed = process_fixture(30, Some(20), Some(300));
        seed.parent_in_workload = Some(true);
        let (tree, truncated) = build_ancestor_closed_process_tree(vec![seed], 32, |_| None);

        assert!(truncated);
        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0].parent_in_tree, Some(false));
    }

    #[test]
    fn executable_hints_are_bounded_counted_and_deterministic() {
        let mut first = process_fixture(1, None, Some(10));
        first.executable = Some("browser".to_owned());
        first.executable_path = Some("/usr/bin/browser".to_owned());
        let mut second = process_fixture(2, None, Some(20));
        second.executable = Some("browser".to_owned());
        second.executable_path = Some("/usr/bin/browser".to_owned());
        let mut third = process_fixture(3, None, Some(30));
        third.executable = Some("renderer".to_owned());
        third.executable_path = Some("/opt/app/renderer".to_owned());

        let hints = build_executable_hints(&[third, first, second], 1);
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].path, "/usr/bin/browser");
        assert_eq!(hints[0].basename, "browser");
        assert_eq!(hints[0].observed_processes, 2);
    }

    #[test]
    fn executable_hints_ignore_incomplete_identity_metadata() {
        let process = process_fixture(1, None, Some(10));
        assert!(build_executable_hints(&[process], 8).is_empty());
    }

    #[test]
    fn parses_unified_process_cgroup_membership() {
        let parsed = parse_unified_process_cgroup(
            "12:memory:/legacy\n0::/user.slice/user-1000.slice/app.slice/app-demo.scope\n",
        );
        assert_eq!(
            parsed,
            Some(PathBuf::from(
                "user.slice/user-1000.slice/app.slice/app-demo.scope"
            ))
        );
        assert!(parse_unified_process_cgroup("2:cpu:/system.slice/demo.service").is_none());
        assert!(parse_unified_process_cgroup("0::/../../etc").is_none());
    }

    #[test]
    fn parses_process_parent_pid_with_spaces_and_parentheses_in_comm() {
        let stat = "4321 (worker (child)) S 1234 4321 4321 0 -1 4194304 10 0 0 0 1 2 0 0 20 0 4 0 987654 0 0";
        assert_eq!(parse_process_parent_pid(stat), Some(1234));
        assert_eq!(parse_process_parent_pid("malformed"), None);
    }

    #[test]
    fn parses_process_rss_as_bytes_without_treating_it_as_aggregate_memory() {
        let status = "Name:\tdemo\nVmSize:\t900000 kB\nVmRSS:\t1234 kB\n";
        assert_eq!(parse_process_rss_bytes(status), Some(1_263_616));
        assert_eq!(parse_process_rss_bytes("Name:\tdemo\n"), None);
    }

    #[test]
    fn maps_nested_process_cgroups_to_the_accounting_boundary() {
        let workload = WorkloadSnapshot {
            slice: "app.slice".to_owned(),
            name: "app-demo.scope".to_owned(),
            path: "/sys/fs/cgroup/user.slice/user-1000.slice/app.slice/app-demo.scope".to_owned(),
            memory_current_bytes: Some(4096),
            memory_high_limit: Some("max".to_owned()),
            memory_max_limit: Some("max".to_owned()),
            memory_anon_bytes: None,
            memory_file_bytes: None,
            cpu_usage_usec: None,
            pids_current: Some(2),
            io_read_bytes: 0,
            io_write_bytes: 0,
            memory_events: BTreeMap::new(),
            process_count_observed: 0,
            top_processes: Vec::new(),
            process_tree: Vec::new(),
            process_tree_truncated: false,
            executable_hints: Vec::new(),
        };
        let workloads = vec![workload];
        assert!(
            workload_for_cgroup(
                &workloads,
                Path::new("user.slice/user-1000.slice/app.slice/app-demo.scope/child")
            )
            .is_some()
        );
        assert!(
            workload_for_cgroup(
                &workloads,
                Path::new("user.slice/user-1000.slice/app.slice/app-demo.scope-other")
            )
            .is_none()
        );
    }

    #[test]
    fn vmstat_aggregates_allocstall_zones_and_keeps_oom_counters() {
        let parsed = parse_vmstat(
            "oom_kill 2\nallocstall_dma 1\nallocstall_dma32 2\nallocstall_normal 4\npgscan_direct 9\nnot_selected 100\n",
        );
        assert_eq!(parsed.get("oom_kill"), Some(&2));
        assert_eq!(parsed.get("allocstall"), Some(&7));
        assert_eq!(parsed.get("pgscan_direct"), Some(&9));
        assert!(!parsed.contains_key("not_selected"));
    }

    #[test]
    fn parses_meminfo_values_in_kib() {
        let parsed = parse_meminfo("MemTotal:       8000000 kB\nMemAvailable:  2000000 kB\n");
        assert_eq!(parsed.get("MemTotal"), Some(&8_000_000));
        assert_eq!(
            kib_to_bytes(parsed.get("MemAvailable").copied()),
            Some(2_048_000_000)
        );
    }

    #[test]
    fn parses_cgroup_controller_lists() {
        assert_eq!(
            parse_controller_list("cpu memory pids\n"),
            vec!["cpu", "memory", "pids"]
        );
        assert_eq!(
            parse_controller_list("+cpu -io memory"),
            vec!["cpu", "io", "memory"]
        );
    }

    #[test]
    fn parses_cgroup_key_values() {
        let parsed = parse_key_values("low 1\nhigh 2\nmax 3\n");
        assert_eq!(parsed.get("high"), Some(&2));
    }

    #[test]
    fn accepts_absolute_kernel_cgroup_path_as_relative_to_mount() {
        let path = safe_cgroup_relative_path("/user.slice/user-1000.slice").unwrap();
        assert_eq!(path, PathBuf::from("user.slice/user-1000.slice"));
    }

    #[test]
    fn decodes_systemd_hex_escaped_unit_names() {
        assert_eq!(
            decode_systemd_escape(r"app-Remote\x2dDesktop\x2dCommander.service"),
            "app-Remote-Desktop-Commander.service"
        );
        assert_eq!(
            decode_systemd_escape(r"app-demo\x40scope"),
            "app-demo@scope"
        );
        assert_eq!(
            decode_systemd_escape("plain-name.service"),
            "plain-name.service"
        );
    }

    #[test]
    fn finds_user_manager_root_without_assuming_app_slice() {
        let app_path =
            Path::new("/user.slice/user-1000.slice/user@1000.service/app.slice/app-demo.scope");
        assert_eq!(
            user_manager_root(app_path),
            Some(PathBuf::from(
                "user.slice/user-1000.slice/user@1000.service"
            ))
        );
        let session_path = Path::new("/user.slice/user-1000.slice/session-2.scope");
        assert_eq!(
            user_manager_root(session_path),
            Some(PathBuf::from("user.slice/user-1000.slice"))
        );
    }

    #[test]
    fn rejects_paths_without_a_user_manager_or_user_slice() {
        assert!(user_manager_root(Path::new("/system.slice/sshd.service")).is_none());
    }

    #[test]
    fn rejects_parent_traversal_in_cgroup_path() {
        assert!(safe_cgroup_relative_path("/../../etc").is_none());
    }

    #[test]
    fn sums_io_stat_bytes_across_devices() {
        let (read, write) = parse_io_stat(
            "8:0 rbytes=1024 wbytes=2048 rios=1 wios=2\n259:0 rbytes=4096 wbytes=8192 rios=3 wios=4\n",
        );
        assert_eq!(read, 5120);
        assert_eq!(write, 10240);
    }

    #[test]
    fn parses_kscreen_runtime_output_state_and_current_mode() {
        let json = r#"{"outputs":[{"name":"eDP-1","connected":true,"enabled":true,"currentModeId":"1","modes":[{"id":"1","name":"1366x768@60"}],"size":{"width":1366,"height":768},"pos":{"x":0,"y":0}}]}"#;
        let outputs = parse_kscreen_outputs(json).unwrap();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].name, "eDP-1");
        assert!(outputs[0].connected);
        assert!(outputs[0].enabled);
        assert_eq!(outputs[0].mode, "1366x768@60");
        assert_eq!((outputs[0].width, outputs[0].height), (1366, 768));
    }

    #[test]
    fn drm_connector_name_filter_excludes_cards_and_render_nodes() {
        assert!(is_drm_connector_name("card1-eDP-1"));
        assert!(is_drm_connector_name("card1-HDMI-A-1"));
        assert!(!is_drm_connector_name("card1"));
        assert!(!is_drm_connector_name("renderD128"));
        assert!(!is_drm_connector_name("cardx-DP-1"));
    }

    #[test]
    fn graphics_event_filter_keeps_compositor_and_egl_failures() {
        let input = "systemd started user manager\nkwin_wayland: atomic commit failed\nchatgpt: EGL Driver message glXGetMscRateOML failed\nplasmashell: tooltip warning\n";
        let parsed = parse_graphics_events(input, 2);
        assert_eq!(parsed.len(), 2);
        assert!(parsed[0].contains("atomic commit failed"));
        assert!(parsed[1].contains("EGL Driver message"));
    }

    #[test]
    fn graphics_event_filter_prioritizes_atomic_failures_over_repeated_screen_warnings() {
        let mut input = String::from("kwin_wayland: Atomic commit failed: EACCESS\n");
        for index in 0..60 {
            input.push_str(&format!(
                "2026-11-15T15:52:{index:02} archlinux plasmashell[920]: requesting unexisting screen geometry 0\n"
            ));
        }
        let parsed = parse_graphics_events(&input, 2);
        assert_eq!(parsed.len(), 2);
        assert!(
            parsed
                .iter()
                .any(|line| line.contains("Atomic commit failed"))
        );
        assert!(parsed.iter().any(|line| line.contains("unexisting screen")));
    }

    #[test]
    fn graphics_event_filter_deduplicates_repeated_screen_geometry_warnings() {
        let input = "2026-11-15T15:52:44 archlinux plasmashell[920]: requesting unexisting screen geometry 0\n2026-11-15T15:52:45 archlinux plasmashell[920]: requesting unexisting screen geometry 0\n";
        let parsed = parse_graphics_events(input, 8);
        assert_eq!(parsed.len(), 1);
    }

    #[test]
    fn graphics_event_filter_keeps_display_output_loss_and_hotplug_events() {
        let input = "kded6: There are no outputs - creating placeholder screen\norg_kde_powerdevil: prop_subsystem: drm\n";
        let parsed = parse_graphics_events(input, 8);
        assert_eq!(parsed.len(), 2);
        assert!(parsed[0].contains("There are no outputs"));
        assert!(parsed[1].contains("prop_subsystem: drm"));
    }

    #[test]
    fn graphics_event_filter_returns_empty_for_unrelated_logs() {
        assert!(parse_graphics_events("pipewire started\n", 40).is_empty());
    }

    #[test]
    fn kernel_event_filter_keeps_freeze_relevant_lines_and_is_bounded() {
        let input = "normal boot line\nirq 27: nobody cared\ni915 GPU HANG: reset\nACPI BIOS Error: bad thermal sensor\n";
        let parsed = parse_kernel_events(input, 2);
        assert_eq!(parsed.len(), 2);
        assert!(parsed[0].contains("i915 GPU HANG"));
        assert!(parsed[1].contains("ACPI BIOS Error"));
    }

    #[test]
    fn kernel_event_filter_deduplicates_repeated_acpi_sensor_errors() {
        let input = "2026-11-16T14:42:38 archlinux kernel: ACPI BIOS Error (bug): Could not resolve symbol [\\_SB.PC00.LPCB.HEC.TSR5], AE_NOT_FOUND\n2026-11-16T14:42:40 archlinux kernel: ACPI BIOS Error (bug): Could not resolve symbol [\\_SB.PC00.LPCB.HEC.TSR5], AE_NOT_FOUND\n";
        let parsed = parse_kernel_events(input, 8);
        assert_eq!(parsed.len(), 1);
    }

    #[test]
    fn kernel_event_filter_returns_empty_for_unrelated_logs() {
        assert!(parse_kernel_events("systemd started user manager\n", 40).is_empty());
    }

    #[test]
    fn parses_relevant_interrupt_counters_and_bounds_details() {
        let input = "CPU0 CPU1\n 27: 10 20 IR-IO-APIC 27-fasteoi idma64.1\n 31: 5 7 IR-IO-APIC 31-fasteoi nvme0q1\n 44: 9 9 IR-PCI-MSI unrelated\n";
        let parsed = parse_interrupts(input, 8);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].irq, "27");
        assert_eq!(parsed[0].cpu_counts, vec![10, 20]);
        assert!(parsed[0].detail.contains("idma64.1"));
        assert_eq!(parsed[1].irq, "31");
        assert!(parsed[1].detail.contains("nvme0q1"));
    }

    #[test]
    fn interrupt_parser_respects_entry_limit() {
        let input = "27: 1 2 idma64\n28: 3 4 i2c_dw\n29: 5 6 nvme\n";
        assert_eq!(parse_interrupts(input, 2).len(), 2);
    }

    #[test]
    fn parses_thermal_throttle_counters_without_accepting_invalid_values() {
        assert_eq!(parse_thermal_throttle_counter("176853\n"), Some(176_853));
        assert_eq!(parse_thermal_throttle_counter("unknown"), None);
        assert_eq!(parse_thermal_throttle_counter("-1"), None);
    }

    #[test]
    fn parses_psi_line() {
        let line = "some avg10=0.50 avg60=0.25 avg300=0.10 total=12345";
        let mut parts = line.split_whitespace();
        assert_eq!(parts.next(), Some("some"));
        let fields: BTreeMap<_, _> = parts.filter_map(|part| part.split_once('=')).collect();
        assert_eq!(fields.get("avg10"), Some(&"0.50"));
        assert_eq!(fields.get("total"), Some(&"12345"));
    }
}
