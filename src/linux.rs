use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const MEMINFO: &str = "/proc/meminfo";
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

#[derive(Debug, Serialize)]
pub(crate) struct Snapshot {
    pub(crate) schema_version: u32,
    pub(crate) timestamp_unix_ms: u128,
    pub(crate) platform: &'static str,
    pub(crate) memory: Memory,
    pub(crate) pressure: Pressure,
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
}

#[derive(Debug, Serialize)]
pub(crate) struct Pressure {
    pub(crate) some: Option<PsiLine>,
    pub(crate) full: Option<PsiLine>,
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
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ProcessSnapshot {
    pub(crate) pid: u32,
    pub(crate) comm: String,
    pub(crate) executable: Option<String>,
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
    };

    let pressure = Pressure {
        some: read_psi_line("/proc/pressure/memory", "some")
            .ok()
            .flatten(),
        full: read_psi_line("/proc/pressure/memory", "full")
            .ok()
            .flatten(),
    };

    let timestamp_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();

    Ok(Snapshot {
        schema_version: 5,
        timestamp_unix_ms,
        platform: "linux",
        memory,
        pressure,
        zram: read_zram("zram0").ok().flatten(),
        vmstat: read_vmstat()?,
        cgroup_v2: read_current_cgroup().ok().flatten(),
        cgroup_capabilities: read_cgroup_capabilities(),
        workloads: read_workloads().unwrap_or_default(),
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

fn read_vmstat() -> io::Result<BTreeMap<String, u64>> {
    const SELECTED: &[&str] = &[
        "pgmajfault",
        "pswpin",
        "pswpout",
        "allocstall",
        "pgscan_kswapd",
        "pgscan_direct",
        "pgsteal_kswapd",
        "pgsteal_direct",
    ];
    let contents = fs::read_to_string("/proc/vmstat")?;
    Ok(contents
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let key = parts.next()?;
            if !SELECTED.contains(&key) {
                return None;
            }
            Some((key.to_owned(), parts.next()?.parse().ok()?))
        })
        .collect())
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

fn read_workloads() -> io::Result<Vec<WorkloadSnapshot>> {
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
            });
        }
    }

    correlate_processes(&mut workloads);
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
        let executable = fs::read_link(process_dir.join("exe"))
            .ok()
            .and_then(|path| {
                path.file_name()
                    .map(|name| name.to_string_lossy().into_owned())
            });
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
    let executable = fs::read_link(process_dir.join("exe"))
        .ok()
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        });
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
        parent_pid,
        parent_comm,
        parent_in_workload,
        parent_in_tree: None,
        rss_estimate_bytes,
    })
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
    fn parses_psi_line() {
        let line = "some avg10=0.50 avg60=0.25 avg300=0.10 total=12345";
        let mut parts = line.split_whitespace();
        assert_eq!(parts.next(), Some("some"));
        let fields: BTreeMap<_, _> = parts.filter_map(|part| part.split_once('=')).collect();
        assert_eq!(fields.get("avg10"), Some(&"0.50"));
        assert_eq!(fields.get("total"), Some(&"12345"));
    }
}
