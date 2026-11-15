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
            out.push_str("Top user workloads (cgroup memory):\n");
            for workload in self.workloads.iter().take(8) {
                let memory_gib =
                    workload.memory_current_bytes.unwrap_or(0) as f64 / 1_073_741_824.0;
                out.push_str(&format!(
                    "  {}/{}: {:.2} GiB, {} tasks\n",
                    workload.slice,
                    workload.name,
                    memory_gib,
                    workload.pids_current.unwrap_or(0)
                ));
            }
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
        schema_version: 2,
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
            let name = entry.file_name().to_string_lossy().into_owned();
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
            });
        }
    }

    workloads.sort_by_key(|item| std::cmp::Reverse(item.memory_current_bytes.unwrap_or(0)));
    Ok(workloads)
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
