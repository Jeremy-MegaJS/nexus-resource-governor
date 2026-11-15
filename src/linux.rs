use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const MEMINFO: &str = "/proc/meminfo";
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

#[derive(Debug, Serialize)]
pub struct Snapshot {
    schema_version: u32,
    timestamp_unix_ms: u128,
    platform: &'static str,
    memory: Memory,
    pressure: Pressure,
    zram: Option<Zram>,
    vmstat: BTreeMap<String, u64>,
    cgroup_v2: Option<CgroupSnapshot>,
}

#[derive(Debug, Serialize)]
struct Memory {
    total_bytes: Option<u64>,
    available_bytes: Option<u64>,
    free_bytes: Option<u64>,
    buffers_bytes: Option<u64>,
    cached_bytes: Option<u64>,
    reclaimable_slab_bytes: Option<u64>,
    unreclaimable_slab_bytes: Option<u64>,
    swap_total_bytes: Option<u64>,
    swap_free_bytes: Option<u64>,
    swap_used_bytes: Option<u64>,
    committed_bytes: Option<u64>,
    commit_limit_bytes: Option<u64>,
}

#[derive(Debug, Serialize)]
struct Pressure {
    some: Option<PsiLine>,
    full: Option<PsiLine>,
}

#[derive(Debug, Serialize)]
struct PsiLine {
    avg10: Option<f64>,
    avg60: Option<f64>,
    avg300: Option<f64>,
    total_us: Option<u64>,
}

#[derive(Debug, Serialize)]
struct Zram {
    device: String,
    disk_size_bytes: Option<u64>,
    original_data_bytes: Option<u64>,
    compressed_data_bytes: Option<u64>,
    memory_used_bytes: Option<u64>,
    compression_ratio: Option<f64>,
}

#[derive(Debug, Serialize)]
struct CgroupSnapshot {
    path: String,
    memory_current_bytes: Option<u64>,
    memory_high_bytes: Option<u64>,
    memory_max_bytes: Option<u64>,
    memory_swap_current_bytes: Option<u64>,
    memory_swap_max_bytes: Option<u64>,
    memory_events: BTreeMap<String, u64>,
}

impl Snapshot {
    pub fn to_human(&self) -> String {
        let mut out = String::new();
        out.push_str("Nexus Resource Governor — read-only Linux snapshot\n");
        out.push_str("No resource controls were changed.\n\n");
        push_metric(&mut out, "Physical RAM total", self.memory.total_bytes);
        push_metric(&mut out, "Physical RAM available", self.memory.available_bytes);
        push_metric(&mut out, "Physical RAM free", self.memory.free_bytes);
        push_metric(&mut out, "Swap used", self.memory.swap_used_bytes);
        if let Some(zram) = &self.zram {
            push_metric(&mut out, &format!("{} compressed data", zram.device), zram.compressed_data_bytes);
            push_metric(&mut out, &format!("{} physical memory used", zram.device), zram.memory_used_bytes);
            if let Some(ratio) = zram.compression_ratio {
                out.push_str(&format!("{} compression ratio: {:.2}:1\n", zram.device, ratio));
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
            push_metric(&mut out, "Cgroup memory.current", cgroup.memory_current_bytes);
            push_metric(&mut out, "Cgroup memory.high", cgroup.memory_high_bytes);
        } else {
            out.push_str("Current cgroup: unavailable (not cgroup v2 or inaccessible)\n");
        }
        out
    }
}

fn push_metric(out: &mut String, label: &str, value: Option<u64>) {
    match value {
        Some(bytes) => out.push_str(&format!("{label}: {} ({:.2} GiB)\n", bytes, bytes as f64 / 1_073_741_824.0)),
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
        some: read_psi_line("/proc/pressure/memory", "some").ok().flatten(),
        full: read_psi_line("/proc/pressure/memory", "full").ok().flatten(),
    };

    let timestamp_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();

    Ok(Snapshot {
        schema_version: 1,
        timestamp_unix_ms,
        platform: "linux",
        memory,
        pressure,
        zram: read_zram("zram0").ok().flatten(),
        vmstat: read_vmstat()?,
        cgroup_v2: read_current_cgroup().ok().flatten(),
    })
}

fn parse_meminfo(input: &str) -> BTreeMap<String, u64> {
    input.lines().filter_map(|line| {
        let (key, value) = line.split_once(':')?;
        let number = value.split_whitespace().next()?.parse::<u64>().ok()?;
        Some((key.to_owned(), number))
    }).collect()
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
    let values: Vec<u64> = stats.split_whitespace().filter_map(|v| v.parse().ok()).collect();
    let original = values.first().copied();
    let compressed = values.get(1).copied();
    let memory_used = values.get(2).copied();
    let ratio = match (original, compressed) {
        (Some(orig), Some(comp)) if comp > 0 => Some(orig as f64 / comp as f64),
        _ => None,
    };
    Ok(Some(Zram {
        device: device.to_owned(),
        disk_size_bytes: read_u64(base.join("disksize")).ok(),
        original_data_bytes: original,
        compressed_data_bytes: compressed,
        memory_used_bytes: memory_used,
        compression_ratio: ratio,
    }))
}

fn read_vmstat() -> io::Result<BTreeMap<String, u64>> {
    const SELECTED: &[&str] = &[
        "pgmajfault", "pswpin", "pswpout", "allocstall",
        "pgscan_kswapd", "pgscan_direct", "pgsteal_kswapd", "pgsteal_direct",
    ];
    let contents = fs::read_to_string("/proc/vmstat")?;
    Ok(contents.lines().filter_map(|line| {
        let mut parts = line.split_whitespace();
        let key = parts.next()?;
        if !SELECTED.contains(&key) {
            return None;
        }
        Some((key.to_owned(), parts.next()?.parse().ok()?))
    }).collect())
}

fn read_current_cgroup() -> io::Result<Option<CgroupSnapshot>> {
    let contents = fs::read_to_string("/proc/self/cgroup")?;
    let relative = contents.lines().find_map(|line| {
        let mut parts = line.splitn(3, ':');
        if parts.next()? == "0" && parts.next()? == "" {
            Some(parts.next()?.to_owned())
        } else {
            None
        }
    });
    let Some(relative) = relative else { return Ok(None) };

    let relative_path = Path::new(&relative);
    if relative_path.components().any(|part| matches!(part, Component::ParentDir | Component::RootDir | Component::Prefix(_))) {
        return Ok(None);
    }
    let base = Path::new(CGROUP_ROOT).join(relative_path);
    if !base.join("memory.current").exists() {
        return Ok(None);
    }

    let memory_events = fs::read_to_string(base.join("memory.events"))
        .map(|text| parse_key_values(&text))
        .unwrap_or_default();

    Ok(Some(CgroupSnapshot {
        path: relative,
        memory_current_bytes: read_u64(base.join("memory.current")).ok(),
        memory_high_bytes: read_limit(base.join("memory.high")).ok().flatten(),
        memory_max_bytes: read_limit(base.join("memory.max")).ok().flatten(),
        memory_swap_current_bytes: read_u64(base.join("memory.swap.current")).ok(),
        memory_swap_max_bytes: read_limit(base.join("memory.swap.max")).ok().flatten(),
        memory_events,
    }))
}

fn read_u64(path: PathBuf) -> io::Result<u64> {
    fs::read_to_string(path)?.trim().parse().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid numeric value"))
}

fn read_limit(path: PathBuf) -> io::Result<Option<u64>> {
    let value = fs::read_to_string(path)?;
    let trimmed = value.trim();
    if trimmed == "max" {
        Ok(None)
    } else {
        trimmed.parse().map(Some).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid cgroup limit"))
    }
}

fn parse_key_values(input: &str) -> BTreeMap<String, u64> {
    input.lines().filter_map(|line| {
        let mut parts = line.split_whitespace();
        Some((parts.next()?.to_owned(), parts.next()?.parse().ok()?))
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_meminfo_values_in_kib() {
        let parsed = parse_meminfo("MemTotal:       8000000 kB\nMemAvailable:  2000000 kB\n");
        assert_eq!(parsed.get("MemTotal"), Some(&8_000_000));
        assert_eq!(kib_to_bytes(parsed.get("MemAvailable").copied()), Some(2_048_000_000));
    }

    #[test]
    fn parses_cgroup_key_values() {
        let parsed = parse_key_values("low 1\nhigh 2\nmax 3\n");
        assert_eq!(parsed.get("high"), Some(&2));
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
