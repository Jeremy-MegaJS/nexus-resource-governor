use serde::Serialize;
use std::io::{self, Write};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(target_os = "linux")]
mod budget;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod monitor;
#[cfg(target_os = "linux")]
mod policy;
#[cfg(target_os = "linux")]
#[allow(dead_code)]
// Transaction transitions are covered by tests and reserved for the future UI/IPC layer.
mod rescue;

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = args.first().map(String::as_str).unwrap_or("--json");

    if mode == "--help" || mode == "-h" {
        println!(
            "nrg-agent [--json|--human|--diagnose|--monitor [INTERVAL_MS]|--watch [INTERVAL_MS]|--watch-full [INTERVAL_MS]|--policy|--budget-plan [balanced|gaming|study|development]|--rescue-plan TARGET EXTRA_MIB|--rescue-transaction TARGET EXTRA_MIB [TTL_SECONDS]]\n\nRead-only Linux telemetry and notification-only monitoring. No system settings are changed.\n--policy evaluates memory pressure, OOM, swap, and reclaim signals.\n--monitor runs lightweight notifications and keeps bounded local history.\n--watch emits lightweight JSONL and sends desktop notifications.\n--watch-full also scans /proc for process attribution.\n--diagnose summarizes memory, CPU, I/O, IRQ, display, thermal, and bounded kernel/desktop journal signals.\n--rescue-plan creates a user-action plan; it never pauses or closes apps.\n--rescue-transaction creates a save/approval/expiry/rollback simulation; it never applies controls.\n--budget-plan estimates profile-aware per-app soft ceilings from bounded history; it is dry-run only."
        );
        return;
    }

    if mode == "--diagnose" {
        match linux::collect_snapshot() {
            Ok(snapshot) => println!("{}", snapshot.to_diagnostic()),
            Err(error) => {
                eprintln!("Could not collect diagnostic snapshot: {error}");
                std::process::exit(1);
            }
        }
        return;
    }

    if mode == "--budget-plan" {
        let profile = args.get(1).map(String::as_str).unwrap_or("balanced");
        let snapshot = match linux::collect_monitor_snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                eprintln!("Could not collect resource snapshot: {error}");
                std::process::exit(1);
            }
        };
        let plan = budget::build_plan(&snapshot, profile);
        println!(
            "{}",
            serde_json::to_string_pretty(&plan).expect("budget plan serialization")
        );
        return;
    }

    if mode == "--policy" || mode == "--rescue-plan" || mode == "--rescue-transaction" {
        let snapshot = match linux::collect_snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                eprintln!("Could not collect resource snapshot: {error}");
                std::process::exit(1);
            }
        };
        if mode == "--policy" {
            let report = policy::evaluate(&snapshot);
            println!(
                "{}",
                serde_json::to_string_pretty(&report).expect("policy report serialization")
            );
        } else {
            let target = args.get(1).unwrap_or_else(|| {
                if mode == "--rescue-plan" {
                    eprintln!("Usage: nrg-agent --rescue-plan TARGET EXTRA_MIB");
                } else {
                    eprintln!(
                        "Usage: nrg-agent --rescue-transaction TARGET EXTRA_MIB [TTL_SECONDS]"
                    );
                }
                std::process::exit(2);
            });
            let extra = match args.get(2).and_then(|v| v.parse::<u64>().ok()) {
                Some(value) if value > 0 => value,
                _ => {
                    eprintln!("EXTRA_MIB must be a positive integer");
                    std::process::exit(2);
                }
            };
            if mode == "--rescue-plan" {
                let plan = policy::rescue_plan(&snapshot, target, extra);
                println!(
                    "{}",
                    serde_json::to_string_pretty(&plan).expect("rescue plan serialization")
                );
            } else {
                let ttl_seconds = match args.get(3) {
                    Some(value) => match value.parse::<u64>() {
                        Ok(value) => value,
                        Err(_) => {
                            eprintln!("TTL_SECONDS must be an integer between 30 and 900");
                            std::process::exit(2);
                        }
                    },
                    None => 300,
                };
                let now_unix_secs = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let transaction = match rescue::build_transaction(
                    &snapshot,
                    target,
                    extra,
                    ttl_seconds,
                    now_unix_secs,
                ) {
                    Ok(transaction) => transaction,
                    Err(error) => {
                        eprintln!("Could not create Rescue Mode transaction: {error:?}");
                        std::process::exit(2);
                    }
                };
                println!(
                    "{}",
                    serde_json::to_string_pretty(&transaction)
                        .expect("rescue transaction serialization")
                );
            }
        }
        return;
    }

    if mode == "--monitor" || mode == "--watch" || mode == "--watch-full" {
        let monitor_only = mode == "--monitor";
        let full_process_details = mode == "--watch-full";
        let interval_ms = match args.get(1) {
            Some(value) => match value.parse::<u64>() {
                Ok(value) if (1_000..=60_000).contains(&value) => value,
                _ => {
                    eprintln!("Interval must be between 1000 and 60000 milliseconds.");
                    std::process::exit(2);
                }
            },
            None => 2_000,
        };
        let mut monitor = monitor::MonitorState::default();
        let stdout = io::stdout();
        let mut output = stdout.lock();
        let mut last_history_write: Option<Instant> = None;
        loop {
            let sample = if full_process_details {
                linux::collect_snapshot()
            } else {
                linux::collect_monitor_snapshot()
            };
            match sample {
                Ok(snapshot) => {
                    for notification in monitor.update(&snapshot) {
                        send_notification(&notification);
                    }
                    if monitor_only
                        && last_history_write
                            .is_none_or(|last| last.elapsed() >= Duration::from_secs(10))
                    {
                        if let Err(error) = write_history_sample(&snapshot) {
                            eprintln!("NRG bounded history write failed: {error}");
                        }
                        last_history_write = Some(Instant::now());
                    }
                    if !monitor_only {
                        if let Err(error) = serde_json::to_writer(&mut output, &snapshot) {
                            eprintln!("Could not serialize telemetry sample: {error}");
                            std::process::exit(1);
                        }
                        if let Err(error) = output.write_all(b"\n") {
                            eprintln!("Could not write telemetry sample: {error}");
                            std::process::exit(1);
                        }
                        if let Err(error) = output.flush() {
                            eprintln!("Could not flush telemetry sample: {error}");
                            std::process::exit(1);
                        }
                    }
                }
                Err(error) => {
                    eprintln!("Could not collect resource snapshot: {error}");
                    std::process::exit(1);
                }
            }
            thread::sleep(Duration::from_millis(interval_ms));
        }
    }

    match linux::collect_snapshot() {
        Ok(snapshot) if mode == "--human" => println!("{}", snapshot.to_human()),
        Ok(snapshot) => match serde_json::to_string_pretty(&snapshot) {
            Ok(json) => println!("{json}"),
            Err(error) => {
                eprintln!("Could not serialize resource snapshot: {error}");
                std::process::exit(1);
            }
        },
        Err(error) => {
            eprintln!("Could not collect resource snapshot: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Serialize)]
struct HistorySample {
    schema_version: u32,
    timestamp_unix_ms: u128,
    memory_total_bytes: Option<u64>,
    memory_available_bytes: Option<u64>,
    swap_used_bytes: Option<u64>,
    memory_psi_some_avg10: Option<f64>,
    memory_psi_full_avg10: Option<f64>,
    cpu_psi_full_avg10: Option<f64>,
    io_psi_full_avg10: Option<f64>,
    kernel_oom_kill_events_since_boot: Option<u64>,
    direct_alloc_stalls_since_boot: Option<u64>,
    direct_reclaim_scans_since_boot: Option<u64>,
    cpu_core_throttle_total_time_ms: Option<u64>,
    cpu_package_throttle_total_time_ms: Option<u64>,
    workloads: Vec<HistoryWorkload>,
}

#[cfg(target_os = "linux")]
#[derive(Serialize)]
struct HistoryWorkload {
    name: String,
    memory_current_bytes: Option<u64>,
    cpu_usage_usec: Option<u64>,
    memory_high_events: u64,
    memory_oom_events: u64,
    memory_oom_kill_events: u64,
}

#[cfg(target_os = "linux")]
fn write_history_sample(snapshot: &linux::Snapshot) -> io::Result<()> {
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
    let state_root = std::env::var_os("XDG_STATE_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".local/state"))
        })
        .ok_or_else(|| io::Error::other("neither XDG_STATE_HOME nor HOME is set"))?;
    let directory = state_root.join("nrg");
    fs::create_dir_all(&directory)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    let path = directory.join("telemetry.jsonl");
    let backup = directory.join("telemetry.jsonl.1");

    let sample = HistorySample {
        schema_version: snapshot.schema_version,
        timestamp_unix_ms: snapshot.timestamp_unix_ms,
        memory_total_bytes: snapshot.memory.total_bytes,
        memory_available_bytes: snapshot.memory.available_bytes,
        swap_used_bytes: snapshot.memory.swap_used_bytes,
        memory_psi_some_avg10: snapshot.pressure.some.as_ref().and_then(|p| p.avg10),
        memory_psi_full_avg10: snapshot.pressure.full.as_ref().and_then(|p| p.avg10),
        cpu_psi_full_avg10: snapshot.cpu_pressure.full.as_ref().and_then(|p| p.avg10),
        io_psi_full_avg10: snapshot.io_pressure.full.as_ref().and_then(|p| p.avg10),
        kernel_oom_kill_events_since_boot: snapshot.vmstat.get("oom_kill").copied(),
        direct_alloc_stalls_since_boot: snapshot.vmstat.get("allocstall").copied(),
        direct_reclaim_scans_since_boot: snapshot.vmstat.get("pgscan_direct").copied(),
        cpu_core_throttle_total_time_ms: snapshot
            .cpu_thermal_throttle
            .as_ref()
            .and_then(|t| t.core_throttle_total_time_ms),
        cpu_package_throttle_total_time_ms: snapshot
            .cpu_thermal_throttle
            .as_ref()
            .and_then(|t| t.package_throttle_total_time_ms),
        workloads: {
            let mut apps: Vec<_> = snapshot
                .workloads
                .iter()
                .filter(|w| w.slice == "app.slice")
                .collect();
            apps.sort_by_key(|workload| {
                std::cmp::Reverse(workload.memory_current_bytes.unwrap_or(0))
            });
            apps.truncate(8);
            apps.into_iter()
                .map(|w| HistoryWorkload {
                    name: w.name.clone(),
                    memory_current_bytes: w.memory_current_bytes,
                    cpu_usage_usec: w.cpu_usage_usec,
                    memory_high_events: w.memory_events.get("high").copied().unwrap_or(0),
                    memory_oom_events: w.memory_events.get("oom").copied().unwrap_or(0),
                    memory_oom_kill_events: w.memory_events.get("oom_kill").copied().unwrap_or(0),
                })
                .collect()
        },
    };
    let mut line = serde_json::to_vec(&sample)
        .map_err(|error| io::Error::other(format!("history serialization: {error}")))?;
    line.push(b'\n');

    let current_size = fs::metadata(&path)
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    if current_size.saturating_add(line.len() as u64) > MAX_FILE_BYTES {
        let _ = fs::remove_file(&backup);
        if path.exists() {
            fs::rename(&path, &backup)?;
        }
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    use std::io::Write;
    file.write_all(&line)?;
    file.flush()
}

#[cfg(target_os = "linux")]
fn send_notification(notification: &monitor::Notification) {
    let urgency = if notification.critical {
        "critical"
    } else {
        "normal"
    };
    match std::process::Command::new("notify-send")
        .args([
            "--app-name=Nexus Resource Governor",
            &format!("--urgency={urgency}"),
            "--expire-time=10000",
            &notification.title,
            &notification.body,
        ])
        .status()
    {
        Ok(status) if status.success() => {}
        Ok(status) => eprintln!("NRG notification failed: {status}"),
        Err(error) => eprintln!("NRG could not invoke notify-send: {error}"),
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("The Linux telemetry backend is not available on this platform yet.");
    std::process::exit(2);
}
