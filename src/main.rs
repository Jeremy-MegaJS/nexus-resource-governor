use std::io::{self, Write};
use std::thread;
use std::time::Duration;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod policy;

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = args.first().map(String::as_str).unwrap_or("--json");

    if mode == "--help" || mode == "-h" {
        println!(
            "nrg-agent [--json|--human|--watch [INTERVAL_MS]|--policy|--rescue-plan TARGET EXTRA_MIB]\n\nRead-only Linux telemetry and dry-run policy evaluation. No system settings are changed.\n--policy evaluates the early OOM guard.\n--rescue-plan creates a user-action plan; it never pauses or closes apps."
        );
        return;
    }

    if mode == "--policy" || mode == "--rescue-plan" {
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
                eprintln!("Usage: nrg-agent --rescue-plan TARGET EXTRA_MIB");
                std::process::exit(2);
            });
            let extra = match args.get(2).and_then(|v| v.parse::<u64>().ok()) {
                Some(value) if value > 0 => value,
                _ => {
                    eprintln!("EXTRA_MIB must be a positive integer");
                    std::process::exit(2);
                }
            };
            let plan = policy::rescue_plan(&snapshot, target, extra);
            println!(
                "{}",
                serde_json::to_string_pretty(&plan).expect("rescue plan serialization")
            );
        }
        return;
    }

    if mode == "--watch" {
        let interval_ms = match args.get(1) {
            Some(value) => match value.parse::<u64>() {
                Ok(value) if (250..=60_000).contains(&value) => value,
                _ => {
                    eprintln!("Interval must be between 250 and 60000 milliseconds.");
                    std::process::exit(2);
                }
            },
            None => 1_000,
        };
        let stdout = io::stdout();
        let mut output = stdout.lock();
        loop {
            match linux::collect_snapshot() {
                Ok(snapshot) => {
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

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("The Linux telemetry backend is not available on this platform yet.");
    std::process::exit(2);
}

[executed on device: archlinux (bc227e4e-b47b-4157-8834-d4e1828760c0)]