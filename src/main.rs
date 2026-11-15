use std::io::{self, Write};
use std::thread;
use std::time::Duration;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = args.first().map(String::as_str).unwrap_or("--json");

    if mode == "--help" || mode == "-h" {
        println!(
            "nrg-agent [--json|--human|--watch [INTERVAL_MS]]\n\nRead-only Linux resource telemetry. No system settings are changed.\n--watch emits newline-delimited JSON until interrupted (default 1000 ms)."
        );
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
                    if let Err(error) = serde_json::to_writer(&mut output, &snapshot)
                        .and_then(|_| output.write_all(b"\n").map_err(serde_json::Error::io))
                    {
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
