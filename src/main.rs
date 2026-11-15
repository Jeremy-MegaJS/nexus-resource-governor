#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
fn main() {
    let mode = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "--json".to_owned());

    if mode == "--help" || mode == "-h" {
        println!(
            "nrg-agent [--json|--human]\n\nRead-only Linux resource snapshot. No system settings are changed."
        );
        return;
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

