# Nexus Resource Governor

**Intelligent, policy-driven resource management for Linux and Windows.**

NRG monitors system and application resource usage, predicts resource pressure, and applies graduated, user-configurable policies to keep the operating system responsive without unexpectedly terminating important work.

> **Status:** Linux telemetry monitor, deterministic adaptive memory-budget planner, and Rescue Mode simulator. Resource-control enforcement is still disabled.

## Why NRG exists

Operating systems manage memory, CPU time, storage I/O, and process scheduling, but users still lack one clear place to define application budgets and understand what happens when workloads compete for limited resources.

NRG aims to provide:
- Per-application and per-workload resource budgets.
- An adaptive system safety margin.
- Admission checks for workloads launched through NRG.
- Graduated responses to pressure instead of immediate termination.
- Transparent explanations, telemetry, and user-controlled overrides.
- A shared policy engine with native operating-system backends.

NRG complements the OS; it does not replace the kernel memory manager or Windows memory manager.

## Design principles

1. **Protect responsiveness, not an arbitrary free-memory number.** The initial 2 GiB physical-memory reserve is a normal-use target, not a hard allocation or universal limit. Gaming and performance profiles may temporarily consume that margin.
2. **Measure pressure, not just utilization.** Consider available memory, reclaimable cache, swap/compressed memory, pressure-stall information, and per-workload usage.
3. **Prefer reversible actions.** Warn, throttle, adjust priorities, and ask before disruptive actions.
4. **Never silently kill user work.** Hard limits and termination require explicit policy and clear warnings.
5. **Explain every intervention.** Show the signal, policy, affected workload, action, and recovery path.
6. **Fail safely.** Monitoring or enforcement failure must not leave workloads trapped under stale limits.
7. **Use native platform controls.** Share policy and UX while using each OS's supported control interfaces.

## Core capabilities

| Capability | Purpose |
|---|---|
| Resource monitor | Collect system and per-workload memory, CPU, I/O, and pressure metrics |
| Workload identity | Group a process tree into an application or workload |
| Budget engine | Define soft targets, warning thresholds, and optional hard ceilings |
| Admission controller | Estimate whether a workload fits the current policy |
| Pressure controller | Apply graduated, reversible responses |
| Recovery coordinator | Restore normal settings when pressure clears |
| Audit and explanations | Record why each decision was made |

## Platform strategy

### Linux — first implementation
- cgroup v2 for workload accounting and supported controls.
- PSI from /proc/pressure to detect memory, CPU, and I/O stalls.
- systemd integration where available.
- Separate accounting for physical memory and swap/zram.
- Native process and device telemetry.

### Windows — planned
- Job Objects for process-tree grouping and supported resource limits.
- Windows process, memory, and performance APIs for monitoring.
- Native notifications and startup integration.
- A Windows backend implementing the same policy contracts as Linux.

The policy engine and configuration format should be portable. Enforcement is platform-specific.

## Resource model

NRG treats these as separate dimensions:
- **Physical memory:** working sets, committed usage, reclaimable cache, and system availability.
- **Swap / compressed memory:** Linux swap and zram, accounted separately from physical RAM.
- **CPU:** usage, scheduling weight, and throttling where supported.
- **Storage I/O:** throughput, operations, and I/O pressure where supported.
- **GPU memory:** later capability; integrated GPUs share system memory and attribution may be limited.
- **Network:** later capability; shaping is outside the initial scope.

A workload budget is not automatically a hard cap. Soft targets and pressure responses are the default; hard ceilings are opt-in.

## Pressure response model

1. **Observe** — collect metrics and establish a baseline.
2. **Warn** — explain which workload is consuming the budget and why it matters.
3. **Contain** — apply reversible controls such as memory.high, CPU weights, or I/O weights where supported.
4. **Rebalance** — offer or apply policy-approved budget changes and prioritization.
5. **Recover** — restore normal settings when pressure subsides.
6. **Escalate** — request explicit approval before actions that could lose work.

NRG cannot generically save every application's state. Graceful save/close support requires application-specific APIs or adapters.

## Safety boundaries

- No arbitrary root shell exposed to the UI or policy engine.
- No silent SIGKILL or equivalent termination.
- No hard memory cap by default.
- No assumption that swap or zram is equivalent to physical RAM.
- No intervention based only on a single utilization percentage.
- Every applied limit must have an owner, expiry/recovery behavior, and audit record.

## Linux telemetry prototype

The first implementation is a read-only Rust CLI. It currently samples:
- Physical memory and swap from /proc/meminfo.
- Memory, CPU, and I/O PSI from /proc/pressure.
- Bounded interrupt counters for IRQ 27 and selected graphics/storage/input drivers.
- DRM device/driver identity, connector status/modes, KScreen userspace output state and DPMS mode, thermal-zone readings, and CPU core/package thermal-throttle counters with delta-based monitor alerts (no GPU engine utilization claim).
- Filtered, bounded kernel and user-session journal events from the current boot and three preceding boots, including KWin/Plasma/XWayland/EGL messages when journal access is available.
- ZRAM compression and physical-memory accounting from sysfs.
- Selected paging and reclaim counters from /proc/vmstat.
- The collector process's current cgroup v2 memory counters.
- cgroup v2 controller availability, child-controller enablement, and a non-mutating write-open probe for the current cgroup (not a guarantee of systemd delegation).
- Per-workload cgroup memory, CPU, process-count, and I/O counters from user application, session, and background slices.

The lightweight watch mode emits one JSON snapshot per line and flushes each sample, without scanning every process. It sends desktop notifications (requests a 10-second expiry) when it detects a new application workload, when an app crosses its warning or critical memory budget, when system pressure escalates, and when OOM/reclaim events occur. The default polling interval is 2 seconds. The notification-only --monitor mode runs silently and stores a compact sample every 10 seconds in ~/.local/state/nrg/telemetry.jsonl. Retention is bounded to 8 MiB plus one rotated 8 MiB backup; directories/files use private permissions. History contains no PIDs, command lines, or raw journal text. The --watch-full mode opts into more expensive per-process attribution. Per-app notification thresholds can be overridden in ~/.config/nrg/budgets.conf; initialize it with mkdir -p ~/.config/nrg && cp config/budgets.example.conf ~/.config/nrg/budgets.conf. These are warning thresholds only, not enforced cgroup limits. Schema version 14 includes per-workload cgroup memory.high/memory.max snapshots and CPU thermal-throttling counters; the lightweight monitor skips process attribution but records throttle deltas. OOM-kill/direct-reclaim counters and Linux overcommit mode are included. Commit usage is compared with CommitLimit only in strict overcommit mode 2; in modes 0/1 the ratio is not a reliable OOM predictor. The --diagnose command correlates memory/CPU/I/O pressure, IRQ, display, thermal, and bounded kernel/desktop journal events from the current and three preceding boots. It cannot yet identify GPU engine hangs directly or infer that an IRQ is disabled from counters alone.

These policy commands are currently advisory only:

```sh
cargo run -- --policy
cargo run -- --budget-plan gaming
cargo run -- --budget-plan study
cargo run -- --diagnose
cargo run -- --rescue-plan brave 512
cargo run -- --rescue-transaction brave 512 300
```

`--budget-plan [balanced|gaming|study|development]` calculates profile-aware per-app soft-memory proposals from bounded historical P95 samples, current usage, and a system reserve. New apps receive a conservative bootstrap estimate until at least five samples exist. The planner prioritizes workloads by profile, preserves the captured memory.max, and refuses to propose limits if current-use safety floors cannot fit. It is dry-run only; no cgroup values are written. User-editable profiles and live enforcement are not implemented yet.

`--rescue-plan` takes a case-insensitive workload-name fragment and extra MiB requested by the priority workload. `--rescue-transaction TARGET EXTRA_MIB [TTL_SECONDS]` (30–900 seconds; default 300) emits a transaction-shaped dry-run: it captures the target's previous `memory.high`/`memory.max`, proposes a soft `memory.high` only when the current value is numeric, records an expiry and restore plan, and models save verification plus separate pause/close approval. Every state-changing simulation transition checks the expiry; expired plans reject further approvals and measurements, while the user can decline at any active stage. The expiry is metadata/state validation only—there is no persistent transaction daemon or automatic timer yet. No cgroup values are written and no process is controlled. `memory.max` is never proposed for change. No application adapters are registered yet; a user attestation is not an application-confirmed save. Before/after `memory.current` is an observed delta, not proof that a particular action caused the decrease. Pausing a process does not itself free resident memory. Target delegation and ancestor limits are not yet validated, so enforcement remains disabled. The Linux kernel remains responsible for reclaiming file cache and swapping anonymous memory; NRG does not route allocations directly to swap. The Windows backend is not implemented.

Build and run on Linux:

```sh
cargo test
cargo run -- --human
cargo run -- --json
# Build the monitor binary and prepare its private state directory:
cargo build --release
mkdir -p ~/.local/state/nrg
# Install the user-session monitor at login:
install -Dm644 packaging/systemd/nrg-monitor.service ~/.config/systemd/user/nrg-monitor.service
systemctl --user daemon-reload
systemctl --user enable --now nrg-monitor.service
# Stream lightweight JSONL manually when correlating a freeze:
cargo run --release -- --watch 2000 >> nrg-session.jsonl
# More expensive process-attribution sampling:
cargo run --release -- --watch-full 5000 >> nrg-session-full.jsonl
```

## NRG Desktop (early GUI)

A lightweight bilingual (English/Spanish) PySide6 desktop interface is available for KDE/Linux. It provides a live resource overview (RAM, swap, CPU, PSI, home-volume free space, exposed dedicated GPU memory, and aggregate network throughput), a read-only process inventory, heuristic anomaly indicators, the adaptive memory-budget planner, and the kernel/graphics/IRQ/thermal diagnostic report.

Build the agent with cargo build --release, then install the launcher with ./packaging/install-desktop.sh. Open NRG Desktop from the application menu. The UI refreshes process metrics every five seconds and can be closed independently of the nrg-monitor.service background monitor.

The process view reads /proc metadata (PID, executable path, owner, RSS, CPU counters, and I/O counters). It does not read process command-line arguments or environment variables. Indicators include sustained high CPU, rapid RSS growth, sustained disk writes, deleted executables, executables launched from temporary directories, unusually rapid process-count growth, and parent processes creating unusually large bursts of direct children. These are investigation clues, not malware detection or a virus verdict. RSS is an estimate and must not be summed as unique physical memory.

The GUI requires the system Python PySide6 package. It runs as the logged-in user and does not require root. The process table provides guarded per-PID STOP/CONT/HUP/INT/TERM/KILL signals, nice-value adjustment, and CPU affinity. TERM/KILL require confirmation; PID identity is revalidated to avoid PID-reuse mistakes, and NRG refuses to signal PID 1 or its own ancestor chain. Linux permissions still apply; this is not a root helper and cannot manage protected processes without authorization. No cgroup memory limits or network shaping are applied. Profile selection, language, and optional anomaly monitoring are saved to ~/.config/nrg/desktop.json. Use Edit coasters to manage ~/.config/nrg/profiles.json, with profile priorities ordered from highest to lowest. The Rust planner reads those priorities when generating dry-run memory proposals.

Optional hardware readings are taken from KDE KSystemStats over the user D-Bus session (CPU/GPU temperatures and utilization, GPU VRAM where exposed, battery, Wi-Fi signal, fan, and disk I/O); missing sensors are shown as unavailable. Dedicated VRAM is reported only when NVIDIA, DRM, or KSystemStats exposes it. Integrated graphics are labelled as shared with system RAM rather than being assigned a fictitious VRAM total. Network throughput is aggregate per active physical interface, not per application. The opt-in network test uses speedtest-cli for bidirectional download/upload/ping when installed; otherwise it performs a bounded 25 MB Cloudflare download-only test and explicitly leaves upload unmeasured. The budget preview uses the lower of contracted and measured capacity separately for each direction, then reserves a 10% safety margin. It does not configure tc, eBPF, nftables, or change Wi-Fi. The anomaly toggle disables heuristic scoring, process-creation checks, and executable-path inspection while retaining the basic process table. These signals are investigation clues, not malware verdicts.

## Development

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/ROADMAP.md](docs/ROADMAP.md).

## License

License not selected yet.
