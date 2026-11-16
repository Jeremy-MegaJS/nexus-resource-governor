# Nexus Resource Governor — Roadmap

The project currently has a read-only Linux telemetry backend and a policy/Rescue Mode simulator. Controlled enforcement, the desktop UI, and the Windows backend are not implemented. The order prioritizes trustworthy measurement and safe recovery before enforcement.

## Phase 0 — Requirements and architecture
- [x] Define Linux-first, Windows-planned strategy.
- [x] Define shared policy engine and native backend boundary.
- [x] Define physical-memory reserve as an adaptive target, not a hard reservation.
- [x] Separate physical RAM from swap/zram accounting.
- [x] Define graduated responses and no-silent-kill safety rule.
- [ ] Select UI toolkit and IPC protocol.
- [ ] Define configuration schema and compatibility rules.

## Phase 1 — Read-only Linux telemetry
- [x] Add read-only Linux snapshot CLI for physical memory, swap, zram, memory PSI, selected vmstat counters, and current cgroup v2 metrics.
- [x] Add parser tests and safe cgroup-path validation.
- [x] Add JSONL watch mode with per-sample flush for pressure/freeze correlation.
- [x] Add a lightweight watch path that skips per-process /proc attribution.
- [x] Add notification-only application discovery, per-workload memory warning/critical thresholds, pressure escalation, and OOM-kill delta alerts with hysteresis.
- [x] Add compact 10-second local history with bounded 8 MiB rotation and private file permissions.
- [x] Package and enable a user-scoped, read-only notification monitor service for Arch/Linux.
- [x] Expose kernel OOM-kill and direct-reclaim counters plus per-workload cgroup high/oom/oom_kill event totals.
- [x] Read Linux overcommit mode and avoid treating Committed_AS / CommitLimit as a strict admission ratio unless overcommit mode is 2.
- [x] Add CPU/I/O PSI, bounded IRQ counters, DRM driver and connector identity, thermal zones, CPU thermal-throttle counters and delta alerts, filtered kernel and desktop-session journal events from the current and three preceding boots, and a read-only freeze triage view.
- [x] Detect cgroup v2 controllers, child-controller enablement, and current-cgroup subtree-control write access (read-only probe; delegation is not assumed).
- [x] Collect per-workload memory, CPU, process-count, and I/O counters from user cgroup slices.
- [x] Discover workloads from the per-user systemd cgroup hierarchy, independent of whether NRG runs in `app.slice`.
- [x] Use top-level workload cgroups as accounting boundaries; document that `memory.current` includes descendants and must not be summed with nested child cgroups.
- [x] Correlate top-level workload cgroups with observed `/proc` process membership and bounded per-process RSS diagnostics (not additive).
- [x] Capture PPID and parent cgroup relationship for observed processes.
- [x] Add a bounded (32-node) ancestor-closed process graph rooted at the five highest-RSS processes, with same-workload parent validation and truncation metadata.
- [x] Expose a bounded `/proc/PID/exe` target path alongside executable basename as an additional identity hint; do not collect command-line arguments.
- [x] Aggregate a bounded, deterministic inventory of executable paths observed in each sampled workload; keep it explicitly as identity hints, not an asserted app identity.
- [ ] Add GPU engine/reset telemetry where exposed.
- [ ] Provide a stable sampling API for external clients.
- [ ] Improve application identity beyond cgroup membership and executable metadata using confidence-scored, non-secret signals.
- [ ] Validate metrics against system tools under normal and stressed workloads.

**Exit criteria:** NRG explains which workloads consume resources, whether the system is under pressure, and correlates relevant display/kernel events without changing system state.

## Phase 2 — Policy engine and simulator
- [x] Define a first portable policy input using normalized Linux telemetry.
- [x] Implement deterministic early OOM-risk evaluation and dry-run Rescue Mode planning.
- [x] Add a deterministic dry-run adaptive memory-budget planner using bounded per-app P95 history, system reserve, and named workload profiles.
- [ ] Define persistent workload identities, configurable budgets, and backend capabilities.
- [x] Add initial balanced, gaming, study, and development priority profiles to the dry-run planner.
- [ ] Add user-editable profile definitions and battery-conscious profile.
- [ ] Implement admission-control simulation.
- [x] Refuse to propose soft limits when current-use safety floors exceed the allocatable budget or captured hard limits conflict.
- [ ] Add hysteresis, cooldowns, and degraded-mode behavior.
- [ ] Replay captured telemetry to test decisions without enforcement.
- [ ] Add persisted workload identities and configurable long-lived budgets; current per-app thresholds are notification-only.
- [x] Model expiring Rescue Mode budget overrides, capture original per-workload memory.high/memory.max, and emit a restore plan (dry-run only).
- [x] Add a save-attestation/adapter-verification state machine with separate pause/close approval gates (no application adapters are registered yet).
- [x] Recheck transaction expiry on every state transition and allow immediate user decline.
- [x] Record before/after memory.current deltas as observations without claiming causality.
- [ ] Implement a real adapter registry and user-facing save/close workflow.

**Exit criteria:** the same input snapshot and policy always produce the same explainable decision. Current implementation includes a deterministic OOM guard, transaction-shaped Rescue Mode simulator, and a profile-aware adaptive budget planner; these do not write cgroups, signal processes, pause/close applications, or enforce budgets.

## Phase 3 — Linux controlled enforcement
- [ ] Create managed workload scopes.
- [ ] Add reversible CPU and I/O prioritization.
- [ ] Add memory.high support with explicit opt-in and rollback.
- [ ] Add optional hard ceilings only after safety testing.
- [ ] Implement action ownership, expiry, crash recovery, and audit log.
- [ ] Test under synthetic pressure and real desktop workloads.

**Exit criteria:** every intervention is bounded, observable, reversible, and tested against failure cases.

## Phase 4 — Desktop experience
- [x] Build initial PySide6 NRG Desktop for live read-only resource/process diagnostics, heuristic anomaly review, and adaptive budget-plan inspection.
- [x] Live resource overview with RAM, swap, CPU, PSI, and home-volume free space.
- [ ] System tray integration.
- [ ] Per-application budgets and profiles.
- [ ] Clear explanations and confirmation prompts.
- [ ] Temporary overrides and one-click restoration.
- [x] Add English/Spanish UI language selection.
- [x] Add editable named coaster profiles with ordered application-name priority fragments; Rust planner consumes the saved priorities.
- [x] Add exposed dedicated-GPU-memory telemetry and aggregate physical-interface network throughput.
- [x] Add a contracted-bandwidth network budget preview (simulation only; no traffic shaping).
- [x] Add rapid process-count and per-parent child-burst review signals (heuristics only).
- [x] Add guarded per-process signals, nice-value adjustment, and CPU affinity controls.
- [x] Add optional KSystemStats sensor integration for CPU/GPU thermal/usage, battery, Wi-Fi signal, fan, and disk I/O where available.
- [x] Add opt-in speed test: bidirectional with speedtest-cli; bounded download-only fallback otherwise.
- [x] Add a user toggle to disable anomaly heuristics and executable-path inspection while retaining the process manager.
- [x] Add an Applications view grouped by cgroup v2 workload with cgroup memory.current and process drill-down.
- [x] Add a History view for RAM, swap, PSI pressure, and top workload memory using the monitor's bounded telemetry.
- [x] Improve dashboard hierarchy with circular primary gauges, compact secondary metrics, and responsive scrolling.
- [x] Resolve app names/icons from desktop entries, aggregate sibling cgroups, and filter system/autostart noise from the Applications view.
- [x] Replace the false-positive deleted-executable alert with no signal unless supported by other evidence.
- [x] Add an explicit Work profile alongside Gaming in the dry-run planner.
- [ ] Add system tray integration and configurable refresh/telemetry cost modes.
- [ ] Add persistent workload identity and editable per-app memory floors/ceilings.
- [x] Add confirmation-gated STOP/CONT/TERM/KILL actions for the currently observed PIDs in a selected cgroup workload.
- [ ] Add package ownership, complete process-tree growth correlation, per-cgroup network counters, per-process GPU/network attribution, full app-group lifecycle tracking, connection/persistence context, without collecting command-line arguments or secrets.
- [ ] Implement safe, capability-checked cgroup memory.high enforcement with explicit approval, expiry, audit, and rollback.
- [ ] Implement per-workload network shaping using a validated cgroup-v2/eBPF or equivalent backend, with explicit approval and rollback.

## Phase 5 — Windows backend
- [ ] Implement Windows telemetry provider.
- [ ] Implement Job Object workload management.
- [ ] Map shared policy capabilities to Windows-native controls.
- [ ] Add Windows-specific integration and recovery tests.
- [ ] Document controls that differ from Linux.

## Phase 6 — Advanced capabilities
- [ ] Application adapters for graceful save/close.
- [ ] GPU and integrated-GPU memory telemetry where attribution is reliable.
- [ ] Network monitoring and optional shaping.
- [ ] Workload recommendations based on historical patterns.
- [ ] Exportable diagnostics and privacy-conscious telemetry.

## Non-goals for early releases
- Replacing the operating system's memory manager.
- Guaranteeing that memory utilization never reaches 100%.
- Killing applications automatically to meet a free-memory number.
- Claiming generic save-state support for arbitrary applications.
- Applying kernel, registry, or global scheduler tweaks without evidence.
