# Nexus Resource Governor — Roadmap

The project is in the requirements and architecture phase. The order prioritizes trustworthy measurement and safe recovery before enforcement.

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
- [x] Add CPU/I/O PSI, bounded IRQ counters, DRM driver and connector identity, thermal zones, filtered kernel and desktop-session journal events from the current and three preceding boots, and a read-only freeze triage view.
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
- [ ] Provide a stable sampling API and bounded local history.
- [ ] Improve application identity beyond cgroup membership and executable metadata using confidence-scored, non-secret signals.
- [ ] Validate metrics against system tools under normal and stressed workloads.

**Exit criteria:** NRG explains which workloads consume resources, whether the system is under pressure, and correlates relevant display/kernel events without changing system state.

## Phase 2 — Policy engine and simulator
- [x] Define a first portable policy input using normalized Linux telemetry.
- [x] Implement deterministic early OOM-risk evaluation and dry-run Rescue Mode planning.
- [ ] Define persistent workload identities, configurable budgets, and backend capabilities.
- [ ] Add normal, gaming/performance, and battery-conscious profiles.
- [ ] Implement admission-control simulation.
- [ ] Add hysteresis, cooldowns, and degraded-mode behavior.
- [ ] Replay captured telemetry to test decisions without enforcement.
- [ ] Add per-workload soft/warning budgets and expiring temporary overrides.
- [ ] Add explicit save/close adapter protocol and user-confirmed Rescue Mode workflow.

**Exit criteria:** the same input snapshot and policy always produce the same explainable decision. Current first pass: deterministic OOM guard and dry-run rescue planner; no enforcement.

## Phase 3 — Linux controlled enforcement
- [ ] Create managed workload scopes.
- [ ] Add reversible CPU and I/O prioritization.
- [ ] Add memory.high support with explicit opt-in and rollback.
- [ ] Add optional hard ceilings only after safety testing.
- [ ] Implement action ownership, expiry, crash recovery, and audit log.
- [ ] Test under synthetic pressure and real desktop workloads.

**Exit criteria:** every intervention is bounded, observable, reversible, and tested against failure cases.

## Phase 4 — Desktop experience
- [ ] System tray and live resource overview.
- [ ] Per-application budgets and profiles.
- [ ] Clear explanations and confirmation prompts.
- [ ] Temporary overrides and one-click restoration.
- [ ] Accessibility, localization, and startup behavior.

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
