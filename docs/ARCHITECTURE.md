# Nexus Resource Governor — Architecture

**Status:** Proposed architecture. Enforcement remains disabled until the relevant backend is implemented and tested.

## 1. Product boundary

NRG is a user-space resource policy and control layer. The operating system remains responsible for low-level memory management, scheduling, paging, and process execution.

NRG has five responsibilities:
1. Observe system and workload state.
2. Translate user intent into resource policies.
3. Predict whether a new workload fits the current policy.
4. Apply supported, reversible controls when pressure rises.
5. Explain decisions and recover from temporary interventions.

It must not promise that the machine can never reach 100% memory utilization. It should reduce the probability and impact of sustained resource pressure.

## 2. High-level components

    Desktop UI
        | typed local IPC
    Policy Engine
        | shared rules, admission, pressure stages, explanations
        +---------------------------+
        |                           |
    Linux Backend               Windows Backend
    cgroup v2                   Job Objects
    PSI / procfs                Process and memory APIs
    systemd integration         Windows telemetry
        |                           |
        +-------------+-------------+
                      |
              Telemetry + Audit Store

These are logical boundaries, not a commitment to a specific UI toolkit or IPC protocol.

## 3. Shared policy model

The shared engine must not contain Linux paths, Windows handles, or platform-specific kernel details. It operates on normalized observations and backend capabilities.

### Observation

A snapshot should include:
- Timestamp and sampling interval.
- Physical memory total, available, and reclaimable estimates.
- Swap capacity and usage, including compressed swap when exposed.
- Memory pressure and stall metrics.
- CPU utilization and pressure.
- Storage I/O utilization and pressure when available.
- Workload identity, process tree, and per-workload counters.
- Backend health and metric confidence.

Metrics retain their source and confidence. Missing telemetry is unavailable, not zero.

### Workload identity

A workload is a logical application instance, not merely a process name. It may include:
- A root process and descendants.
- One or more cgroups or Windows Job Objects.
- Launch origin and executable identity.
- User-selected classification (game, browser, editor, background task).
- Optional application adapter.

Names alone are not a safe identity: unrelated processes can share an executable name. Linux snapshots therefore expose a bounded inventory of executable paths observed in the sampled process graph, with occurrence counts. This is diagnostic evidence only: the highest-RSS process is not assumed to be the application root, helper processes are not classified by guesswork, and the inventory is not a persistent workload identity.

### Budget

A policy distinguishes:
- **Target:** preferred operating range.
- **Warning threshold:** point where the user is informed.
- **Soft limit:** point where reversible pressure controls may begin.
- **Hard limit:** optional enforcement ceiling, disabled by default.
- **System reserve target:** desired available physical-memory margin.
- **Override:** temporary user-approved exception with expiry.

RAM and swap/zram are separate budgets. CPU and I/O policies are separate dimensions.

## 4. Dynamic system reserve

The initial product target is approximately **2 GiB of available physical RAM during normal desktop use** on the reference 8 GiB machine. This is a policy target, not memory preallocated or permanently withheld from applications.

The reserve adapts to:
- Total installed memory.
- Desktop and system baseline.
- Current memory pressure and reclaimability.
- Active workload profile.
- User overrides.

A gaming/performance profile may lower the reserve target and allow a game to use more memory. The governor must not enforce a fixed 2 GiB ceiling on games.

The first implementation measures before it enforces. Reserve values are tuned from telemetry, not treated as universal defaults.

## 5. Admission control

Admission control is reliable only when NRG controls or participates in workload launch.

Initial supported path:
1. User launches an application through NRG or an NRG-managed launcher entry.
2. Backend estimates current pressure and the application's configured budget.
3. Policy engine returns allow, allow-with-warning, or require-confirmation.
4. Backend starts the process inside its workload container where supported.
5. Monitor tracks the workload and applies its policy.

NRG must not claim that it can intercept every application launch. Existing processes may be adopted only where the platform supports safe assignment and required permissions are available.

The estimate is advisory: applications can allocate unpredictable amounts after launch.

## 6. Graduated pressure controller

The controller is a state machine with hysteresis, not a single threshold trigger.

Suggested states:
- NORMAL
- WATCH
- PRESSURE
- CONTAINED
- RECOVERY
- DEGRADED

Transitions use sustained measurements and separate enter/exit thresholds to prevent rapid oscillation.

Response order:
1. Notify and explain.
2. Identify the workload contributing to pressure.
3. Apply soft, reversible controls supported by the backend.
4. Offer a temporary budget change or prioritization decision.
5. Ask before suspending, closing, or terminating a workload.
6. Never kill a process unless the user explicitly enabled a policy that permits it.

A hard cgroup memory limit can trigger OOM handling inside a workload. It is an advanced opt-in feature, not the default pressure response.

## 7. Linux backend

### Monitoring
- cgroup v2 memory.current, memory.stat, memory.events, and memory.pressure.
- memory.swap.current and memory.swap.max where available.
- /proc/pressure/memory, /proc/pressure/cpu, and /proc/pressure/io.
- /proc/meminfo, /proc/vmstat, selected bounded /proc/interrupts counters, and zram sysfs statistics.
- DRM device/driver identity, bounded display-connector status/mode inventory, KScreen userspace output state and DPMS mode, and thermal-zone readings. These are diagnostic signals, not GPU engine utilization or GPU-hang detection.
- Process metadata and systemd user-slice hierarchy. The read-only process sample exposes both executable basename and a bounded (512-character) `/proc/PID/exe` target path as identity hints; neither is treated as a unique application identity. Command-line arguments are intentionally not collected because they may contain secrets.
- A bounded --diagnose report filters relevant kernel and user-session journal events from the current and three preceding boots, including KWin/Plasma, XWayland/EGL, DRM, IRQ, ACPI, thermal, and storage messages. Journal access is optional; unavailable logs are reported as unavailable, not interpreted as clean.

The backend detects whether cgroup v2 controllers are available and delegated. It must not assume every distribution exposes identical permissions.

### Enforcement
Potential controls, enabled only after validation:
- memory.high for pressure throttling/reclaim.
- memory.max only for explicit hard limits.
- memory.swap.max as a separate swap constraint.
- CPU weights and quotas.
- I/O weights and limits.

Prefer systemd-managed scopes/slices where feasible so ownership and cleanup are explicit. Do not modify global kernel settings as a routine per-app action.

### Safety
- Run monitoring unprivileged where possible.
- Use a narrowly scoped privileged helper only for operations that require it.
- Never run the whole desktop UI or remote-control service as root.
- Track every applied value and restore it on policy removal, shutdown, or backend recovery.

## 8. Windows backend — not implemented

There is currently no Windows telemetry, policy-enforcement, or Job Object backend. The following is a future design direction, not available functionality:
- Job Objects for grouping a process tree and applying supported job limits.
- Process and system memory APIs for telemetry.
- CPU and I/O controls where Windows exposes reliable equivalents.
- Native notifications and startup integration.

Some controls and telemetry will not map one-to-one between Windows and Linux. The shared engine exposes backend capabilities so the UI does not imply unsupported controls exist.

NRG should launch managed workloads into a Job Object from process creation where possible. Assigning arbitrary existing processes may fail because of permissions, existing job membership, or process state.

## 9. Persistence and audit

Persist:
- User profiles and workload policies.
- Backend capability discovery.
- Recent state transitions.
- Actions taken, previous values, and restoration status.
- User overrides and expiry.
- Errors and degraded-mode events.

Avoid storing high-frequency raw telemetry indefinitely. Use bounded retention and aggregate older samples.

Every action record should answer: **what changed, why, on which workload, under which policy, when, and how will it be restored?**

## 10. Application adapters and progress preservation

NRG cannot generically save an application's unsaved state. An adapter may integrate with an application's documented API, save mechanism, or graceful shutdown protocol.

Without an adapter, NRG can still:
- Warn the user.
- Reduce priority or apply reversible limits.
- Request that the user save work.
- Suspend a process only where supported and safe.
- Avoid forced termination.

An adapter declares its capabilities. NRG must never report a save as successful unless the application confirms it.

## 11. Security model

- UI-to-engine communication uses authenticated local IPC and strict message schemas.
- Policy evaluation is separate from privileged enforcement.
- Privileged operations are allowlisted, validated, logged, and narrowly scoped.
- No arbitrary shell command or root command is exposed to models, plugins, or UI inputs.
- Configuration and audit data are owned by the current user, with integrity checks for privileged state.
- Backend failure triggers safe restoration or an explicit degraded state.

## 12. Technology direction

Proposed direction:
- **Core and policy engine:** Rust, for memory safety and a portable shared codebase.
- **Platform backends:** Rust modules with small native FFI boundaries.
- **UI:** choose after validating desktop integration and accessibility requirements; keep it separate from policy logic.
- **IPC:** versioned local protocol with explicit capability negotiation.
- **Tests:** deterministic policy tests, backend integration tests, stress tests, and fault-injection tests.

This is a proposed stack, not a locked implementation decision.


## 13. Early OOM guard and Rescue Mode

The first policy implementation is deliberately read-only. It evaluates available physical RAM and memory PSI into NORMAL, WATCH, PRESSURE, and CRITICAL states. The reserve target is adaptive (25% of detected physical memory, bounded between 512 MiB and 2 GiB) and is a policy signal, not preallocated memory. The guard never terminates a process.

Rescue Mode accepts a priority workload and a requested temporary headroom amount. It calculates the current shortfall against the reserve target and ranks other user application cgroups as possible candidates for a user-approved save/close or pause. Reported cgroup usage is only an upper bound: it is not a prediction of reclaimable memory. The collector's own cgroup and desktop/session infrastructure are excluded from candidate selection.

The transaction-shaped simulator now captures the target workload's original `memory.high` and `memory.max`, computes a proposed soft `memory.high` only when the current value is numeric, attaches a bounded expiry, and emits an explicit restore plan. It models candidate selection, a user save attestation or a positive adapter result, separate pause/close approval, and before/after `memory.current` measurement. Every transition rechecks the expiry; stale transactions cannot accept further save/action approvals or measurements, and the user may decline before completing the save flow. Expiry is currently state validation, not a persistent timer or recovery daemon. User attestation is not application verification. A pause does not itself release resident memory; only an observed cgroup delta is reported, and concurrent activity prevents causal attribution. No application adapters are registered, no cgroup files are written, and no processes are signalled, paused, or closed. The simulator never proposes a `memory.max` change. The captured current-cgroup write-open probe does not prove that the target workload is delegated; target write access and ancestor limits remain unvalidated. Real enforcement is blocked until those checks, durable action ownership, expiry recovery, and rollback verification exist.

The OOM guard is an early-warning and coordination layer, not a replacement for the Linux kernel OOM killer. It should intervene before the kernel reaches OOM where telemetry allows, while leaving the kernel as the final safety mechanism. The Windows backend remains unimplemented; the current CLI reports that the Linux telemetry backend is unavailable on other platforms.

## 14. cgroup v2 capability discovery

The Linux snapshot reports the controllers visible to the current cgroup, the controllers enabled for its children, whether memory accounting files are present, and whether cgroup.subtree_control can be opened for writing by the current process. The write-open check does not write to the control file and does not change system state.

This is a capability signal, not proof that systemd delegated a complete writable subtree: creating child cgroups, enabling controllers, and managing processes require additional permissions and hierarchy checks. Enforcement must revalidate those permissions at the point of use and must never infer delegation from controller visibility alone. The snapshot schema was bumped to version 2 when capability reporting was added; version 3 added bounded process-correlation diagnostics; version 4 added parent-process relationship fields; version 5 added a bounded parent-linked process sample and explicit truncation/edge metadata; version 6 added executable-path hints; version 7 added a bounded executable inventory; version 8 added CPU/I/O PSI, selected IRQ counters, graphics-driver identity, and thermal zones; version 9 added DRM connector status, enabled state, and mode counts; versions 10–12 added lightweight monitor metadata, OOM/reclaim counters, and overcommit context; version 13 adds per-workload memory.high and memory.max snapshots for dry-run restoration planning; version 14 adds cumulative CPU thermal-throttling counters where sysfs exposes them. The separate --diagnose view reads bounded kernel and desktop-session journal excerpts but does not embed journal text into every JSONL sample.


## 15. Workload hierarchy and memory attribution

Workload discovery derives the per-user systemd manager root from the current cgroup path. It does not assume that NRG itself runs under `app.slice`; it can also discover workloads when launched from a session or another user-owned cgroup.

For each supported user slice (`app.slice`, `session.slice`, and `background.slice`), NRG records immediate child cgroups as workload boundaries. A cgroup v2 `memory.current` value includes the memory charged to that cgroup and its descendants. Therefore NRG must not emit and sum both a parent workload and its nested child cgroups as independent consumers. The current snapshot deliberately uses the top-level child as the accounting boundary and preserves its full cgroup path as the workload identity.

This is cgroup-level attribution, not proof that every byte belongs exclusively to one GUI application: shared services, delegated sub-cgroups, and processes outside these user slices need separate attribution rules. Missing or inaccessible cgroups remain unavailable rather than being estimated. Discovery remains read-only.


## 16. Process-to-workload correlation

The read-only Linux collector scans numeric `/proc` entries and maps each process's unified cgroup path to the nearest discovered top-level workload accounting boundary. It reports the observed process count, the five highest-RSS process diagnostics, and a separate ancestor-closed graph capped at 32 nodes per workload. The graph starts from those five highest-RSS processes and follows parent links only while the parent remains inside the same workload; it never imports a parent from another workload. `parent_pid` carries graph edges, `parent_in_tree` makes missing parents explicit, and `process_tree_truncated` indicates that workload processes or required ancestors were omitted. A parent can exit or have its PID reused while `/proc` is being read, so this remains a bounded best-effort snapshot rather than an atomic process tree. `pids.current` counts tasks, while the `/proc` scan counts process directories, so those values are not interchangeable. Per-process `VmRSS` is an estimate and must not be summed because shared pages can be counted more than once; cgroup `memory.current` remains the aggregate accounting source. Command-line arguments are deliberately not collected because they can contain credentials or other sensitive data.

`memory.current` remains the authoritative aggregate workload charge, including descendants. Per-process `VmRSS` is an informational estimate only: shared pages can appear in multiple processes' RSS, so process RSS values must never be summed as a replacement for cgroup accounting. Process enumeration is inherently racy; exited, inaccessible, or rapidly moving processes may be missed. The observed count is therefore diagnostic and may differ from `pids.current` (which counts tasks, including threads).

Systemd-escaped unit names are decoded for display and policy matching (for example, `\x2d` becomes `-`). The original cgroup path remains unchanged and is the authoritative workload locator. This matters for protected-workload checks: matching a human-readable unit name against its escaped kernel cgroup spelling can otherwise fail.


## 17. Adaptive memory-budget planner — dry-run implementation

The Linux CLI exposes --budget-plan [balanced|gaming|study|development]. It reads the bounded telemetry history (the current 8 MiB JSONL file and one 8 MiB rotation) and keeps at most the latest 1,000 observations per normalized application key in memory. It estimates demand using the nearest-rank P95 after five or more samples, with a conservative 35% bootstrap margin before enough history exists and a 10% margin after learning.

The initial system reserve is 25% of detected physical RAM, clamped between 512 MiB and 2 GiB. Each active app receives a minimum safe floor above current cgroup usage: the greater of 64 MiB or 5% of its current charge. If those floors cannot fit in the app budget, the planner refuses all proposals. Otherwise, it allocates additional headroom in profile-priority order and reports when lower-priority workloads are constrained. The desktop editor stores named profiles in ~/.config/nrg/profiles.json using an ordered priorities array of safe application-name fragments. The Rust planner reads the selected profile and uses its ordered fragments instead of the built-in ordering for that profile; unmatched workloads receive normal priority. This remains a dry-run planner.

The output proposes memory.high soft thresholds only, records the previously observed memory.high and memory.max, and never changes either file. Existing finite memory.max values bound the proposed soft threshold; missing or conflicting hard-limit data causes a fail-closed result. This is a planning/simulation layer, not active memory enforcement. The planner does not promise that a workload will stay below its soft threshold, nor does it prevent the kernel from reclaiming cache or swapping anonymous memory.

## 18. NRG Desktop — initial read-only user interface

The optional PySide6 application in desktop/nrg_desktop.py is a separate user-session interface; it does not replace or supervise the low-overhead systemd user monitor. It samples /proc every five seconds while open and presents process CPU deltas, RSS estimates, disk read/write rates, process owner, and executable path. It never reads /proc/PID/cmdline or /proc/PID/environ.

Initial anomaly heuristics are deliberately narrow and explainable: sustained CPU use (>=80% of one logical core for three samples), repeated RSS growth (>=128 MiB per sample for two samples), sustained writes (>=100 MiB/s for three samples), deleted executables, and executables launched from temporary directories. These signals prioritize manual review; they are not a malware classifier and can produce false positives for builds, games, browsers, renderers, and other legitimate workloads.

System-wide state uses MemAvailable, swap use, CPU utilization, home-volume free space, and memory/CPU/I/O PSI. The GUI also reads dedicated VRAM counters from nvidia-smi or DRM sysfs when available and queries KDE KSystemStats through the user-session D-Bus for optional CPU/GPU temperature/utilization, battery, Wi-Fi signal, fan, and disk I/O sensors. Integrated graphics are identified as shared-memory devices when dedicated VRAM is not exposed. Aggregate RX/TX rates are calculated from active physical network-interface counters and are not attributed to individual applications. The anomaly toggle disables heuristic scoring, process-burst tracking, and executable-path inspection while leaving process inventory/CPU/I/O monitoring active. Rapid process-creation heuristics flag large process-count growth and unusually large bursts of direct children under one parent for manual investigation. They do not yet reconstruct a complete live process-tree growth graph and are not a fork-bomb or malware classifier.

The existing --diagnose report is exposed in the GUI for kernel, DRM, display, IRQ, ACPI, and thermal investigation. The budget planner supports named user profiles stored in ~/.config/nrg/profiles.json; each profile contains an ordered array of application-name fragments. The desktop language and selected profile are persisted in ~/.config/nrg/desktop.json with user-only permissions. The network test prefers the optional speedtest-cli binary for bidirectional throughput and latency; without it, a bounded Cloudflare 25 MB download test is used and upload remains explicitly unmeasured. The network budget preview independently caps each contracted direction by its latest measured value (when available), reserves 10% for protocol overhead/measurement variance, and reports simulated shares only. No tc/eBPF/nftables rules are installed and no bandwidth is shaped.

The Applications view groups the /proc inventory by its cgroup-v2 path and reads each workload's memory.current when accessible; RSS aggregation is shown separately because shared pages can be double-counted. Double-clicking a workload filters the process view. Its context menu can signal the currently observed PIDs as a group; TERM/KILL require one confirmation and each PID's start time and cgroup membership are revalidated before pidfd signaling. The History view reads the monitor's bounded JSONL telemetry and plots the latest 360 samples for available RAM, swap, PSI, and top workload memory.

The process table supports per-PID STOP/CONT/HUP/INT/TERM/KILL signals, nice-value adjustment, and CPU affinity. TERM/KILL are confirmation-gated. Before any action, NRG re-reads /proc/PID/stat and verifies the kernel start-time value to guard against PID reuse; signals use pidfd_send_signal when supported so the signal is bound to the opened process identity. PID 1 and the NRG process's ancestor chain are protected. Operations remain subject to the logged-in user's Linux permissions. This is not a privileged helper and does not manage complete desktop application process groups yet.

The desktop entry is installed under ~/.local/share/applications by packaging/install-desktop.sh. The application runs as the logged-in user, requires PySide6, and makes no cgroup, scheduler, kernel, process-control, network-shaping, or privilege changes. The background monitor continues when the UI closes.



The desktop presentation keeps four primary circular gauges and a compact secondary metric grid. Application identity is resolved from systemd app cgroups and installed desktop entries; sibling cgroups for one app are aggregated for memory and process controls, with per-PID cgroup/start-time revalidation before signals. A deleted executable path is not considered suspicious on its own because in-place package upgrades routinely leave existing processes mapped to an unlinked old binary.
