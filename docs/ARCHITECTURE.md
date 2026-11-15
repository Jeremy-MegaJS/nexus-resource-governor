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

Names alone are not a safe identity: unrelated processes can share an executable name.

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
- /proc/meminfo, /proc/vmstat, and zram sysfs statistics.
- Process metadata and systemd user-slice hierarchy. The read-only process sample exposes both executable basename and a bounded (512-character) `/proc/PID/exe` target path as identity hints; neither is treated as a unique application identity. Command-line arguments are intentionally not collected because they may contain secrets.

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

## 8. Windows backend

The Windows backend implements the same policy interface using native APIs:
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

The next implementation must replace this advisory plan with a transaction-like workflow: confirm the target and candidates, request save through an application adapter or direct user action, verify the save result where possible, apply a scoped and expiring budget override, monitor the temporary window, and restore prior values. If the application cannot confirm save, NRG must say so and must not close it automatically.

The OOM guard is an early-warning and coordination layer, not a replacement for the Linux kernel OOM killer. It should intervene before the kernel reaches OOM where telemetry allows, while leaving the kernel as the final safety mechanism.

## 14. cgroup v2 capability discovery

The Linux snapshot reports the controllers visible to the current cgroup, the controllers enabled for its children, whether memory accounting files are present, and whether cgroup.subtree_control can be opened for writing by the current process. The write-open check does not write to the control file and does not change system state.

This is a capability signal, not proof that systemd delegated a complete writable subtree: creating child cgroups, enabling controllers, and managing processes require additional permissions and hierarchy checks. Enforcement must revalidate those permissions at the point of use and must never infer delegation from controller visibility alone. The snapshot schema was bumped to version 2 when capability reporting was added; version 3 added bounded process-correlation diagnostics; version 4 added parent-process relationship fields; version 5 adds a bounded parent-linked process sample and explicit truncation/edge metadata.


## 15. Workload hierarchy and memory attribution

Workload discovery derives the per-user systemd manager root from the current cgroup path. It does not assume that NRG itself runs under `app.slice`; it can also discover workloads when launched from a session or another user-owned cgroup.

For each supported user slice (`app.slice`, `session.slice`, and `background.slice`), NRG records immediate child cgroups as workload boundaries. A cgroup v2 `memory.current` value includes the memory charged to that cgroup and its descendants. Therefore NRG must not emit and sum both a parent workload and its nested child cgroups as independent consumers. The current snapshot deliberately uses the top-level child as the accounting boundary and preserves its full cgroup path as the workload identity.

This is cgroup-level attribution, not proof that every byte belongs exclusively to one GUI application: shared services, delegated sub-cgroups, and processes outside these user slices need separate attribution rules. Missing or inaccessible cgroups remain unavailable rather than being estimated. Discovery remains read-only.


## 16. Process-to-workload correlation

The read-only Linux collector scans numeric `/proc` entries and maps each process's unified cgroup path to the nearest discovered top-level workload accounting boundary. It reports the observed process count, the five highest-RSS process diagnostics, and a separate ancestor-closed graph capped at 32 nodes per workload. The graph starts from those five highest-RSS processes and follows parent links only while the parent remains inside the same workload; it never imports a parent from another workload. `parent_pid` carries graph edges, `parent_in_tree` makes missing parents explicit, and `process_tree_truncated` indicates that workload processes or required ancestors were omitted. A parent can exit or have its PID reused while `/proc` is being read, so this remains a bounded best-effort snapshot rather than an atomic process tree. `pids.current` counts tasks, while the `/proc` scan counts process directories, so those values are not interchangeable. Per-process `VmRSS` is an estimate and must not be summed because shared pages can be counted more than once; cgroup `memory.current` remains the aggregate accounting source. Command-line arguments are deliberately not collected because they can contain credentials or other sensitive data.

`memory.current` remains the authoritative aggregate workload charge, including descendants. Per-process `VmRSS` is an informational estimate only: shared pages can appear in multiple processes' RSS, so process RSS values must never be summed as a replacement for cgroup accounting. Process enumeration is inherently racy; exited, inaccessible, or rapidly moving processes may be missed. The observed count is therefore diagnostic and may differ from `pids.current` (which counts tasks, including threads).

Systemd-escaped unit names are decoded for display and policy matching (for example, `\x2d` becomes `-`). The original cgroup path remains unchanged and is the authoritative workload locator. This matters for protected-workload checks: matching a human-readable unit name against its escaped kernel cgroup spelling can otherwise fail.
