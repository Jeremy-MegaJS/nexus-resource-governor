# Nexus Resource Governor

**Intelligent, policy-driven resource management for Linux and Windows.**

NRG monitors system and application resource usage, predicts resource pressure, and applies graduated, user-configurable policies to keep the operating system responsive without unexpectedly terminating important work.

> **Status:** Architecture and requirements phase. Resource-control actions are not implemented or enabled yet.

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
- Memory PSI from /proc/pressure/memory.
- ZRAM compression and physical-memory accounting from sysfs.
- Selected paging and reclaim counters from /proc/vmstat.
- The collector process's current cgroup v2 memory counters.

It does not enforce budgets, change cgroups, reserve RAM, or manage other applications yet.

Build and run on Linux:

```sh
cargo test
cargo run -- --human
cargo run -- --json
```

## Development

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/ROADMAP.md](docs/ROADMAP.md).

## License

License not selected yet.
