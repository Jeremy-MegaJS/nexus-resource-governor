#!/usr/bin/env python3
"""Reversible, user-session gaming controls for NRG Desktop.

Only systemd user units are changed. No kernel, network, IRQ, USB, or global
scheduler settings are modified. A systemd timer performs crash-safe rollback.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

STATE_DIR = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "nrg"
STATE_FILE = STATE_DIR / "gaming-session.json"
ROLLBACK_UNIT = "nrg-gaming-rollback"

TARGETS = {
    "cloud": ("geforcenow", "GeForce NOW"),
    "native": ("steam|lutris|heroic|bottles", "Native game"),
    "emulation": ("retroarch|dolphin|pcsx2|rpcs3|ryujinx|citra|yuzu|waydroid", "Emulator"),
}
PROTECTED_SERVICES = (
    "plasma-kwin_wayland.service",
    "pipewire.service",
    "wireplumber.service",
    "app-Remote\\x2dDesktop\\x2dCommander@",
    "app-RDC\\x20Admin\\x20Mode@",
    "dbus-broker.service",
    "plasma-polkit-agent.service",
)


def run(args: list[str], timeout: float = 8.0, check: bool = True) -> str:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    if check and result.returncode:
        raise RuntimeError((result.stderr or result.stdout or f"Command failed: {args[0]}").strip())
    return result.stdout.strip()


def user_systemctl(*args: str, check: bool = True) -> str:
    return run(["systemctl", "--user", *args], check=check)


def active(unit: str) -> bool:
    return user_systemctl("is-active", unit, check=False) == "active"


def property_value(unit: str, name: str, default: int = 100) -> int:
    raw = user_systemctl("show", "--property=" + name, "--value", unit, check=False).strip()
    try:
        value = int(raw)
        return max(1, min(10000, value))
    except (TypeError, ValueError):
        return default


def unit_snapshot(unit: str) -> dict:
    return {
        "unit": unit,
        "cpu_weight": property_value(unit, "CPUWeight"),
        "io_weight": property_value(unit, "IOWeight"),
    }


def set_weights(unit: str, cpu: int, io: int) -> None:
    user_systemctl(
        "set-property", "--runtime", unit,
        f"CPUWeight={cpu}", f"IOWeight={io}",
    )


def running_scopes() -> list[str]:
    output = user_systemctl(
        "list-units", "--type=scope", "--state=running", "--no-legend", "--plain",
        check=False,
    )
    units = []
    for line in output.splitlines():
        fields = line.split()
        if fields and fields[0].startswith("app-") and fields[0].endswith(".scope"):
            units.append(fields[0])
    return sorted(set(units))


def running_services() -> list[str]:
    output = user_systemctl(
        "list-units", "--type=service", "--state=running", "--no-legend", "--plain",
        check=False,
    )
    return sorted({line.split()[0] for line in output.splitlines() if line.split()})


def find_target(mode: str) -> str:
    patterns, _ = TARGETS[mode]
    tokens = patterns.split("|")
    matches = [unit for unit in running_scopes() if any(token in unit.lower() for token in tokens)]
    if not matches:
        raise RuntimeError(f"No active {TARGETS[mode][1]} scope was found. Launch the game first.")
    # Prefer the longest exact application identifier if multiple instances exist.
    return sorted(matches, key=lambda value: (len(value), value), reverse=True)[0]


def power_profile() -> str | None:
    if not shutil_which("powerprofilesctl"):
        return None
    result = subprocess.run(["powerprofilesctl", "get"], capture_output=True, text=True, timeout=3)
    return result.stdout.strip() if result.returncode == 0 else None


def shutil_which(name: str) -> str | None:
    from shutil import which
    return which(name)


def ac_online() -> bool:
    for path in Path("/sys/class/power_supply").glob("*"):
        try:
            if (path / "type").read_text().strip() == "Mains":
                return (path / "online").read_text().strip() == "1"
        except OSError:
            continue
    return False


def save_state(state: dict) -> None:
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = STATE_FILE.with_suffix(".tmp")
    temporary.write_text(json.dumps(state, indent=2) + "\n")
    temporary.chmod(0o600)
    os.replace(temporary, STATE_FILE)


def load_state() -> dict | None:
    try:
        data = json.loads(STATE_FILE.read_text())
        return data if isinstance(data, dict) and data.get("schema") == 1 else None
    except (OSError, ValueError, TypeError):
        return None


def schedule_rollback(ttl_seconds: int) -> None:
    user_systemctl("stop", ROLLBACK_UNIT + ".timer", check=False)
    script = str(Path(__file__).resolve())
    run([
        "systemd-run", "--user", "--unit=" + ROLLBACK_UNIT,
        f"--on-active={ttl_seconds}s", "--collect",
        sys.executable, script, "--restore",
    ], timeout=10)


def cancel_rollback() -> None:
    user_systemctl("stop", ROLLBACK_UNIT + ".timer", check=False)


def restore_session() -> dict:
    state = load_state()
    if not state:
        cancel_rollback()
        return {"ok": True, "active": False, "message": "No active gaming session."}

    failures = []
    for item in reversed(state.get("units", [])):
        unit = item.get("unit")
        if not isinstance(unit, str):
            continue
        try:
            # Restore saved effective values even if the unit stopped during the session.
            set_weights(unit, int(item.get("cpu_weight", 100)), int(item.get("io_weight", 100)))
        except Exception as exc:  # retain state so restoration can be retried
            failures.append(f"{unit}: {exc}")

    baloo = state.get("baloo", {})
    if baloo.get("was_active") and not active("kde-baloo.service"):
        try:
            user_systemctl("start", "kde-baloo.service")
        except Exception as exc:
            failures.append(f"kde-baloo.service: {exc}")

    previous_power = state.get("power_profile")
    if previous_power and state.get("power_profile_changed") and shutil_which("powerprofilesctl"):
        try:
            run(["powerprofilesctl", "set", previous_power], timeout=5)
        except Exception as exc:
            failures.append(f"power profile: {exc}")

    if failures:
        return {"ok": False, "active": True, "failures": failures,
                "message": "Some settings could not be restored; recovery state was retained."}

    cancel_rollback()
    try:
        STATE_FILE.unlink(missing_ok=True)
    except OSError as exc:
        return {"ok": False, "active": True, "message": f"Restored, but could not remove state: {exc}"}
    return {"ok": True, "active": False, "message": "Original session settings restored."}


def start_session(mode: str = "cloud", ttl_minutes: int = 60) -> dict:
    if mode not in TARGETS:
        raise ValueError("Unknown gaming profile.")
    if not 15 <= int(ttl_minutes) <= 180:
        raise ValueError("Session duration must be between 15 and 180 minutes.")

    existing = load_state()
    if existing:
        restored = restore_session()
        if not restored.get("ok"):
            raise RuntimeError("An earlier session could not be restored: " + str(restored))

    target = find_target(mode)
    scopes = running_scopes()
    services = running_services()
    changes = [unit_snapshot(target)]
    changes[0]["role"] = "game"

    # Keep the compositor, audio, accessibility, and RDC control path responsive.
    protected = []
    for unit in services:
        if any(fragment in unit for fragment in PROTECTED_SERVICES):
            protected.append(unit_snapshot(unit))
            protected[-1]["role"] = "interactive"

    # Other application scopes remain alive, but yield CPU and disk scheduling to the game.
    background = []
    for unit in scopes:
        if unit == target:
            continue
        background.append(unit_snapshot(unit))
        background[-1]["role"] = "background"

    baloo_was_active = active("kde-baloo.service")
    previous_power = power_profile()
    power_changed = bool(previous_power and previous_power != "performance" and ac_online())

    state = {
        "schema": 1,
        "created_unix": int(time.time()),
        "expires_unix": int(time.time()) + int(ttl_minutes) * 60,
        "mode": mode,
        "target": target,
        "units": changes + protected + background,
        "baloo": {"was_active": baloo_was_active},
        "power_profile": previous_power,
        "power_profile_changed": power_changed,
    }
    save_state(state)

    try:
        # Install rollback before changing any resource policy.
        schedule_rollback(int(ttl_minutes) * 60)
        for item in changes:
            set_weights(item["unit"], 1000, 500)
        for item in protected:
            set_weights(item["unit"], 500, 250)
        for item in background:
            set_weights(item["unit"], 25, 25)
        if baloo_was_active:
            user_systemctl("stop", "kde-baloo.service")
        if power_changed:
            run(["powerprofilesctl", "set", "performance"], timeout=5)
    except Exception:
        restore_session()
        raise

    return {
        "ok": True,
        "active": True,
        "mode": mode,
        "target": target,
        "duration_minutes": int(ttl_minutes),
        "prioritized_units": [item["unit"] for item in changes + protected],
        "deprioritized_units": [item["unit"] for item in background],
        "baloo_paused": baloo_was_active,
        "power_profile": "performance" if power_changed else previous_power,
        "message": "Gaming session active; automatic rollback is scheduled.",
    }


def session_status() -> dict:
    state = load_state()
    if not state:
        return {"active": False}
    remaining = max(0, int(state.get("expires_unix", 0)) - int(time.time()))
    return {
        "active": True,
        "mode": state.get("mode", "unknown"),
        "target": state.get("target", "unknown"),
        "remaining_seconds": remaining,
        "units": [item.get("unit") for item in state.get("units", [])],
    }


def main() -> int:
    try:
        if len(sys.argv) > 1 and sys.argv[1] == "--restore":
            result = restore_session()
        elif len(sys.argv) > 1 and sys.argv[1] == "--start":
            mode = sys.argv[2] if len(sys.argv) > 2 else "cloud"
            minutes = int(sys.argv[3]) if len(sys.argv) > 3 else 60
            result = start_session(mode, minutes)
        elif len(sys.argv) > 1 and sys.argv[1] == "--status":
            result = session_status()
        else:
            print("Usage: nrg_gaming.py --start [cloud|native|emulation] [15..180] | --restore | --status")
            return 2
        print(json.dumps(result, indent=2))
        return 0 if result.get("ok", True) else 1
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
