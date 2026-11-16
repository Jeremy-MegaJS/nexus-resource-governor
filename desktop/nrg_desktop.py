#!/usr/bin/env python3
"""NRG Desktop: resource monitoring, guarded process management, and diagnostics."""
from __future__ import annotations
import configparser, json, os, pwd, re, signal, shutil, subprocess, sys, time, urllib.request, platform, socket
from pathlib import Path
from PySide6.QtCore import Qt, QProcess, QTimer, QThread, Signal, QPointF
from PySide6.QtGui import QFont, QColor, QPainter, QPen, QPolygonF, QIcon
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QGridLayout,
    QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMenu, QMessageBox, QPushButton,
    QInputDialog, QTabWidget, QTableWidget, QTableWidgetItem, QTextEdit, QVBoxLayout,
    QWidget, QHeaderView, QScrollArea,
)

ROOT = Path(__file__).resolve().parents[1]
CANDIDATES = [ROOT / "target/release/nrg-agent", ROOT / "target/debug/nrg-agent"]
AGENT = next((p for p in CANDIDATES if p.is_file()), None)
REFRESH_MS, MAX_ROWS = 5000, 120
PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
CLK_TCK = os.sysconf("SC_CLK_TCK")
CPU_COUNT = os.cpu_count() or 1
def read_hwmon_sensors():
    """Read kernel hwmon values directly; no KSystemStats/D-Bus dependency."""
    sensors = {"temperatures": [], "fans": [], "voltages": [], "power": []}
    for device in Path("/sys/class/hwmon").glob("hwmon*"):
        try:
            chip = (device / "name").read_text().strip()
        except OSError:
            continue
        for label_path in device.glob("*_label"):
            stem = label_path.name[:-6]
            try:
                label = label_path.read_text().strip()
                raw = float((device / f"{stem}_input").read_text().strip())
            except (OSError, ValueError):
                continue
            if stem.startswith("temp"):
                if raw > 0:
                    sensors["temperatures"].append({"chip": chip, "label": label, "celsius": raw / 1000})
            elif stem.startswith("fan"):
                if raw > 0:
                    sensors["fans"].append({"chip": chip, "label": label, "rpm": raw})
            elif stem.startswith("in"):
                sensors["voltages"].append({"chip": chip, "label": label, "volts": raw / 1000})
            elif stem.startswith("power"):
                sensors["power"].append({"chip": chip, "label": label, "watts": raw / 1_000_000})
        # Some drivers omit labels; expose only meaningful positive fan readings.
        for input_path in device.glob("fan*_input"):
            try:
                rpm = float(input_path.read_text().strip())
            except (OSError, ValueError):
                continue
            if rpm > 0 and not any(x["chip"] == chip and x["rpm"] == rpm for x in sensors["fans"]):
                sensors["fans"].append({"chip": chip, "label": input_path.stem, "rpm": rpm})
    return sensors


def read_cpu_cores():
    """Per-logical-CPU utilization counters from /proc/stat."""
    cores = {}
    try:
        for line in Path("/proc/stat").read_text().splitlines():
            fields = line.split()
            if not fields or not re.fullmatch(r"cpu\d+", fields[0]):
                continue
            values = [int(value) for value in fields[1:]]
            idle = values[3] + (values[4] if len(values) > 4 else 0)
            cores[fields[0]] = (sum(values[:8]), idle)
    except (OSError, ValueError):
        return {}
    return cores


def cpu_core_percentages(current, previous):
    result = {}
    for name, (total, idle) in current.items():
        old = previous.get(name)
        if old is None:
            result[name] = None
            continue
        delta_total = max(0, total - old[0])
        delta_idle = max(0, idle - old[1])
        result[name] = max(0.0, min(100.0, 100 * (delta_total - delta_idle) / delta_total)) if delta_total else 0.0
    return result


def read_network_interfaces():
    """Per-interface byte/packet/error counters and IP addresses, using kernel interfaces."""
    addresses = {}
    try:
        result = subprocess.run(["ip", "-j", "address", "show"], capture_output=True,
                                text=True, timeout=0.7, check=False)
        if result.returncode == 0:
            for item in json.loads(result.stdout):
                addresses[item.get("ifname", "")] = {
                    "ipv4": [a.get("local", "") for a in item.get("addr_info", []) if a.get("family") == "inet"],
                    "ipv6": [a.get("local", "") for a in item.get("addr_info", []) if a.get("family") == "inet6"],
                }
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    result = {}
    for interface in Path("/sys/class/net").iterdir():
        name = interface.name
        if name == "lo" or name.startswith(("veth", "docker", "br-", "virbr", "tun", "tap")):
            continue
        try:
            stats = interface / "statistics"
            operstate = (interface / "operstate").read_text().strip()
            result[name] = {
                "state": operstate,
                "kind": "Wi-Fi" if (interface / "wireless").exists() else "Ethernet" if name.startswith(("en", "eth")) else "Network",
                "rx": int((stats / "rx_bytes").read_text()),
                "tx": int((stats / "tx_bytes").read_text()),
                "rx_packets": int((stats / "rx_packets").read_text()),
                "tx_packets": int((stats / "tx_packets").read_text()),
                "rx_errors": int((stats / "rx_errors").read_text()),
                "tx_errors": int((stats / "tx_errors").read_text()),
                "addresses": addresses.get(name, {"ipv4": [], "ipv6": []}),
            }
        except (OSError, ValueError):
            continue
    return result


def read_wireless_signal():
    try:
        for line in Path("/proc/net/wireless").read_text().splitlines()[2:]:
            fields = line.replace(":", " ").split()
            if len(fields) >= 4:
                quality, level = float(fields[2]), float(fields[3])
                return f"{quality:.0f}/70 · {level:.0f} dBm"
    except (OSError, ValueError, IndexError):
        pass
    return "—"


def read_block_devices():
    """Physical block-device identity, capacity, and live I/O counters."""
    devices = {}
    for device in Path("/sys/block").iterdir():
        name = device.name
        if name.startswith(("loop", "ram", "zram", "dm-", "md")):
            continue
        try:
            sectors = int((device / "size").read_text())
            stat = [int(x) for x in (device / "stat").read_text().split()]
            model = ""
            for candidate in (device / "device/model", device / "device/name"):
                try:
                    model = candidate.read_text().strip()
                    if model: break
                except OSError:
                    pass
            devices[name] = {
                "model": model or name, "bytes": sectors * 512,
                "read_sectors": stat[2], "read_ms": stat[3],
                "write_sectors": stat[6], "write_ms": stat[7],
                "busy_ms": stat[9] if len(stat) > 9 else 0,
            }
        except (OSError, ValueError, IndexError):
            continue
    return devices


def read_gpu_info():
    """GPU identity and driver telemetry; unknown utilization stays unknown."""
    gpus = []
    for card in sorted(Path("/sys/class/drm").glob("card[0-9]*")):
        if re.search(r"-", card.name):
            continue
        device = card / "device"
        try:
            vendor = (device / "vendor").read_text().strip()
            pci_id = (device / "device").read_text().strip()
            driver = Path(os.path.realpath(device / "driver")).name
        except OSError:
            continue
        name = {"0x8086": "Intel integrated graphics", "0x10de": "NVIDIA graphics",
                "0x1002": "AMD graphics"}.get(vendor, f"GPU {vendor}")
        item = {"card": card.name, "name": name, "vendor": vendor, "device": pci_id,
                "driver": driver, "usage": None, "memory_used": None, "memory_total": None,
                "frequency_mhz": None, "temperature": None, "rc6_residency_ms": None,
                "kind": "shared" if vendor == "0x8086" else "unknown"}
        for path, key in (("mem_info_vram_used", "memory_used"), ("mem_info_vram_total", "memory_total"),
                          ("gpu_busy_percent", "usage"), ("gt_cur_freq_mhz", "frequency_mhz")):
            try:
                item[key] = int((device / path).read_text().strip())
            except (OSError, ValueError):
                pass
        if item["frequency_mhz"] is None:
            for freq_path in (device / f"drm/{card.name}/gt/gt0/rps_cur_freq_mhz",
                              device / f"drm/{card.name}/gt/gt0/rps_act_freq_mhz"):
                try:
                    item["frequency_mhz"] = int(freq_path.read_text().strip())
                    break
                except (OSError, ValueError):
                    continue
        try:
            item["rc6_residency_ms"] = int((device / f"drm/{card.name}/gt/gt0/rc6_residency_ms").read_text().strip())
        except (OSError, ValueError):
            pass
        if vendor == "0x10de" and shutil.which("nvidia-smi"):
            try:
                query = subprocess.run(["nvidia-smi", "--query-gpu=memory.used,memory.total,utilization.gpu,temperature.gpu,clocks.gr",
                    "--format=csv,noheader,nounits"], capture_output=True, text=True, timeout=.8, check=False)
                if query.returncode == 0 and query.stdout.strip():
                    fields = [value.strip() for value in query.stdout.splitlines()[0].split(",")]
                    item["memory_used"], item["memory_total"] = int(fields[0]) * 1024**2, int(fields[1]) * 1024**2
                    item["usage"], item["temperature"], item["frequency_mhz"] = int(fields[2]), int(fields[3]), int(fields[4])
            except (OSError, ValueError, IndexError, subprocess.TimeoutExpired):
                pass
        gpus.append(item)
    return gpus


def read_system_info():
    core_ids = set()
    for topology in Path("/sys/devices/system/cpu").glob("cpu[0-9]*/topology/core_id"):
        try: core_ids.add(int(topology.read_text()))
        except (OSError, ValueError): pass
    info = {"Hostname": socket.gethostname(), "Kernel": platform.release(),
            "Architecture": platform.machine(), "Logical CPUs": str(os.cpu_count() or "—"),
            "Physical cores": str(len(core_ids)) if core_ids else "—"}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if line.startswith("PRETTY_NAME="):
                info["Operating system"] = line.split("=", 1)[1].strip().strip('"')
                break
    except OSError:
        pass
    try:
        cpu_lines = Path("/proc/cpuinfo").read_text().splitlines()
        info["Processor"] = next(line.split(":", 1)[1].strip() for line in cpu_lines
                                 if line.startswith("model name"))
    except (OSError, StopIteration):
        pass
    for key, path in (("Manufacturer", "/sys/class/dmi/id/sys_vendor"),
                      ("Product", "/sys/class/dmi/id/product_name"),
                      ("BIOS", "/sys/class/dmi/id/bios_version")):
        try:
            value = Path(path).read_text().strip()
            if value and value != "None":
                info[key] = value
        except OSError:
            pass
    mem = read_meminfo()
    if mem.get("MemTotal"):
        info["Physical memory"] = fmt_bytes(mem["MemTotal"])
    return info


def read_battery_info():
    batteries = []
    for device in Path("/sys/class/power_supply").glob("*"):
        try:
            if (device / "type").read_text().strip() != "Battery":
                continue
            def read(name):
                try:
                    return (device / name).read_text().strip()
                except OSError:
                    return ""
            batteries.append({"name": device.name, "model": read("model_name"),
                "manufacturer": read("manufacturer"), "capacity": read("capacity"),
                "status": read("status"), "energy_now": read("energy_now"),
                "energy_full": read("energy_full"), "power_now": read("power_now"),
                "voltage_now": read("voltage_now")})
        except OSError:
            continue
    return batteries


def read_meminfo():
    result = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, value = line.split(":", 1)
            result[key] = int(value.strip().split()[0]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return result


def read_psi(path):
    result = {}
    try:
        for line in Path(path).read_text().splitlines():
            fields = dict(part.split("=", 1) for part in line.split()[1:])
            result[line.split()[0]] = float(fields.get("avg10", 0))
    except (OSError, ValueError):
        pass
    return result


def read_cpu_stat():
    try:
        fields = Path("/proc/stat").read_text().splitlines()[0].split()[1:]
        values = [int(x) for x in fields]
        return sum(values[:8]), values[3] + (values[4] if len(values) > 4 else 0)
    except (OSError, ValueError, IndexError):
        return None


def scan_processes(include_security=True):
    """Read-only /proc inventory. Never reads command-line arguments or environments."""
    now, procs, count = time.monotonic(), [], 0
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        count += 1
        pid, base = int(entry.name), Path("/proc") / entry.name
        try:
            raw = (base / "stat").read_text()
            close = raw.rfind(")")
            if close < 0:
                continue
            comm, fields = raw[raw.find("(") + 1:close], raw[close + 2:].split()
            state, ppid = fields[0], int(fields[1])
            ticks, start = int(fields[11]) + int(fields[12]), int(fields[19])
            rss = max(0, int(fields[21])) * PAGE_SIZE
            uid = None
            try:
                for line in (base / "status").read_text().splitlines():
                    if line.startswith("Uid:"):
                        uid = int(line.split()[1]); break
            except (OSError, ValueError, IndexError):
                pass
            if include_security:
                try:
                    exe = os.readlink(base / "exe")
                except OSError:
                    exe = ""
            else:
                exe = ""
            cgroup = ""
            try:
                for line in (base / "cgroup").read_text().splitlines():
                    if line.startswith("0::"):
                        cgroup = line.split("::", 1)[1]
                        break
            except OSError:
                pass
            read_bytes = write_bytes = 0
            try:
                for line in (base / "io").read_text().splitlines():
                    key, value = line.split(":", 1)
                    if key == "read_bytes": read_bytes = int(value)
                    elif key == "write_bytes": write_bytes = int(value)
            except (OSError, ValueError):
                pass
            try:
                owner = pwd.getpwuid(uid).pw_name if uid is not None else "?"
            except KeyError:
                owner = str(uid)
            procs.append({
                "pid": pid, "ppid": ppid, "name": comm, "state": state,
                "ticks": ticks, "start": start, "rss": rss, "uid": uid,
                "owner": owner, "exe": exe, "cgroup": cgroup, "read": read_bytes,
                "write": write_bytes, "seen": now,
            })
        except (OSError, ValueError, IndexError, PermissionError):
            continue
    return procs, count, read_cpu_stat(), time.monotonic()


def fmt_bytes(value):
    value = max(0, int(value or 0))
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TiB"


def cell(value, align=None):
    obj = QTableWidgetItem(str(value))
    if align is not None: obj.setTextAlignment(align)
    return obj


def load_history_samples(path=None, max_samples=360):
    path = path or (Path.home() / ".local/state/nrg/telemetry.jsonl")
    try:
        lines = path.read_text(errors="replace").splitlines()[-max_samples:]
    except OSError:
        return []
    samples = []
    for line in lines:
        try:
            item = json.loads(line)
            if isinstance(item, dict) and isinstance(item.get("timestamp_unix_ms"), (int, float)):
                samples.append(item)
        except (ValueError, TypeError):
            continue
    return samples


class HistoryChart(QWidget):
    PALETTE = ["#48b8e8", "#e2ad55", "#b28ae6", "#69c69a", "#e47777"]

    def __init__(self, title, parent=None):
        super().__init__(parent)
        self.title = title
        self.series = {}
        self.times = []
        self.setMinimumHeight(175)

    def set_data(self, series, times):
        self.series = {name: [float(value) for value in values] for name, values in series.items()}
        self.times = list(times)
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(QColor("#e9e9eb"))
        painter.drawText(12, 20, self.title)
        if not self.series or not any(self.series.values()):
            painter.setPen(QColor("#9a9da6"))
            painter.drawText(18, 58, "No history samples available")
            painter.end()
            return
        left, top, right, bottom = 58, 34, 16, 54
        width = max(1, self.width() - left - right)
        height = max(1, self.height() - top - bottom)
        all_values = [v for values in self.series.values() for v in values if v == v]
        if not all_values:
            painter.end(); return
        low, high = min(all_values), max(all_values)
        if high - low < 0.001:
            high = low + 1.0
        else:
            pad = (high - low) * 0.08
            low, high = max(0, low - pad), high + pad
        painter.setPen(QPen(QColor("#343840"), 1))
        for tick in range(5):
            y = top + height * tick / 4
            painter.drawLine(int(left), int(y), int(left + width), int(y))
            value = high - (high - low) * tick / 4
            painter.setPen(QColor("#9a9da6"))
            painter.drawText(4, int(y + 4), f"{value:.1f}")
            painter.setPen(QPen(QColor("#343840"), 1))
        for index, (name, values) in enumerate(self.series.items()):
            if len(values) < 2: continue
            points = QPolygonF()
            count = len(values)
            for i, value in enumerate(values):
                x = left + width * i / max(1, count - 1)
                y = top + height * (high - value) / (high - low)
                points.append(QPointF(x, y))
            painter.setPen(QPen(QColor(self.PALETTE[index % len(self.PALETTE)]), 2))
            painter.drawPolyline(points)
        painter.setPen(QColor("#9a9da6"))
        if self.times:
            painter.drawText(int(left), self.height() - 7, self.times[0])
            painter.drawText(int(left + width - 90), self.height() - 7, self.times[-1])
        legend_x, legend_y = left, self.height() - 24
        for index, name in enumerate(self.series):
            if legend_x > self.width() - 130:
                legend_x = left
                legend_y -= 17
            painter.setPen(QPen(QColor(self.PALETTE[index % len(self.PALETTE)]), 3))
            painter.drawLine(int(legend_x), int(legend_y - 4), int(legend_x + 12), int(legend_y - 4))
            painter.setPen(QColor("#c7c8cc"))
            label = name[:18]
            painter.drawText(int(legend_x + 17), int(legend_y), label)
            legend_x += min(180, 28 + len(label) * 7)
        painter.end()


class NetworkTestWorker(QThread):
    completed = Signal(object)

    def run(self):
        cli = shutil.which("speedtest-cli")
        if cli:
            try:
                result = subprocess.run([cli, "--secure", "--json"], capture_output=True,
                                        text=True, timeout=90, check=False)
                if result.returncode != 0:
                    raise RuntimeError(result.stderr.strip() or f"speedtest-cli exit {result.returncode}")
                data = json.loads(result.stdout)
                self.completed.emit({
                    "ok": True, "download_mbps": float(data["download"]) / 1_000_000,
                    "upload_mbps": float(data["upload"]) / 1_000_000,
                    "ping_ms": float(data.get("ping", 0)),
                    "server": data.get("server", {}).get("name", "Speedtest server"),
                    "provider": "Ookla speedtest-cli",
                })
                return
            except Exception as exc:
                self.completed.emit({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
                return
        try:
            started = time.monotonic()
            with urllib.request.urlopen("https://speed.cloudflare.com/__down?bytes=25000000", timeout=25) as response:
                downloaded = 0
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk: break
                    downloaded += len(chunk)
            elapsed = max(0.001, time.monotonic() - started)
            self.completed.emit({"ok": True, "download_mbps": downloaded * 8 / elapsed / 1_000_000,
                                 "upload_mbps": None, "provider": "Cloudflare download endpoint",
                                 "needs_upload_cli": True})
        except Exception as exc:
            self.completed.emit({"ok": False, "error": f"{type(exc).__name__}: {exc}"})


class ProcessDetails(QDialog):
    def __init__(self, proc, parent=None, language="en"):
        super().__init__(parent)
        es = language == "es"
        self.setWindowTitle(("NRG · Proceso " if es else "NRG · Process ") + str(proc["pid"]))
        self.resize(680, 420)
        layout = QVBoxLayout(self)
        view = QTextEdit(); view.setReadOnly(True)
        reasons = proc["reasons"] or (["No hay indicadores heurísticos actuales."] if es else ["No current heuristic indicators."])
        if es:
            reasons = [reason.replace("Sustained high CPU", "Uso elevado y sostenido de CPU")
                .replace("Rapid resident-memory growth", "Crecimiento rápido de memoria residente")
                .replace("Sustained high disk writes", "Escrituras de disco elevadas y sostenidas")
                .replace("Executable deleted while process is alive", "Ejecutable eliminado mientras el proceso sigue activo")
                .replace("Executable launched from a temporary directory", "Ejecutable iniciado desde un directorio temporal")
                .replace("Rapid child-process fan-out", "Creación rápida de procesos hijos")
                for reason in reasons]
        view.setPlainText("\n".join([
            f"{'Proceso' if es else 'Process'}: {proc['name']} (PID {proc['pid']})",
            f"PID padre: {proc['ppid']} · {'Propietario' if es else 'Owner'}: {proc['owner']} · {'Estado' if es else 'State'}: {proc['state']}",
            f"CPU: {proc['cpu']:.1f}% {'de un núcleo lógico' if es else 'of one logical core'}",
            f"Estimación RSS: {fmt_bytes(proc['rss'])}" if es else f"RSS estimate: {fmt_bytes(proc['rss'])}",
            f"Lectura/escritura de disco: {fmt_bytes(proc['read_rate'])}/s · {fmt_bytes(proc['write_rate'])}/s" if es else f"Disk read/write: {fmt_bytes(proc['read_rate'])}/s · {fmt_bytes(proc['write_rate'])}/s",
            f"Ejecutable: {proc['exe'] or 'no legible'}" if es else f"Executable: {proc['exe'] or 'not readable'}", "",
            "Indicadores para revisar:" if es else "Review indicators:", *reasons, "",
            "Son pistas de investigación, no un veredicto de malware. El uso de recursos por sí solo no identifica un virus." if es else "These are investigation clues, not a malware verdict. Resource usage alone cannot identify a virus.",
        ]))
        layout.addWidget(view)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject); layout.addWidget(buttons)


class CircularGauge(QWidget):
    def __init__(self, title, parent=None):
        super().__init__(parent)
        self.title, self.value_text, self.fraction, self.subtitle = title, "—", None, ""
        self.setMinimumSize(132, 154)
        self.setFixedHeight(154)

    def set_metric(self, value_text, fraction=None, subtitle=""):
        self.value_text = value_text
        self.fraction = max(0.0, min(1.0, float(fraction))) if fraction is not None else None
        self.subtitle = subtitle
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        diameter = max(48, min(70, h - 58, w - 16))
        x, y = (w - diameter) / 2, 34
        painter.setPen(QColor("#c8cbd2"))
        painter.drawText(4, 19, w - 8, 16, Qt.AlignmentFlag.AlignHCenter, self.title)
        painter.setPen(QPen(QColor("#30343b"), 7, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawArc(int(x), int(y), int(diameter), int(diameter), 90 * 16, -360 * 16)
        if self.fraction is not None:
            painter.setPen(QPen(QColor("#48b8e8"), 7, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            painter.drawArc(int(x), int(y), int(diameter), int(diameter), 90 * 16, int(-360 * self.fraction * 16))
        painter.setPen(QColor("#f2f3f5"))
        font = painter.font(); font.setBold(True); font.setPointSize(11); painter.setFont(font)
        painter.drawText(int(x), int(y + diameter/2 - 12), int(diameter), 24, Qt.AlignmentFlag.AlignCenter, self.value_text)
        painter.setPen(QColor("#9a9da6"))
        font = painter.font(); font.setBold(False); font.setPointSize(8); painter.setFont(font)
        painter.drawText(2, int(y + diameter + 17), w - 4, 16, Qt.AlignmentFlag.AlignHCenter, self.subtitle)
        painter.end()


class NRGWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NRG Desktop · Nexus Resource Governor")
        self.resize(980, 700)
        self.setMinimumSize(760, 540)
        self.previous, self.previous_cpu, self.last_scan = {}, None, None
        self.processes, self.process_rows = [], {}
        self.language = "en"
        self.previous_network = None
        self.network_rates = (0.0, 0.0)
        self.previous_cores = {}
        self.previous_disks = {}
        self.previous_gpu_rc6 = {}
        self.interface_rates = {}
        self.hardware_history = []
        self.process_spawn_high = 0
        self.process_spawn_warning = False
        self.process_baseline_ready = False
        self.parent_spawn_high = {}
        self.new_processes_last = 0
        self.security_enabled = True
        self.measured_down_mbps = None
        self.measured_up_mbps = None
        self.network_worker = None
        self._build_ui()
        self.timer = QTimer(self); self.timer.timeout.connect(self.refresh)
        self.timer.start(REFRESH_MS)
        self.history_timer = QTimer(self)
        self.history_timer.timeout.connect(self.refresh_history)
        self.history_timer.start(30_000)
        self.refresh()
        self.refresh_history()

    def _build_ui(self):
        self.setStyleSheet("""
            QMainWindow,QWidget{background:#101114;color:#e9e9eb}
            QTabWidget::pane{border:1px solid #303238;border-radius:8px}
            QTabBar::tab{background:#1a1c21;padding:8px 12px;margin:2px;border-radius:6px}
            QTabBar::tab:selected{background:#292c33;border-bottom:2px solid #d94b45}
            QTabBar{qproperty-expanding:false}
            QTabBar::tab:selected{background:#292c33;border-bottom:2px solid #d94b45}
            QLabel#muted{color:#9a9da6}
            QLabel#metric{font-size:24px;font-weight:650;color:#f1f1f2}
            QLabel#section{font-size:17px;font-weight:650}
            QPushButton{background:#292c33;border:1px solid #41444c;border-radius:6px;padding:8px 14px}
            QPushButton:hover{border-color:#d94b45}
            QComboBox,QLineEdit{background:#1b1d22;border:1px solid #3a3d45;border-radius:5px;padding:7px}
            QTableWidget,QTextEdit{background:#17191e;alternate-background-color:#1d2026;gridline-color:#30333a;border:1px solid #30333a}
            QHeaderView::section{background:#24272d;padding:7px;border:0;color:#c8c9cd}
        """)
        central, root = QWidget(), QVBoxLayout()
        central.setLayout(root)
        head = QHBoxLayout()
        brand = QLabel("NRG"); brand.setStyleSheet("font-size:25px;font-weight:800;color:#e15a50")
        self.subtitle = QLabel("Nexus Resource Governor  /  local diagnostics"); self.subtitle.setObjectName("muted")
        self.live = QLabel("Starting…"); self.live.setObjectName("muted")
        self.language_box = QComboBox(); self.language_box.addItem("English", "en"); self.language_box.addItem("Español", "es")
        head.addWidget(brand); head.addWidget(self.subtitle); head.addStretch()
        head.addWidget(self.language_box); head.addWidget(self.live)
        root.addLayout(head)
        self.tabs = QTabWidget()
        self.tabs.setUsesScrollButtons(True)
        self.tabs.currentChanged.connect(lambda index: self.refresh_history() if index == 4 else None)
        root.addWidget(self.tabs)
        self._dashboard(); self._hardware_tab(); self._process_tab(); self._applications_tab(); self._history_tab(); self._diagnostics_tab()
        self.language_box.currentIndexChanged.connect(self.change_language)
        self.language = self.language_box.currentData() or "en"
        page_scroll = QScrollArea()
        page_scroll.setWidgetResizable(True)
        page_scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        page_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        page_scroll.setWidget(central)
        self.setCentralWidget(page_scroll)
        self.apply_language()

    def _metric(self, title):
        box, layout = QWidget(), QVBoxLayout()
        box.setLayout(layout); layout.setContentsMargins(12, 10, 12, 10)
        name = QLabel(title); name.setObjectName("muted"); name.setWordWrap(True)
        value = QLabel("—"); value.setObjectName("metric")
        layout.addWidget(name); layout.addWidget(value)
        box.setStyleSheet("background:#1a1c21;border:1px solid #303238;border-radius:8px")
        return box, value

    def _dashboard(self):
        page, layout = QWidget(), QVBoxLayout()
        page.setLayout(layout)
        self.metric_gauges = {}
        gauge_grid = QGridLayout()
        for col, (key, title) in enumerate([
            ("available", "RAM AVAILABLE"), ("cpu", "CPU UTILIZATION"),
            ("gpu_usage", "GPU UTILIZATION"), ("swap", "SWAP IN USE"),
        ]):
            gauge = CircularGauge(title)
            self.metric_gauges[key] = gauge
            gauge_grid.addWidget(gauge, 0, col)
        layout.addLayout(gauge_grid)
        self.metrics, self.metric_title_labels = {}, {}
        secondary = [
            ("used","RAM IN USE"), ("processes","PROCESSES"), ("pressure","MEMORY PSI FULL"),
            ("disk","HOME VOLUME FREE"), ("gpu","GPU MEMORY"), ("network","NETWORK RX / TX"),
            ("cpu_temp","CPU TEMPERATURE"), ("gpu_temp","GPU TEMPERATURE"), ("battery","BATTERY"),
            ("wifi","WI-FI SIGNAL"), ("disk_io","DISK READ / WRITE"), ("fan","FAN SPEED"),
        ]
        grid = QGridLayout()
        for i, (key, title) in enumerate(secondary):
            box, value = self._metric(title)
            value.setStyleSheet("font-size:15px;font-weight:600;color:#f1f1f2")
            self.metrics[key] = value
            self.metric_title_labels[key] = box.layout().itemAt(0).widget()
            box.layout().setContentsMargins(8, 5, 8, 5)
            grid.addWidget(box, i // 4, i % 4)
        layout.addLayout(grid)
        self.health = QLabel("Collecting resource signals…")
        self.health.setObjectName("section"); self.health.setWordWrap(True); layout.addWidget(self.health)
        self.alert_heading = QLabel("Processes that deserve a closer look"); layout.addWidget(self.alert_heading)
        self.alert_table = QTableWidget(0, 3)
        self.alert_table.setHorizontalHeaderLabels(["Process", "PID", "Signal"])
        for col, mode in enumerate([QHeaderView.ResizeMode.ResizeToContents,
                                    QHeaderView.ResizeMode.ResizeToContents,
                                    QHeaderView.ResizeMode.Stretch]):
            self.alert_table.horizontalHeader().setSectionResizeMode(col, mode)
        self.alert_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.alert_table.cellDoubleClicked.connect(self.open_alert_details)
        self.alert_table.setMaximumHeight(190); layout.addWidget(self.alert_table)
        self.dashboard_note = QLabel("System telemetry is read-only by default. Process controls require an explicit selection; no kernel or cgroup limits are changed.")
        self.dashboard_note.setObjectName("muted"); self.dashboard_note.setWordWrap(True); layout.addWidget(self.dashboard_note)
        self.tabs.addTab(page, "Overview")

    def _hardware_table(self, headers):
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setAlternatingRowColors(True)
        table.setSortingEnabled(False)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setStretchLastSection(True)
        return table

    def _hardware_tab(self):
        page, layout = QWidget(), QVBoxLayout()
        page.setLayout(layout)
        self.hardware_summary = QLabel("Live hardware inventory · kernel interfaces")
        self.hardware_summary.setObjectName("section")
        layout.addWidget(self.hardware_summary)
        self.hardware_system = self._hardware_table(["System property", "Value"])
        layout.addWidget(self.hardware_system)
        self.hardware_cpu = self._hardware_table(["Logical CPU", "Physical core", "Usage", "Temperature"])
        self.hardware_gpu = self._hardware_table(["GPU", "Driver", "Utilization", "Memory", "Frequency", "Temperature"])
        self.hardware_network = self._hardware_table(["Interface", "Type / state", "Link / signal", "Download", "Upload", "IPv4", "IPv6", "Errors"])
        self.hardware_disks = self._hardware_table(["Device", "Model", "Capacity", "Read", "Write", "Busy"])
        self.hardware_thermals = self._hardware_table(["Sensor", "Component", "Temperature / value"])
        self.hardware_section_labels = {}
        for key, title, table in (("cpu", "CPU · per logical core", self.hardware_cpu),
                                  ("gpu", "Graphics processors", self.hardware_gpu),
                                  ("network", "Network interfaces", self.hardware_network),
                                  ("disk", "Storage devices", self.hardware_disks),
                                  ("sensors", "Thermal / hardware sensors", self.hardware_thermals)):
            heading = QLabel(title); heading.setObjectName("section")
            self.hardware_section_labels[key] = heading
            layout.addWidget(heading)
            layout.addWidget(table)
        self.hardware_note = QLabel("Metrics are read directly from Linux /proc, /sys, hwmon and network interfaces. Intel i915 GPU activity is estimated from RC6 idle residency, not measured engine busy; integrated graphics share system RAM rather than dedicated VRAM. Unsupported hardware values are shown as unavailable.")
        self.hardware_note.setWordWrap(True); self.hardware_note.setObjectName("muted"); layout.addWidget(self.hardware_note)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setWidget(page)
        self.tabs.addTab(scroll, "Hardware")

    def _process_tab(self):
        page, layout = QWidget(), QVBoxLayout(); page.setLayout(layout)
        row = QHBoxLayout()
        self.search = QLineEdit(); self.search.setPlaceholderText("Filter by process, PID, owner or executable…")
        self.search.textChanged.connect(self.populate_process_table)
        self.count_label = QLabel("—"); row.addWidget(self.search,1); row.addWidget(self.count_label)
        layout.addLayout(row)
        self.process_table = QTableWidget(0,9)
        self.process_table.setHorizontalHeaderLabels(["Process","PID","CPU %","RAM","Owner","I/O read","I/O write","State","Review"])
        self.process_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.process_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.process_table.setAlternatingRowColors(True); self.process_table.setSortingEnabled(True)
        self.process_table.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeMode.Stretch)
        for col in range(1,9): self.process_table.horizontalHeader().setSectionResizeMode(col,QHeaderView.ResizeMode.ResizeToContents)
        self.process_table.cellDoubleClicked.connect(self.open_process_details)
        self.process_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.process_table.customContextMenuRequested.connect(self.process_context_menu)
        self.process_actions_button = QPushButton("Manage selected process…")
        self.process_actions_button.clicked.connect(self.show_process_actions)
        action_row = QHBoxLayout(); action_row.addWidget(self.process_actions_button); action_row.addStretch()
        layout.addLayout(action_row)
        layout.addWidget(self.process_table)
        self.process_note = QLabel("CPU is normalized to one logical core. RSS may double-count shared pages. Network traffic is system-wide; per-process network accounting is not available in this collector yet.")
        self.process_note.setObjectName("muted"); layout.addWidget(self.process_note)
        self.tabs.addTab(page,"Processes")

    def _applications_tab(self):
        page, layout = QWidget(), QVBoxLayout(); page.setLayout(layout)
        self.applications_heading = QLabel("Application workloads · grouped by cgroup v2")
        layout.addWidget(self.applications_heading)
        self.applications_table = QTableWidget(0,6)
        self.applications_table.setHorizontalHeaderLabels([
            "Application", "Processes", "CPU %", "Memory", "Disk read / write", "Review"])
        self.applications_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.applications_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.applications_table.setAlternatingRowColors(True)
        self.applications_table.setSortingEnabled(True)
        self.applications_table.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeMode.Stretch)
        for col in range(1,6):
            self.applications_table.horizontalHeader().setSectionResizeMode(col,QHeaderView.ResizeMode.ResizeToContents)
        self.applications_table.cellDoubleClicked.connect(self.open_application_processes)
        self.applications_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.applications_table.customContextMenuRequested.connect(self.application_context_menu)
        self.application_actions_button = QPushButton("Manage selected workload…")
        self.application_actions_button.clicked.connect(self.show_application_actions)
        action_row = QHBoxLayout(); action_row.addWidget(self.application_actions_button); action_row.addStretch()
        layout.addLayout(action_row)
        layout.addWidget(self.applications_table,1)
        self.applications_note = QLabel(
            "Cgroup memory is the preferred per-workload total. RSS sum can double-count shared pages. Double-click a workload to inspect its processes. Network traffic is not yet attributed per application.")
        self.applications_note.setObjectName("muted"); layout.addWidget(self.applications_note)
        self.tabs.addTab(page,"Applications")

    def _history_tab(self):
        page, layout = QWidget(), QVBoxLayout(); page.setLayout(layout)
        row = QHBoxLayout()
        self.history_heading = QLabel("Resource history · last 60 minutes")
        self.history_refresh_button = QPushButton("Refresh history")
        self.history_refresh_button.clicked.connect(self.refresh_history)
        self.history_status = QLabel("Waiting for telemetry…"); self.history_status.setObjectName("muted")
        row.addWidget(self.history_heading); row.addStretch(); row.addWidget(self.history_status); row.addWidget(self.history_refresh_button)
        layout.addLayout(row)
        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        content, charts_layout = QWidget(), QVBoxLayout()
        content.setLayout(charts_layout)
        self.history_charts = {
            "cpu": HistoryChart("CPU utilization by logical core (%)"),
            "gpu": HistoryChart("GPU activity estimate (%) · driver-supported metrics only"),
            "memory": HistoryChart("Memory available and swap (GiB)"),
            "pressure": HistoryChart("Pressure Stall Information (PSI %)"),
            "workloads": HistoryChart("Largest application workloads (MiB)"),
        }
        for chart in self.history_charts.values():
            charts_layout.addWidget(chart)
        self.history_workload_table = QTableWidget(0, 2)
        self.history_workload_table.setHorizontalHeaderLabels(["Application", "Memory"])
        self.history_workload_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.history_workload_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.history_workload_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.history_workload_table.setMaximumHeight(160)
        charts_layout.addWidget(self.history_workload_table)
        charts_layout.addStretch()
        scroll.setWidget(content); layout.addWidget(scroll,1)
        self.history_note = QLabel("RAM / PSI / workload history is stored by the NRG service. CPU per-core and GPU history is session-only while this window is open.")
        self.history_note.setObjectName("muted"); layout.addWidget(self.history_note)
        self.tabs.addTab(page,"History")

    def _diagnostics_tab(self):
        page, layout = QWidget(), QVBoxLayout(); page.setLayout(layout)
        row = QHBoxLayout()
        self.profile_label = QLabel("Profile")
        self.profile = QComboBox(); self.reload_profiles()
        self.profile.currentTextChanged.connect(self.save_profile)
        self.plan_button = QPushButton("Calculate memory plan"); self.plan_button.clicked.connect(self.run_plan)
        self.diag_button = QPushButton("Run system diagnosis"); self.diag_button.clicked.connect(self.run_diagnosis)
        self.edit_profiles_button = QPushButton("Edit coasters"); self.edit_profiles_button.clicked.connect(self.edit_profiles)
        self.security_toggle = QCheckBox("Enable anomaly / security monitoring")
        self.security_toggle.setChecked(True); self.security_toggle.toggled.connect(self.set_security_enabled)
        row.addWidget(self.profile_label); row.addWidget(self.profile)
        row.addWidget(self.plan_button); row.addWidget(self.diag_button); row.addWidget(self.edit_profiles_button)
        row.addWidget(self.security_toggle); row.addStretch()
        layout.addLayout(row)
        self.plan_note = QLabel("Adaptive memory plan · simulation only")
        layout.addWidget(self.plan_note)
        self.plan_table = QTableWidget(0,5)
        self.plan_table.setHorizontalHeaderLabels(["Application","Priority","Current","Proposed soft ceiling","Samples"])
        self.plan_table.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeMode.Stretch)
        for col in range(1,5): self.plan_table.horizontalHeader().setSectionResizeMode(col,QHeaderView.ResizeMode.ResizeToContents)
        self.plan_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers); layout.addWidget(self.plan_table,1)
        network_row = QHBoxLayout()
        self.download_plan = QLineEdit(); self.download_plan.setPlaceholderText("Download plan Mbps"); self.download_plan.setMaximumWidth(130)
        self.upload_plan = QLineEdit(); self.upload_plan.setPlaceholderText("Upload plan Mbps"); self.upload_plan.setMaximumWidth(130)
        self.primary_share = QLineEdit("70"); self.primary_share.setMaximumWidth(70)
        self.network_preview_button = QPushButton("Preview network budget")
        self.network_preview_button.clicked.connect(self.preview_network_budget)
        self.network_plan_label = QLabel("Internet plan ↓ / ↑ Mbps")
        self.network_share_label = QLabel("Top app %")
        network_row.addWidget(self.network_plan_label); network_row.addWidget(self.download_plan)
        network_row.addWidget(self.upload_plan); network_row.addWidget(self.network_share_label); network_row.addWidget(self.primary_share)
        network_row.addWidget(self.network_preview_button); network_row.addStretch()
        layout.addLayout(network_row)
        self.network_test_button = QPushButton("Run network speed test")
        self.network_test_button.setToolTip("Uses speedtest-cli for download/upload/ping if installed; otherwise measures a 25 MB download only.")
        self.network_test_button.clicked.connect(self.run_network_test)
        layout.addWidget(self.network_test_button)
        self.network_test_result = QLabel("No speed test yet. Test runs only when you click; fallback download uses up to 25 MB.")
        self.network_test_result.setWordWrap(True); layout.addWidget(self.network_test_result)
        self.network_preview = QLabel("Network budget preview is advisory; no traffic shaping is applied.")
        self.network_preview.setWordWrap(True); layout.addWidget(self.network_preview)
        self.diag_output = QTextEdit(); self.diag_output.setReadOnly(True)
        self.diag_output.setPlaceholderText("System diagnosis output appears here."); layout.addWidget(self.diag_output,2)
        self.load_profile()
        self.tabs.addTab(page,"Diagnosis & Profiles")

    def refresh(self):
        try:
            procs, count, cpu_total, now = scan_processes(include_security=self.security_enabled)
            mem = read_meminfo()
            pm, pc, pi = (read_psi("/proc/pressure/"+name) for name in ("memory","cpu","io"))
            elapsed = max(.001, now-self.last_scan) if self.last_scan else REFRESH_MS/1000
            cpu_pct = None
            old_cpu = self.previous_cpu
            if cpu_total and old_cpu:
                dt = max(1,cpu_total[0]-old_cpu[0]); di = max(0,cpu_total[1]-old_cpu[1])
                cpu_pct = max(0,min(100,100*(dt-di)/dt))
            self.update_process_metrics(procs,count,cpu_total,old_cpu,elapsed)
            self.previous_cpu, self.last_scan = cpu_total, now
            total, avail = mem.get("MemTotal",0), mem.get("MemAvailable",0)
            swap = max(0,mem.get("SwapTotal",0)-mem.get("SwapFree",0))
            disk_stat = os.statvfs(Path.home())
            disk_total = disk_stat.f_blocks * disk_stat.f_frsize
            disk_free = disk_stat.f_bavail * disk_stat.f_frsize
            sensors = read_hwmon_sensors()
            disks_now = read_block_devices()
            batteries = read_battery_info()
            gpu_list = read_gpu_info()
            for gpu_item in gpu_list:
                if gpu_item["usage"] is None and gpu_item["rc6_residency_ms"] is not None:
                    old_rc6 = self.previous_gpu_rc6.get(gpu_item["card"])
                    if old_rc6 is not None:
                        idle_ms = max(0, gpu_item["rc6_residency_ms"] - old_rc6)
                        gpu_item["usage"] = max(0.0, min(100.0, 100.0 * (1.0 - idle_ms / max(1.0, elapsed * 1000))))
                        gpu_item["usage_source"] = "RC6 idle-residency estimate"
                if gpu_item["rc6_residency_ms"] is not None:
                    self.previous_gpu_rc6[gpu_item["card"]] = gpu_item["rc6_residency_ms"]
            primary_gpu = gpu_list[0] if gpu_list else {"name": "GPU", "usage": None, "memory_used": None, "memory_total": None, "kind": "unknown"}
            gpu = {"name": primary_gpu["name"], "used": primary_gpu["memory_used"] or 0,
                   "total": primary_gpu["memory_total"], "util": primary_gpu["usage"],
                   "kind": "dedicated" if primary_gpu["memory_total"] else "shared"}
            if gpu["kind"] == "dedicated":
                gpu_text = f"{fmt_bytes(gpu['used'])} / {fmt_bytes(gpu['total'])}"
                if gpu.get("util") is not None: gpu_text += f" · {gpu['util']}%"
            else:
                gpu_text = ("Compartida con RAM del sistema / VRAM dedicada no expuesta" if self.language == "es"
                            else "Shared with system RAM / no dedicated VRAM exposed")
            interfaces_now = read_network_interfaces()
            network = {"rx": sum(x["rx"] for x in interfaces_now.values()),
                       "tx": sum(x["tx"] for x in interfaces_now.values()),
                       "interfaces": [{"name": name, "wifi": x["kind"] == "Wi-Fi"}
                                      for name, x in interfaces_now.items()]}
            self.interface_rates = {}
            for ifname, info in interfaces_now.items():
                old_info = (self.previous_network or {}).get("by_interface", {}).get(ifname)
                self.interface_rates[ifname] = {
                    "rx": max(0, info["rx"] - old_info["rx"]) / max(0.001, elapsed) if old_info else 0.0,
                    "tx": max(0, info["tx"] - old_info["tx"]) / max(0.001, elapsed) if old_info else 0.0,
                }
            network["by_interface"] = interfaces_now
            if self.previous_network:
                dt = max(0.001, elapsed)
                rx_rate = max(0, network["rx"] - self.previous_network["rx"]) * 8 / dt / 1_000_000
                tx_rate = max(0, network["tx"] - self.previous_network["tx"]) * 8 / dt / 1_000_000
                self.network_rates = (rx_rate, tx_rate)
            self.previous_network = network
            iface = ", ".join(item["name"] for item in network["interfaces"]) or "no active interface"
            network_text = f"{self.network_rates[0]:.1f} / {self.network_rates[1]:.1f} Mbps · {iface}"
            for key, value in [
                ("available",fmt_bytes(avail)),("used",fmt_bytes(max(0,total-avail))),
                ("swap",fmt_bytes(swap)),("cpu",f"{cpu_pct:.0f}%" if cpu_pct is not None else "—"),
                ("processes",str(count)),("pressure",f"{pm.get('full',0):.2f}%"),
                ("disk",fmt_bytes(disk_free)),("gpu",gpu_text),("network",network_text),
                ("cpu_temp", f"{max((x['celsius'] for x in sensors['temperatures'] if x['chip'].startswith('coretemp')), default=0):.0f} °C" if any(x["chip"].startswith("coretemp") for x in sensors["temperatures"]) else "—"),
                ("gpu_usage", f"{gpu.get('util'):.0f}%" if gpu.get("util") is not None else "—"),
                ("gpu_temp", "—"),
                ("battery", (f"{batteries[0]['capacity']}% · {batteries[0]['status']}" if batteries and batteries[0]["capacity"] else "—")),
                ("wifi", read_wireless_signal()),
                ("disk_io", self._block_io_text(disks_now, self.previous_disks, elapsed)),
                ("fan", ", ".join(f"{x['rpm']:.0f} RPM" for x in sensors["fans"]) or ("No expuesto" if self.language == "es" else "Not exposed")),
            ]:
                if key in self.metrics:
                    self.metrics[key].setText(value)
            ram_fraction = (total - avail) / total if total else None
            swap_total = mem.get("SwapTotal", 0)
            swap_fraction = swap / swap_total if swap_total else None
            gpu_fraction = (gpu["used"] / gpu["total"] if gpu.get("total") else
                            (gpu.get("util") / 100 if gpu.get("util") is not None else None))
            self.metric_gauges["available"].title = "RAM DISPONIBLE" if self.language == "es" else "RAM AVAILABLE"
            self.metric_gauges["available"].set_metric(
                f"{avail/1024**3:.1f} GiB", (avail / total if total else None),
                f"{(avail / total * 100):.0f}% available" if total else "")
            self.metric_gauges["cpu"].set_metric(f"{cpu_pct:.0f}%" if cpu_pct is not None else "—",
                cpu_pct / 100 if cpu_pct is not None else None, "total")
            self.metric_gauges["gpu_usage"].set_metric(
                (f"{gpu.get('util'):.0f}% est." if primary_gpu.get("usage_source") else f"{gpu.get('util'):.0f}%")
                if gpu.get("util") is not None else "—",
                gpu_fraction, (gpu.get("name", "GPU") + (" · RC6 estimate" if primary_gpu.get("usage_source") else "")))
            self.metric_gauges["swap"].set_metric(f"{swap/1024**3:.1f} GiB", swap_fraction,
                f"{(swap_fraction or 0)*100:.0f}% used" if swap_total else "not configured")
            cores_now = read_cpu_cores()
            core_values = cpu_core_percentages(cores_now, self.previous_cores)
            self.previous_cores = cores_now
            gpu_usage = primary_gpu["usage"]
            self.hardware_history.append({"time": time.time(), "cpu": core_values, "gpu": gpu_usage})
            self.hardware_history = self.hardware_history[-360:]
            self._refresh_hardware_tables(cores_now, core_values, gpu_list, interfaces_now,
                                          disks_now, sensors, elapsed, batteries)
            self.previous_disks = disks_now
            self.update_health(avail,total,cpu_pct,pm,pc,pi,disk_free,disk_total)
            self.live.setText("LIVE  ·  "+time.strftime("%H:%M:%S"))
        except Exception as exc:
            self.live.setText(f"Collection error: {exc}")

    @staticmethod
    def _block_io_text(current, previous, elapsed):
        reads = writes = 0
        for name, item in current.items():
            old = previous.get(name)
            if old:
                reads += max(0, item["read_sectors"] - old["read_sectors"]) * 512 / max(.001, elapsed)
                writes += max(0, item["write_sectors"] - old["write_sectors"]) * 512 / max(.001, elapsed)
        return f"{fmt_bytes(reads)}/s · {fmt_bytes(writes)}/s"

    def _fill_hardware_table(self, table, rows):
        table.setSortingEnabled(False)
        table.setRowCount(len(rows))
        for r, values in enumerate(rows):
            for c, value in enumerate(values):
                table.setItem(r, c, cell(value))
        table.setSortingEnabled(False)

    def _refresh_hardware_tables(self, cores, core_values, gpus, interfaces, disks, sensors, elapsed, batteries):
        temps = sensors.get("temperatures", [])
        core_temps = {int(item["label"].split()[-1]): item["celsius"] for item in temps
                      if item["chip"].startswith("coretemp") and item["label"].startswith("Core ")
                      and item["label"].split()[-1].isdigit()}
        cpu_rows = []
        for name, value in sorted(core_values.items(), key=lambda x: int(x[0][3:])):
            try:
                core_id = int((Path("/sys/devices/system/cpu") / name / "topology/core_id").read_text())
            except (OSError, ValueError):
                core_id = -1
            temperature = core_temps.get(core_id)
            cpu_rows.append((name.upper(), str(core_id) if core_id >= 0 else "—",
                             f"{value:.1f}%" if value is not None else "—",
                             f"{temperature:.0f} °C" if temperature is not None else "—"))
        self._fill_hardware_table(self.hardware_cpu, cpu_rows)
        system_labels = {"Hostname": "Host", "Kernel": "Kernel", "Architecture": "Architecture",
                         "Logical CPUs": "Logical CPUs", "Operating system": "Operating system",
                         "Processor": "Processor", "Manufacturer": "Manufacturer",
                         "Product": "Product", "BIOS": "BIOS", "Physical memory": "Physical memory"}
        if self.language == "es":
            system_labels.update({"Hostname": "Equipo", "Kernel": "Kernel", "Architecture": "Arquitectura",
                "Logical CPUs": "CPU lógicas", "Operating system": "Sistema operativo",
                "Processor": "Procesador", "Manufacturer": "Fabricante", "Product": "Modelo",
                "BIOS": "BIOS", "Physical memory": "Memoria física"})
        system_rows = [(system_labels.get(k, k), v) for k, v in read_system_info().items()]
        for battery in batteries:
            system_rows.extend([
                (f"Battery · {battery['name']}", f"{battery['capacity']}% · {battery['status']}"),
                ("Battery model", battery["model"] or battery["manufacturer"] or "—"),
                ("Battery voltage", f"{int(battery['voltage_now']) / 1_000_000:.2f} V" if battery["voltage_now"].isdigit() else "—"),
                ("Battery power", f"{int(battery['power_now']) / 1_000_000:.2f} W" if battery["power_now"].isdigit() else "—"),
            ])
        self._fill_hardware_table(self.hardware_system, system_rows)
        gpu_rows = []
        gpu_temps = [item for item in temps if any(token in item["chip"].casefold() for token in ("amdgpu", "nvidia", "nouveau"))]
        for gpu in gpus:
            gpu_temp = next((item["celsius"] for item in gpu_temps
                             if (gpu["vendor"] == "0x10de" and "nvidia" in item["chip"].casefold())
                             or (gpu["vendor"] == "0x1002" and "amdgpu" in item["chip"].casefold())), None)
            memory = (f"{fmt_bytes(gpu['memory_used'] or 0)} / {fmt_bytes(gpu['memory_total'])}"
                      if gpu["memory_total"] else "Shared system RAM / no dedicated VRAM")
            gpu_rows.append((gpu["name"], gpu["driver"],
                (f"{gpu['usage']:.0f}% (estimate)" if gpu.get("usage_source") else f"{gpu['usage']:.0f}%")
                if gpu["usage"] is not None else "Not exposed by driver",
                memory, f"{gpu['frequency_mhz']} MHz" if gpu["frequency_mhz"] is not None else "—",
                f"{gpu['temperature']} °C" if gpu["temperature"] is not None else "—"))
        self._fill_hardware_table(self.hardware_gpu, gpu_rows)
        net_rows = []
        for name, info in sorted(interfaces.items()):
            rates = self.interface_rates.get(name, {"rx": 0, "tx": 0})
            addresses = info["addresses"]
            errors = info["rx_errors"] + info["tx_errors"]
            link = "—"
            try:
                speed = (Path("/sys/class/net") / name / "speed").read_text().strip()
                if speed.isdigit() and int(speed) > 0:
                    link = f"{speed} Mbps"
            except OSError:
                pass
            if info["kind"] == "Wi-Fi":
                try:
                    for line in Path("/proc/net/wireless").read_text().splitlines()[2:]:
                        if line.strip().startswith(name + ":"):
                            fields = line.replace(":", " ").split()
                            link = f"{float(fields[2]):.0f}/70 · {float(fields[3]):.0f} dBm"
                            break
                except (OSError, ValueError, IndexError):
                    pass
            net_rows.append((name, f"{info['kind']} · {info['state']}", link,
                f"{fmt_bytes(rates['rx'])}/s", f"{fmt_bytes(rates['tx'])}/s",
                ", ".join(addresses["ipv4"]) or "—", ", ".join(addresses["ipv6"]) or "—", str(errors)))
        self._fill_hardware_table(self.hardware_network, net_rows)
        disk_rows = []
        for name, info in sorted(disks.items()):
            old = self.previous_disks.get(name)
            read_rate = max(0, info["read_sectors"] - old["read_sectors"]) * 512 / max(.001, elapsed) if old else 0
            write_rate = max(0, info["write_sectors"] - old["write_sectors"]) * 512 / max(.001, elapsed) if old else 0
            disk_rows.append((name, info["model"], fmt_bytes(info["bytes"]),
                f"{fmt_bytes(read_rate)}/s", f"{fmt_bytes(write_rate)}/s",
                f"{max(0, info['busy_ms'] - old['busy_ms']) / max(.001, elapsed * 10):.1f}%" if old else "—"))
        self._fill_hardware_table(self.hardware_disks, disk_rows)
        thermal_rows = []
        for item in temps:
            thermal_rows.append((item["chip"], item["label"], f"{item['celsius']:.1f} °C"))
        for item in sensors.get("fans", []):
            thermal_rows.append((item["chip"], item["label"], f"{item['rpm']:.0f} RPM"))
        for item in sensors.get("voltages", []):
            thermal_rows.append((item["chip"], item["label"], f"{item['volts']:.2f} V"))
        for item in sensors.get("power", []):
            thermal_rows.append((item["chip"], item["label"], f"{item['watts']:.2f} W"))
        self._fill_hardware_table(self.hardware_thermals, thermal_rows)

    def update_process_metrics(self, procs,count,cpu_total,old_cpu,elapsed):
        total_ticks = max(1,cpu_total[0]-old_cpu[0]) if cpu_total and old_cpu else max(1,int(elapsed*CLK_TCK*CPU_COUNT))
        current = {}
        had_baseline = self.process_baseline_ready and self.security_enabled
        new_children_by_parent = {}
        new_processes = 0
        if had_baseline:
            for item in procs:
                if (item["pid"], item["start"]) not in self.previous:
                    new_processes += 1
                    parent = item["ppid"]
                    new_children_by_parent[parent] = new_children_by_parent.get(parent, 0) + 1
        self.process_baseline_ready = self.security_enabled
        self.new_processes_last = new_processes
        self.process_spawn_high = self.process_spawn_high + 1 if new_processes >= 40 else 0
        self.process_spawn_warning = self.process_spawn_high >= 2 or new_processes >= 120
        active_pids = {item["pid"] for item in procs}
        self.parent_spawn_high = {
            pid: (self.parent_spawn_high.get(pid, 0) + 1 if new_children_by_parent.get(pid, 0) >= 8 else 0)
            for pid in active_pids
        }
        for proc in procs:
            key=(proc["pid"],proc["start"]); old=self.previous.get(key)
            cpu=read_rate=write_rate=0.0
            if old:
                cpu=max(0,(proc["ticks"]-old["ticks"])/total_ticks*CPU_COUNT*100)
                read_rate=max(0,proc["read"]-old["read"])/elapsed
                write_rate=max(0,proc["write"]-old["write"])/elapsed
                cpu_high=(old["cpu_high"]+1 if cpu>=80 else 0) if self.security_enabled else 0
                growth_high=(old["growth_high"]+1 if proc["rss"]-old["rss"]>=128*1024**2 else 0) if self.security_enabled else 0
                write_high=(old["write_high"]+1 if write_rate>=100*1024**2 else 0) if self.security_enabled else 0
            else:
                cpu_high=growth_high=write_high=0
            score,reasons=0,[]
            if self.security_enabled:
                if cpu_high>=3: score+=25; reasons.append("Sustained high CPU (>=80% of one core)")
                if growth_high>=2: score+=25; reasons.append("Rapid resident-memory growth")
                if write_high>=3: score+=15; reasons.append("Sustained high disk writes")
                child_burst = new_children_by_parent.get(proc["pid"], 0)
                if child_burst >= 12 or self.parent_spawn_high.get(proc["pid"], 0) >= 2:
                    score += 40
                    reasons.append(f"Rapid child-process fan-out ({child_burst} new direct children)")
                exe=proc["exe"]
                if exe.endswith(" (deleted)"):
                    pass  # Common after package updates; not a security signal on its own.
                elif exe.startswith(("/tmp/","/var/tmp/","/dev/shm/")):
                    score+=15; reasons.append("Executable launched from a temporary directory")
            proc.update(cpu=cpu,read_rate=read_rate,write_rate=write_rate,score=score,reasons=reasons)
            current[key]={"ticks":proc["ticks"],"read":proc["read"],"write":proc["write"],
                          "rss":proc["rss"],"cpu_high":cpu_high,"growth_high":growth_high,"write_high":write_high}
        self.previous=current
        procs.sort(key=lambda p:(p["score"],p["cpu"],p["rss"]),reverse=True)
        self.processes=procs; self.process_rows={p["pid"]:p for p in procs}
        alerts=[p for p in procs if p["score"]>=25][:10]
        self.alert_table.setRowCount(len(alerts))
        for row,proc in enumerate(alerts):
            for col,value in enumerate([proc["name"],proc["pid"],"; ".join(proc["reasons"])]):
                self.alert_table.setItem(row,col,cell(value))
        self.count_label.setText(f"{count} processes observed · showing up to {MAX_ROWS}")
        self.populate_process_table()

    def populate_process_table(self):
        if not hasattr(self,"process_table"): return
        query=self.search.text().lower()
        rows=[p for p in self.processes if not query or query in " ".join(
            (p["name"],str(p["pid"]),p["owner"],p["exe"],p.get("cgroup", ""))).lower()]
        self.process_table.setSortingEnabled(False); self.process_table.setRowCount(min(MAX_ROWS,len(rows)))
        for row,proc in enumerate(rows[:MAX_ROWS]):
            values=[proc["name"],proc["pid"],f"{proc['cpu']:.1f}",fmt_bytes(proc["rss"]),
                    proc["owner"],fmt_bytes(proc["read_rate"])+"/s",fmt_bytes(proc["write_rate"])+"/s",
                    proc["state"],f"{proc['score']} · Review" if proc["score"] else "—"]
            for col,value in enumerate(values):
                obj=cell(value,Qt.AlignmentFlag.AlignRight|Qt.AlignmentFlag.AlignVCenter if col in (1,2,3,5,6,8) else None)
                obj.setData(Qt.ItemDataRole.UserRole,(proc["pid"],proc["start"]))
                self.process_table.setItem(row,col,obj)
        self.process_table.setSortingEnabled(True)
        self.populate_applications_table()

    @staticmethod
    def _resolve_app_icon(icon_name):
        if not icon_name:
            return QIcon()
        icon = QIcon.fromTheme(icon_name)
        if not icon.isNull():
            return icon
        candidates = []
        name = Path(icon_name)
        if name.is_absolute():
            candidates.append(name)
        else:
            for root in (Path("/usr/share/pixmaps"), Path.home() / ".local/share/pixmaps",
                         Path("/usr/share/icons/hicolor"), Path.home() / ".local/share/icons/hicolor",
                         Path("/usr/share/icons/breeze"), Path("/usr/share/icons/breeze-dark")):
                if root.exists():
                    candidates.extend(root.glob(f"**/apps/{icon_name}.*"))
                    candidates.extend(root.glob(f"**/{icon_name}.*"))
        for path in candidates:
            if path.is_file() and path.suffix.lower() in (".png", ".svg", ".xpm"):
                return QIcon(str(path))
        return QIcon.fromTheme("applications-internet") if icon_name == "chromium" else QIcon()

    @staticmethod
    def _desktop_app_index():
        index = {}
        roots = [Path("/usr/share/applications"), Path.home() / ".local/share/applications",
                 Path("/var/lib/flatpak/exports/share/applications"),
                 Path.home() / ".local/share/flatpak/exports/share/applications"]
        for root in roots:
            if not root.is_dir():
                continue
            for path in root.glob("*.desktop"):
                try:
                    parser = configparser.ConfigParser(interpolation=None, strict=False)
                    parser.read(path, encoding="utf-8")
                    section = parser["Desktop Entry"]
                    if section.get("NoDisplay", "false").lower() == "true":
                        continue
                    record = {"name": section.get("Name", path.stem),
                              "icon": NRGWindow._resolve_app_icon(section.get("Icon", ""))}
                    index[path.stem.casefold()] = record
                    index.setdefault(record["name"].casefold(), record)
                except (OSError, KeyError, configparser.Error):
                    continue
        return index

    @staticmethod
    def _application_label(cgroup, fallback):
        leaf = cgroup.rstrip("/").rsplit("/", 1)[-1] if cgroup else fallback
        leaf = re.sub(r"\\x([0-9a-fA-F]{2})", lambda match: chr(int(match.group(1), 16)), leaf)
        leaf = re.sub(r"^app-", "", leaf)
        leaf = re.sub(r"@[0-9a-f]{12,}(?=\.service$)", "", leaf, flags=re.I)
        leaf = re.sub(r"-[0-9]+(?=\.scope$)", "", leaf)
        leaf = re.sub(r"\.(scope|service)$", "", leaf)
        leaf = leaf.removeprefix("flatpak-")
        return leaf.replace("-", " ").strip() or fallback

    def populate_applications_table(self):
        if not hasattr(self, "applications_table"):
            return
        groups = {}
        for proc in self.processes:
            cgroup = proc.get("cgroup", "")
            leaf = cgroup.rstrip("/").rsplit("/", 1)[-1] if cgroup else ""
            if not leaf.startswith("app-"):
                continue
            if any(token in leaf.casefold() for token in ("autostart", "notifier")):
                continue
            app_id = re.sub(r"\\x([0-9a-fA-F]{2})", lambda match: chr(int(match.group(1), 16)), leaf)
            app_id = re.sub(r"^app-", "", app_id)
            app_id = re.sub(r"@[0-9a-f]{12,}(?=\.service$)", "", app_id, flags=re.I)
            app_id = re.sub(r"-[0-9]+(?=\.scope$)", "", app_id)
            app_id = re.sub(r"\.(scope|service)$", "", app_id)
            app_id = app_id.removeprefix("flatpak-")
            key = app_id.casefold()
            item = groups.setdefault(key, {"cgroup": cgroup, "cgroups": set(), "filter": app_id,
                "name": self._application_label(cgroup, proc["name"]), "pids": [],
                "cpu": 0.0, "rss": 0, "read": 0.0, "write": 0.0, "score": 0})
            item["cgroups"].add(cgroup)
            item["pids"].append(proc["pid"])
            item["cpu"] += proc["cpu"]
            item["rss"] += proc["rss"]
            item["read"] += proc["read_rate"]
            item["write"] += proc["write_rate"]
            item["score"] = max(item["score"], proc["score"])
        ordered = sorted(groups.values(), key=lambda item: (item["score"], item["rss"]), reverse=True)
        self.application_groups = {key: item for key, item in groups.items()}
        if not hasattr(self, "desktop_app_index"):
            self.desktop_app_index = self._desktop_app_index()
        self.applications_table.setSortingEnabled(False)
        self.applications_table.setRowCount(len(ordered))
        for row, item in enumerate(ordered):
            cgroup_values = []
            for workload_cgroup in item["cgroups"]:
                if ".." in Path(workload_cgroup).parts:
                    continue
                try:
                    cgroup_values.append(int((Path("/sys/fs/cgroup") / workload_cgroup.lstrip("/") / "memory.current").read_text()))
                except (OSError, ValueError):
                    continue
            cgroup_memory = sum(cgroup_values) if cgroup_values else None
            app_id = item["filter"]
            desktop_aliases = {"org.chromium.Chromium": "chromium"}
            original_app_id = app_id
            app_id = desktop_aliases.get(app_id, app_id)
            metadata = self.desktop_app_index.get((app_id + ".desktop").casefold())
            if metadata is None:
                metadata = self.desktop_app_index.get(item["name"].casefold())
            if original_app_id == "org.chromium.Chromium":
                metadata = {"name": "Chromium", "icon": self._resolve_app_icon("internet-web-browser")}
            if metadata is None and item["name"].casefold() == "remote desktop commander":
                metadata = {"name": "Remote Desktop Commander", "icon": self._resolve_app_icon("utilities-terminal")}
            if metadata is None and item["name"].casefold() == "alacritty":
                metadata = {"name": "Alacritty", "icon": self._resolve_app_icon("utilities-terminal")}
            display_name = metadata["name"] if metadata else item["name"]
            memory_value = fmt_bytes(cgroup_memory) if cgroup_memory is not None else fmt_bytes(item["rss"]) + " RSS"
            values = [display_name, len(item["pids"]), f"{item['cpu']:.1f}",
                memory_value, f"{fmt_bytes(item['read'])}/s · {fmt_bytes(item['write'])}/s",
                f"{item['score']} · Review" if item["score"] else "—"]
            for col, value in enumerate(values):
                obj = cell(value, Qt.AlignmentFlag.AlignRight|Qt.AlignmentFlag.AlignVCenter if col in (1,2,3,5) else None)
                obj.setData(Qt.ItemDataRole.UserRole, key)
                self.applications_table.setItem(row,col,obj)
            name_item = self.applications_table.item(row, 0)
            if name_item and metadata and not metadata["icon"].isNull():
                name_item.setIcon(metadata["icon"])
            elif name_item:
                name_item.setIcon(self._resolve_app_icon("application-x-executable"))
            if name_item:
                name_item.setToolTip(" · ".join(sorted(item["cgroups"])))
            memory_item = self.applications_table.item(row, 3)
            if memory_item and cgroup_memory is None:
                memory_item.setToolTip("RSS is an estimate and may count shared pages more than once.")
        self.applications_table.setSortingEnabled(True)

    def open_application_processes(self, row, col):
        item = self.applications_table.item(row, 0)
        app_key = item.data(Qt.ItemDataRole.UserRole) if item else ""
        if not app_key:
            return
        group = self.application_groups.get(app_key)
        self.search.setText(group["filter"] if group else app_key)
        self.tabs.setCurrentWidget(self.process_table.parentWidget())

    def refresh_history(self):
        samples = load_history_samples()
        if not samples:
            self.history_status.setText("No hay telemetría" if self.language == "es" else "No telemetry found")
            for chart in self.history_charts.values(): chart.set_data({}, [])
            return
        times = [time.strftime("%H:%M", time.localtime(item["timestamp_unix_ms"] / 1000)) for item in samples]
        memory = {
            "Available RAM": [item.get("memory_available_bytes", 0) / 1024**3 for item in samples],
            "Swap used": [item.get("swap_used_bytes", 0) / 1024**3 for item in samples],
        }
        pressure = {
            "Memory some": [item.get("memory_psi_some_avg10", 0) for item in samples],
            "Memory full": [item.get("memory_psi_full_avg10", 0) for item in samples],
            "CPU full": [item.get("cpu_psi_full_avg10", 0) for item in samples],
            "I/O full": [item.get("io_psi_full_avg10", 0) for item in samples],
        }
        latest = samples[-1].get("workloads", [])
        top_names = [w.get("name", "") for w in sorted(
            latest, key=lambda item: item.get("memory_current_bytes") or 0, reverse=True)[:4]]
        workloads = {}
        for name in top_names:
            workloads[self._application_label("/" + name, name)[:22]] = [
                next((w.get("memory_current_bytes", 0) / 1024**2 for w in item.get("workloads", []) if w.get("name") == name), 0)
                for item in samples
            ]
        session = self.hardware_history
        if session:
            session_times = [time.strftime("%H:%M:%S", time.localtime(x["time"])) for x in session]
            cpu_series = {}
            for core in sorted({name for sample in session for name in sample["cpu"]}, key=lambda n: int(n[3:])):
                cpu_series[core.upper()] = [sample["cpu"].get(core) or 0 for sample in session]
            self.history_charts["cpu"].set_data(cpu_series, session_times)
            gpu_points = [sample["gpu"] for sample in session]
            if any(value is not None for value in gpu_points):
                self.history_charts["gpu"].set_data({"GPU": [value or 0 for value in gpu_points]}, session_times)
            else:
                self.history_charts["gpu"].set_data({}, [])
        self.history_charts["memory"].set_data(memory, times)
        self.history_charts["pressure"].set_data(pressure, times)
        self.history_charts["workloads"].set_data(workloads, times)
        self.history_workload_table.setRowCount(len(top_names))
        for row, name in enumerate(top_names):
            latest_value = next((w.get("memory_current_bytes", 0) for w in latest if w.get("name") == name), 0)
            self.history_workload_table.setItem(row, 0, cell(name.split("@", 1)[0]))
            self.history_workload_table.setItem(row, 1, cell(fmt_bytes(latest_value)))
        first = time.strftime("%H:%M", time.localtime(samples[0]["timestamp_unix_ms"] / 1000))
        last = time.strftime("%H:%M", time.localtime(samples[-1]["timestamp_unix_ms"] / 1000))
        self.history_status.setText(
            f"{len(samples)} muestras · {first}–{last}" if self.language == "es"
            else f"{len(samples)} samples · {first}–{last}")

    def application_context_menu(self, position):
        index = self.applications_table.indexAt(position)
        if index.isValid():
            self.applications_table.selectRow(index.row())
        self.show_application_actions(self.applications_table.viewport().mapToGlobal(position))

    def show_application_actions(self, global_position=None):
        row = self.applications_table.currentRow()
        if row < 0:
            QMessageBox.information(self, "NRG", "Select an application workload first.")
            return
        item = self.applications_table.item(row, 0)
        cgroup = item.data(Qt.ItemDataRole.UserRole) if item else ""
        group = self.application_groups.get(cgroup)
        if not group:
            return
        menu = QMenu(self)
        actions = [
            ("Suspend workload (STOP)", signal.SIGSTOP),
            ("Continue workload (CONT)", signal.SIGCONT),
            ("Terminate workload (TERM)…", signal.SIGTERM),
            ("Force kill workload (KILL)…", signal.SIGKILL),
        ]
        for label, sig in actions:
            action = menu.addAction(label if self.language == "en" else
                label.replace("Suspend", "Suspender").replace("Continue", "Continuar")
                     .replace("Terminate", "Terminar").replace("Force kill", "Forzar cierre"))
            action.triggered.connect(lambda checked=False, cg=cgroup, sg=sig: self.send_application_signal(cg, sg))
        if global_position is None:
            global_position = self.mapToGlobal(self.rect().center())
        menu.exec(global_position)

    def send_application_signal(self, cgroup, sig):
        group = self.application_groups.get(cgroup)
        if not group:
            return
        destructive = sig in (signal.SIGTERM, signal.SIGKILL)
        if destructive:
            name = "SIGKILL" if sig == signal.SIGKILL else "SIGTERM"
            answer = QMessageBox.warning(
                self, f"Confirm {name}",
                f"Send {name} to {group['name']} ({len(group['pids'])} processes)? Unsaved work may be lost.",
                QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
                QMessageBox.StandardButton.Cancel,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        sent, skipped = 0, 0
        for pid in list(group["pids"]):
            proc = self.process_rows.get(pid)
            if not proc:
                skipped += 1
                continue
            pidfd = None
            try:
                expected_cgroup = proc.get("cgroup", "")
                self._validate_process_identity(proc, expected_cgroup=expected_cgroup)
                if hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"):
                    pidfd = os.pidfd_open(pid, 0)
                    self._validate_process_identity(proc, expected_cgroup=expected_cgroup)
                    signal.pidfd_send_signal(pidfd, sig)
                else:
                    self._validate_process_identity(proc, expected_cgroup=expected_cgroup)
                    os.kill(pid, sig)
                sent += 1
            except (OSError, ValueError, ProcessLookupError, PermissionError):
                skipped += 1
            finally:
                if pidfd is not None:
                    os.close(pidfd)
        self.live.setText(
            f"{signal.Signals(sig).name}: {sent} sent, {skipped} skipped · {group['name']}"
        )

    def process_context_menu(self, position):
        index = self.process_table.indexAt(position)
        if index.isValid():
            self.process_table.selectRow(index.row())
        self.show_process_actions(self.process_table.viewport().mapToGlobal(position))

    def show_process_actions(self, global_position=None):
        proc = self.selected_process(self.process_table)
        if not proc:
            QMessageBox.information(self, "NRG", "Select a process first.")
            return
        menu = QMenu(self)
        labels = [
            ("Suspend (STOP)" if self.language == "en" else "Suspender (STOP)", signal.SIGSTOP),
            ("Continue (CONT)" if self.language == "en" else "Continuar (CONT)", signal.SIGCONT),
            ("Hangup (HUP)" if self.language == "en" else "Colgar (HUP)", signal.SIGHUP),
            ("Interrupt (INT)" if self.language == "en" else "Interrumpir (INT)", signal.SIGINT),
            ("Terminate (TERM)…" if self.language == "en" else "Terminar (TERM)…", signal.SIGTERM),
            ("Kill (KILL)…" if self.language == "en" else "Matar (KILL)…", signal.SIGKILL),
        ]
        for label, sig in labels:
            action = menu.addAction(label)
            action.triggered.connect(lambda checked=False, p=proc, s=sig: self.send_process_signal(p, s))
        menu.addSeparator()
        priority = menu.addAction("Set priority / Ajustar prioridad…")
        priority.triggered.connect(lambda: self.change_process_priority(proc))
        affinity = menu.addAction("Set CPU affinity / Afinidad de CPU…")
        affinity.triggered.connect(lambda: self.change_process_affinity(proc))
        menu.addSeparator()
        details = menu.addAction("Process details / Detalles del proceso…")
        details.triggered.connect(lambda: ProcessDetails(proc, self, self.language).exec())
        if global_position is None:
            global_position = self.process_table.viewport().mapToGlobal(
                self.process_table.visualItemRect(self.process_table.currentItem()).center()
            ) if self.process_table.currentItem() else self.mapToGlobal(self.rect().center())
        menu.exec(global_position)

    def _protected_process(self, pid):
        protected = {1, os.getpid()}
        current = os.getpid()
        for _ in range(32):
            try:
                raw = Path(f"/proc/{current}/stat").read_text()
                close = raw.rfind(")")
                parent = int(raw[close + 2:].split()[1])
            except (OSError, ValueError, IndexError):
                break
            if parent <= 1 or parent in protected:
                break
            protected.add(parent); current = parent
        return pid in protected

    def _validate_process_identity(self, proc, expected_cgroup=None):
        pid = int(proc["pid"])
        if self._protected_process(pid):
            raise PermissionError("NRG refuses to control PID 1 or one of its own ancestor processes.")
        try:
            raw = Path(f"/proc/{pid}/stat").read_text()
            close = raw.rfind(")")
            current_start = int(raw[close + 2:].split()[19])
        except (OSError, ValueError, IndexError) as exc:
            raise ProcessLookupError(f"Process {pid} no longer exists or cannot be inspected.") from exc
        if current_start != int(proc["start"]):
            raise ProcessLookupError("The PID was reused; the selected process identity changed. Refresh and select it again.")
        if expected_cgroup is not None:
            try:
                current_cgroup = next((line.split("::", 1)[1] for line in Path(f"/proc/{pid}/cgroup").read_text().splitlines()
                                       if line.startswith("0::")), "")
            except OSError as exc:
                raise ProcessLookupError("The process cgroup could not be revalidated.") from exc
            if current_cgroup != expected_cgroup:
                raise ProcessLookupError("The process moved to another workload; refresh the application list.")
        return pid

    def send_process_signal(self, proc, sig):
        destructive = sig in (signal.SIGTERM, signal.SIGKILL)
        if destructive:
            name = "SIGKILL" if sig == signal.SIGKILL else "SIGTERM"
            answer = QMessageBox.warning(
                self, f"Confirm {name}",
                f"Send {name} to {proc['name']} (PID {proc['pid']})? Unsaved work may be lost.",
                QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
                QMessageBox.StandardButton.Cancel,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        try:
            pid = self._validate_process_identity(proc)
            if hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"):
                pidfd = os.pidfd_open(pid, 0)
                try:
                    self._validate_process_identity(proc)
                    signal.pidfd_send_signal(pidfd, sig)
                finally:
                    os.close(pidfd)
            else:
                self._validate_process_identity(proc)
                os.kill(pid, sig)
            self.live.setText(f"Sent {signal.Signals(sig).name} to {proc['name']} ({pid})")
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "Process action failed", str(exc))

    def change_process_priority(self, proc):
        try:
            pid = self._validate_process_identity(proc)
            current = os.getpriority(os.PRIO_PROCESS, pid)
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "Priority unavailable", str(exc)); return
        value, accepted = QInputDialog.getInt(
            self, "Process priority / Prioridad del proceso",
            "Nice value (-20 = highest, 19 = lowest):", current, -20, 19, 1,
        )
        if not accepted: return
        try:
            self._validate_process_identity(proc)
            os.setpriority(os.PRIO_PROCESS, pid, value)
            self.live.setText(f"Nice value for PID {pid}: {value}")
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "Priority change failed", f"{exc}\nNon-root users generally cannot increase scheduling priority (lower nice value).")

    def change_process_affinity(self, proc):
        try:
            pid = self._validate_process_identity(proc)
            current = set(os.sched_getaffinity(pid))
            allowed = sorted(os.sched_getaffinity(0))
            if not current.issubset(set(allowed)):
                allowed = sorted(current | set(allowed))
        except (AttributeError, OSError, ValueError) as exc:
            QMessageBox.warning(self, "CPU affinity unavailable", str(exc)); return
        dialog = QDialog(self); dialog.setWindowTitle(f"CPU affinity · PID {pid}")
        dialog_layout = QVBoxLayout(dialog)
        dialog_layout.addWidget(QLabel("Select the logical CPUs this process may run on:"))
        checks = []
        grid = QGridLayout()
        for index, cpu in enumerate(allowed):
            check = QCheckBox(f"CPU {cpu}"); check.setChecked(cpu in current)
            checks.append((cpu, check)); grid.addWidget(check, index // 6, index % 6)
        dialog_layout.addLayout(grid)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Apply | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept); buttons.rejected.connect(dialog.reject)
        dialog_layout.addWidget(buttons)
        if dialog.exec() != QDialog.DialogCode.Accepted: return
        selected = {cpu for cpu, check in checks if check.isChecked()}
        if not selected:
            QMessageBox.warning(self, "Invalid affinity", "At least one CPU must remain enabled."); return
        try:
            self._validate_process_identity(proc)
            os.sched_setaffinity(pid, selected)
            self.live.setText(f"CPU affinity for PID {pid}: {', '.join(map(str, sorted(selected)))}")
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "Affinity change failed", str(exc))

    def update_health(self,avail,total,cpu,mem,cpu_psi,io_psi,disk_free,disk_total):
        ratio=avail/total if total else 1
        disk_ratio=disk_free/disk_total if disk_total else 1
        mf,ms,cf,iof=mem.get("full",0),mem.get("some",0),cpu_psi.get("full",0),io_psi.get("full",0)
        level="NORMAL"
        if ratio<.06 or mf>=5 or disk_ratio<.02: level="CRITICAL"
        elif ratio<.12 or mf>=2 or iof>=15 or cf>=20 or disk_ratio<.05: level="WARNING"
        signals=[]
        if ratio<.12: signals.append(f"RAM available {ratio*100:.1f}%")
        if disk_ratio<.05: signals.append(f"home volume has only {disk_ratio*100:.1f}% free")
        if ms>=5 or mf>=1: signals.append(f"memory PSI some/full {ms:.2f}% / {mf:.2f}%")
        if cpu is not None and cpu>=95: signals.append(f"CPU utilization {cpu:.0f}%")
        if cf>=10: signals.append(f"CPU full PSI {cf:.2f}%")
        if iof>=10: signals.append(f"I/O full PSI {iof:.2f}%")
        if self.process_spawn_warning:
            signals.append(f"rapid process creation: {self.new_processes_last} new processes in the last sample; inspect process ancestry")
            if level == "NORMAL": level = "WARNING"
        colors={"NORMAL":"#72c89b","WARNING":"#e0b35a","CRITICAL":"#ef6961"}
        if self.language == "es":
            level_label = {"NORMAL":"NORMAL", "WARNING":"ADVERTENCIA", "CRITICAL":"CRÍTICO"}[level]
            translated = []
            for signal in signals:
                signal = (signal.replace("RAM available", "RAM disponible")
                    .replace("home volume has only", "el volumen home solo tiene")
                    .replace("memory PSI some/full", "PSI de memoria some/full")
                    .replace("CPU utilization", "uso de CPU")
                    .replace("CPU full PSI", "PSI full de CPU")
                    .replace("I/O full PSI", "PSI full de E/S")
                    .replace("rapid process creation", "creación acelerada de procesos")
                    .replace("new processes in the last sample; inspect process ancestry", "procesos nuevos en la última muestra; revisar el árbol de procesos"))
                translated.append(signal)
            empty = "No se superaron umbrales globales de presión."
            self.health.setText(f"ESTADO DEL SISTEMA: {level_label}   ·   "+"; ".join(translated or [empty]))
        else:
            self.health.setText(f"RESOURCE STATE: {level}   ·   "+"; ".join(signals or ["No system-wide pressure threshold crossed."]))
        self.health.setStyleSheet(f"color:{colors[level]};padding:12px;background:#1a1c21;border-radius:7px")

    def selected_process(self,table):
        row=table.currentRow()
        if row<0:return None
        first=table.item(row,0)
        key=first.data(Qt.ItemDataRole.UserRole) if first else None
        if key:return next((p for p in self.processes if (p["pid"],p["start"])==tuple(key)),None)
        pid=table.item(row,1)
        return self.process_rows.get(int(pid.text())) if pid else None

    def open_process_details(self,row,col):
        proc=self.selected_process(self.process_table)
        if proc: ProcessDetails(proc,self,self.language).exec()

    def open_alert_details(self,row,col):
        pid=self.alert_table.item(row,1)
        proc=self.process_rows.get(int(pid.text())) if pid else None
        if proc: ProcessDetails(proc,self,self.language).exec()

    def config_dir(self):
        return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "nrg"

    def profile_config_path(self):
        return self.config_dir() / "desktop.json"

    def profiles_path(self):
        return self.config_dir() / "profiles.json"

    def reload_profiles(self):
        names = ["balanced", "gaming", "work", "study", "development"]
        try:
            data = json.loads(self.profiles_path().read_text())
            profiles = data.get("profiles", {})
            if isinstance(profiles, dict):
                for name, value in profiles.items():
                    if (isinstance(name, str) and re.fullmatch(r"[a-zA-Z0-9_-]{1,32}", name)
                            and isinstance(value, dict) and isinstance(value.get("priorities"), list)
                            and name.lower() not in [x.lower() for x in names]):
                        names.append(name.lower())
        except (OSError, ValueError, TypeError, AttributeError):
            pass
        current = self.profile.currentText() if hasattr(self, "profile") else "balanced"
        self.profile.blockSignals(True)
        self.profile.clear(); self.profile.addItems(names)
        self.profile.setCurrentText(current if current in names else "balanced")
        self.profile.blockSignals(False)

    def load_profile(self):
        try:
            data = json.loads(self.profile_config_path().read_text())
            profile = data.get("active_profile")
            if isinstance(profile, str) and profile in [self.profile.itemText(i) for i in range(self.profile.count())]:
                self.profile.setCurrentText(profile)
            language = data.get("language", "en")
            self.language_box.setCurrentIndex(1 if language == "es" else 0)
            self.download_plan.setText(str(data.get("download_plan_mbps", "")))
            self.upload_plan.setText(str(data.get("upload_plan_mbps", "")))
            self.primary_share.setText(str(data.get("network_primary_share", 70)))
            self.security_enabled = bool(data.get("security_enabled", True))
            self.security_toggle.setChecked(self.security_enabled)
            self.measured_down_mbps = data.get("measured_down_mbps")
            self.measured_up_mbps = data.get("measured_up_mbps")
            if self.measured_down_mbps and self.measured_up_mbps:
                self.network_test_result.setText(
                    f"Last measured: {float(self.measured_down_mbps):.1f} Mbps down / {float(self.measured_up_mbps):.1f} Mbps up")
        except (OSError, ValueError, TypeError, AttributeError):
            pass

    def save_desktop_config(self, **updates):
        path = self.profile_config_path()
        try:
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            try:
                data = json.loads(path.read_text())
                if not isinstance(data, dict): data = {}
            except (OSError, ValueError, TypeError):
                data = {}
            data.update(updates)
            path.write_text(json.dumps(data, indent=2) + "\n")
            path.chmod(0o600)
        except OSError as exc:
            self.diag_output.setPlainText(f"Could not save NRG preferences: {exc}")

    def save_profile(self, profile):
        if re.fullmatch(r"[a-z0-9_-]{1,32}", profile):
            self.save_desktop_config(active_profile=profile)

    def set_security_enabled(self, enabled):
        self.security_enabled = bool(enabled)
        self.save_desktop_config(security_enabled=self.security_enabled)
        self.process_spawn_high = 0
        self.process_spawn_warning = False
        self.parent_spawn_high.clear()
        self.process_baseline_ready = False
        if not self.security_enabled:
            self.new_processes_last = 0
        self.live.setText("Anomaly monitoring enabled" if enabled else "Anomaly monitoring disabled")

    def change_language(self, index):
        self.language = self.language_box.currentData() or "en"
        self.apply_language()
        self.save_desktop_config(language=self.language)

    def apply_language(self):
        es = self.language == "es"
        tr = lambda en, es_text: es_text if es else en
        if not hasattr(self, "tabs"): return
        self.subtitle.setText(tr("Nexus Resource Governor  /  local diagnostics", "Nexus Resource Governor  /  diagnóstico local"))
        self.tabs.setTabText(0, tr("Overview", "Resumen"))
        self.tabs.setTabText(1, tr("Hardware", "Hardware"))
        self.tabs.setTabText(2, tr("Processes", "Procesos"))
        self.tabs.setTabText(3, tr("Applications", "Aplicaciones"))
        self.tabs.setTabText(4, tr("History", "Historial"))
        self.tabs.setTabText(5, tr("Diagnosis & Profiles", "Diagnóstico y perfiles"))
        titles = {
            "available": ("RAM AVAILABLE", "RAM DISPONIBLE"),
            "used": ("RAM IN USE", "RAM EN USO"),
            "swap": ("SWAP IN USE", "SWAP EN USO"),
            "cpu": ("CPU UTILIZATION", "USO DE CPU"),
            "processes": ("PROCESSES", "PROCESOS"),
            "pressure": ("MEMORY PSI FULL", "PRESIÓN DE MEMORIA PSI FULL"),
            "disk": ("HOME VOLUME FREE", "ESPACIO LIBRE EN HOME"),
            "gpu": ("GPU MEMORY", "MEMORIA DE GPU"),
            "network": ("NETWORK RX / TX", "RED RX / TX"),
            "cpu_temp": ("CPU TEMPERATURE", "TEMPERATURA CPU"),
            "gpu_usage": ("GPU UTILIZATION", "USO DE GPU"),
            "gpu_temp": ("GPU TEMPERATURE", "TEMPERATURA GPU"),
            "battery": ("BATTERY", "BATERÍA"),
            "wifi": ("WI-FI SIGNAL", "SEÑAL WI-FI"),
            "disk_io": ("DISK READ / WRITE", "LECTURA / ESCRITURA DISCO"),
            "fan": ("FAN SPEED", "VELOCIDAD DEL VENTILADOR"),
        }
        for key, label in self.metric_title_labels.items(): label.setText(tr(*titles[key]))
        self.metric_gauges["available"].title = tr("RAM AVAILABLE", "RAM DISPONIBLE")
        self.metric_gauges["cpu"].title = tr("CPU UTILIZATION", "USO DE CPU")
        self.metric_gauges["gpu_usage"].title = tr("GPU UTILIZATION", "USO DE GPU")
        self.metric_gauges["swap"].title = tr("SWAP IN USE", "SWAP EN USO")
        for gauge in self.metric_gauges.values(): gauge.update()
        self.alert_heading.setText(tr("Processes that deserve a closer look", "Procesos que requieren revisión"))
        self.dashboard_note.setText(tr(
            "System telemetry is read-only by default. Process controls require an explicit selection; no kernel or cgroup limits are changed.",
            "La telemetría es de solo lectura por defecto. El control de procesos requiere selección explícita; no se modifican kernel ni límites cgroup."))
        self.alert_table.setHorizontalHeaderLabels([tr("Process", "Proceso"), "PID", tr("Signal", "Señal")])
        self.search.setPlaceholderText(tr("Filter by process, PID, owner or executable…", "Filtrar por proceso, PID, propietario o ejecutable…"))
        self.profile_label.setText(tr("Profile", "Perfil"))
        self.plan_button.setText(tr("Calculate memory plan", "Calcular plan de memoria"))
        self.diag_button.setText(tr("Run system diagnosis", "Ejecutar diagnóstico del sistema"))
        self.edit_profiles_button.setText(tr("Edit coasters", "Editar coasters"))
        self.plan_note.setText(tr("Adaptive memory plan · simulation only", "Plan adaptativo de memoria · solo simulación"))
        self.plan_table.setHorizontalHeaderLabels([tr("Application", "Aplicación"), tr("Priority", "Prioridad"), tr("Current", "Actual"), tr("Proposed soft ceiling", "Techo flexible propuesto"), tr("Samples", "Muestras")])
        self.diag_output.setPlaceholderText(tr("System diagnosis output appears here.", "El diagnóstico del sistema aparecerá aquí."))
        self.process_actions_button.setText(tr("Manage selected process…", "Administrar proceso seleccionado…"))
        self.tabs.setTabText(1, tr("Hardware", "Hardware"))
        self.tabs.setTabText(2, tr("Processes", "Procesos"))
        self.tabs.setTabText(3, tr("Applications", "Aplicaciones"))
        self.tabs.setTabText(4, tr("History", "Historial"))
        self.tabs.setTabText(5, tr("Diagnosis & Profiles", "Diagnóstico y perfiles"))
        self.hardware_summary.setText(tr("Live hardware inventory · kernel interfaces", "Inventario de hardware en vivo · interfaces del kernel"))
        self.hardware_note.setText(tr(
            "Metrics are read directly from Linux /proc, /sys, hwmon and network interfaces. Intel i915 GPU activity is estimated from RC6 idle residency, not measured engine busy; integrated graphics share system RAM rather than dedicated VRAM. Unsupported values are shown as unavailable.",
            "Las métricas se leen directamente de /proc, /sys, hwmon e interfaces de red. La actividad de Intel i915 se estima mediante la residencia inactiva RC6, no mide directamente la actividad de motores; los gráficos integrados comparten RAM del sistema en vez de tener VRAM dedicada. Los datos no expuestos se indican como no disponibles."))
        for key, labels in {
            "cpu": ("CPU · per logical core", "CPU · por núcleo lógico"),
            "gpu": ("Graphics processors", "Procesadores gráficos"),
            "network": ("Network interfaces", "Interfaces de red"),
            "disk": ("Storage devices", "Unidades de almacenamiento"),
            "sensors": ("Thermal / hardware sensors", "Sensores térmicos / hardware"),
        }.items():
            self.hardware_section_labels[key].setText(tr(*labels))
        self.hardware_system.setHorizontalHeaderLabels([tr("System property", "Propiedad del sistema"), tr("Value", "Valor")])
        self.hardware_cpu.setHorizontalHeaderLabels([tr("Logical CPU", "CPU lógico"), tr("Physical core", "Núcleo físico"), tr("Usage", "Uso"), tr("Temperature", "Temperatura")])
        self.hardware_gpu.setHorizontalHeaderLabels([tr("GPU", "GPU"), tr("Driver", "Controlador"), tr("Utilization", "Uso"), tr("Memory", "Memoria"), tr("Frequency", "Frecuencia"), tr("Temperature", "Temperatura")])
        self.hardware_network.setHorizontalHeaderLabels([tr("Interface", "Interfaz"), tr("Type / state", "Tipo / estado"), tr("Link / signal", "Enlace / señal"), tr("Download", "Descarga"), tr("Upload", "Subida"), "IPv4", "IPv6", tr("Errors", "Errores")])
        self.hardware_disks.setHorizontalHeaderLabels([tr("Device", "Dispositivo"), tr("Model", "Modelo"), tr("Capacity", "Capacidad"), tr("Read", "Lectura"), tr("Write", "Escritura"), tr("Busy", "Actividad")])
        self.hardware_thermals.setHorizontalHeaderLabels([tr("Sensor", "Sensor"), tr("Component", "Componente"), tr("Temperature / value", "Temperatura / valor")])
        self.history_heading.setText(tr("Resource history · last 60 minutes", "Historial de recursos · últimos 60 minutos"))
        self.history_refresh_button.setText(tr("Refresh history", "Actualizar historial"))
        self.history_workload_table.setHorizontalHeaderLabels([tr("Application", "Aplicación"), tr("Memory", "Memoria")])
        self.history_note.setText(tr(
            "RAM / PSI / workload history is stored by the NRG service. CPU per-core and GPU history is session-only while this window is open.",
            "El servicio NRG guarda RAM / PSI / aplicaciones. El historial por núcleo de CPU y GPU solo se recopila mientras esta ventana está abierta."))
        self.history_charts["cpu"].title = tr("CPU utilization by logical core (%)", "Uso de CPU por núcleo lógico (%)")
        self.history_charts["gpu"].title = tr("GPU activity estimate (%) · driver-supported metrics only", "Estimación de actividad GPU (%) · solo métricas compatibles con el controlador")
        self.history_charts["memory"].title = tr("Memory available and swap (GiB)", "RAM disponible e intercambio (GiB)")
        self.history_charts["pressure"].title = tr("Pressure Stall Information (PSI %)", "Presión del sistema (PSI %)")
        self.history_charts["workloads"].title = tr("Largest application workloads (MiB)", "Aplicaciones con mayor consumo (MiB)")
        for chart in self.history_charts.values(): chart.update()
        self.applications_heading.setText(tr("Application workloads · grouped by cgroup v2", "Aplicaciones · agrupadas por cgroup v2"))
        self.applications_table.setHorizontalHeaderLabels([
            tr("Application", "Aplicación"), tr("Processes", "Procesos"), "CPU %",
            tr("Memory", "Memoria"), tr("Disk read / write", "Lectura / escritura"),
            tr("Review", "Revisar")])
        self.application_actions_button.setText(tr("Manage selected workload…", "Administrar carga seleccionada…"))
        self.applications_note.setText(tr(
            "Memory uses cgroup totals when available; RSS is shown as an estimate otherwise. Double-click a workload to inspect its processes. Group controls affect only the listed application processes.",
            "La memoria usa el total cgroup cuando está disponible; de lo contrario muestra RSS estimada. Doble clic para inspeccionar procesos. Los controles afectan solo a los procesos de la aplicación listada."))
        self.security_toggle.setText(tr("Enable anomaly / security monitoring", "Activar monitoreo de anomalías / seguridad"))
        self.security_toggle.setChecked(self.security_enabled)
        self.process_table.setHorizontalHeaderLabels(
            ["Process" if not es else "Proceso", "PID", "CPU %", "RAM", "Owner" if not es else "Usuario",
             "I/O read" if not es else "Lectura E/S", "I/O write" if not es else "Escritura E/S",
             "State" if not es else "Estado", "Review" if not es else "Revisar"])
        self.process_note.setText(tr(
            "CPU is normalized to one logical core. RSS may double-count shared pages. Network traffic is system-wide; per-process network accounting is not available in this collector yet.",
            "CPU se normaliza por núcleo lógico. RSS puede contar páginas compartidas más de una vez. El tráfico de red es global; aún no se atribuye a cada proceso."))
        self.download_plan.setPlaceholderText(tr("Download Mbps", "Descarga Mbps"))
        self.upload_plan.setPlaceholderText(tr("Upload Mbps", "Subida Mbps"))
        self.network_preview_button.setText(tr("Preview network budget", "Simular presupuesto de red"))
        self.network_test_button.setText(tr("Run network speed test", "Probar velocidad de red"))
        if self.measured_down_mbps and self.measured_up_mbps:
            self.network_test_result.setText(
                f"Última prueba: {self.measured_down_mbps:.1f} Mbps descarga / {self.measured_up_mbps:.1f} Mbps subida"
                if es else f"Last test: {self.measured_down_mbps:.1f} Mbps download / {self.measured_up_mbps:.1f} Mbps upload")
        else:
            self.network_test_result.setText(tr(
                "No speed test yet. Click to run; fallback download uses up to 25 MB.",
                "Sin prueba todavía. Pulsa para iniciar; la prueba alternativa usa hasta 25 MB de descarga."))
        self.network_preview.setText(tr("Network budget preview is advisory; no traffic shaping is applied.",
            "La simulación de red es orientativa; no aplica control de tráfico."))
        self.network_plan_label.setText(tr("Internet plan ↓ / ↑ Mbps", "Plan de Internet ↓ / ↑ Mbps"))
        self.network_share_label.setText(tr("Top app %", "% app prioritaria"))

    def preview_network_budget(self):
        try:
            down = float(self.download_plan.text().strip())
            up = float(self.upload_plan.text().strip())
            share = float(self.primary_share.text().strip())
            if not (0 < down <= 100000 and 0 < up <= 100000 and 1 <= share <= 100):
                raise ValueError("Values out of range")
        except ValueError:
            QMessageBox.warning(self, "Invalid network plan", "Enter valid download/upload Mbps (1–100000) and a top-app share (1–100%).")
            return
        # Reserve 10% for protocol overhead and measurement variance.
        effective_down = min(down, float(self.measured_down_mbps)) if self.measured_down_mbps else down
        effective_up = min(up, float(self.measured_up_mbps)) if self.measured_up_mbps else up
        down_source = "measured" if self.measured_down_mbps else "contracted plan"
        up_source = "measured" if self.measured_up_mbps else "contracted plan"
        usable_down, usable_up = effective_down * 0.90, effective_up * 0.90
        priority_down, priority_up = usable_down * share / 100, usable_up * share / 100
        rest_down, rest_up = usable_down - priority_down, usable_up - priority_up
        self.save_desktop_config(download_plan_mbps=down, upload_plan_mbps=up, network_primary_share=share)
        profile = self.profile.currentText()
        top_app = {
            "gaming": "GeForce NOW / game workload",
            "study": "Top study/work application",
            "development": "Top development workload",
        }.get(profile, "Top-priority workload")
        es = self.language == "es"
        if es:
            self.network_preview.setText(
                f"Perfil {profile}: {top_app} recibiría como objetivo simulado {priority_down:.1f} Mbps ↓ / {priority_up:.1f} Mbps ↑. "
                f"Resto de apps: {rest_down:.1f} Mbps ↓ / {rest_up:.1f} Mbps ↑. "
                f"Capacidad efectiva: {effective_down:.1f} Mbps descarga ({down_source}) / {effective_up:.1f} Mbps subida ({up_source}). "
                f"Tras reservar 10%: {usable_down:.1f} / {usable_up:.1f} Mbps. SIMULACIÓN; no se aplican límites.")
        else:
            self.network_preview.setText(
                f"Profile {profile}: {top_app} would receive a simulated target of {priority_down:.1f} Mbps down / {priority_up:.1f} Mbps up. "
                f"Other apps: {rest_down:.1f} / {rest_up:.1f} Mbps. "
                f"Effective capacity: {effective_down:.1f} Mbps down ({down_source}) / {effective_up:.1f} Mbps up ({up_source}). "
                f"Usable after 10% safety margin: {usable_down:.1f} / {usable_up:.1f} Mbps. SIMULATION; no limits applied.")

    def run_network_test(self):
        if self.network_worker and self.network_worker.isRunning():
            return
        self.network_test_button.setEnabled(False)
        self.network_test_result.setText(
            "Probando descarga y subida; puede consumir hasta 33 MB…" if self.language == "es"
            else "Testing download and upload; may use up to 33 MB…")
        self.network_worker = NetworkTestWorker(self)
        self.network_worker.completed.connect(self.network_test_finished)
        self.network_worker.start()

    def network_test_finished(self, result):
        self.network_test_button.setEnabled(True)
        if not result.get("ok"):
            self.network_test_result.setText(
                ("Falló la prueba: " if self.language == "es" else "Speed test failed: ") + result.get("error", "unknown error"))
            return
        self.measured_down_mbps = round(float(result["download_mbps"]), 2)
        updates = {"measured_down_mbps": self.measured_down_mbps}
        if result.get("upload_mbps") is not None:
            self.measured_up_mbps = round(float(result["upload_mbps"]), 2)
            updates["measured_up_mbps"] = self.measured_up_mbps
        self.save_desktop_config(**updates)
        if result.get("needs_upload_cli"):
            self.network_test_result.setText(
                (f"Descarga medida: {self.measured_down_mbps:.1f} Mbps. Para medir subida y latencia instala el paquete Arch speedtest-cli."
                 if self.language == "es" else
                 f"Measured download: {self.measured_down_mbps:.1f} Mbps. Install Arch's speedtest-cli package to measure upload and latency."))
        else:
            self.network_test_result.setText(
                f"Última prueba: {self.measured_down_mbps:.1f} Mbps descarga / {self.measured_up_mbps:.1f} Mbps subida · {result.get('ping_ms', 0):.1f} ms ping · {result.get('server', '')}"
                if self.language == "es" else
                f"Last test: {self.measured_down_mbps:.1f} Mbps download / {self.measured_up_mbps:.1f} Mbps upload · {result.get('ping_ms', 0):.1f} ms ping · {result.get('server', '')}")
        if self.download_plan.text().strip() and self.upload_plan.text().strip():
            self.preview_network_budget()

    def edit_profiles(self):
        defaults = {
            "profiles": {
                "gaming": {"priorities": ["geforcenow", "geometry", "steam", "gamescope"]},
                "work": {"priorities": ["chatgpt", "wordcraft", "libreoffice", "onlyoffice", "firefox", "chromium", "spotify"]},
                "study": {"priorities": ["wordcraft", "libreoffice", "onlyoffice", "chatgpt", "firefox", "chromium"]},
                "development": {"priorities": ["codium", "code", "jetbrains", "terminal", "codex", "agy"]},
                "balanced": {"priorities": ["chatgpt", "wordcraft", "geforcenow", "geometry", "firefox", "chromium"]}
            }
        }
        try:
            content = self.profiles_path().read_text()
        except OSError:
            content = json.dumps(defaults, indent=2)
        dialog = QDialog(self); dialog.setWindowTitle("Editar coasters / Edit coasters"); dialog.resize(680, 520)
        layout = QVBoxLayout(dialog)
        hint = QLabel("Ordena prioridades de mayor a menor. Usa fragmentos de nombre de app (sin comandos ni rutas).\nHigher priority first. Use app-name fragments only; no commands or paths.")
        hint.setWordWrap(True); layout.addWidget(hint)
        editor = QTextEdit(); editor.setPlainText(content); layout.addWidget(editor, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept); buttons.rejected.connect(dialog.reject); layout.addWidget(buttons)
        if dialog.exec() != QDialog.DialogCode.Accepted: return
        try:
            data = json.loads(editor.toPlainText())
            profiles = data.get("profiles")
            if not isinstance(profiles, dict) or not profiles or len(profiles) > 24:
                raise ValueError("profiles must be an object with 1–24 profiles")
            clean = {}
            for name, spec in profiles.items():
                if not isinstance(name, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,32}", name):
                    raise ValueError(f"Invalid profile name: {name!r}")
                priorities = spec.get("priorities") if isinstance(spec, dict) else None
                if not isinstance(priorities, list) or len(priorities) > 64:
                    raise ValueError(f"{name}: priorities must be a list of at most 64 app fragments")
                values = []
                for item in priorities:
                    if not isinstance(item, str) or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,80}", item.strip()):
                        raise ValueError(f"{name}: invalid app fragment {item!r}")
                    values.append(item.strip().lower())
                clean[name.lower()] = {"priorities": values}
            path = self.profiles_path(); path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_text(json.dumps({"profiles": clean}, indent=2) + "\n"); path.chmod(0o600)
            selected = self.profile.currentText()
            self.reload_profiles()
            if selected in [self.profile.itemText(i) for i in range(self.profile.count())]:
                self.profile.setCurrentText(selected)
            QMessageBox.information(self, "NRG", "Coasters saved. The Rust planner will use these priorities on the next calculation.")
        except (ValueError, TypeError, OSError, AttributeError) as exc:
            QMessageBox.warning(self, "Invalid profile configuration", str(exc))

    def run_plan(self):
        if not AGENT:
            QMessageBox.warning(self,"NRG agent missing","Build the release binary first: cargo build --release"); return
        self.plan_button.setEnabled(False); self.diag_output.setPlainText(
            "Calculando plan de memoria de solo lectura…" if self.language == "es" else "Calculating read-only memory plan…")
        self.plan_process=QProcess(self); self.plan_process.finished.connect(self.plan_finished)
        self.plan_process.start(str(AGENT),["--budget-plan",self.profile.currentText()])

    def plan_finished(self,code,status):
        self.plan_button.setEnabled(True)
        raw=bytes(self.plan_process.readAllStandardOutput()).decode(errors="replace")
        err=bytes(self.plan_process.readAllStandardError()).decode(errors="replace")
        try:
            plan=json.loads(raw); rows=plan.get("workloads",[])
            self.plan_table.setRowCount(len(rows))
            for row,w in enumerate(rows):
                vals=[w.get("application_key",w.get("workload","?")),
                      f"{w.get('priority','?')} · #{w.get('priority_rank','?')}",
                      fmt_bytes(w.get("current_bytes",0)),fmt_bytes(w.get("proposed_memory_high_bytes",0)),
                      str(w.get("historical_samples",0))]
                for col,val in enumerate(vals): self.plan_table.setItem(row,col,cell(val))
            if self.language == "es":
                self.diag_output.setPlainText(
                    f"Perfil: {plan.get('profile')}\nEstado: {plan.get('status')}\n"
                    f"Muestras históricas: {plan.get('history_samples_loaded')}\n"
                    f"Aplicación de límites activa: {plan.get('enforcement_enabled')}\n\n"
                    "Las propuestas memory.high son solo simulaciones de límites flexibles. memory.max nunca se modifica. "
                    "Se protege el uso actual más un margen; si no cabe dentro de la reserva del sistema, NRG no propone límites.\n\n"+err)
            else:
                self.diag_output.setPlainText(
                    f"Profile: {plan.get('profile')}\nStatus: {plan.get('status')}\n"
                    f"History samples: {plan.get('history_samples_loaded')}\n"
                    f"Enforcement enabled: {plan.get('enforcement_enabled')}\n\n{plan.get('explanation','')}\n\n{err}")
        except (ValueError,TypeError):
            self.diag_output.setPlainText(raw+"\n"+err)

    def run_diagnosis(self):
        if not AGENT:
            QMessageBox.warning(self,"NRG agent missing","Build the release binary first: cargo build --release"); return
        self.diag_button.setEnabled(False); self.diag_output.setPlainText(
            "Recopilando diagnóstico de kernel, gráficos, memoria, IRQ y temperatura…" if self.language == "es"
            else "Collecting kernel, graphics, memory, IRQ and thermal diagnostics…")
        self.diag_process=QProcess(self); self.diag_process.finished.connect(self.diagnosis_finished)
        self.diag_process.start(str(AGENT),["--diagnose"])

    def diagnosis_finished(self,code,status):
        self.diag_button.setEnabled(True)
        raw=bytes(self.diag_process.readAllStandardOutput()).decode(errors="replace")
        err=bytes(self.diag_process.readAllStandardError()).decode(errors="replace")
        self.diag_output.setPlainText(raw+("\n\nERRORS:\n"+err if err else ""))


def main():
    if "--self-test" in sys.argv:
        procs,count,cpu,now=scan_processes(); mem=read_meminfo()
        print(json.dumps({"process_count":count,"sampled_processes":len(procs),
            "ram_total_bytes":mem.get("MemTotal"),"ram_available_bytes":mem.get("MemAvailable"),
            "cpu_counters_available":cpu is not None,
            "sample_process":{k:procs[0].get(k) for k in ("pid","name","rss","exe")} if procs else None},indent=2))
        return 0
    if not AGENT:
        print("NRG release binary not found. Run cargo build --release.",file=sys.stderr); return 2
    app=QApplication(sys.argv); app.setApplicationName("NRG Desktop"); app.setFont(QFont("Noto Sans",10))
    window=NRGWindow(); window.show()
    return app.exec()


if __name__=="__main__":
    raise SystemExit(main())
