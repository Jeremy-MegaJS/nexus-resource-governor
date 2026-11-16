#!/usr/bin/env python3
"""NRG Desktop: resource monitoring, guarded process management, and diagnostics."""
from __future__ import annotations
import json, os, pwd, re, signal, shlex, shutil, subprocess, sys, time, urllib.request
from pathlib import Path
from PySide6.QtCore import Qt, QProcess, QTimer, QThread, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QGridLayout,
    QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMenu, QMessageBox, QPushButton,
    QInputDialog, QTabWidget, QTableWidget, QTableWidgetItem, QTextEdit, QVBoxLayout,
    QWidget, QHeaderView,
)

ROOT = Path(__file__).resolve().parents[1]
CANDIDATES = [ROOT / "target/release/nrg-agent", ROOT / "target/debug/nrg-agent"]
AGENT = next((p for p in CANDIDATES if p.is_file()), None)
REFRESH_MS, MAX_ROWS = 5000, 120
PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
CLK_TCK = os.sysconf("SC_CLK_TCK")
CPU_COUNT = os.cpu_count() or 1
_KDE_SENSOR_IDS = None


def read_ksystemstats():
    """Read KDE's own hardware sensor service when available; all sensors remain optional."""
    global _KDE_SENSOR_IDS
    if _KDE_SENSOR_IDS is None:
        try:
            listed = subprocess.run(["kstatsviewer", "--list"], capture_output=True,
                                    text=True, timeout=2.0, check=False)
            ids = []
            for line in listed.stdout.splitlines():
                sensor = line.split(maxsplit=1)[0] if line.split() else ""
                if (sensor in ("cpu/all/averageTemperature", "cpu/all/maximumTemperature")
                    or sensor.startswith(("gpu/", "power/", "network/", "disk/", "lmsensors/"))
                    and sensor.rsplit("/", 1)[-1] in (
                        "usage", "temperature", "usedVram", "totalVram", "usedPercent",
                        "charge", "health", "signal", "download", "upload", "read", "write",
                        "fan1", "fan2", "temp1", "temp2", "temp3")):
                    ids.append(sensor)
            _KDE_SENSOR_IDS = list(dict.fromkeys(ids))[:48]
        except (OSError, subprocess.TimeoutExpired):
            _KDE_SENSOR_IDS = []
    if not _KDE_SENSOR_IDS:
        return {}
    try:
        command = ["busctl", "--user", "call", "org.kde.ksystemstats1",
                   "/org/kde/ksystemstats1", "org.kde.ksystemstats1", "sensorData",
                   "as", str(len(_KDE_SENSOR_IDS)), *_KDE_SENSOR_IDS]
        result = subprocess.run(command, capture_output=True, text=True, timeout=1.2, check=False)
        if result.returncode:
            return {}
        tokens = shlex.split(result.stdout)
        values = {}
        if len(tokens) < 2:
            return values
        index = 2
        while index + 2 < len(tokens):
            name, kind, raw = tokens[index:index+3]
            index += 3
            if kind in ("i", "u", "x", "t", "d", "n", "q"):
                try: values[name] = float(raw)
                except ValueError: pass
        return values
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return {}


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
                "owner": owner, "exe": exe, "read": read_bytes,
                "write": write_bytes, "seen": now,
            })
        except (OSError, ValueError, IndexError, PermissionError):
            continue
    return procs, count, read_cpu_stat(), time.monotonic()


def read_gpu_memory():
    """Return dedicated GPU memory only when the driver exposes it."""
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=memory.used,memory.total,utilization.gpu", "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=0.8, check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            fields = [part.strip() for part in result.stdout.splitlines()[0].split(",")]
            used, total = int(fields[0]), int(fields[1])
            try: util = int(fields[2])
            except (ValueError, IndexError): util = None
            return {"name": "NVIDIA", "used": used * 1024**2, "total": total * 1024**2, "util": util, "kind": "dedicated"}
    except (OSError, ValueError, IndexError, subprocess.TimeoutExpired):
        pass
    for card in sorted(Path("/sys/class/drm").glob("card[0-9]*")):
        device = card / "device"
        try:
            total = int((device / "mem_info_vram_total").read_text().strip())
            used = int((device / "mem_info_vram_used").read_text().strip())
            return {"name": card.name, "used": used, "total": total, "util": None, "kind": "dedicated"}
        except (OSError, ValueError):
            continue
    return {"name": "Integrated/shared", "used": None, "total": None, "util": None, "kind": "shared"}


def read_network_counters():
    """Aggregate physical network counters; does not attribute traffic to apps."""
    totals = {"rx": 0, "tx": 0, "interfaces": []}
    for interface in Path("/sys/class/net").iterdir():
        name = interface.name
        if name == "lo" or name.startswith(("veth", "docker", "br-", "virbr", "tun", "tap")):
            continue
        try:
            if (interface / "operstate").read_text().strip() not in ("up", "unknown"):
                continue
            rx = int((interface / "statistics/rx_bytes").read_text().strip())
            tx = int((interface / "statistics/tx_bytes").read_text().strip())
            wifi = (interface / "wireless").exists()
            totals["rx"] += rx; totals["tx"] += tx
            totals["interfaces"].append({"name": name, "wifi": wifi})
        except (OSError, ValueError):
            continue
    return totals


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


class NRGWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NRG Desktop · Nexus Resource Governor")
        self.resize(1180, 760)
        self.previous, self.previous_cpu, self.last_scan = {}, None, None
        self.processes, self.process_rows = [], {}
        self.language = "en"
        self.previous_network = None
        self.network_rates = (0.0, 0.0)
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
        self.refresh()

    def _build_ui(self):
        self.setStyleSheet("""
            QMainWindow,QWidget{background:#101114;color:#e9e9eb}
            QTabWidget::pane{border:1px solid #303238;border-radius:8px}
            QTabBar::tab{background:#1a1c21;padding:10px 18px;margin:3px;border-radius:6px}
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
        self.tabs = QTabWidget(); root.addWidget(self.tabs)
        self._dashboard(); self._process_tab(); self._diagnostics_tab()
        self.language_box.currentIndexChanged.connect(self.change_language)
        self.language = self.language_box.currentData() or "en"
        self.setCentralWidget(central)
        self.apply_language()

    def _metric(self, title):
        box, layout = QWidget(), QVBoxLayout()
        box.setLayout(layout); layout.setContentsMargins(12, 10, 12, 10)
        name = QLabel(title); name.setObjectName("muted")
        value = QLabel("—"); value.setObjectName("metric")
        layout.addWidget(name); layout.addWidget(value)
        box.setStyleSheet("background:#1a1c21;border:1px solid #303238;border-radius:8px")
        return box, value

    def _dashboard(self):
        page, layout = QWidget(), QVBoxLayout()
        page.setLayout(layout)
        grid = QGridLayout(); self.metrics = {}
        self.metric_title_labels = {}
        for i, (key, title) in enumerate([
            ("available","RAM AVAILABLE"),("used","RAM IN USE"),("swap","SWAP IN USE"),
            ("cpu","CPU UTILIZATION"),("processes","PROCESSES"),("pressure","MEMORY PSI FULL"),
            ("disk","HOME VOLUME FREE"),("gpu","GPU MEMORY"),("network","NETWORK RX / TX"),
            ("cpu_temp","CPU TEMPERATURE"),("gpu_usage","GPU UTILIZATION"),("gpu_temp","GPU TEMPERATURE"),
            ("battery","BATTERY"),("wifi","WI-FI SIGNAL"),("disk_io","DISK READ / WRITE"),("fan","FAN SPEED"),
        ]):
            box, value = self._metric(title); self.metrics[key] = value
            self.metric_title_labels[key] = box.layout().itemAt(0).widget()
            grid.addWidget(box, i//4, i%4)
        layout.addLayout(grid)
        self.health = QLabel("Collecting resource signals…"); self.health.setObjectName("section")
        self.health.setWordWrap(True); layout.addWidget(self.health)
        self.alert_heading = QLabel("Processes that deserve a closer look")
        layout.addWidget(self.alert_heading)
        self.alert_table = QTableWidget(0,4)
        self.alert_table.setHorizontalHeaderLabels(["Process","PID","Signal","Executable"])
        for col, mode in enumerate([QHeaderView.ResizeMode.ResizeToContents,
                                    QHeaderView.ResizeMode.ResizeToContents,
                                    QHeaderView.ResizeMode.Stretch,QHeaderView.ResizeMode.Stretch]):
            self.alert_table.horizontalHeader().setSectionResizeMode(col, mode)
        self.alert_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.alert_table.cellDoubleClicked.connect(self.open_alert_details)
        layout.addWidget(self.alert_table, 1)
        self.dashboard_note = QLabel("Read-only monitoring. No process is terminated and no kernel/cgroup setting is changed.")
        self.dashboard_note.setObjectName("muted"); layout.addWidget(self.dashboard_note)
        self.tabs.addTab(page, "Overview")

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
            sensors = read_ksystemstats()
            gpu = read_gpu_memory()
            kde_gpu_used = sensors.get("gpu/all/usedVram")
            kde_gpu_total = sensors.get("gpu/all/totalVram")
            if gpu["kind"] != "dedicated" and kde_gpu_total and kde_gpu_total > 0:
                gpu = {"name":"KDE GPU sensor", "used":int(kde_gpu_used or 0),
                       "total":int(kde_gpu_total), "util":sensors.get("gpu/gpu0/usage"), "kind":"dedicated"}
            if gpu["kind"] == "dedicated":
                gpu_text = f"{fmt_bytes(gpu['used'])} / {fmt_bytes(gpu['total'])}"
                if gpu.get("util") is not None: gpu_text += f" · {gpu['util']}%"
            else:
                gpu_text = ("Compartida con RAM del sistema / VRAM dedicada no expuesta" if self.language == "es"
                            else "Shared with system RAM / no dedicated VRAM exposed")
            network = read_network_counters()
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
                ("cpu_temp", f"{sensors['cpu/all/averageTemperature']:.0f} °C" if sensors.get("cpu/all/averageTemperature", 0) > 0 else "—"),
                ("gpu_usage", f"{sensors['gpu/gpu0/usage']:.0f}%" if "gpu/gpu0/usage" in sensors else "—"),
                ("gpu_temp", f"{sensors['gpu/gpu0/temperature']:.0f} °C" if sensors.get("gpu/gpu0/temperature", 0) > 0 else "—"),
                ("battery", f"{sensors['power/123456789/charge']:.0f}%" if "power/123456789/charge" in sensors else self._sensor_value(sensors, "power/", "/charge", "%")),
                ("wifi", self._sensor_value(sensors, "network/", "/signal", "%")),
                ("disk_io", self._disk_io_text(sensors)),
                ("fan", self._sensor_value(sensors, "lmsensors/", "/fan1", " RPM")),
            ]: self.metrics[key].setText(value)
            self.update_health(avail,total,cpu_pct,pm,pc,pi,disk_free,disk_total)
            self.live.setText("LIVE  ·  "+time.strftime("%H:%M:%S"))
        except Exception as exc:
            self.live.setText(f"Collection error: {exc}")

    @staticmethod
    def _sensor_value(sensors, prefix, suffix, unit):
        match = next((value for key, value in sensors.items() if key.startswith(prefix) and key.endswith(suffix)), None)
        return f"{match:.0f}{unit}" if match is not None and match > 0 else "—"

    @staticmethod
    def _disk_io_text(sensors):
        if "disk/all/read" in sensors:
            read_rate = sensors["disk/all/read"]
        else:
            read_rate = sum(v for k, v in sensors.items()
                            if k.startswith("disk/nvme") and k.endswith("/read"))
        if "disk/all/write" in sensors:
            write_rate = sensors["disk/all/write"]
        else:
            write_rate = sum(v for k, v in sensors.items()
                             if k.startswith("disk/nvme") and k.endswith("/write"))
        if read_rate <= 0 and write_rate <= 0: return "—"
        return f"{fmt_bytes(read_rate)}/s · {fmt_bytes(write_rate)}/s"

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
                if exe.endswith(" (deleted)"): score+=35; reasons.append("Executable deleted while process is alive")
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
            for col,value in enumerate([proc["name"],proc["pid"],"; ".join(proc["reasons"]),proc["exe"] or "unavailable"]):
                self.alert_table.setItem(row,col,cell(value))
        self.count_label.setText(f"{count} processes observed · showing up to {MAX_ROWS}")
        self.populate_process_table()

    def populate_process_table(self):
        if not hasattr(self,"process_table"): return
        query=self.search.text().lower()
        rows=[p for p in self.processes if not query or query in " ".join(
            (p["name"],str(p["pid"]),p["owner"],p["exe"])).lower()]
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

    def _validate_process_identity(self, proc):
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
        names = ["balanced", "gaming", "study", "development"]
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
        self.tabs.setTabText(1, tr("Processes", "Procesos"))
        self.tabs.setTabText(2, tr("Diagnosis & Profiles", "Diagnóstico y perfiles"))
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
        self.alert_heading.setText(tr("Processes that deserve a closer look", "Procesos que requieren revisión"))
        self.dashboard_note.setText(tr("Read-only monitoring. No process is terminated and no kernel/cgroup setting is changed.",
            "Monitorización de solo lectura. No termina procesos ni modifica el kernel o los cgroups."))
        self.alert_table.setHorizontalHeaderLabels([tr("Process", "Proceso"), "PID", tr("Signal", "Señal"), tr("Executable", "Ejecutable")])
        self.search.setPlaceholderText(tr("Filter by process, PID, owner or executable…", "Filtrar por proceso, PID, propietario o ejecutable…"))
        self.process_table.setHorizontalHeaderLabels([tr("Process", "Proceso"), "PID", "CPU %", "RAM", tr("Owner", "Propietario"), tr("I/O write", "Escritura E/S"), tr("Review", "Revisión")])
        self.process_note.setText(tr("CPU is normalized to one logical core (100% = one full core). RSS estimates can double-count shared pages.",
            "CPU se expresa por núcleo lógico (100% = un núcleo completo). RSS puede contar páginas compartidas más de una vez."))
        self.profile_label.setText(tr("Profile", "Perfil"))
        self.plan_button.setText(tr("Calculate memory plan", "Calcular plan de memoria"))
        self.diag_button.setText(tr("Run system diagnosis", "Ejecutar diagnóstico del sistema"))
        self.edit_profiles_button.setText(tr("Edit coasters", "Editar coasters"))
        self.plan_note.setText(tr("Adaptive memory plan · simulation only", "Plan adaptativo de memoria · solo simulación"))
        self.plan_table.setHorizontalHeaderLabels([tr("Application", "Aplicación"), tr("Priority", "Prioridad"), tr("Current", "Actual"), tr("Proposed soft ceiling", "Techo flexible propuesto"), tr("Samples", "Muestras")])
        self.diag_output.setPlaceholderText(tr("System diagnosis output appears here.", "El diagnóstico del sistema aparecerá aquí."))
        self.process_actions_button.setText(tr("Manage selected process…", "Administrar proceso seleccionado…"))
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
