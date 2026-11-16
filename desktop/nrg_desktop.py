#!/usr/bin/env python3
"""NRG Desktop: lightweight, read-only resource and process diagnostics."""
from __future__ import annotations
import json, os, pwd, re, subprocess, sys, time
from pathlib import Path
from PySide6.QtCore import Qt, QProcess, QTimer
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication, QComboBox, QDialog, QDialogButtonBox, QGridLayout,
    QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMessageBox, QPushButton,
    QTabWidget, QTableWidget, QTableWidgetItem, QTextEdit, QVBoxLayout,
    QWidget, QHeaderView,
)

ROOT = Path(__file__).resolve().parents[1]
CANDIDATES = [ROOT / "target/release/nrg-agent", ROOT / "target/debug/nrg-agent"]
AGENT = next((p for p in CANDIDATES if p.is_file()), None)
REFRESH_MS, MAX_ROWS = 5000, 120
PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
CLK_TCK = os.sysconf("SC_CLK_TCK")
CPU_COUNT = os.cpu_count() or 1


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


def scan_processes():
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
            try:
                exe = os.readlink(base / "exe")
            except OSError:
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
        ]):
            box, value = self._metric(title); self.metrics[key] = value
            self.metric_title_labels[key] = box.layout().itemAt(0).widget()
            grid.addWidget(box, i//3, i%3)
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
        self.process_table = QTableWidget(0,7)
        self.process_table.setHorizontalHeaderLabels(["Process","PID","CPU %","RAM","Owner","I/O write","Review"])
        self.process_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.process_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.process_table.setAlternatingRowColors(True); self.process_table.setSortingEnabled(True)
        self.process_table.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeMode.Stretch)
        for col in range(1,7): self.process_table.horizontalHeader().setSectionResizeMode(col,QHeaderView.ResizeMode.ResizeToContents)
        self.process_table.cellDoubleClicked.connect(self.open_process_details)
        layout.addWidget(self.process_table)
        self.process_note = QLabel("CPU is normalized to one logical core (100% = one full core). RSS estimates can double-count shared pages.")
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
        row.addWidget(self.profile_label); row.addWidget(self.profile)
        row.addWidget(self.plan_button); row.addWidget(self.diag_button); row.addWidget(self.edit_profiles_button); row.addStretch()
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
        self.network_preview = QLabel("Network budget preview is advisory; no traffic shaping is applied.")
        self.network_preview.setWordWrap(True); layout.addWidget(self.network_preview)
        self.diag_output = QTextEdit(); self.diag_output.setReadOnly(True)
        self.diag_output.setPlaceholderText("System diagnosis output appears here."); layout.addWidget(self.diag_output,2)
        self.load_profile()
        self.tabs.addTab(page,"Diagnosis & Profiles")

    def refresh(self):
        try:
            procs, count, cpu_total, now = scan_processes()
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
            gpu = read_gpu_memory()
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
            ]: self.metrics[key].setText(value)
            self.update_health(avail,total,cpu_pct,pm,pc,pi,disk_free,disk_total)
            self.live.setText("LIVE  ·  "+time.strftime("%H:%M:%S"))
        except Exception as exc:
            self.live.setText(f"Collection error: {exc}")

    def update_process_metrics(self, procs,count,cpu_total,old_cpu,elapsed):
        total_ticks = max(1,cpu_total[0]-old_cpu[0]) if cpu_total and old_cpu else max(1,int(elapsed*CLK_TCK*CPU_COUNT))
        current = {}
        had_baseline = self.process_baseline_ready
        new_children_by_parent = {}
        new_processes = 0
        if had_baseline:
            for item in procs:
                if (item["pid"], item["start"]) not in self.previous:
                    new_processes += 1
                    parent = item["ppid"]
                    new_children_by_parent[parent] = new_children_by_parent.get(parent, 0) + 1
        self.process_baseline_ready = True
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
                cpu_high=old["cpu_high"]+1 if cpu>=80 else 0
                growth_high=old["growth_high"]+1 if proc["rss"]-old["rss"]>=128*1024**2 else 0
                write_high=old["write_high"]+1 if write_rate>=100*1024**2 else 0
            else:
                cpu_high=growth_high=write_high=0
            score,reasons=0,[]
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
                    proc["owner"],fmt_bytes(proc["write_rate"])+"/s",
                    f"{proc['score']} · Review" if proc["score"] else "—"]
            for col,value in enumerate(values):
                obj=cell(value,Qt.AlignmentFlag.AlignRight|Qt.AlignmentFlag.AlignVCenter if col in (1,2,3,5,6) else None)
                obj.setData(Qt.ItemDataRole.UserRole,(proc["pid"],proc["start"]))
                self.process_table.setItem(row,col,obj)
        self.process_table.setSortingEnabled(True)

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
        self.download_plan.setPlaceholderText(tr("Download Mbps", "Descarga Mbps"))
        self.upload_plan.setPlaceholderText(tr("Upload Mbps", "Subida Mbps"))
        self.network_preview_button.setText(tr("Preview network budget", "Simular presupuesto de red"))
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
        usable_down, usable_up = down * 0.90, up * 0.90
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
                f"Capacidad utilizable estimada tras reservar 10%: {usable_down:.1f} / {usable_up:.1f} Mbps. SIMULACIÓN; no se aplican límites.")
        else:
            self.network_preview.setText(
                f"Profile {profile}: {top_app} would receive a simulated target of {priority_down:.1f} Mbps down / {priority_up:.1f} Mbps up. "
                f"Other apps: {rest_down:.1f} / {rest_up:.1f} Mbps. "
                f"Estimated usable capacity after a 10% safety margin: {usable_down:.1f} / {usable_up:.1f} Mbps. SIMULATION; no limits applied.")

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
