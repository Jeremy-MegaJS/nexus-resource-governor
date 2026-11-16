#!/usr/bin/env python3
"""NRG Desktop: lightweight, read-only resource and process diagnostics."""
from __future__ import annotations
import json, os, pwd, sys, time
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
    def __init__(self, proc, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"NRG · Process {proc['pid']}")
        self.resize(680, 420)
        layout = QVBoxLayout(self)
        view = QTextEdit(); view.setReadOnly(True)
        reasons = proc["reasons"] or ["No current heuristic indicators."]
        view.setPlainText("\n".join([
            f"Process: {proc['name']} (PID {proc['pid']})",
            f"Parent PID: {proc['ppid']} · Owner: {proc['owner']} · State: {proc['state']}",
            f"CPU: {proc['cpu']:.1f}% of one logical core",
            f"RSS estimate: {fmt_bytes(proc['rss'])}",
            f"Disk read/write: {fmt_bytes(proc['read_rate'])}/s · {fmt_bytes(proc['write_rate'])}/s",
            f"Executable: {proc['exe'] or 'not readable'}", "",
            "Review indicators:", *reasons, "",
            "These are investigation clues, not a malware verdict. Resource usage alone cannot identify a virus.",
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
        subtitle = QLabel("Nexus Resource Governor  /  local diagnostics"); subtitle.setObjectName("muted")
        self.live = QLabel("Starting…"); self.live.setObjectName("muted")
        head.addWidget(brand); head.addWidget(subtitle); head.addStretch(); head.addWidget(self.live)
        root.addLayout(head)
        self.tabs = QTabWidget(); root.addWidget(self.tabs)
        self._dashboard(); self._process_tab(); self._diagnostics_tab()
        self.setCentralWidget(central)

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
        for i, (key, title) in enumerate([
            ("available","RAM AVAILABLE"),("used","RAM IN USE"),("swap","SWAP IN USE"),
            ("cpu","CPU UTILIZATION"),("processes","PROCESSES"),("pressure","MEMORY PSI FULL"),
            ("disk","HOME VOLUME FREE"),
        ]):
            box, value = self._metric(title); self.metrics[key] = value
            grid.addWidget(box, i//3, i%3)
        layout.addLayout(grid)
        self.health = QLabel("Collecting resource signals…"); self.health.setObjectName("section")
        self.health.setWordWrap(True); layout.addWidget(self.health)
        layout.addWidget(QLabel("Processes that deserve a closer look"))
        self.alert_table = QTableWidget(0,4)
        self.alert_table.setHorizontalHeaderLabels(["Process","PID","Signal","Executable"])
        for col, mode in enumerate([QHeaderView.ResizeMode.ResizeToContents,
                                    QHeaderView.ResizeMode.ResizeToContents,
                                    QHeaderView.ResizeMode.Stretch,QHeaderView.ResizeMode.Stretch]):
            self.alert_table.horizontalHeader().setSectionResizeMode(col, mode)
        self.alert_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.alert_table.cellDoubleClicked.connect(self.open_alert_details)
        layout.addWidget(self.alert_table, 1)
        note = QLabel("Read-only monitoring. No process is terminated and no kernel/cgroup setting is changed.")
        note.setObjectName("muted"); layout.addWidget(note)
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
        note = QLabel("CPU is normalized to one logical core (100% = one full core). RSS estimates can double-count shared pages.")
        note.setObjectName("muted"); layout.addWidget(note)
        self.tabs.addTab(page,"Processes")

    def _diagnostics_tab(self):
        page, layout = QWidget(), QVBoxLayout(); page.setLayout(layout)
        row = QHBoxLayout()
        self.profile = QComboBox(); self.profile.addItems(["balanced","gaming","study","development"])
        self.load_profile()
        self.profile.currentTextChanged.connect(self.save_profile)
        self.plan_button = QPushButton("Calculate memory plan"); self.plan_button.clicked.connect(self.run_plan)
        self.diag_button = QPushButton("Run system diagnosis"); self.diag_button.clicked.connect(self.run_diagnosis)
        row.addWidget(QLabel("Profile")); row.addWidget(self.profile)
        row.addWidget(self.plan_button); row.addWidget(self.diag_button); row.addStretch()
        layout.addLayout(row); layout.addWidget(QLabel("Adaptive memory plan · simulation only"))
        self.plan_table = QTableWidget(0,5)
        self.plan_table.setHorizontalHeaderLabels(["Application","Priority","Current","Proposed soft ceiling","Samples"])
        self.plan_table.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeMode.Stretch)
        for col in range(1,5): self.plan_table.horizontalHeader().setSectionResizeMode(col,QHeaderView.ResizeMode.ResizeToContents)
        self.plan_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers); layout.addWidget(self.plan_table,1)
        self.diag_output = QTextEdit(); self.diag_output.setReadOnly(True)
        self.diag_output.setPlaceholderText("System diagnosis output appears here."); layout.addWidget(self.diag_output,2)
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
            for key, value in [
                ("available",fmt_bytes(avail)),("used",fmt_bytes(max(0,total-avail))),
                ("swap",fmt_bytes(swap)),("cpu",f"{cpu_pct:.0f}%" if cpu_pct is not None else "—"),
                ("processes",str(count)),("pressure",f"{pm.get('full',0):.2f}%"),
                ("disk",fmt_bytes(disk_free)),
            ]: self.metrics[key].setText(value)
            self.update_health(avail,total,cpu_pct,pm,pc,pi,disk_free,disk_total)
            self.live.setText("LIVE  ·  "+time.strftime("%H:%M:%S"))
        except Exception as exc:
            self.live.setText(f"Collection error: {exc}")

    def update_process_metrics(self, procs,count,cpu_total,old_cpu,elapsed):
        total_ticks = max(1,cpu_total[0]-old_cpu[0]) if cpu_total and old_cpu else max(1,int(elapsed*CLK_TCK*CPU_COUNT))
        current = {}
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
        colors={"NORMAL":"#72c89b","WARNING":"#e0b35a","CRITICAL":"#ef6961"}
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
        if proc: ProcessDetails(proc,self).exec()

    def open_alert_details(self,row,col):
        pid=self.alert_table.item(row,1)
        proc=self.process_rows.get(int(pid.text())) if pid else None
        if proc: ProcessDetails(proc,self).exec()

    def profile_config_path(self):
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
        return base / "nrg" / "desktop.json"

    def load_profile(self):
        try:
            data = json.loads(self.profile_config_path().read_text())
            profile = data.get("active_profile")
            if profile in ("balanced", "gaming", "study", "development"):
                self.profile.setCurrentText(profile)
        except (OSError, ValueError, TypeError):
            pass

    def save_profile(self, profile):
        if profile not in ("balanced", "gaming", "study", "development"):
            return
        path = self.profile_config_path()
        try:
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_text(json.dumps({"active_profile": profile}, indent=2) + "\n")
            path.chmod(0o600)
        except OSError as exc:
            self.diag_output.setPlainText(f"Could not save selected profile: {exc}")

    def run_plan(self):
        if not AGENT:
            QMessageBox.warning(self,"NRG agent missing","Build the release binary first: cargo build --release"); return
        self.plan_button.setEnabled(False); self.diag_output.setPlainText("Calculating read-only memory plan…")
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
            self.diag_output.setPlainText(
                f"Profile: {plan.get('profile')}\nStatus: {plan.get('status')}\n"
                f"History samples: {plan.get('history_samples_loaded')}\n"
                f"Enforcement enabled: {plan.get('enforcement_enabled')}\n\n{plan.get('explanation','')}\n\n{err}")
        except (ValueError,TypeError):
            self.diag_output.setPlainText(raw+"\n"+err)

    def run_diagnosis(self):
        if not AGENT:
            QMessageBox.warning(self,"NRG agent missing","Build the release binary first: cargo build --release"); return
        self.diag_button.setEnabled(False); self.diag_output.setPlainText("Collecting kernel, graphics, memory, IRQ and thermal diagnostics…")
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
