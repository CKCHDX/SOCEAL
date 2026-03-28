"""
SOCeal - Flask realtime backend.

Endpoints used by the dashboard:
  GET  /api/status          overall system health + counters
  GET  /api/threats         live threat list
  GET  /api/events          live event stream (filterable)
  GET  /api/quarantine      quarantined files
  GET  /api/firewall        active SOCeal firewall rules
  GET  /api/rules           detection rule list
  GET  /api/mode            current mode (safe/active)
  POST /api/mode            switch mode {"mode": "safe"|"active"}
  PATCH /api/rules/<id>     toggle a rule {"enabled": true|false}
  POST /api/manual/block    block an IP {"ip": "..."}
  POST /api/manual/unblock  unblock an IP {"ip": "..."}
  POST /api/manual/kill     kill a PID {"pid": 1234}
  DELETE /api/firewall/cleanup   remove all SOCeal_Block_* rules
"""

import datetime
import json
import os
import platform
import subprocess
import sys
import time
import uuid
from collections import deque
from threading import Lock, Thread

try:
    from flask import Flask, jsonify, request
    from flask_cors import CORS
except ImportError as e:
    print(f"[ERROR] Flask/flask-cors not installed: {e}")
    sys.exit(1)

try:
    import psutil
except ImportError:
    psutil = None

# ─────────────────────────────────────────────────────────────────────────────
# State
# ─────────────────────────────────────────────────────────────────────────────
_lock      = Lock()
_mode      = "safe"                # "safe" | "active"
_threats   = []                    # [{id, title, severity, time, meta}, ...]
_events    = deque(maxlen=500)     # [{id, type, msg, time}, ...]
_quarantine = []                   # [{name, sha256, original_path, size, time}]
_fw_rules  = []                    # [{name, ip, direction, time}]
_start_time = time.time()

_rules = [
    {"id": "r01", "name": "Port Scan Detection",      "enabled": True,  "category": "network"},
    {"id": "r02", "name": "Brute Force SSH/RDP",       "enabled": True,  "category": "network"},
    {"id": "r03", "name": "DNS Tunnelling",             "enabled": True,  "category": "network"},
    {"id": "r04", "name": "ICMP Flood",                "enabled": True,  "category": "network"},
    {"id": "r05", "name": "Reverse Shell Detection",   "enabled": True,  "category": "network"},
    {"id": "r06", "name": "Suspicious Outbound HTTP",  "enabled": True,  "category": "network"},
    {"id": "r07", "name": "Lateral Movement (SMB)",    "enabled": True,  "category": "network"},
    {"id": "r08", "name": "Beaconing Pattern",         "enabled": False, "category": "network"},
    {"id": "r09", "name": "Ransomware File Pattern",   "enabled": True,  "category": "file"},
    {"id": "r10", "name": "Macro Document Drop",       "enabled": True,  "category": "file"},
    {"id": "r11", "name": "Executable in Temp",        "enabled": True,  "category": "file"},
    {"id": "r12", "name": "LSASS Memory Access",       "enabled": True,  "category": "process"},
    {"id": "r13", "name": "Mimikatz Signature",        "enabled": True,  "category": "process"},
    {"id": "r14", "name": "Process Hollow Detection",  "enabled": True,  "category": "process"},
    {"id": "r15", "name": "Privilege Escalation",      "enabled": True,  "category": "process"},
    {"id": "r16", "name": "Suspicious Sched Task",     "enabled": True,  "category": "persistence"},
    {"id": "r17", "name": "Registry Run Key Mod",      "enabled": True,  "category": "persistence"},
    {"id": "r18", "name": "Startup Folder Write",      "enabled": False, "category": "persistence"},
    {"id": "r19", "name": "WMI Subscription",          "enabled": True,  "category": "persistence"},
    {"id": "r20", "name": "DLL Sideloading",           "enabled": True,  "category": "evasion"},
    {"id": "r21", "name": "AMSI Bypass Pattern",       "enabled": True,  "category": "evasion"},
    {"id": "r22", "name": "ETW Patching",              "enabled": True,  "category": "evasion"},
    {"id": "r23", "name": "Base64 PowerShell",         "enabled": True,  "category": "evasion"},
    {"id": "r24", "name": "USB Device Inserted",       "enabled": True,  "category": "hardware"},
    {"id": "r25", "name": "Unusual CPU Spike",         "enabled": False, "category": "anomaly"},
]


def _ts():
    return datetime.datetime.now().strftime("%H:%M:%S")


def _add_event(etype: str, msg: str):
    with _lock:
        _events.appendleft({
            "id":   str(uuid.uuid4())[:8],
            "type": etype,
            "msg":  msg,
            "time": _ts(),
        })

# ─────────────────────────────────────────────────────────────────────────────
# Windows helpers (gracefully degrade on non-Windows)
# ─────────────────────────────────────────────────────────────────────────────
def _is_windows():
    return platform.system() == "Windows"


def _fw_block(ip: str) -> bool:
    if not _is_windows():
        return False
    name = f"SOCeal_Block_{ip.replace('.', '_')}"
    try:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={name}", "dir=in", "action=block",
             f"remoteip={ip}", "enable=yes"],
            capture_output=True, check=True
        )
        return True
    except Exception:
        return False


def _fw_unblock(ip: str) -> bool:
    if not _is_windows():
        return False
    name = f"SOCeal_Block_{ip.replace('.', '_')}"
    try:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"],
            capture_output=True, check=True
        )
        return True
    except Exception:
        return False


def _fw_cleanup() -> int:
    """Remove all SOCeal_Block_* rules. Returns count removed."""
    if not _is_windows():
        return 0
    removed = 0
    for rule in list(_fw_rules):
        if _fw_unblock(rule["ip"]):
            removed += 1
    with _lock:
        _fw_rules.clear()
    return removed


def _kill_pid(pid: int) -> bool:
    if not psutil:
        return False
    try:
        p = psutil.Process(pid)
        p.kill()
        return True
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Monitoring thread (real psutil data, no dummies)
# ─────────────────────────────────────────────────────────────────────────────
def _monitor_loop(active_mode: bool):
    """Continuously gather real system data and populate state."""
    while True:
        try:
            if psutil:
                # check for suspicious processes: high CPU or temp-dir executables
                for proc in psutil.process_iter(["pid", "name", "exe", "cpu_percent"]):
                    try:
                        info = proc.info
                        exe  = info.get("exe") or ""
                        cpu  = info.get("cpu_percent") or 0
                        # rule r11: executable in Temp
                        if exe and ("\\Temp\\" in exe or "/tmp/" in exe.lower()):
                            threat_id = f"t_{info['pid']}_exe_temp"
                            if not any(t["id"] == threat_id for t in _threats):
                                with _lock:
                                    _threats.insert(0, {
                                        "id":       threat_id,
                                        "title":    f"Executable in Temp: {info['name']}",
                                        "severity": "HIGH",
                                        "time":     _ts(),
                                        "meta":     {"pid": info["pid"], "exe": exe},
                                        "rule":     "r11",
                                    })
                                _add_event("DETECT",
                                    f"Exe in Temp: {info['name']} (PID {info['pid']})")
                        # rule r25: unusual CPU spike (>90% for a single process)
                        if cpu > 90:
                            threat_id = f"t_{info['pid']}_cpu"
                            if not any(t["id"] == threat_id for t in _threats):
                                with _lock:
                                    _threats.insert(0, {
                                        "id":       threat_id,
                                        "title":    f"High CPU: {info['name']} ({cpu:.0f}%)",
                                        "severity": "MEDIUM",
                                        "time":     _ts(),
                                        "meta":     {"pid": info["pid"]},
                                        "rule":     "r25",
                                    })
                                _add_event("DETECT",
                                    f"CPU spike: {info['name']} {cpu:.0f}%")
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                # check open network connections
                for conn in psutil.net_connections(kind="inet"):
                    raddr = conn.raddr
                    if not raddr:
                        continue
                    ip = raddr.ip
                    # trivial: flag connections to private ranges on unusual ports
                    # (placeholder for deeper heuristics)
                    if conn.status == "ESTABLISHED" and raddr.port in (4444, 1337, 31337, 5555):
                        threat_id = f"t_conn_{ip}_{raddr.port}"
                        if not any(t["id"] == threat_id for t in _threats):
                            with _lock:
                                _threats.insert(0, {
                                    "id":       threat_id,
                                    "title":    f"Suspicious connection → {ip}:{raddr.port}",
                                    "severity": "CRITICAL",
                                    "time":     _ts(),
                                    "meta":     {"ip": ip, "port": raddr.port},
                                    "rule":     "r05",
                                })
                            _add_event("BLOCK" if active_mode else "DETECT",
                                f"Suspicious port {raddr.port} → {ip}")
                            if active_mode:
                                _fw_block(ip)
                                with _lock:
                                    _fw_rules.insert(0, {
                                        "name":  f"SOCeal_Block_{ip.replace('.','_')}",
                                        "ip":    ip,
                                        "dir":   "IN",
                                        "time":  _ts(),
                                    })

        except Exception as ex:
            _add_event("MONITOR", f"Monitor loop error: {ex}")

        time.sleep(5)


# ─────────────────────────────────────────────────────────────────────────────
# Flask app factory
# ─────────────────────────────────────────────────────────────────────────────
def create_app(active_mode: bool = False, data_dir: str = ".", cfg_dir: str = "."):
    global _mode
    _mode = "active" if active_mode else "safe"

    app = Flask(__name__)
    CORS(app)

    # ── start monitor thread ──────────────────────────────────────────────────
    t = Thread(target=_monitor_loop, args=(active_mode,), daemon=True)
    t.start()
    _add_event("MONITOR", f"SOCeal started in {_mode.upper()} mode.")

    # ── routes ────────────────────────────────────────────────────────────────
    @app.route("/api/status")
    def api_status():
        uptime = int(time.time() - _start_time)
        cpu    = psutil.cpu_percent(interval=None) if psutil else 0
        mem    = psutil.virtual_memory().percent   if psutil else 0
        with _lock:
            tc = len(_threats)
            ec = len(_events)
            qc = len(_quarantine)
        return jsonify({
            "mode":          _mode,
            "uptime_sec":    uptime,
            "threat_count":  tc,
            "event_count":   ec,
            "quarantine_count": qc,
            "cpu_percent":   cpu,
            "mem_percent":   mem,
            "platform":      platform.system(),
        })

    @app.route("/api/threats")
    def api_threats():
        with _lock:
            return jsonify(list(_threats))

    @app.route("/api/events")
    def api_events():
        etype = request.args.get("type", "").upper()
        with _lock:
            ev = list(_events)
        if etype and etype != "ALL":
            ev = [e for e in ev if e["type"] == etype]
        return jsonify(ev)

    @app.route("/api/quarantine")
    def api_quarantine():
        with _lock:
            return jsonify(list(_quarantine))

    @app.route("/api/firewall")
    def api_firewall():
        with _lock:
            return jsonify(list(_fw_rules))

    @app.route("/api/rules", methods=["GET"])
    def api_rules_get():
        return jsonify(_rules)

    @app.route("/api/rules/<rid>", methods=["PATCH"])
    def api_rules_patch(rid):
        data = request.get_json(force=True, silent=True) or {}
        for r in _rules:
            if r["id"] == rid:
                if "enabled" in data:
                    r["enabled"] = bool(data["enabled"])
                _add_event("MONITOR",
                    f"Rule {r['name']} {'enabled' if r['enabled'] else 'disabled'}")
                return jsonify(r)
        return jsonify({"error": "rule not found"}), 404

    @app.route("/api/mode", methods=["GET"])
    def api_mode_get():
        return jsonify({"mode": _mode})

    @app.route("/api/mode", methods=["POST"])
    def api_mode_post():
        global _mode
        data = request.get_json(force=True, silent=True) or {}
        new_mode = data.get("mode", "").lower()
        if new_mode in ("safe", "active"):
            _mode = new_mode
            _add_event("MONITOR", f"Mode switched to {_mode.upper()}")
            return jsonify({"mode": _mode})
        return jsonify({"error": "invalid mode"}), 400

    @app.route("/api/manual/block", methods=["POST"])
    def api_manual_block():
        data = request.get_json(force=True, silent=True) or {}
        ip = data.get("ip", "").strip()
        if not ip:
            return jsonify({"error": "ip required"}), 400
        ok = _fw_block(ip)
        with _lock:
            _fw_rules.insert(0, {
                "name": f"SOCeal_Block_{ip.replace('.','_')}",
                "ip":   ip,
                "dir":  "IN",
                "time": _ts(),
            })
        _add_event("BLOCK", f"Manual block: {ip} ({'ok' if ok else 'FW unavailable'})")
        return jsonify({"blocked": ip, "fw": ok})

    @app.route("/api/manual/unblock", methods=["POST"])
    def api_manual_unblock():
        data = request.get_json(force=True, silent=True) or {}
        ip = data.get("ip", "").strip()
        if not ip:
            return jsonify({"error": "ip required"}), 400
        ok = _fw_unblock(ip)
        with _lock:
            _fw_rules[:] = [r for r in _fw_rules if r["ip"] != ip]
        _add_event("MONITOR", f"Manual unblock: {ip}")
        return jsonify({"unblocked": ip, "fw": ok})

    @app.route("/api/manual/kill", methods=["POST"])
    def api_manual_kill():
        data = request.get_json(force=True, silent=True) or {}
        pid = data.get("pid")
        if not pid:
            return jsonify({"error": "pid required"}), 400
        try:
            pid = int(pid)
        except ValueError:
            return jsonify({"error": "pid must be integer"}), 400
        ok = _kill_pid(pid)
        _add_event("BLOCK" if ok else "MONITOR",
            f"Kill PID {pid}: {'ok' if ok else 'failed/not found'}")
        return jsonify({"pid": pid, "killed": ok})

    @app.route("/api/firewall/cleanup", methods=["DELETE"])
    def api_fw_cleanup():
        n = _fw_cleanup()
        _add_event("MONITOR", f"Firewall cleanup: {n} rules removed.")
        return jsonify({"removed": n})

    # ── static dashboard files ────────────────────────────────────────────────
    from flask import send_from_directory

    @app.route("/")
    def dashboard_root():
        return send_from_directory(data_dir.replace("data", "dashboard"), "index.html")

    @app.route("/<path:path>")
    def dashboard_static(path):
        return send_from_directory(data_dir.replace("data", "dashboard"), path)

    return app
