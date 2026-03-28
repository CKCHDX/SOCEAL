# SOCeal – Project VALE

> **Vigilant · Automated · Local · Endpoint Protector**

```
   _____ ____   _____           _
  / ____/ __ \ / ____|         | |
 | (___| |  | | |     ___  __ _| |
  \___ \ |  | | |    / _ \/ _` | |
  ____) | |__| | |__|  __/ (_| | |
 |_____/ \____/ \_____\___|\__,_|_|

  P R O J E C T   V A L E
```

SOCeal is a **personal, local SOC-style endpoint protector** for **Windows 10/11** written in Python. It monitors your machine in real time, detects suspicious activity, takes automatic countermeasures (kill process, block IP, quarantine file), and presents everything inside a **cinematic SOC dashboard** — all from a single `.exe` you run on your own PC.

---

## Features

| Feature | Description |
|---|---|
| 🔍 **Event Log Monitoring** | Real-time Windows Security/System/Application log subscription via `pywin32` |
| ⚙️ **Process Monitoring** | Tracks running processes, parent-child trees, suspicious names/paths via `psutil` |
| 📁 **File Monitoring** | Watches `Downloads`, `Temp`, `AppData` for suspicious file creation via `watchdog` |
| 🧠 **Rules Engine** | JSON-based rule set (brute-force, malware names, LOLBAS, encoded PS, etc.) |
| ⚡ **Kill Process** | Terminates malicious processes by PID instantly |
| 🔒 **Block IP** | Adds Windows Firewall DROP rules via `netsh` with optional auto-expiry |
| 📦 **Quarantine File** | Moves suspicious files to a secure quarantine folder with hash + metadata log |
| 🎛️ **Safe Mode** | Monitor-only mode — detects and logs everything but takes no action |
| 🖥️ **SOC Dashboard** | Cinematic dark-theme HTML/JS/CSS dashboard served locally via Flask |
| 📦 **Single EXE** | Packaged with PyInstaller — one file, no install needed |

---

## Project Structure

```
SOCEAL/
├── SOCEAL/
│   ├── src/
│   │   ├── main.py                  # Entry point — wires all components
│   │   ├── sensors/
│   │   │   ├── eventlog.py          # Windows Event Log sensor (pywin32)
│   │   │   ├── process_monitor.py   # Process watcher (psutil)
│   │   │   └── file_monitor.py      # File system watcher (watchdog)
│   │   ├── rules/
│   │   │   ├── engine.py            # Rules evaluation engine
│   │   │   ├── actions.py           # Countermeasure handlers
│   │   │   └── __init__.py
│   │   ├── ui/
│   │   │   ├── SOCeal_dashboard.html  # Full SOC dashboard (HTML/JS/CSS)
│   │   │   ├── realtime_server.py     # Flask API server
│   │   │   ├── dashboard_ui.py        # Browser / WebView launcher
│   │   │   └── __init__.py
│   │   └── utils/
│   │       ├── firewall.py          # netsh firewall helpers
│   │       ├── soc_logging.py       # Threat + structured logging
│   │       └── __init__.py
│   ├── config/
│   │   ├── config.yaml              # Global settings
│   │   └── rules.json               # Detection rules
│   ├── data/
│   │   ├── logs/                    # Threat logs (JSON)
│   │   └── quarantine/              # Quarantined files
│   └── requirements.txt
├── build.bat                        # PyInstaller build script (Windows)
├── .gitignore
└── README.md
```

---

## Quick Start

### Prerequisites

- **Windows 10 or Windows 11** (required — uses Windows-only APIs)
- **Python 3.10+**
- **Run as Administrator** (required for firewall rules and event log access)

### 1. Clone the repository

```bash
git clone https://github.com/CKCHDX/SOCEAL.git
cd SOCEAL
```

### 2. Install dependencies

```bash
pip install -r SOCEAL/requirements.txt
```

### 3. Run SOCeal

```bash
# From the repo root, run as Administrator:
python SOCEAL/src/main.py
```

This will:
- Start all sensors (event log, process monitor, file monitor).
- Launch a local Flask server at `http://127.0.0.1:8081`.
- Open the SOC dashboard in your default browser.

### Run in Safe Mode (no blocking, monitor only)

```bash
python SOCEAL/src/main.py --safe-mode
```

### Run in Active Mode (monitor + automatic countermeasures)

```bash
python SOCEAL/src/main.py --active-mode
```

### Run headless (no browser)

```bash
python SOCEAL/src/main.py --no-ui
```

---

## Configuration

Edit `SOCEAL/config/config.yaml` to customize:

```yaml
safe_mode: true          # true = monitor only, false = active countermeasures

ui:
  host: 127.0.0.1
  port: 8081

polling:
  eventlog: 1            # seconds between event log reads
  process: 5             # seconds between process scans

log_dir: data/logs
quarantine_dir: data/quarantine
rules_file: config/rules.json
```

---

## Detection Rules

Rules live in `SOCEAL/config/rules.json`. Example:

```json
{
  "id": "LOGIN_BRUTEFORCE",
  "type": "eventlog",
  "event_id": 4625,
  "window_seconds": 60,
  "threshold": 10,
  "action": "block_ip",
  "enabled": true
}
```

### Built-in rules

| Rule ID | Trigger | Action |
|---|---|---|
| `LOGIN_BRUTEFORCE` | 10+ failed logins in 60s | Block source IP |
| `MALICIOUS_PROCESS` | Known-bad process name (mimikatz, nc.exe, etc.) | Kill process |
| `ENCODED_POWERSHELL` | `powershell.exe -Enc` or `-EncodedCommand` | Kill + log |
| `SUSPICIOUS_TEMP_EXE` | `.exe` created in `Temp` / `AppData` | Quarantine file |
| `NEW_SERVICE_INSTALLED` | EventID 7045 (new service) | Alert |
| `REVERSE_SHELL_PORT` | Outbound connection on port 4444/1337/9001 | Block IP |
| `LOLBAS_CHAIN` | `explorer → cmd → powershell` process chain | Kill + alert |

---

## Countermeasures

When a rule fires in **active mode**, SOCeal can:

- **Kill Process** — `psutil.Process(pid).kill()`
- **Block IP** — `netsh advfirewall firewall add rule name="SOCeal_Block_<ip>" dir=in action=block remoteip=<ip>`
- **Quarantine File** — moves to `data/quarantine/<timestamp>_<filename>` + stores SHA-256 hash
- **Log Event** — structured JSON entry in `data/logs/threats.json`

All actions appear live in the **Countermeasures** panel of the dashboard.

---

## Dashboard API Endpoints

The Flask server exposes these endpoints (local only):

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Serves the SOC dashboard HTML |
| `/api/threats` | GET | Returns active threats (JSON) |
| `/api/actions` | GET | Returns recent countermeasures (JSON) |
| `/api/stats` | GET | Returns system stats + security score (JSON) |
| `/api/events` | GET | Returns recent event log entries (JSON) |
| `/api/mode` | POST | Toggle safe/active mode: `{"safe_mode": true}` |

---

## Build Single EXE

Run the build script (Windows only, requires `PyInstaller`):

```bash
build.bat
```

Output: `dist/SOCeal.exe` — a self-contained executable, no Python installation required.

---

## Security Notes

- SOCeal **must run as Administrator** to access Windows Security event logs and modify firewall rules.
- The dashboard is served on **127.0.0.1 only** — never exposed externally.
- In **safe mode** (default), SOCeal never modifies your system — it only monitors and logs.
- Always review `rules.json` before enabling active mode.

---

## Roadmap

- [ ] Native WebView2 window (no browser needed)
- [ ] Auto-expiring IP blocks (timed unblock)
- [ ] Threat feed integration (community blocklists)
- [ ] Export SOC report (PDF/HTML)
- [ ] Globe map with real GeoIP data
- [ ] Rule editor UI inside dashboard
- [ ] Alert notifications (Windows toast notifications)

---

## Tech Stack

| Layer | Technology |
|---|---|
| Core language | Python 3.10+ |
| Event log | `pywin32` (`win32evtlog`) |
| Process/system | `psutil` |
| File watch | `watchdog` |
| Firewall | `subprocess` + `netsh` |
| API server | `Flask` |
| Dashboard UI | HTML5 / CSS3 / Vanilla JS |
| Packaging | `PyInstaller` |

---

## License

MIT License — Personal & Educational use. See `LICENSE`.

---

*Built by Alex Jonsson — Project VALE*
