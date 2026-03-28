"""
SOCeal - Project VALE
Vigilant . Automated . Local . Endpoint Protector

Entry point: parses CLI args, starts the Flask realtime server,
and optionally opens the dashboard in a browser or pywebview.
"""

import argparse
import os
import sys
import threading
import time
import webbrowser

# ── resolve project paths ────────────────────────────────────────────────────
SRC_DIR   = os.path.dirname(os.path.abspath(__file__))
PROJECT   = os.path.dirname(SRC_DIR)          # …/SOCEAL/
ROOT      = os.path.dirname(PROJECT)           # repo root
DASH_DIR  = os.path.join(PROJECT, "dashboard")
DATA_DIR  = os.path.join(PROJECT, "data")
CFG_DIR   = os.path.join(PROJECT, "config")

# ensure these exist
for d in (DATA_DIR, CFG_DIR, DASH_DIR):
    os.makedirs(d, exist_ok=True)

sys.path.insert(0, SRC_DIR)

# ── CLI args ─────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(description="SOCeal - Project VALE")
parser.add_argument("--safe-mode",   action="store_true", default=True,
                    help="Monitor/detect only (no auto-block).")
parser.add_argument("--active-mode", action="store_true",
                    help="Enable auto-block and auto-kill countermeasures.")
parser.add_argument("--no-ui",       action="store_true",
                    help="Headless: start backend only, no browser.")
parser.add_argument("--webview",     action="store_true",
                    help="Open dashboard inside a native pywebview window.")
parser.add_argument("--port",        type=int, default=8081,
                    help="Port for the Flask server (default: 8081).")
args = parser.parse_args()

# active-mode overrides safe-mode flag
if args.active_mode:
    args.safe_mode = False

MODE   = "ACTIVE" if args.active_mode else "SAFE"
PORT   = args.port
URL    = f"http://127.0.0.1:{PORT}"

print(f"""\n  SOCeal  |  Project VALE
  Mode : {MODE}
  URL  : {URL}\n""")

# ── import backend ────────────────────────────────────────────────────────────
try:
    from realtime_server import create_app
except ImportError as e:
    print(f"[ERROR] Could not import realtime_server: {e}")
    print("  Make sure SOCEAL/src/realtime_server.py exists.")
    sys.exit(1)

app = create_app(active_mode=args.active_mode, data_dir=DATA_DIR, cfg_dir=CFG_DIR)

# ── launch server in background thread ───────────────────────────────────────
def _serve():
    import logging
    log = logging.getLogger("werkzeug")
    log.setLevel(logging.WARNING)
    app.run(host="127.0.0.1", port=PORT, debug=False, use_reloader=False)

server_thread = threading.Thread(target=_serve, daemon=True)
server_thread.start()

# wait for server to be ready
time.sleep(1.5)

# ── open UI ──────────────────────────────────────────────────────────────────
if not args.no_ui:
    if args.webview:
        try:
            import webview
            print(f"  Opening WebView window → {URL}")
            webview.create_window("SOCeal", URL, width=1440, height=900,
                                  resizable=True, min_size=(900, 600))
            webview.start()
        except ImportError:
            print("  [WARN] pywebview not installed — falling back to browser.")
            webbrowser.open(URL)
    else:
        webbrowser.open(URL)

# ── keep alive ───────────────────────────────────────────────────────────────
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\n  SOCeal stopped.")
