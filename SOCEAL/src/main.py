"""
SOCeal – Project VALE
Main entry point: ties sensors, rules engine, UI server, and dashboard together.
"""

import os
import sys
import time
import queue
import signal
import logging
import argparse
from pathlib import Path

# Ensure project root is on the path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / 'src'))

from utils.soc_logging import setup_logging, ThreatLogger
from rules.engine import RulesEngine
from rules.actions import ActionHandler
from sensors.eventlog import EventLogSensor
from sensors.process_monitor import ProcessMonitor
from sensors.file_monitor import FileMonitor
from ui.realtime_server import RealtimeServer
from ui.dashboard_ui import launch_browser, launch_webview

logger = logging.getLogger('soceal.main')

BANNER = r"""
   _____ ____   _____           _
  / ____/ __ \ / ____|         | |
 | (___| |  | | |     ___  __ _| |
  \___ \ |  | | |    / _ \/ _` | |
  ____) | |__| | |__|  __/ (_| | |
 |_____/ \____/ \_____\___|\__,_|_|

  P R O J E C T   V A L E
  Vigilant · Automated · Local · Endpoint Protector
  ─────────────────────────────────────────────────
"""


def load_config(config_path):
    """Load configuration from YAML file."""
    try:
        import yaml
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        logger.info("Configuration loaded from %s", config_path)
        return config or {}
    except ImportError:
        logger.warning("PyYAML not installed — using defaults")
        return {}
    except FileNotFoundError:
        logger.warning("Config file not found: %s — using defaults", config_path)
        return {}


def resolve_path(base, rel_path):
    """Resolve a relative path against the project root."""
    p = Path(rel_path)
    if p.is_absolute():
        return p
    return base / p


def main():
    # ── Parse arguments ──
    parser = argparse.ArgumentParser(
        description='SOCeal – Project VALE: Personal SOC Endpoint Protector'
    )
    parser.add_argument('--safe-mode', action='store_true', default=None,
                        help='Enable safe mode (monitor only, no actions)')
    parser.add_argument('--active-mode', action='store_true',
                        help='Enable active mode (monitor + countermeasures)')
    parser.add_argument('--port', type=int, default=None,
                        help='Override UI server port')
    parser.add_argument('--no-ui', action='store_true',
                        help='Run headless (no browser/webview)')
    parser.add_argument('--webview', action='store_true',
                        help='Use native WebView2 window instead of browser')
    parser.add_argument('--config', type=str, default=None,
                        help='Path to config.yaml')
    args = parser.parse_args()

    # ── Print banner ──
    print(BANNER)

    # ── Load config ──
    config_path = args.config or str(PROJECT_ROOT / 'config' / 'config.yaml')
    config = load_config(config_path)

    # Resolve settings
    safe_mode = config.get('safe_mode', True)
    if args.safe_mode is not None:
        safe_mode = True
    if args.active_mode:
        safe_mode = False

    ui_host = config.get('ui', {}).get('host', '127.0.0.1')
    ui_port = args.port or config.get('ui', {}).get('port', 8081)

    log_dir = resolve_path(PROJECT_ROOT, config.get('log_dir', 'data/logs'))
    quarantine_dir = resolve_path(PROJECT_ROOT, config.get('quarantine_dir', 'data/quarantine'))
    rules_path = resolve_path(PROJECT_ROOT, config.get('rules_file', 'config/rules.json'))

    # ── Setup logging ──
    setup_logging(str(log_dir))

    mode_str = "SAFE MODE (monitor only)" if safe_mode else "ACTIVE MODE (monitor + countermeasures)"
    logger.info("SOCeal starting — %s", mode_str)
    print(f"  Mode: {mode_str}")
    print(f"  UI:   http://{ui_host}:{ui_port}")
    print()

    # ── Initialize components ──
    event_queue = queue.Queue()

    threat_logger = ThreatLogger(str(log_dir))

    action_handler = ActionHandler(
        quarantine_dir=str(quarantine_dir),
        log_dir=str(log_dir),
        safe_mode=safe_mode,
    )

    rules_engine = RulesEngine(
        rules_path=str(rules_path),
        action_handler=action_handler,
        safe_mode=safe_mode,
    )

    # Sensors
    eventlog_sensor = EventLogSensor(
        event_queue=event_queue,
        channels=config.get('eventlog_channels', ['Security', 'System', 'Application']),
        poll_interval=config.get('polling', {}).get('eventlog', 1),
    )

    process_monitor = ProcessMonitor(
        event_queue=event_queue,
        interval=config.get('polling', {}).get('process', 5),
    )

    file_monitor = FileMonitor(
        event_queue=event_queue,
    )

    # UI Server
    server = RealtimeServer(
        host=ui_host,
        port=ui_port,
        threat_logger=threat_logger,
        rules_engine=rules_engine,
        action_handler=action_handler,
        process_monitor=process_monitor,
    )

    # ── Graceful shutdown ──
    shutdown = False

    def signal_handler(sig, frame):
        nonlocal shutdown
        if shutdown:
            print("\nForce quit.")
            sys.exit(1)
        shutdown = True
        print("\n  Shutting down SOCeal...")
        logger.info("Shutdown signal received")

    signal.signal(signal.SIGINT, signal_handler)

    # ── Start everything ──
    try:
        eventlog_sensor.start()
        process_monitor.start()
        file_monitor.start()
        server.start()

        # Give server a moment to start
        time.sleep(0.5)

        # Launch UI
        if not args.no_ui:
            if args.webview:
                # WebView blocks — run in thread
                import threading
                threading.Thread(
                    target=launch_webview,
                    args=(server.url,),
                    daemon=True,
                ).start()
            else:
                launch_browser(server.url)

        logger.info("SOCeal is running. Press Ctrl+C to stop.")
        print("  SOCeal is running. Press Ctrl+C to stop.\n")

        # ── Main event processing loop ──
        while not shutdown:
            try:
                event = event_queue.get(timeout=1)
                threat_logger.log_event()
                rules_engine.process_event(event)

                # Log for display
                etype = event.get('type', 'unknown')
                msg = event.get('message', '')
                severity = event.get('severity', 'info')
                if severity in ('critical', 'high'):
                    threat_logger.log_threat(etype, severity, msg, event)

            except queue.Empty:
                continue
            except Exception as e:
                logger.error("Event processing error: %s", e)

    except Exception as e:
        logger.critical("Fatal error: %s", e)
        raise
    finally:
        # ── Cleanup ──
        logger.info("Stopping all components...")
        eventlog_sensor.stop()
        process_monitor.stop()
        file_monitor.stop()
        server.stop()
        logger.info("SOCeal stopped.")
        print("  SOCeal stopped. Goodbye.")


if __name__ == '__main__':
    main()
