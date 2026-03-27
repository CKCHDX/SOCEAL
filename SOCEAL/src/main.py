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
from sensors.network_monitor import NetworkMonitor
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
    p = Path(rel_path)
    if p.is_absolute():
        return p
    return base / p


def expand_path(p):
    """Expand ~ and %ENV% variables in paths."""
    return Path(os.path.expandvars(os.path.expanduser(str(p))))


def main():
    parser = argparse.ArgumentParser(
        description='SOCeal – Project VALE: Personal SOC Endpoint Protector'
    )
    parser.add_argument('--safe-mode', action='store_true', default=None)
    parser.add_argument('--active-mode', action='store_true')
    parser.add_argument('--port', type=int, default=None)
    parser.add_argument('--no-ui', action='store_true')
    parser.add_argument('--webview', action='store_true')
    parser.add_argument('--config', type=str, default=None)
    args = parser.parse_args()

    print(BANNER)

    config_path = args.config or str(PROJECT_ROOT / 'config' / 'config.yaml')
    config = load_config(config_path)

    safe_mode = config.get('safe_mode', True)
    if args.safe_mode:
        safe_mode = True
    if args.active_mode:
        safe_mode = False

    ui_host = config.get('ui', {}).get('host', '127.0.0.1')
    ui_port = args.port or config.get('ui', {}).get('port', 8081)
    open_browser = config.get('ui', {}).get('open_browser', True)

    log_dir = resolve_path(PROJECT_ROOT, config.get('log_dir', 'data/logs'))
    quarantine_dir = resolve_path(PROJECT_ROOT, config.get('quarantine_dir', 'data/quarantine'))
    rules_file = resolve_path(PROJECT_ROOT, config.get('rules_file', 'config/rules.json'))

    # Setup logging
    setup_logging(log_dir)
    logger.info("SOCeal starting — safe_mode=%s, port=%d", safe_mode, ui_port)
    if safe_mode:
        logger.info("⚠️  SAFE MODE: monitoring only, no countermeasures")
    else:
        logger.warning("⚡ ACTIVE MODE: countermeasures ENABLED")

    # ── Core components ──
    event_queue = queue.Queue(maxsize=10000)
    threat_logger = ThreatLogger(log_dir)

    action_handler = ActionHandler(
        quarantine_dir=str(quarantine_dir),
        log_dir=str(log_dir),
        safe_mode=safe_mode,
    )

    rules_engine = RulesEngine(
        rules_path=str(rules_file),
        action_handler=action_handler,
        safe_mode=safe_mode,
    )

    # ── Sensors ──
    poll = config.get('polling', {})
    eventlog_channels = config.get('eventlog_channels', ['Security', 'System', 'Application'])
    watch_paths_raw = config.get('watch_paths', None)
    watch_paths = [expand_path(p) for p in watch_paths_raw] if watch_paths_raw else None
    extra_procs = set(config.get('suspicious_processes', []))

    event_sensor = EventLogSensor(
        event_queue=event_queue,
        channels=eventlog_channels,
        poll_interval=poll.get('eventlog', 1),
    )

    process_monitor = ProcessMonitor(
        event_queue=event_queue,
        interval=poll.get('process', 5),
        suspicious_names=ProcessMonitor.SUSPICIOUS_NAMES | extra_procs,
    )

    file_monitor = FileMonitor(
        event_queue=event_queue,
        watch_paths=watch_paths,
    )

    network_monitor = NetworkMonitor(
        event_queue=event_queue,
        interval=poll.get('network', 10),
    )
    network_monitor.set_rules(rules_engine.rules)

    # ── UI server ──
    server = RealtimeServer(
        host=ui_host,
        port=ui_port,
        threat_logger=threat_logger,
        rules_engine=rules_engine,
        action_handler=action_handler,
        process_monitor=process_monitor,
        network_monitor=network_monitor,
    )

    # ── Graceful shutdown ──
    def shutdown(sig=None, frame=None):
        logger.info("SOCeal shutting down...")
        event_sensor.stop()
        process_monitor.stop()
        file_monitor.stop()
        network_monitor.stop()
        server.stop()
        logger.info("SOCeal stopped.")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # ── Start everything ──
    server.start()
    event_sensor.start()
    process_monitor.start()
    file_monitor.start()
    network_monitor.start()

    logger.info("SOCeal dashboard: http://%s:%d", ui_host, ui_port)

    if not args.no_ui:
        import threading
        def _open_ui():
            time.sleep(1.5)
            if args.webview:
                launch_webview(f"http://{ui_host}:{ui_port}")
            elif open_browser:
                launch_browser(f"http://{ui_host}:{ui_port}")
        threading.Thread(target=_open_ui, daemon=True).start()

    # ── Main event processing loop ──
    logger.info("SOCeal is running. Press Ctrl+C to stop.")
    while True:
        try:
            event = event_queue.get(timeout=1.0)
            threat_logger.log_event()

            # Log the raw event to threat logger
            severity = event.get('severity', 'info')
            msg = event.get('message', str(event)[:120])
            if severity in ('critical', 'high'):
                threat_logger.log_threat(
                    event_type=event.get('type', 'unknown'),
                    severity=severity,
                    message=msg,
                    metadata=event,
                )

            # Pass to rules engine for evaluation
            rules_engine.process_event(event)

        except queue.Empty:
            continue
        except Exception as e:
            logger.error("Event processing error: %s", e)


if __name__ == '__main__':
    main()
