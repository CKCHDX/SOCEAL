"""
SOCeal – Project VALE
Realtime Server: Flask-based local HTTP server for the dashboard and JSON API.
"""

import os
import time
import logging
import threading
from pathlib import Path

logger = logging.getLogger('soceal.ui.server')

try:
    from flask import Flask, jsonify, request, send_file
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False
    logger.warning("Flask not installed — RealtimeServer unavailable")


class RealtimeServer:
    """Local HTTP server serving the SOCeal dashboard and JSON API endpoints."""

    def __init__(self, host='127.0.0.1', port=8081, dashboard_path=None,
                 threat_logger=None, rules_engine=None, action_handler=None,
                 process_monitor=None):
        """
        Args:
            host: Bind address (default 127.0.0.1).
            port: Port number (default 8081).
            dashboard_path: Path to SOCeal_dashboard.html.
            threat_logger: ThreatLogger instance.
            rules_engine: RulesEngine instance.
            action_handler: ActionHandler instance.
            process_monitor: ProcessMonitor instance.
        """
        self.host = host
        self.port = port
        self.dashboard_path = dashboard_path or str(
            Path(__file__).parent / 'SOCeal_dashboard.html'
        )
        self.threat_logger = threat_logger
        self.rules_engine = rules_engine
        self.action_handler = action_handler
        self.process_monitor = process_monitor
        self._start_time = time.time()
        self._thread = None
        self._app = None

    def create_app(self):
        """Create and configure the Flask application."""
        if not HAS_FLASK:
            raise RuntimeError("Flask not installed")

        app = Flask(__name__)
        app.config['JSON_SORT_KEYS'] = False

        # Suppress Flask request logging
        wlog = logging.getLogger('werkzeug')
        wlog.setLevel(logging.WARNING)

        @app.after_request
        def add_cors(response):
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
            return response

        @app.route('/')
        def index():
            if os.path.exists(self.dashboard_path):
                return send_file(self.dashboard_path)
            return '<h1>SOCeal Dashboard not found</h1>', 404

        @app.route('/api/threats')
        def api_threats():
            threats = []
            if self.rules_engine:
                threats = self.rules_engine.get_active_threats()
            # Format for UI
            ui_threats = []
            for t in threats[:50]:
                ui_threats.append({
                    'name': t.get('name', t.get('rule_id', 'Unknown')),
                    'meta': t.get('meta', ''),
                    'severity': t.get('severity', 'medium'),
                })
            return jsonify(ui_threats)

        @app.route('/api/actions')
        def api_actions():
            actions = []
            if self.action_handler:
                actions = self.action_handler.get_recent_actions()
            return jsonify(actions[:50])

        @app.route('/api/stats')
        def api_stats():
            stats = {}
            if self.threat_logger:
                stats.update(self.threat_logger.get_stats())

            # Process count
            proc_count = 0
            if self.process_monitor:
                proc_count = self.process_monitor.get_process_count()

            # IP block count
            ips_blocked = 0
            if self.action_handler:
                ips_blocked = len([a for a in self.action_handler.get_recent_actions()
                                  if a.get('action_type') == 'block_ip'])

            # Quarantine count
            quarantine_count = 0
            if self.action_handler:
                quarantine_count = self.action_handler.get_quarantine_count()

            # Net connections
            net_connections = 0
            try:
                import psutil
                net_connections = len(psutil.net_connections(kind='inet'))
            except Exception:
                pass

            # Uptime
            uptime_sec = int(time.time() - self._start_time)

            # Security score (simple heuristic)
            threats_1h = stats.get('threats_1h', 0)
            score = max(0, min(100, 100 - threats_1h * 5 - ips_blocked * 3))

            stats.update({
                'security_score': score,
                'processes_watched': proc_count,
                'ips_blocked': ips_blocked,
                'files_quarantined': quarantine_count,
                'net_connections': net_connections,
                'uptime': uptime_sec,
            })
            return jsonify(stats)

        @app.route('/api/events')
        def api_events():
            events = []
            if self.threat_logger:
                events = self.threat_logger.get_recent_threats(limit=100)
            return jsonify(events)

        @app.route('/api/mode', methods=['POST'])
        def api_mode():
            data = request.get_json(silent=True) or {}
            safe_mode = data.get('safe_mode', True)
            if self.rules_engine:
                self.rules_engine.set_safe_mode(safe_mode)
            if self.action_handler:
                self.action_handler.set_safe_mode(safe_mode)
            logger.info("Mode changed: safe_mode=%s", safe_mode)
            return jsonify({'safe_mode': safe_mode})

        self._app = app
        return app

    def start(self):
        """Start the Flask server in a background thread."""
        if not HAS_FLASK:
            logger.error("Flask not available — server cannot start")
            return

        app = self.create_app()
        self._thread = threading.Thread(
            target=lambda: app.run(
                host=self.host, port=self.port,
                threaded=True, use_reloader=False,
            ),
            daemon=True,
            name='RealtimeServer',
        )
        self._thread.start()
        logger.info("RealtimeServer started at http://%s:%d", self.host, self.port)

    def stop(self):
        """Stop the server (best-effort — Flask doesn't have a clean shutdown in threads)."""
        logger.info("RealtimeServer stop requested")

    @property
    def url(self):
        return f"http://{self.host}:{self.port}"
