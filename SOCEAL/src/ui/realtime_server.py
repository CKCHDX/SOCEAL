"""
SOCeal - Project VALE
Realtime Server: Flask-based local HTTP server for the dashboard and JSON API.
"""

import os
import sys
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
    logger.warning("Flask not installed -- RealtimeServer unavailable")


def get_resource_path(relative_path):
    """Get absolute path to a resource, works for dev and PyInstaller."""
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), relative_path)


class RealtimeServer:
    """Local HTTP server serving the SOCeal dashboard and JSON API endpoints."""

    def __init__(self, host='127.0.0.1', port=8081, dashboard_path=None,
                 threat_logger=None, rules_engine=None, action_handler=None,
                 process_monitor=None):
        self.host = host
        self.port = port
        self.dashboard_path = dashboard_path or get_resource_path('SOCeal_dashboard.html')
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

        # -- Dashboard --

        @app.route('/')
        def index():
            if os.path.exists(self.dashboard_path):
                return send_file(self.dashboard_path)
            return '<h1>SOCeal Dashboard not found</h1>', 404

        # -- Data endpoints --

        @app.route('/api/threats')
        def api_threats():
            threats = []
            if self.rules_engine:
                threats = self.rules_engine.get_active_threats()
            ui_threats = []
            for t in threats[:50]:
                event = t.get('event', {})
                ui_threats.append({
                    'name': t.get('name', t.get('rule_id', 'Unknown')),
                    'meta': t.get('meta', ''),
                    'severity': t.get('severity', 'medium'),
                    'timestamp': t.get('timestamp', ''),
                    'pid': event.get('pid') or event.get('process_id'),
                    'ip': event.get('source_ip', ''),
                    'path': event.get('path') or event.get('exe_path', ''),
                    'rule_id': t.get('rule_id', ''),
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

            proc_count = 0
            if self.process_monitor:
                proc_count = self.process_monitor.get_process_count()

            ips_blocked = 0
            try:
                from utils.firewall import get_blocked_ip_count
                ips_blocked = get_blocked_ip_count()
            except Exception:
                if self.action_handler:
                    ips_blocked = len([a for a in self.action_handler.get_recent_actions()
                                      if a.get('action_type') == 'block_ip'])

            quarantine_count = 0
            if self.action_handler:
                quarantine_count = self.action_handler.get_quarantine_count()

            net_connections = 0
            try:
                import psutil
                net_connections = len(psutil.net_connections(kind='inet'))
            except Exception:
                pass

            uptime_sec = int(time.time() - self._start_time)

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

        # -- Mode (GET + POST) --

        @app.route('/api/mode', methods=['GET', 'POST'])
        def api_mode():
            if request.method == 'GET':
                safe_mode = self.rules_engine.safe_mode if self.rules_engine else True
                return jsonify({'safe_mode': safe_mode})
            data = request.get_json(silent=True) or {}
            safe_mode = data.get('safe_mode', True)
            if self.rules_engine:
                self.rules_engine.set_safe_mode(safe_mode)
            if self.action_handler:
                self.action_handler.set_safe_mode(safe_mode)
            logger.info("Mode changed: safe_mode=%s", safe_mode)
            return jsonify({'safe_mode': safe_mode})

        # -- Manual action endpoints --

        @app.route('/api/action/kill', methods=['POST'])
        def api_action_kill():
            data = request.get_json(silent=True) or {}
            pid = data.get('pid')
            if not pid:
                return jsonify({'success': False, 'error': 'Missing pid'}), 400
            try:
                pid = int(pid)
            except (ValueError, TypeError):
                return jsonify({'success': False, 'error': 'Invalid pid'}), 400
            if self.action_handler:
                self.action_handler.execute('kill_process', {
                    'event': {'pid': pid, 'name': data.get('name', ''), 'process_name': data.get('name', '')},
                    'rule_id': 'MANUAL',
                    'severity': 'high',
                    'message': f"Manual kill: PID {pid}",
                })
                return jsonify({'success': True, 'pid': pid})
            return jsonify({'success': False, 'error': 'Action handler not available'}), 500

        @app.route('/api/action/block', methods=['POST'])
        def api_action_block():
            data = request.get_json(silent=True) or {}
            ip = data.get('ip', '').strip()
            if not ip:
                return jsonify({'success': False, 'error': 'Missing ip'}), 400
            if self.action_handler:
                self.action_handler.execute('block_ip', {
                    'event': {'source_ip': ip},
                    'ip': ip,
                    'rule_id': 'MANUAL',
                    'severity': 'high',
                    'message': f"Manual block: {ip}",
                })
                return jsonify({'success': True, 'ip': ip})
            return jsonify({'success': False, 'error': 'Action handler not available'}), 500

        @app.route('/api/action/unblock', methods=['POST'])
        def api_action_unblock():
            data = request.get_json(silent=True) or {}
            ip = data.get('ip', '').strip()
            if not ip:
                return jsonify({'success': False, 'error': 'Missing ip'}), 400
            if self.action_handler:
                self.action_handler.execute('unblock_ip', {
                    'ip': ip,
                    'rule_id': 'MANUAL',
                    'severity': 'info',
                    'message': f"Manual unblock: {ip}",
                })
                return jsonify({'success': True, 'ip': ip})
            return jsonify({'success': False, 'error': 'Action handler not available'}), 500

        @app.route('/api/action/quarantine', methods=['POST'])
        def api_action_quarantine():
            data = request.get_json(silent=True) or {}
            filepath = data.get('path', '').strip()
            if not filepath:
                return jsonify({'success': False, 'error': 'Missing path'}), 400
            if self.action_handler:
                self.action_handler.execute('quarantine', {
                    'event': {'path': filepath, 'filename': os.path.basename(filepath)},
                    'rule_id': 'MANUAL',
                    'severity': 'high',
                    'message': f"Manual quarantine: {filepath}",
                })
                return jsonify({'success': True, 'path': filepath})
            return jsonify({'success': False, 'error': 'Action handler not available'}), 500

        # -- Live data endpoints --

        @app.route('/api/processes')
        def api_processes():
            if self.process_monitor:
                processes = self.process_monitor.get_process_list()
                return jsonify(processes)
            return jsonify([])

        @app.route('/api/connections')
        def api_connections():
            try:
                import psutil
                connections = []
                pid_name_map = {}
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        pid_name_map[proc.info['pid']] = proc.info['name']
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                for conn in psutil.net_connections(kind='inet'):
                    if conn.status == 'NONE':
                        continue
                    local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ''
                    remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ''
                    connections.append({
                        'local': local,
                        'remote': remote,
                        'remote_ip': conn.raddr.ip if conn.raddr else '',
                        'remote_port': conn.raddr.port if conn.raddr else 0,
                        'status': conn.status,
                        'pid': conn.pid or 0,
                        'process': pid_name_map.get(conn.pid, ''),
                    })
                # Sort: ESTABLISHED first, then by remote IP
                connections.sort(key=lambda c: (c['status'] != 'ESTABLISHED', c['remote']))
                return jsonify(connections[:200])
            except Exception as e:
                logger.error("connections API error: %s", e)
                return jsonify([])

        @app.route('/api/blocked-ips')
        def api_blocked_ips():
            try:
                from utils.firewall import list_soceal_rules, RULE_PREFIX
                rules = list_soceal_rules()
                ips = [r.replace(RULE_PREFIX, '') for r in rules]
                return jsonify(ips)
            except Exception as e:
                logger.error("blocked-ips API error: %s", e)
                return jsonify([])

        @app.route('/api/quarantine')
        def api_quarantine_list():
            if not self.action_handler:
                return jsonify([])
            try:
                qdir = self.action_handler.quarantine_dir
                files = []
                for f in qdir.iterdir():
                    if f.name.endswith('.meta.json'):
                        continue
                    meta_path = qdir / f"{f.name}.meta.json"
                    meta = {}
                    if meta_path.exists():
                        import json
                        with open(meta_path, 'r') as mf:
                            meta = json.load(mf)
                    files.append({
                        'filename': f.name,
                        'original_path': meta.get('original_path', ''),
                        'sha256': meta.get('sha256', ''),
                        'timestamp': meta.get('timestamp', ''),
                        'size': meta.get('size', f.stat().st_size if f.exists() else 0),
                    })
                files.sort(key=lambda x: x['timestamp'], reverse=True)
                return jsonify(files)
            except Exception as e:
                logger.error("quarantine API error: %s", e)
                return jsonify([])

        self._app = app
        return app

    def start(self):
        """Start the Flask server in a background thread."""
        if not HAS_FLASK:
            logger.error("Flask not available -- server cannot start")
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
        """Stop the server (best-effort -- Flask doesn't have a clean shutdown in threads)."""
        logger.info("RealtimeServer stop requested")

    @property
    def url(self):
        return f"http://{self.host}:{self.port}"
