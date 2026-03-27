"""
SOCeal – Project VALE
Network Monitor: psutil-based live network connection monitoring.
Detects reverse shell ports, suspicious outbound C2, and abnormal connections.
"""

import threading
import time
import logging
from collections import defaultdict

logger = logging.getLogger('soceal.sensors.network')

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    logger.warning("psutil not installed — NetworkMonitor will run in stub mode")


C2_PORTS = {4444, 1337, 9001, 8888, 4445, 5555, 6666, 7777, 31337}
SMB_PORTS = {445, 139}
RDP_PORTS = {3389}
SUSPICIOUS_OUTBOUND_PORTS = C2_PORTS | SMB_PORTS


class NetworkMonitor:
    """Monitors live network connections for suspicious activity."""

    def __init__(self, event_queue, interval=10, rules=None):
        """
        Args:
            event_queue: queue.Queue for emitting network events.
            interval: Seconds between connection scans.
            rules: Optional list of rule dicts from rules.json (type=network).
        """
        self.event_queue = event_queue
        self.interval = interval
        self._rules = rules or []
        self._stop_event = threading.Event()
        self._thread = None
        self._known_conns = set()  # (laddr, raddr, status) tuples already seen

    def set_rules(self, rules):
        """Inject rules from the engine (type=network)."""
        self._rules = [r for r in rules if r.get('type') == 'network']

    def start(self):
        if not HAS_PSUTIL:
            logger.error("psutil not available — NetworkMonitor cannot run")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name='NetworkMonitor')
        self._thread.start()
        logger.info("NetworkMonitor started (interval=%ds)", self.interval)

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
            logger.info("NetworkMonitor stopped")

    def _monitor_loop(self):
        while not self._stop_event.is_set():
            try:
                self._scan_connections()
            except Exception as e:
                logger.error("NetworkMonitor scan error: %s", e)
            self._stop_event.wait(self.interval)

    def _scan_connections(self):
        try:
            conns = psutil.net_connections(kind='inet')
        except psutil.AccessDenied:
            logger.warning("NetworkMonitor: access denied — run as Administrator for full network visibility")
            return

        for conn in conns:
            if conn.status != 'ESTABLISHED':
                continue
            if not conn.raddr:
                continue

            rip = conn.raddr.ip
            rport = conn.raddr.port
            lport = conn.laddr.port if conn.laddr else 0

            conn_key = (rip, rport)
            if conn_key in self._known_conns:
                continue
            self._known_conns.add(conn_key)

            # Resolve process name
            proc_name = 'unknown'
            pid = conn.pid
            if pid:
                try:
                    proc_name = psutil.Process(pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            # Check against network rules
            for rule in self._rules:
                ports = rule.get('ports', [])
                if rport in ports:
                    severity = rule.get('severity', 'high')
                    rule_id = rule.get('id', 'NETWORK_RULE')
                    event = {
                        'type': 'network',
                        'rule_id': rule_id,
                        'source_ip': rip,
                        'remote_port': rport,
                        'local_port': lport,
                        'process_name': proc_name,
                        'pid': pid,
                        'severity': severity,
                        'direction': rule.get('direction', 'outbound'),
                        'action': rule.get('action', 'log'),
                        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                        'message': (
                            f"{proc_name} (PID {pid}) connected to "
                            f"{rip}:{rport} — matches rule {rule_id}"
                        ),
                    }
                    self.event_queue.put(event)
                    logger.warning(
                        "Network rule triggered: %s — %s:%d (process: %s PID %d)",
                        rule_id, rip, rport, proc_name, pid or 0
                    )
                    break

            # Built-in C2 port check (no rules needed)
            elif rport in C2_PORTS:
                event = {
                    'type': 'network',
                    'rule_id': 'REVERSE_SHELL_PORT',
                    'source_ip': rip,
                    'remote_port': rport,
                    'local_port': lport,
                    'process_name': proc_name,
                    'pid': pid,
                    'severity': 'critical',
                    'direction': 'outbound',
                    'action': 'block_ip',
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'message': f"Reverse shell C2 port {rport} detected — {proc_name} → {rip}:{rport}",
                }
                self.event_queue.put(event)
                logger.warning("C2 port detected: %s:%d via %s (PID %d)", rip, rport, proc_name, pid or 0)

    def get_connection_count(self):
        """Return total live ESTABLISHED connections."""
        if not HAS_PSUTIL:
            return 0
        try:
            return len([c for c in psutil.net_connections(kind='inet') if c.status == 'ESTABLISHED'])
        except Exception:
            return 0
