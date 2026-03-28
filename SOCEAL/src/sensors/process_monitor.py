"""
SOCeal - Project VALE
Process Monitor: psutil-based process enumeration and suspicious process detection.
"""

import threading
import queue
import time
import re
import logging
from pathlib import Path

logger = logging.getLogger('soceal.sensors.process')

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    logger.warning("psutil not installed -- ProcessMonitor will run in stub mode")


class ProcessMonitor:
    """Monitors running processes and detects suspicious activity."""

    SUSPICIOUS_NAMES = {
        'mimikatz', 'mimikatz.exe',
        'cobalt', 'cobaltstrike', 'beacon.exe',
        'nc.exe', 'nc64.exe', 'ncat.exe', 'ncat',
        'plink.exe', 'plink',
        'psexec.exe', 'psexec64.exe',
        'procdump.exe', 'procdump64.exe',
        'lazagne.exe',
        'rubeus.exe',
        'sharphound.exe', 'bloodhound.exe',
        'winpeas.exe', 'linpeas.sh',
        'chisel.exe',
        'socat.exe',
        'msfconsole', 'msfvenom',
        'certutil.exe',  # Sometimes abused for download
    }

    SUSPICIOUS_PATH_PATTERNS = [
        re.compile(r'\\Temp\\[a-z0-9]{4,8}\.exe$', re.IGNORECASE),
        re.compile(r'\\AppData\\Local\\Temp\\', re.IGNORECASE),
        re.compile(r'\\AppData\\Roaming\\[^\\]+\.exe$', re.IGNORECASE),
        re.compile(r'\\Downloads\\[^\\]+\.(scr|pif|bat|cmd|vbs|js|ps1)$', re.IGNORECASE),
    ]

    def __init__(self, event_queue, interval=5, suspicious_names=None):
        """
        Args:
            event_queue: queue.Queue for emitting process events.
            interval: Polling interval in seconds.
            suspicious_names: Optional custom set of suspicious process names.
        """
        self.event_queue = event_queue
        self.interval = interval
        self.suspicious_names = suspicious_names or self.SUSPICIOUS_NAMES
        self._stop_event = threading.Event()
        self._thread = None
        self._known_pids = set()

    def start(self):
        """Start process monitoring thread."""
        if self._thread and self._thread.is_alive():
            logger.warning("ProcessMonitor already running")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name='ProcessMonitor')
        self._thread.start()
        logger.info("ProcessMonitor started (interval=%ds)", self.interval)

    def stop(self):
        """Stop the monitoring thread."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
            logger.info("ProcessMonitor stopped")

    def get_process_count(self):
        """Return current number of running processes."""
        if not HAS_PSUTIL:
            return 0
        try:
            return len(list(psutil.process_iter()))
        except Exception:
            return 0

    def _monitor_loop(self):
        """Main monitoring loop."""
        if not HAS_PSUTIL:
            logger.error("psutil not available -- ProcessMonitor cannot run")
            return

        # Initial snapshot
        self._known_pids = {p.pid for p in psutil.process_iter()}

        while not self._stop_event.is_set():
            try:
                current_pids = set()
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'ppid', 'create_time']):
                    try:
                        info = proc.info
                        current_pids.add(info['pid'])

                        # Only check new processes
                        if info['pid'] in self._known_pids:
                            continue

                        suspicious, reason, severity = self._check_suspicious(info)
                        if suspicious:
                            event = {
                                'type': 'process',
                                'pid': info['pid'],
                                'name': info.get('name', 'unknown'),
                                'exe_path': info.get('exe', ''),
                                'cmdline': ' '.join(info.get('cmdline') or []),
                                'parent_pid': info.get('ppid', 0),
                                'severity': severity,
                                'reason': reason,
                                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                                'message': f"Suspicious process: {info.get('name', 'unknown')} (PID {info['pid']}) -- {reason}",
                            }
                            self.event_queue.put(event)
                            logger.warning("Suspicious process detected: %s (PID %d) -- %s",
                                         info.get('name'), info['pid'], reason)

                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue

                self._known_pids = current_pids

            except Exception as e:
                logger.error("ProcessMonitor error: %s", e)

            self._stop_event.wait(self.interval)

    def _check_suspicious(self, proc_info):
        """
        Check if a process is suspicious.

        Returns:
            (is_suspicious: bool, reason: str, severity: str)
        """
        name = (proc_info.get('name') or '').lower()
        exe = proc_info.get('exe') or ''
        cmdline = ' '.join(proc_info.get('cmdline') or [])

        # Check suspicious names
        if name in {n.lower() for n in self.suspicious_names}:
            return True, f"Known suspicious tool: {name}", 'critical'

        # Check suspicious paths
        if exe:
            for pattern in self.SUSPICIOUS_PATH_PATTERNS:
                if pattern.search(exe):
                    return True, f"Executable in suspicious path: {exe}", 'high'

        # Check PowerShell encoded commands
        if 'powershell' in name or 'pwsh' in name:
            if '-encodedcommand' in cmdline.lower() or '-enc ' in cmdline.lower():
                return True, "PowerShell with encoded command", 'critical'
            if '-nop' in cmdline.lower() and '-w hidden' in cmdline.lower():
                return True, "PowerShell hidden window with no profile", 'high'

        # Check cmd spawning powershell (process chain)
        if 'cmd' in name:
            if 'powershell' in cmdline.lower() or 'pwsh' in cmdline.lower():
                return True, "CMD spawning PowerShell", 'high'

        # Check certutil abuse (download)
        if 'certutil' in name and ('-urlcache' in cmdline.lower() or '-split' in cmdline.lower()):
            return True, "Certutil used for download", 'high'

        return False, '', ''

    def get_process_list(self):
        """
        Return full process table for the dashboard UI.

        Returns:
            list[dict]: Each dict has pid, name, cpu_percent, memory_mb,
                        exe_path, cmdline, status, suspicious, reason.
        """
        if not HAS_PSUTIL:
            return []

        processes = []
        try:
            # First call to cpu_percent to initialize (returns 0.0 on first call)
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'status', 'memory_info', 'cpu_percent']):
                try:
                    info = proc.info
                    suspicious, reason, severity = self._check_suspicious(info)

                    mem_info = info.get('memory_info')
                    memory_mb = round(mem_info.rss / (1024 * 1024), 1) if mem_info else 0

                    processes.append({
                        'pid': info['pid'],
                        'name': info.get('name', 'unknown'),
                        'cpu_percent': info.get('cpu_percent', 0) or 0,
                        'memory_mb': memory_mb,
                        'exe_path': info.get('exe') or '',
                        'cmdline': ' '.join(info.get('cmdline') or []),
                        'status': info.get('status', ''),
                        'suspicious': suspicious,
                        'reason': reason,
                        'severity': severity if suspicious else '',
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception as e:
            logger.error("get_process_list error: %s", e)

        # Sort: suspicious first, then by memory descending
        processes.sort(key=lambda p: (not p['suspicious'], -p['memory_mb']))
        return processes

    def get_process_tree(self, pid):
        """Get parent/child process tree for a given PID."""
        if not HAS_PSUTIL:
            return []
        tree = []
        try:
            proc = psutil.Process(pid)
            # Parents
            parent = proc.parent()
            while parent:
                tree.insert(0, {
                    'pid': parent.pid,
                    'name': parent.name(),
                    'relation': 'parent',
                })
                parent = parent.parent()
            # Self
            tree.append({'pid': pid, 'name': proc.name(), 'relation': 'self'})
            # Children
            for child in proc.children(recursive=True):
                tree.append({
                    'pid': child.pid,
                    'name': child.name(),
                    'relation': 'child',
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return tree
