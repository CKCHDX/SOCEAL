"""
SOCeal – Project VALE
Actions: Countermeasure execution — kill processes, quarantine files, block IPs.
"""

import os
import json
import time
import shutil
import hashlib
import logging
from pathlib import Path
from threading import Lock

logger = logging.getLogger('soceal.rules.actions')

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


class ActionHandler:
    """Executes countermeasures and logs all actions."""

    def __init__(self, quarantine_dir, log_dir, safe_mode=True):
        """
        Args:
            quarantine_dir: Directory to move quarantined files into.
            log_dir: Directory for action and threat logs.
            safe_mode: If True, only log — never execute destructive actions.
        """
        self.quarantine_dir = Path(quarantine_dir)
        self.log_dir = Path(log_dir)
        self.safe_mode = safe_mode
        self._lock = Lock()
        self._recent_actions = []
        self._max_actions = 200

        # Ensure directories exist
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def execute(self, action_type, context):
        """
        Dispatch and execute an action.

        Args:
            action_type: One of 'kill_process', 'quarantine', 'block_ip', 'unblock_ip', 'log'.
            context: Dict with action-specific data.
        """
        handlers = {
            'kill_process': self._kill_process,
            'quarantine': self._quarantine_file,
            'block_ip': self._block_ip,
            'unblock_ip': self._unblock_ip,
            'log': self._log_only,
        }

        handler = handlers.get(action_type, self._log_only)

        try:
            result = handler(context)
            self._record_action(action_type, context, result)
        except Exception as e:
            logger.error("Action '%s' failed: %s", action_type, e)
            self._record_action(action_type, context, {'success': False, 'error': str(e)})

    def _kill_process(self, context):
        """Kill a process by PID."""
        event = context.get('event', {})
        pid = event.get('pid') or event.get('process_id')
        name = event.get('name') or event.get('process_name', 'unknown')

        if not pid:
            logger.warning("kill_process: no PID in context")
            return {'success': False, 'error': 'No PID'}

        if not HAS_PSUTIL:
            logger.error("psutil not available — cannot kill process")
            return {'success': False, 'error': 'psutil not available'}

        try:
            proc = psutil.Process(pid)
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except psutil.TimeoutExpired:
                proc.kill()
                logger.warning("Process %s (PID %d) did not terminate — force killed", name, pid)

            logger.info("Killed process: %s (PID %d)", name, pid)
            return {'success': True, 'pid': pid, 'name': name}

        except psutil.NoSuchProcess:
            logger.info("Process %d already terminated", pid)
            return {'success': True, 'pid': pid, 'note': 'already terminated'}
        except psutil.AccessDenied:
            logger.error("Access denied killing PID %d — may need admin", pid)
            return {'success': False, 'error': 'Access denied'}

    def _quarantine_file(self, context):
        """Move a file to the quarantine directory."""
        event = context.get('event', {})
        filepath = event.get('path', '')

        if not filepath or not Path(filepath).exists():
            logger.warning("quarantine: file not found: %s", filepath)
            return {'success': False, 'error': 'File not found'}

        src = Path(filepath)
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        dest_name = f"{timestamp}_{src.name}"
        dest = self.quarantine_dir / dest_name

        try:
            # Calculate hash before moving
            file_hash = self._sha256(src)

            shutil.move(str(src), str(dest))
            logger.info("Quarantined: %s → %s", src, dest)

            # Write metadata
            meta = {
                'original_path': str(src),
                'quarantine_path': str(dest),
                'sha256': file_hash,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'size': dest.stat().st_size,
            }
            meta_path = self.quarantine_dir / f"{dest_name}.meta.json"
            with open(meta_path, 'w') as f:
                json.dump(meta, f, indent=2)

            return {'success': True, 'original': str(src), 'quarantined': str(dest), 'sha256': file_hash}

        except PermissionError:
            logger.error("Permission denied quarantining: %s", src)
            return {'success': False, 'error': 'Permission denied'}

    def _block_ip(self, context):
        """Block an IP address using Windows Firewall (netsh)."""
        import subprocess

        event = context.get('event', {})
        ip = context.get('ip') or event.get('source_ip', '')

        if not ip:
            logger.warning("block_ip: no IP in context")
            return {'success': False, 'error': 'No IP'}

        rule_name = f"SOCeal_Block_{ip}"

        try:
            cmd = [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}',
                'dir=in', 'action=block',
                f'remoteip={ip}',
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                logger.info("Blocked IP: %s (rule: %s)", ip, rule_name)
                return {'success': True, 'ip': ip, 'rule': rule_name}
            else:
                logger.error("Failed to block IP %s: %s", ip, result.stderr.strip())
                return {'success': False, 'error': result.stderr.strip()}

        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Command timed out'}
        except FileNotFoundError:
            return {'success': False, 'error': 'netsh not found'}

    def _unblock_ip(self, context):
        """Remove a SOCeal firewall block rule."""
        import subprocess

        ip = context.get('ip', '')
        if not ip:
            return {'success': False, 'error': 'No IP'}

        rule_name = f"SOCeal_Block_{ip}"

        try:
            cmd = [
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                f'name={rule_name}',
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                logger.info("Unblocked IP: %s", ip)
                return {'success': True, 'ip': ip}
            else:
                return {'success': False, 'error': result.stderr.strip()}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _log_only(self, context):
        """Log the event without taking destructive action."""
        rule_id = context.get('rule_id', 'MANUAL')
        message = context.get('message', '')
        severity = context.get('severity', 'info')
        logger.info("LOG [%s/%s]: %s", rule_id, severity, message)
        return {'success': True, 'action': 'logged'}

    def _record_action(self, action_type, context, result):
        """Record an action for UI display and log file."""
        event = context.get('event', {})

        # Map action types to UI display
        icon_map = {
            'kill_process': '⚡',
            'quarantine': '📦',
            'block_ip': '🔒',
            'unblock_ip': '🔓',
            'log': '📋',
        }
        title_map = {
            'kill_process': 'Process Killed',
            'quarantine': 'File Quarantined',
            'block_ip': 'IP Blocked',
            'unblock_ip': 'IP Unblocked',
            'log': 'Event Logged',
        }

        action_record = {
            'icon': icon_map.get(action_type, '📋'),
            'title': title_map.get(action_type, action_type),
            'detail': self._build_detail(action_type, event, result),
            'time': time.strftime('%H:%M'),
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'action_type': action_type,
            'success': result.get('success', False),
            'rule_id': context.get('rule_id', ''),
        }

        with self._lock:
            self._recent_actions.insert(0, action_record)
            if len(self._recent_actions) > self._max_actions:
                self._recent_actions = self._recent_actions[:self._max_actions]

        # Write to log file
        self._append_log('actions.jsonl', action_record)

    def _build_detail(self, action_type, event, result):
        """Build a detail string for the action."""
        if action_type == 'kill_process':
            name = event.get('name') or event.get('process_name', '?')
            pid = event.get('pid') or event.get('process_id', '?')
            return f"{name} · PID {pid}"
        elif action_type == 'quarantine':
            return event.get('filename') or Path(event.get('path', '?')).name
        elif action_type == 'block_ip':
            return event.get('source_ip', result.get('ip', '?'))
        elif action_type == 'log':
            return event.get('message', event.get('reason', ''))[:80]
        return str(result)[:80]

    def _append_log(self, filename, record):
        """Append a JSON record to a log file."""
        try:
            log_path = self.log_dir / filename
            with open(log_path, 'a') as f:
                f.write(json.dumps(record) + '\n')
        except Exception as e:
            logger.error("Failed to write to %s: %s", filename, e)

    @staticmethod
    def _sha256(filepath):
        """Calculate SHA256 hash of a file."""
        h = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return h.hexdigest()

    def get_recent_actions(self):
        """Return recent actions for UI display."""
        with self._lock:
            return list(self._recent_actions)

    def get_quarantine_count(self):
        """Return number of files in quarantine."""
        try:
            return len([f for f in self.quarantine_dir.iterdir()
                       if not f.name.endswith('.meta.json')])
        except Exception:
            return 0

    def set_safe_mode(self, enabled):
        """Toggle safe mode."""
        self.safe_mode = enabled
        logger.info("ActionHandler safe mode %s", "ENABLED" if enabled else "DISABLED")
