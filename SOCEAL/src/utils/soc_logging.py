"""
SOCeal – Project VALE
Logging: Structured threat and action logging, plus standard Python logging setup.
"""

import json
import time
import logging
from pathlib import Path
from threading import Lock
from collections import deque

logger = logging.getLogger('soceal.utils.logging')


def setup_logging(log_dir, level=logging.INFO):
    """Configure Python logging for the entire SOCeal application."""
    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger('soceal')
    root.setLevel(level)

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(logging.Formatter(
        '\033[36m%(asctime)s\033[0m [%(name)s] %(levelname)s: %(message)s',
        datefmt='%H:%M:%S'
    ))
    root.addHandler(ch)

    # File handler
    fh = logging.FileHandler(str(log_dir / 'soceal.log'), encoding='utf-8')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        '%(asctime)s [%(name)s] %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    root.addHandler(fh)

    logger.info("Logging initialized — log dir: %s", log_dir)


class ThreatLogger:
    """Structured JSON logging for threats and actions."""

    def __init__(self, log_dir):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        self._recent_threats = deque(maxlen=500)
        self._recent_actions = deque(maxlen=500)
        self._event_count_minute = deque(maxlen=600)  # 10 min of per-second counts
        self._events_this_second = 0
        self._last_second = int(time.time())

    def log_threat(self, event_type, severity, message, metadata=None):
        """Log a threat event."""
        record = {
            'event_type': event_type,
            'severity': severity,
            'message': message,
            'metadata': metadata or {},
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        }
        with self._lock:
            self._recent_threats.appendleft(record)
        self._append_file('threats.jsonl', record)
        self._tick_event()

    def log_action(self, action_type, detail, metadata=None):
        """Log a countermeasure action."""
        record = {
            'action_type': action_type,
            'detail': detail,
            'metadata': metadata or {},
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        }
        with self._lock:
            self._recent_actions.appendleft(record)
        self._append_file('actions.jsonl', record)

    def log_event(self):
        """Count an event for events-per-minute tracking."""
        self._tick_event()

    def get_recent_threats(self, limit=50):
        """Return recent threats."""
        with self._lock:
            return list(self._recent_threats)[:limit]

    def get_recent_actions(self, limit=50):
        """Return recent actions."""
        with self._lock:
            return list(self._recent_actions)[:limit]

    def get_stats(self):
        """Return aggregated stats for the UI."""
        now = int(time.time())

        # Events per minute
        epm = sum(self._event_count_minute)

        # Threats in last hour
        one_hour_ago = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() - 3600))
        threats_1h = sum(1 for t in self._recent_threats if t['timestamp'] >= one_hour_ago)

        # Blocked today
        today = time.strftime('%Y-%m-%d')
        blocked_today = sum(
            1 for a in self._recent_actions
            if a.get('action_type') == 'block_ip' and a['timestamp'].startswith(today)
        )

        return {
            'events_per_minute': epm,
            'threats_1h': threats_1h,
            'blocked_today': blocked_today,
        }

    def _tick_event(self):
        """Increment the per-second event counter."""
        now = int(time.time())
        if now != self._last_second:
            self._event_count_minute.append(self._events_this_second)
            self._events_this_second = 0
            self._last_second = now
        self._events_this_second += 1

    def _append_file(self, filename, record):
        """Append a JSON record to a log file."""
        try:
            with open(self.log_dir / filename, 'a', encoding='utf-8') as f:
                f.write(json.dumps(record) + '\n')
        except Exception as e:
            logger.error("Failed to write %s: %s", filename, e)
