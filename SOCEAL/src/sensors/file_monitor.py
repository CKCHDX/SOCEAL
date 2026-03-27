"""
SOCeal – Project VALE
File Monitor: watchdog-based file system monitoring for suspicious file activity.
"""

import threading
import os
import time
import logging
from pathlib import Path

logger = logging.getLogger('soceal.sensors.file')

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False
    logger.warning("watchdog not installed — FileMonitor will run in stub mode")


class SuspiciousFileHandler(FileSystemEventHandler if HAS_WATCHDOG else object):
    """Handles file system events and flags suspicious files."""

    SUSPICIOUS_EXTENSIONS = {
        '.exe', '.scr', '.pif', '.bat', '.cmd', '.ps1', '.vbs',
        '.js', '.wsf', '.hta', '.cpl', '.msi', '.dll', '.com',
    }

    def __init__(self, event_queue, watch_path):
        if HAS_WATCHDOG:
            super().__init__()
        self.event_queue = event_queue
        self.watch_path = watch_path

    def on_created(self, event):
        """Called when a file is created."""
        if event.is_directory:
            return
        self._check_file(event.src_path, 'created')

    def on_modified(self, event):
        """Called when a file is modified — only flag executables."""
        if event.is_directory:
            return
        ext = Path(event.src_path).suffix.lower()
        if ext in self.SUSPICIOUS_EXTENSIONS:
            self._check_file(event.src_path, 'modified')

    def _check_file(self, filepath, action):
        """Evaluate a file event for suspiciousness."""
        try:
            path = Path(filepath)
            ext = path.suffix.lower()
            filename = path.name

            # Determine severity
            if ext in self.SUSPICIOUS_EXTENSIONS:
                severity = 'high'
                reason = f"Suspicious file {action}: {filename} ({ext})"
            else:
                # Non-suspicious extension — only log in certain dirs
                severity = 'low'
                reason = f"File {action}: {filename}"
                # Skip low-severity events to avoid noise
                return

            event = {
                'type': 'file',
                'path': str(filepath),
                'filename': filename,
                'extension': ext,
                'action': action,
                'watch_path': str(self.watch_path),
                'severity': severity,
                'reason': reason,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'message': reason,
            }
            self.event_queue.put(event)
            logger.warning("Suspicious file event: %s", reason)

        except Exception as e:
            logger.debug("Error checking file %s: %s", filepath, e)


class FileMonitor:
    """Monitors filesystem directories for suspicious file creation."""

    def __init__(self, event_queue, watch_paths=None):
        """
        Args:
            event_queue: queue.Queue for emitting file events.
            watch_paths: List of directory paths to monitor.
                         Defaults to user Downloads, Temp, and AppData\Roaming.
        """
        self.event_queue = event_queue

        if watch_paths:
            self.watch_paths = [Path(p) for p in watch_paths]
        else:
            user_home = Path.home()
            self.watch_paths = [
                user_home / 'Downloads',
                Path(os.environ.get('TEMP', user_home / 'AppData' / 'Local' / 'Temp')),
                user_home / 'AppData' / 'Roaming',
            ]

        self._observer = None

    def start(self):
        """Start file monitoring."""
        if not HAS_WATCHDOG:
            logger.error("watchdog not available — FileMonitor cannot run")
            return

        self._observer = Observer()

        for watch_path in self.watch_paths:
            if watch_path.exists() and watch_path.is_dir():
                handler = SuspiciousFileHandler(self.event_queue, watch_path)
                self._observer.schedule(handler, str(watch_path), recursive=False)
                logger.info("Watching directory: %s", watch_path)
            else:
                logger.warning("Watch path does not exist: %s", watch_path)

        self._observer.start()
        logger.info("FileMonitor started — watching %d directories", len(self.watch_paths))

    def stop(self):
        """Stop file monitoring."""
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)
            logger.info("FileMonitor stopped")
