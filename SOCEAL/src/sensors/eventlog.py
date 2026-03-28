"""
SOCeal - Project VALE
EventLog Sensor: Real-time Windows Event Log subscription via pywin32.
"""

import threading
import queue
import time
import logging
from datetime import datetime, timezone

logger = logging.getLogger('soceal.sensors.eventlog')

try:
    import win32evtlog
    import win32event
    import win32con
    import pywintypes
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False
    logger.warning("pywin32 not installed -- EventLog sensor will run in stub mode")


class EventLogSensor:
    """Subscribes to Windows Event Logs and emits parsed events to a queue."""

    DEFAULT_CHANNELS = ['Security', 'System', 'Application']

    def __init__(self, event_queue, channels=None, poll_interval=1):
        """
        Args:
            event_queue: queue.Queue to emit parsed events into.
            channels: List of event log channel names to monitor.
            poll_interval: Seconds between poll cycles.
        """
        self.event_queue = event_queue
        self.channels = channels or self.DEFAULT_CHANNELS
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        """Start the event log monitoring thread."""
        if self._thread and self._thread.is_alive():
            logger.warning("EventLogSensor already running")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name='EventLogSensor')
        self._thread.start()
        logger.info("EventLogSensor started -- monitoring: %s", ', '.join(self.channels))

    def stop(self):
        """Stop the monitoring thread."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
            logger.info("EventLogSensor stopped")

    def _monitor_loop(self):
        """Main monitoring loop -- reads events from each channel."""
        if not HAS_WIN32:
            logger.error("pywin32 not available -- EventLogSensor cannot run")
            return

        handles = {}
        for channel in self.channels:
            try:
                handle = win32evtlog.OpenEventLog(None, channel)
                handles[channel] = handle
                logger.info("Opened event log: %s", channel)
            except pywintypes.error as e:
                logger.warning("Cannot open event log '%s': %s (may require admin)", channel, e)

        # Get current record numbers to only read new events
        bookmarks = {}
        for channel, handle in handles.items():
            try:
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                events = win32evtlog.ReadEventLog(handle, flags, 0)
                if events:
                    bookmarks[channel] = events[0].RecordNumber
                else:
                    bookmarks[channel] = 0
            except pywintypes.error:
                bookmarks[channel] = 0

        while not self._stop_event.is_set():
            for channel, handle in handles.items():
                try:
                    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    events = win32evtlog.ReadEventLog(handle, flags, 0)
                    for event in events:
                        if event.RecordNumber > bookmarks.get(channel, 0):
                            bookmarks[channel] = event.RecordNumber
                            parsed = self._parse_event(event, channel)
                            if parsed:
                                self.event_queue.put(parsed)
                except pywintypes.error as e:
                    if e.winerror == 23:  # ERROR_CRC -- log was cleared
                        logger.warning("Event log '%s' was cleared", channel)
                    else:
                        logger.debug("ReadEventLog error on '%s': %s", channel, e)
                except Exception as e:
                    logger.debug("Error reading '%s': %s", channel, e)

            self._stop_event.wait(self.poll_interval)

        # Cleanup
        for channel, handle in handles.items():
            try:
                win32evtlog.CloseEventLog(handle)
            except Exception:
                pass

    def _parse_event(self, raw_event, channel):
        """Parse a raw win32 event into a structured dict."""
        try:
            strings = raw_event.StringInserts or []
            source_ip = self._extract_ip(strings)
            process_name = ''
            process_id = 0

            # Try to extract process info from event strings
            for s in strings:
                if s and '.exe' in s.lower():
                    process_name = s.strip()
                    break

            # Map event types to levels
            level_map = {
                win32evtlog.EVENTLOG_ERROR_TYPE: 'error',
                win32evtlog.EVENTLOG_WARNING_TYPE: 'warning',
                win32evtlog.EVENTLOG_INFORMATION_TYPE: 'info',
                win32evtlog.EVENTLOG_AUDIT_SUCCESS: 'audit_success',
                win32evtlog.EVENTLOG_AUDIT_FAILURE: 'audit_failure',
            }

            return {
                'type': 'eventlog',
                'event_id': raw_event.EventID & 0xFFFF,  # Mask to get actual ID
                'level': level_map.get(raw_event.EventType, 'info'),
                'timestamp': str(raw_event.TimeGenerated),
                'user': str(raw_event.Sid) if raw_event.Sid else '',
                'source_ip': source_ip,
                'process_name': process_name,
                'process_id': process_id,
                'source': raw_event.SourceName or '',
                'channel': channel,
                'message': ' | '.join(strings[:5]) if strings else '',
                'record_number': raw_event.RecordNumber,
            }
        except Exception as e:
            logger.debug("Failed to parse event: %s", e)
            return None

    @staticmethod
    def _extract_ip(strings):
        """Try to extract an IP address from event string inserts."""
        import re
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        for s in (strings or []):
            if s:
                match = ip_pattern.search(s)
                if match:
                    ip = match.group()
                    # Skip loopback and common local
                    if ip not in ('127.0.0.1', '0.0.0.0'):
                        return ip
        return ''
