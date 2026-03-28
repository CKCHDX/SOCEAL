"""
SOCeal - Project VALE
Rules Engine: Event-based rule matching with rolling buffers and threshold detection.
"""

import json
import time
import logging
from collections import defaultdict
from threading import Lock

logger = logging.getLogger('soceal.rules.engine')


class RulesEngine:
    """Evaluates incoming events against a configurable ruleset."""

    def __init__(self, rules_path, action_handler, safe_mode=True):
        """
        Args:
            rules_path: Path to rules.json file.
            action_handler: ActionHandler instance for executing countermeasures.
            safe_mode: If True, only log -- never execute destructive actions.
        """
        self.rules_path = rules_path
        self.action_handler = action_handler
        self.safe_mode = safe_mode
        self.rules = []
        self._lock = Lock()

        # Rolling event buffers: key -> list of timestamps
        self._ip_buffer = defaultdict(list)   # ip -> [timestamps]
        self._user_buffer = defaultdict(list) # user -> [timestamps]
        self._event_buffer = defaultdict(list) # event_id -> [timestamps]

        # Active threats list
        self._active_threats = []
        self._max_threats = 100

        self.reload_rules()

    def reload_rules(self):
        """Load or reload rules from the JSON file."""
        try:
            with open(self.rules_path, 'r') as f:
                data = json.load(f)
            self.rules = data.get('rules', data) if isinstance(data, dict) else data
            logger.info("Loaded %d rules from %s", len(self.rules), self.rules_path)
        except FileNotFoundError:
            logger.warning("Rules file not found: %s -- using empty ruleset", self.rules_path)
            self.rules = []
        except json.JSONDecodeError as e:
            logger.error("Invalid JSON in rules file: %s", e)
            self.rules = []

    def process_event(self, event):
        """
        Evaluate an event against all enabled rules.

        Args:
            event: Dict with keys like type, event_id, source_ip, process_name, etc.
        """
        now = time.time()

        # Update rolling buffers
        ip = event.get('source_ip', '')
        user = event.get('user', '')
        eid = event.get('event_id', 0)

        if ip:
            self._ip_buffer[ip].append(now)
        if user:
            self._user_buffer[user].append(now)
        if eid:
            self._event_buffer[eid].append(now)

        # Evaluate each rule
        for rule in self.rules:
            if not rule.get('enabled', True):
                continue

            try:
                triggered = False
                context = {}

                rule_type = rule.get('type', '')
                event_type = event.get('type', '')

                # Match rule type to event type
                if rule_type == 'eventlog' and event_type == 'eventlog':
                    if rule.get('event_id') and rule['event_id'] == eid:
                        if rule.get('threshold') and rule.get('window_seconds'):
                            triggered, context = self._check_threshold_rule(rule, event, now)
                        else:
                            triggered = True
                            context = {'event': event}

                elif rule_type == 'process' and event_type == 'process':
                    triggered, context = self._check_pattern_rule(rule, event)

                elif rule_type == 'file' and event_type == 'file':
                    triggered, context = self._check_pattern_rule(rule, event)

                if triggered:
                    self._trigger_rule(rule, event, context)

            except Exception as e:
                logger.error("Error evaluating rule '%s': %s", rule.get('id', '?'), e)

    def _check_threshold_rule(self, rule, event, now):
        """Check if a threshold-based rule has been triggered."""
        window = rule.get('window_seconds', 60)
        threshold = rule.get('threshold', 10)
        ip = event.get('source_ip', '')
        eid = event.get('event_id', 0)

        # Clean old entries and count
        if ip:
            buf = self._ip_buffer[ip]
            self._ip_buffer[ip] = [t for t in buf if now - t < window]
            count = len(self._ip_buffer[ip])
        else:
            buf = self._event_buffer.get(eid, [])
            self._event_buffer[eid] = [t for t in buf if now - t < window]
            count = len(self._event_buffer[eid])

        if count >= threshold:
            return True, {
                'event': event,
                'count': count,
                'window': window,
                'threshold': threshold,
                'ip': ip,
            }
        return False, {}

    def _check_pattern_rule(self, rule, event):
        """Check if a pattern-based rule matches the event."""
        patterns = rule.get('patterns', [])
        if not patterns:
            # If no patterns specified, match by severity or reason
            reason = event.get('reason', '').lower()
            rule_id = rule.get('id', '').lower()
            if rule_id and any(keyword in reason for keyword in rule_id.lower().split('_')):
                return True, {'event': event}
            return False, {}

        name = (event.get('name') or event.get('process_name') or event.get('filename', '')).lower()
        cmdline = event.get('cmdline', '').lower()
        path = (event.get('exe_path') or event.get('path', '')).lower()

        for pattern in patterns:
            p = pattern.lower()
            if p in name or p in cmdline or p in path:
                return True, {'event': event, 'matched_pattern': pattern}

        return False, {}

    def _trigger_rule(self, rule, event, context):
        """Execute the action for a triggered rule."""
        rule_id = rule.get('id', 'UNKNOWN')
        action = rule.get('action', 'log')
        severity = rule.get('severity', event.get('severity', 'medium'))

        logger.warning("Rule triggered: %s (severity=%s, action=%s)", rule_id, severity, action)

        # Record as active threat
        threat = {
            'rule_id': rule_id,
            'name': rule.get('name', rule_id.replace('_', ' ').title()),
            'severity': severity,
            'action': action,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'meta': self._build_meta(event, context),
            'event': event,
        }

        with self._lock:
            self._active_threats.insert(0, threat)
            if len(self._active_threats) > self._max_threats:
                self._active_threats = self._active_threats[:self._max_threats]

        # Execute action
        if self.safe_mode and action != 'log':
            logger.info("SAFE MODE: Would execute '%s' but safe_mode is ON -- logging only", action)
            self.action_handler.execute('log', {
                'rule_id': rule_id,
                'severity': severity,
                'message': f"[SAFE MODE] Rule {rule_id} triggered -- action '{action}' suppressed",
                'event': event,
            })
        else:
            self.action_handler.execute(action, {
                'rule_id': rule_id,
                'severity': severity,
                'event': event,
                **context,
            })

    def _build_meta(self, event, context):
        """Build metadata string for UI display."""
        parts = []
        if event.get('source_ip'):
            parts.append(event['source_ip'])
        if event.get('name') or event.get('process_name'):
            parts.append(event.get('name') or event.get('process_name'))
        if event.get('pid') or event.get('process_id'):
            parts.append(f"PID {event.get('pid') or event.get('process_id')}")
        if event.get('path') or event.get('exe_path'):
            parts.append(event.get('path') or event.get('exe_path'))
        if context.get('count'):
            parts.append(f"{context['count']} events in {context.get('window', 60)}s")
        return ' . '.join(parts) if parts else ''

    def get_active_threats(self):
        """Return list of active threats for UI display."""
        with self._lock:
            return list(self._active_threats)

    def set_safe_mode(self, enabled):
        """Toggle safe mode."""
        self.safe_mode = enabled
        logger.info("Safe mode %s", "ENABLED" if enabled else "DISABLED")
