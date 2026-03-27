"""
SOCeal – Project VALE
Rules Engine: Event-based rule matching with rolling buffers and threshold detection.
Supports eventlog, process, file, and network event types.
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
        self.rules_path = rules_path
        self.action_handler = action_handler
        self.safe_mode = safe_mode
        self.rules = []
        self._lock = Lock()

        self._ip_buffer = defaultdict(list)
        self._user_buffer = defaultdict(list)
        self._event_buffer = defaultdict(list)

        self._active_threats = []
        self._max_threats = 200

        self.reload_rules()

    def reload_rules(self):
        try:
            with open(self.rules_path, 'r') as f:
                data = json.load(f)
            self.rules = data.get('rules', data) if isinstance(data, dict) else data
            logger.info("Loaded %d rules from %s", len(self.rules), self.rules_path)
        except FileNotFoundError:
            logger.warning("Rules file not found: %s — using empty ruleset", self.rules_path)
            self.rules = []
        except json.JSONDecodeError as e:
            logger.error("Invalid JSON in rules file: %s", e)
            self.rules = []

    def process_event(self, event):
        now = time.time()
        ip = event.get('source_ip', '')
        user = event.get('user', '')
        eid = event.get('event_id', 0)

        if ip:
            self._ip_buffer[ip].append(now)
        if user:
            self._user_buffer[user].append(now)
        if eid:
            self._event_buffer[eid].append(now)

        for rule in self.rules:
            if not rule.get('enabled', True):
                continue
            try:
                triggered = False
                context = {}
                rule_type = rule.get('type', '')
                event_type = event.get('type', '')

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

                elif rule_type == 'network' and event_type == 'network':
                    # Network events already pre-matched by NetworkMonitor; pass through
                    rule_id_match = event.get('rule_id', '') == rule.get('id', '')
                    if rule_id_match:
                        triggered = True
                        context = {'event': event, 'ip': event.get('source_ip', '')}

                if triggered:
                    self._trigger_rule(rule, event, context)

            except Exception as e:
                logger.error("Error evaluating rule '%s': %s", rule.get('id', '?'), e)

    def _check_threshold_rule(self, rule, event, now):
        window = rule.get('window_seconds', 60)
        threshold = rule.get('threshold', 10)
        ip = event.get('source_ip', '')
        eid = event.get('event_id', 0)

        if ip:
            self._ip_buffer[ip] = [t for t in self._ip_buffer[ip] if now - t < window]
            count = len(self._ip_buffer[ip])
        else:
            self._event_buffer[eid] = [t for t in self._event_buffer.get(eid, []) if now - t < window]
            count = len(self._event_buffer[eid])

        if count >= threshold:
            return True, {'event': event, 'count': count, 'window': window, 'threshold': threshold, 'ip': ip}
        return False, {}

    def _check_pattern_rule(self, rule, event):
        patterns = rule.get('patterns', [])
        if not patterns:
            return False, {}

        name = (event.get('name') or event.get('process_name') or event.get('filename', '')).lower()
        cmdline = event.get('cmdline', '').lower()
        path = (event.get('exe_path') or event.get('path', '')).lower()
        ext = event.get('extension', '').lower()

        for pattern in patterns:
            p = pattern.lower()
            if p in name or p in cmdline or p in path or p == ext:
                return True, {'event': event, 'matched_pattern': pattern}
        return False, {}

    def _trigger_rule(self, rule, event, context):
        rule_id = rule.get('id', 'UNKNOWN')
        action = rule.get('action', 'log')
        severity = rule.get('severity', event.get('severity', 'medium'))

        logger.warning("Rule triggered: %s (severity=%s, action=%s)", rule_id, severity, action)

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

        if self.safe_mode and action != 'log':
            logger.info("SAFE MODE: rule %s triggered — action '%s' suppressed", rule_id, action)
            self.action_handler.execute('log', {
                'rule_id': rule_id,
                'severity': severity,
                'message': f"[SAFE MODE] {rule_id}: action '{action}' suppressed",
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
        if event.get('remote_port'):
            parts.append(f"port {event['remote_port']}")
        return ' · '.join(parts) if parts else ''

    def get_active_threats(self):
        with self._lock:
            return list(self._active_threats)

    def set_safe_mode(self, enabled):
        self.safe_mode = enabled
        logger.info("Safe mode %s", "ENABLED" if enabled else "DISABLED")
