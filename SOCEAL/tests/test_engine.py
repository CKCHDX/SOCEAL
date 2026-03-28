"""Tests for SOCeal rules engine."""

import os
import sys
import json
import time
import tempfile
import pytest

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from unittest.mock import MagicMock
from rules.engine import RulesEngine


@pytest.fixture
def rules_file(tmp_path):
    """Create a temporary rules file."""
    rules = {
        "rules": [
            {
                "id": "TEST_BRUTEFORCE",
                "type": "eventlog",
                "event_id": 4625,
                "window_seconds": 60,
                "threshold": 3,
                "action": "block_ip",
                "severity": "critical",
                "enabled": True,
            },
            {
                "id": "TEST_SUSPICIOUS_PROC",
                "type": "process",
                "patterns": ["mimikatz", "nc.exe"],
                "action": "kill_process",
                "severity": "critical",
                "enabled": True,
            },
            {
                "id": "TEST_DISABLED",
                "type": "eventlog",
                "event_id": 9999,
                "action": "log",
                "severity": "low",
                "enabled": False,
            },
            {
                "id": "TEST_FILE_RULE",
                "type": "file",
                "patterns": [".exe", ".scr"],
                "action": "quarantine",
                "severity": "high",
                "enabled": True,
            },
        ]
    }
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(rules))
    return str(path)


@pytest.fixture
def mock_action_handler():
    handler = MagicMock()
    handler.execute = MagicMock()
    return handler


@pytest.fixture
def engine(rules_file, mock_action_handler):
    return RulesEngine(rules_file, mock_action_handler, safe_mode=False)


class TestRuleLoading:
    def test_loads_rules(self, engine):
        assert len(engine.rules) == 4

    def test_missing_file(self, mock_action_handler, tmp_path):
        e = RulesEngine(str(tmp_path / "missing.json"), mock_action_handler)
        assert e.rules == []

    def test_invalid_json(self, mock_action_handler, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{invalid")
        e = RulesEngine(str(bad), mock_action_handler)
        assert e.rules == []


class TestThresholdDetection:
    def test_below_threshold_no_trigger(self, engine, mock_action_handler):
        """2 events should not trigger threshold of 3."""
        for _ in range(2):
            engine.process_event({
                'type': 'eventlog',
                'event_id': 4625,
                'source_ip': '10.0.0.1',
            })
        mock_action_handler.execute.assert_not_called()

    def test_at_threshold_triggers(self, engine, mock_action_handler):
        """3 events within window should trigger."""
        for _ in range(3):
            engine.process_event({
                'type': 'eventlog',
                'event_id': 4625,
                'source_ip': '10.0.0.1',
            })
        assert mock_action_handler.execute.called
        call_args = mock_action_handler.execute.call_args
        assert call_args[0][0] == 'block_ip'


class TestPatternMatching:
    def test_suspicious_process_name(self, engine, mock_action_handler):
        engine.process_event({
            'type': 'process',
            'name': 'mimikatz.exe',
            'pid': 1234,
            'cmdline': '',
        })
        assert mock_action_handler.execute.called
        call_args = mock_action_handler.execute.call_args
        assert call_args[0][0] == 'kill_process'

    def test_non_suspicious_process(self, engine, mock_action_handler):
        engine.process_event({
            'type': 'process',
            'name': 'chrome.exe',
            'pid': 5678,
            'cmdline': '',
        })
        mock_action_handler.execute.assert_not_called()

    def test_file_pattern_match(self, engine, mock_action_handler):
        engine.process_event({
            'type': 'file',
            'path': 'C:\\Temp\\payload.exe',
            'filename': 'payload.exe',
        })
        assert mock_action_handler.execute.called


class TestDisabledRules:
    def test_disabled_rule_not_evaluated(self, engine, mock_action_handler):
        engine.process_event({
            'type': 'eventlog',
            'event_id': 9999,
        })
        mock_action_handler.execute.assert_not_called()


class TestSafeMode:
    def test_safe_mode_logs_only(self, rules_file, mock_action_handler):
        engine = RulesEngine(rules_file, mock_action_handler, safe_mode=True)
        engine.process_event({
            'type': 'process',
            'name': 'mimikatz.exe',
            'pid': 1234,
            'cmdline': '',
        })
        # In safe mode, it should call execute with 'log' instead of 'kill_process'
        assert mock_action_handler.execute.called
        call_args = mock_action_handler.execute.call_args
        assert call_args[0][0] == 'log'

    def test_toggle_safe_mode(self, engine):
        engine.set_safe_mode(True)
        assert engine.safe_mode is True
        engine.set_safe_mode(False)
        assert engine.safe_mode is False


class TestActiveThreats:
    def test_threats_recorded(self, engine):
        for _ in range(3):
            engine.process_event({
                'type': 'eventlog',
                'event_id': 4625,
                'source_ip': '10.0.0.1',
            })
        threats = engine.get_active_threats()
        assert len(threats) >= 1
        assert threats[0]['rule_id'] == 'TEST_BRUTEFORCE'
