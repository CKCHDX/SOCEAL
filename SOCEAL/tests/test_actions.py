"""Tests for SOCeal action handler."""

import os
import sys
import json
import tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from unittest.mock import patch, MagicMock
from rules.actions import ActionHandler


@pytest.fixture
def handler(tmp_path):
    qdir = tmp_path / "quarantine"
    ldir = tmp_path / "logs"
    return ActionHandler(
        quarantine_dir=str(qdir),
        log_dir=str(ldir),
        safe_mode=False,
    )


@pytest.fixture
def safe_handler(tmp_path):
    qdir = tmp_path / "quarantine"
    ldir = tmp_path / "logs"
    return ActionHandler(
        quarantine_dir=str(qdir),
        log_dir=str(ldir),
        safe_mode=True,
    )


class TestKillProcess:
    @patch('rules.actions.psutil')
    def test_kill_success(self, mock_psutil, handler):
        mock_proc = MagicMock()
        mock_psutil.Process.return_value = mock_proc
        handler._kill_process({
            'event': {'pid': 1234, 'name': 'test.exe'},
        })
        mock_proc.terminate.assert_called_once()

    def test_kill_no_pid(self, handler):
        result = handler._kill_process({'event': {}})
        assert result['success'] is False

    @patch('rules.actions.psutil')
    def test_kill_access_denied(self, mock_psutil, handler):
        import psutil
        # Need real exception classes for except clauses
        mock_psutil.NoSuchProcess = psutil.NoSuchProcess
        mock_psutil.AccessDenied = psutil.AccessDenied
        mock_psutil.Process.side_effect = psutil.AccessDenied(1234)
        result = handler._kill_process({
            'event': {'pid': 1234, 'name': 'system.exe'},
        })
        assert result['success'] is False
        assert 'Access denied' in result['error']


class TestQuarantine:
    def test_quarantine_success(self, handler, tmp_path):
        # Create a test file
        test_file = tmp_path / "malware.exe"
        test_file.write_bytes(b"fake malware content")

        result = handler._quarantine_file({
            'event': {'path': str(test_file)},
        })
        assert result['success'] is True
        assert not test_file.exists()  # File should be moved
        assert result['sha256']  # Hash should be computed

        # Check metadata file exists in quarantine
        qdir = handler.quarantine_dir
        meta_files = [f for f in qdir.iterdir() if f.name.endswith('.meta.json')]
        assert len(meta_files) == 1

    def test_quarantine_missing_file(self, handler):
        result = handler._quarantine_file({
            'event': {'path': 'C:\\nonexistent\\file.exe'},
        })
        assert result['success'] is False


class TestBlockIP:
    @patch('subprocess.run')
    def test_block_success(self, mock_run, handler):
        mock_run.return_value = MagicMock(returncode=0, stderr='')
        result = handler._block_ip({
            'event': {'source_ip': '10.0.0.1'},
            'ip': '10.0.0.1',
        })
        assert result['success'] is True
        assert '10.0.0.1' in str(mock_run.call_args)

    @patch('subprocess.run')
    def test_block_failure(self, mock_run, handler):
        mock_run.return_value = MagicMock(returncode=1, stderr='Access denied')
        result = handler._block_ip({
            'event': {'source_ip': '10.0.0.1'},
            'ip': '10.0.0.1',
        })
        assert result['success'] is False

    def test_block_no_ip(self, handler):
        result = handler._block_ip({'event': {}})
        assert result['success'] is False


class TestActionRecording:
    def test_actions_recorded(self, handler):
        handler._record_action('log', {'rule_id': 'TEST'}, {'success': True})
        actions = handler.get_recent_actions()
        assert len(actions) == 1
        assert actions[0]['action_type'] == 'log'

    def test_max_actions_limit(self, handler):
        for i in range(250):
            handler._record_action('log', {'rule_id': f'TEST_{i}'}, {'success': True})
        actions = handler.get_recent_actions()
        assert len(actions) == 200  # _max_actions


class TestSafeMode:
    def test_set_safe_mode(self, handler):
        handler.set_safe_mode(True)
        assert handler.safe_mode is True
        handler.set_safe_mode(False)
        assert handler.safe_mode is False


class TestQuarantineCount:
    def test_count_empty(self, handler):
        assert handler.get_quarantine_count() == 0

    def test_count_with_files(self, handler, tmp_path):
        # Create a test file and quarantine it
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"test")
        handler._quarantine_file({'event': {'path': str(test_file)}})
        assert handler.get_quarantine_count() == 1
