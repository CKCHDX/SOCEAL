"""Tests for SOCeal realtime server API endpoints."""

import os
import sys
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from unittest.mock import MagicMock, patch
from ui.realtime_server import RealtimeServer


@pytest.fixture
def mock_components():
    threat_logger = MagicMock()
    threat_logger.get_stats.return_value = {
        'events_per_minute': 42,
        'threats_1h': 3,
    }
    threat_logger.get_recent_threats.return_value = [
        {'severity': 'high', 'message': 'Test threat', 'timestamp': '2024-01-01 12:00:00'},
    ]

    rules_engine = MagicMock()
    rules_engine.safe_mode = True
    rules_engine.get_active_threats.return_value = [
        {
            'rule_id': 'TEST_RULE',
            'name': 'Test Threat',
            'severity': 'critical',
            'meta': '10.0.0.1',
            'timestamp': '12:00',
            'event': {'source_ip': '10.0.0.1', 'pid': 1234},
        },
    ]

    action_handler = MagicMock()
    action_handler.get_recent_actions.return_value = [
        {'icon': '🔒', 'title': 'IP Blocked', 'detail': '10.0.0.1', 'time': '12:00',
         'action_type': 'block_ip', 'success': True},
    ]
    action_handler.get_quarantine_count.return_value = 2
    action_handler.quarantine_dir = MagicMock()
    action_handler.quarantine_dir.iterdir.return_value = []

    process_monitor = MagicMock()
    process_monitor.get_process_count.return_value = 150
    process_monitor.get_process_list.return_value = [
        {'pid': 1, 'name': 'test.exe', 'cpu_percent': 1.0, 'memory_mb': 50.0,
         'exe_path': 'C:\\test.exe', 'cmdline': '', 'status': 'running',
         'suspicious': False, 'reason': '', 'severity': ''},
    ]

    return threat_logger, rules_engine, action_handler, process_monitor


@pytest.fixture
def client(mock_components, tmp_path):
    tl, re, ah, pm = mock_components
    # Create a dummy dashboard file
    html_path = tmp_path / "SOCeal_dashboard.html"
    html_path.write_text("<h1>Test</h1>")

    server = RealtimeServer(
        dashboard_path=str(html_path),
        threat_logger=tl,
        rules_engine=re,
        action_handler=ah,
        process_monitor=pm,
    )
    app = server.create_app()
    app.config['TESTING'] = True
    return app.test_client()


class TestDashboard:
    def test_index(self, client):
        resp = client.get('/')
        assert resp.status_code == 200


class TestThreatsAPI:
    def test_get_threats(self, client):
        resp = client.get('/api/threats')
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]['name'] == 'Test Threat'
        assert data[0]['severity'] == 'critical'
        assert data[0]['ip'] == '10.0.0.1'
        assert data[0]['pid'] == 1234


class TestActionsAPI:
    def test_get_actions(self, client):
        resp = client.get('/api/actions')
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) == 1
        assert data[0]['action_type'] == 'block_ip'


class TestStatsAPI:
    def test_get_stats(self, client):
        resp = client.get('/api/stats')
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'security_score' in data
        assert 'processes_watched' in data
        assert data['processes_watched'] == 150
        assert 'uptime' in data


class TestEventsAPI:
    def test_get_events(self, client):
        resp = client.get('/api/events')
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) == 1


class TestModeAPI:
    def test_get_mode(self, client):
        resp = client.get('/api/mode')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['safe_mode'] is True

    def test_set_mode(self, client):
        resp = client.post('/api/mode',
                          json={'safe_mode': False},
                          content_type='application/json')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['safe_mode'] is False


class TestManualActions:
    def test_kill_action(self, client, mock_components):
        _, _, ah, _ = mock_components
        resp = client.post('/api/action/kill',
                          json={'pid': 1234, 'name': 'test.exe'},
                          content_type='application/json')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        ah.execute.assert_called()

    def test_kill_missing_pid(self, client):
        resp = client.post('/api/action/kill',
                          json={},
                          content_type='application/json')
        assert resp.status_code == 400

    def test_block_action(self, client, mock_components):
        _, _, ah, _ = mock_components
        resp = client.post('/api/action/block',
                          json={'ip': '10.0.0.1'},
                          content_type='application/json')
        assert resp.status_code == 200
        assert resp.get_json()['success'] is True

    def test_block_missing_ip(self, client):
        resp = client.post('/api/action/block',
                          json={},
                          content_type='application/json')
        assert resp.status_code == 400

    def test_unblock_action(self, client, mock_components):
        _, _, ah, _ = mock_components
        resp = client.post('/api/action/unblock',
                          json={'ip': '10.0.0.1'},
                          content_type='application/json')
        assert resp.status_code == 200
        assert resp.get_json()['success'] is True

    def test_quarantine_action(self, client, mock_components):
        _, _, ah, _ = mock_components
        resp = client.post('/api/action/quarantine',
                          json={'path': 'C:\\test\\malware.exe'},
                          content_type='application/json')
        assert resp.status_code == 200
        assert resp.get_json()['success'] is True

    def test_quarantine_missing_path(self, client):
        resp = client.post('/api/action/quarantine',
                          json={},
                          content_type='application/json')
        assert resp.status_code == 400


class TestProcessesAPI:
    def test_get_processes(self, client):
        resp = client.get('/api/processes')
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) == 1
        assert data[0]['name'] == 'test.exe'


class TestQuarantineAPI:
    def test_get_quarantine(self, client):
        resp = client.get('/api/quarantine')
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)
