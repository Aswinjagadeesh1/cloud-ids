"""
Unit tests for the log ingestion parser.
"""
import pytest
from datetime import datetime
from ingestion.parser import _normalise_cloudtrail, _parse_auth_line, _parse_ts

def test_parse_ts():
    """Test parsing of ISO-8601 timestamps."""
    dt = _parse_ts("2023-10-15T12:00:00Z")
    assert isinstance(dt, datetime)
    assert dt.year == 2023
    assert dt.month == 10
    assert dt.day == 15
    assert dt.hour == 12

def test_normalise_cloudtrail():
    """Test standardising a simple dict mimicking a CloudTrail event."""
    raw = {
        "eventTime": "2023-10-15T12:00:00Z",
        "userIdentity": {"userName": "alice"},
        "sourceIPAddress": "192.168.1.100",
        "eventName": "ConsoleLogin",
        "responseElements": {"status": "SUCCESS"}
    }
    res = _normalise_cloudtrail(raw)
    assert res["user"] == "alice"
    assert res["source_ip"] == "192.168.1.100"
    assert res["action"] == "ConsoleLogin"
    assert res["status"] == "SUCCESS"
    assert "_raw" in res

def test_parse_auth_line():
    """Test extracting structured data from syslog auth lines."""
    line = "Mar 15 09:05:33 hostname sshd[1234]: Accepted password for root from 10.0.1.10 port 22 ssh2"
    res = _parse_auth_line(line, 2024)
    assert res is not None
    assert res["user"] == "root"
    assert res["source_ip"] == "10.0.1.10"
    assert res["status"] == "SUCCESS"
    assert "ssh" in res["action"]

def test_parse_auth_line_failed():
    """Test failure state detection in auth log line."""
    line = "Mar 15 09:05:35 hostname sshd[1234]: Failed password for invalid user bob from 10.0.1.11 port 22 ssh2"
    res = _parse_auth_line(line, 2024)
    assert res is not None
    assert res["user"] == "bob"
    assert res["source_ip"] == "10.0.1.11"
    assert res["status"] == "FAILED"
