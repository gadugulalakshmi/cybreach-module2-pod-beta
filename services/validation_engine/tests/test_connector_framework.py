"""
Tests for the Connector Framework: BaseConnector interface and
MockConnector (Week 4).
"""
import pytest

from ve_app.connectors import BaseConnector, MockConnector


def test_base_connector_cannot_be_instantiated_directly():
    """Enforces the read-only, must-implement-everything contract."""
    with pytest.raises(TypeError):
        BaseConnector()


def test_mock_connector_validate_connection_returns_true():
    connector = MockConnector()
    assert connector.validate_connection() is True


def test_mock_connector_poll_returns_empty_list_by_default():
    connector = MockConnector()
    assert connector.poll() == []


def test_mock_connector_query_returns_seeded_results():
    seeded = {"DET-001": [{"observable": "vssadmin.exe seen", "timestamp": "2026-06-17T09:12:00Z"}]}
    connector = MockConnector(config={"seeded_results": seeded})

    results = connector.query("DET-001", ("2026-06-17T09:00:00Z", "2026-06-17T09:30:00Z"))

    assert results == seeded["DET-001"]


def test_mock_connector_query_returns_empty_list_for_unseeded_query():
    connector = MockConnector(config={"seeded_results": {"DET-001": [{"observable": "x", "timestamp": "t"}]}})
    assert connector.query("DET-999", ("t1", "t2")) == []


def test_mock_connector_has_no_write_methods():
    """The read-only guarantee from the technical doc: only query, poll,
    and validate_connection exist on the interface."""
    connector = MockConnector()
    assert not hasattr(connector, "update")
    assert not hasattr(connector, "create")
    assert not hasattr(connector, "delete")
