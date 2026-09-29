import pytest
from fastapi.testclient import TestClient

import main
from config import settings


@pytest.fixture
def client():
    return TestClient(main.app)


def test_api_key_required_when_configured(client, monkeypatch):
    monkeypatch.setattr(settings, "API_KEY", "s3cret")
    assert client.get("/api/stats").status_code == 401
    assert client.get("/api/stats", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/api/health").status_code != 401


def test_correct_api_key_passes_auth(client, monkeypatch):
    monkeypatch.setattr(settings, "API_KEY", "s3cret")
    assert client.get("/api/stats", headers={"X-API-Key": "s3cret"}).status_code != 401


def test_no_key_means_no_auth(client, monkeypatch):
    monkeypatch.setattr(settings, "API_KEY", "")
    assert client.get("/api/stats").status_code != 401


def test_scan_rejects_private_target(client, monkeypatch):
    monkeypatch.setattr(settings, "API_KEY", "")
    response = client.post("/api/scans", json={"target": "10.0.0.1"})
    assert response.status_code == 400


def test_spoofed_forwarded_for_does_not_bypass_rate_limit(client, monkeypatch):
    monkeypatch.setattr(settings, "API_KEY", "")
    monkeypatch.setattr(settings, "TRUST_PROXY_HEADERS", False)
    main._rate_store.clear()
    monkeypatch.setitem(main.RATE_LIMITS, "/api/stats", (3, 60))
    codes = [
        client.get("/api/stats", headers={"X-Forwarded-For": f"1.2.3.{i}"}).status_code
        for i in range(6)
    ]
    assert 429 in codes
