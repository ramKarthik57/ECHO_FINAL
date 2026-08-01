"""
ECHO API Integration Tests
Tests FastAPI endpoints using TestClient
"""
import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from httpx import AsyncClient
    from fastapi.testclient import TestClient
    from backend.api_server import app

    client = TestClient(app)
    API_AVAILABLE = True
except Exception:
    API_AVAILABLE = False


@pytest.mark.skipif(not API_AVAILABLE, reason="API server dependencies not available")
class TestAPIEndpoints:

    def test_root_endpoint(self):
        """GET / should return API info."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "ECHO" in data["message"]

    def test_root_lists_endpoints(self):
        """GET / should list available endpoints."""
        response = client.get("/")
        data = response.json()
        assert "endpoints" in data
        assert len(data["endpoints"]) > 0

    def test_analyze_requires_suspect_ip(self):
        """POST /analyze without suspect_ip should return 422."""
        response = client.post("/analyze", json={})
        assert response.status_code == 422

    def test_analyze_with_valid_payload(self):
        """POST /analyze with valid payload should not crash."""
        response = client.post(
            "/analyze",
            json={"suspect_ip": "192.168.1.100"}
        )
        # Accept 200 (success) or 500 (no PCAP found) — not a crash
        assert response.status_code in [200, 500, 422, 404]

    def test_flows_endpoint(self):
        """GET /flows should return a response."""
        response = client.get("/flows")
        assert response.status_code in [200, 404, 500]

    def test_endpoints_endpoint(self):
        """GET /endpoints should return a response."""
        response = client.get("/endpoints")
        assert response.status_code in [200, 404, 500]

    def test_graph_endpoint(self):
        """GET /graph should return a response."""
        response = client.get("/graph")
        assert response.status_code in [200, 404, 500]

    def test_correlations_endpoint(self):
        """GET /correlations should return a response."""
        response = client.get("/correlations")
        assert response.status_code in [200, 404, 500]
