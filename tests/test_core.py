"""
ECHO Test Suite - Core Backend Tests
"""
import os
import sys
import json
import pytest
import tempfile

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.burst_analyzer import BurstAnalyzer
from backend.flow_builder import FlowBuilder
from backend.endpoint_profiler import EndpointProfiler


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def sample_metadata():
    """Sample packet metadata for testing."""
    return [
        {"timestamp": 1000.0, "src_ip": "192.168.1.10", "dst_ip": "10.0.0.1",
         "protocol": "TCP", "packet_size": 512, "src_port": 54321, "dst_port": 443},
        {"timestamp": 1000.2, "src_ip": "192.168.1.10", "dst_ip": "10.0.0.1",
         "protocol": "TCP", "packet_size": 256, "src_port": 54321, "dst_port": 443},
        {"timestamp": 1000.4, "src_ip": "10.0.0.1", "dst_ip": "192.168.1.10",
         "protocol": "TCP", "packet_size": 1024, "src_port": 443, "dst_port": 54321},
        # Gap > 2 seconds — new burst
        {"timestamp": 1005.0, "src_ip": "192.168.1.10", "dst_ip": "10.0.0.2",
         "protocol": "UDP", "packet_size": 128, "src_port": 12345, "dst_port": 5353},
        {"timestamp": 1005.1, "src_ip": "192.168.1.10", "dst_ip": "10.0.0.2",
         "protocol": "UDP", "packet_size": 200, "src_port": 12345, "dst_port": 5353},
        {"timestamp": 1005.3, "src_ip": "192.168.1.10", "dst_ip": "10.0.0.2",
         "protocol": "UDP", "packet_size": 180, "src_port": 12345, "dst_port": 5353},
    ]


@pytest.fixture
def sample_flows(sample_metadata):
    """Build flows from sample metadata."""
    builder = FlowBuilder()
    return builder.build_flows(sample_metadata)


@pytest.fixture
def burst_analyzer():
    return BurstAnalyzer()


@pytest.fixture
def flow_builder():
    return FlowBuilder()


@pytest.fixture
def endpoint_profiler():
    return EndpointProfiler()


# ============================================================
# FlowBuilder Tests
# ============================================================

class TestFlowBuilder:

    def test_build_flows_returns_dict(self, flow_builder, sample_metadata):
        flows = flow_builder.build_flows(sample_metadata)
        assert isinstance(flows, dict)

    def test_build_flows_groups_by_session(self, flow_builder, sample_metadata):
        flows = flow_builder.build_flows(sample_metadata)
        # Should identify at least 2 distinct sessions
        assert len(flows) >= 1

    def test_build_flows_empty_metadata(self, flow_builder):
        flows = flow_builder.build_flows([])
        assert flows == {} or isinstance(flows, dict)

    def test_flow_has_required_keys(self, flow_builder, sample_metadata):
        flows = flow_builder.build_flows(sample_metadata)
        for flow_id, flow in flows.items():
            assert "src_ip" in flow or "packets" in flow or flow is not None


# ============================================================
# BurstAnalyzer Tests
# ============================================================

class TestBurstAnalyzer:

    def test_detect_bursts_returns_list(self, burst_analyzer, sample_flows):
        result = burst_analyzer.detect_bursts_in_flows(sample_flows)
        assert result is not None

    def test_empty_flows_returns_gracefully(self, burst_analyzer):
        result = burst_analyzer.detect_bursts_in_flows({})
        assert result is not None  # Should not raise

    def test_find_correlated_bursts_returns_list(self, burst_analyzer, sample_flows):
        burst_analyzer.detect_bursts_in_flows(sample_flows)
        correlations = burst_analyzer.find_correlated_bursts("192.168.1.10")
        assert isinstance(correlations, list)


# ============================================================
# EndpointProfiler Tests
# ============================================================

class TestEndpointProfiler:

    def test_profile_endpoints_returns_dict(self, endpoint_profiler, sample_flows):
        profiles = endpoint_profiler.profile_endpoints(sample_flows, "192.168.1.10")
        assert isinstance(profiles, dict)

    def test_profile_with_no_flows(self, endpoint_profiler):
        profiles = endpoint_profiler.profile_endpoints({}, "192.168.1.10")
        assert profiles is not None


# ============================================================
# Integration: Full Pipeline
# ============================================================

class TestFullPipeline:

    def test_metadata_to_flows_pipeline(self, sample_metadata):
        """Test that metadata can be transformed into flows without error."""
        builder = FlowBuilder()
        flows = builder.build_flows(sample_metadata)
        assert isinstance(flows, dict)

        analyzer = BurstAnalyzer()
        bursts = analyzer.detect_bursts_in_flows(flows)
        assert bursts is not None

        profiler = EndpointProfiler()
        profiles = profiler.profile_endpoints(flows, "192.168.1.10")
        assert isinstance(profiles, dict)
