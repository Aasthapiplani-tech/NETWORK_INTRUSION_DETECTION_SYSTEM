"""
Shared pytest fixtures for the NIDS test suite.

Provides:
    - make_packet: factory for lightweight, duck-typed fake packets
      (no real Scapy/ParsedPacket dependency needed for unit tests)
    - analyzer: a fresh TrafficAnalyzer instance per test
    - alert_history: a fresh AlertHistory instance per test
    - make_config: factory for an in-memory-style ConfigManager built
      from a real temp YAML file (via tmp_path), with sensible defaults
      that can be overridden per test
"""

import pytest
import yaml
from datetime import datetime
from types import SimpleNamespace

from src.analyzer.traffic_analyzer import TrafficAnalyzer
from src.alerts import AlertHistory
from src.config.config_manager import ConfigManager


@pytest.fixture
def make_packet():
    """
    Returns a factory function for creating fake packets that duck-type
    the fields TrafficAnalyzer, rules.py, and DetectionEngine actually
    read: timestamp, src_ip, dst_ip, protocol, dst_port, src_port,
    tcp_flags, dns_query.

    Only the fields relevant to a given test need to be passed; sensible
    defaults are used for the rest.

    Usage:
        pkt = make_packet(src_ip="1.2.3.4", protocol="TCP",
                           dst_port=22, tcp_flags="S")
    """
    def _make(
        timestamp=None,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        protocol=None,
        src_port=None,
        dst_port=None,
        tcp_flags=None,
        dns_query=None,
    ):
        return SimpleNamespace(
            timestamp=timestamp or datetime.now(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            tcp_flags=tcp_flags,
            dns_query=dns_query,
        )
    return _make


@pytest.fixture
def analyzer():
    """A fresh, isolated TrafficAnalyzer instance for each test."""
    return TrafficAnalyzer()


@pytest.fixture
def alert_history():
    """A fresh, isolated AlertHistory instance for each test."""
    return AlertHistory(max_size=200)


@pytest.fixture
def make_config(tmp_path):
    """
    Returns a factory function that writes a real temp YAML file and
    loads it through the actual ConfigManager — so tests exercise the
    real YAML parsing and validation path, not a mock.

    Provides sensible detection thresholds by default; any section can
    be overridden by passing a dict that gets deep-merged over the base.

    Usage:
        config = make_config()                              # defaults
        config = make_config(overrides={
            "detection": {"port_scan": {"unique_ports_threshold": 3}}
        })
    """
    base_config = {
        "network": {"interface": "Wi-Fi"},
        "detection": {
            "port_scan": {"unique_ports_threshold": 15, "time_window_seconds": 10},
            "syn_flood": {"syn_count_threshold": 50, "time_window_seconds": 5},
            "icmp_flood": {"icmp_count_threshold": 30, "time_window_seconds": 5},
            "dns_tunneling": {"subdomain_length_threshold": 50},
            "malicious_ips": [],
            "malicious_ports": [],
        },
        "logging": {"log_dir": "logs", "log_level": "INFO", "log_file": "nids.log"},
        "dashboard": {"refresh_interval_seconds": 3},
    }

    def _deep_merge(base: dict, override: dict) -> dict:
        result = dict(base)
        for key, value in override.items():
            if isinstance(value, dict) and isinstance(result.get(key), dict):
                result[key] = _deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    def _make(overrides: dict = None, raw_yaml_text: str = None):
        config_path = tmp_path / "config.yaml"

        if raw_yaml_text is not None:
            # For tests that need to write intentionally broken/raw YAML.
            config_path.write_text(raw_yaml_text)
        else:
            merged = _deep_merge(base_config, overrides or {})
            config_path.write_text(yaml.dump(merged))

        return ConfigManager(str(config_path))

    return _make