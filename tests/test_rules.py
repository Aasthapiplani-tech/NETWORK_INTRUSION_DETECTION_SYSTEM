"""
Tests for detection rules (src/detector/rules.py).

Covers all 6 rule functions: check_port_scan, check_syn_flood,
check_icmp_flood, check_dns_tunneling, check_malicious_ip,
check_malicious_port. Each is tested for: firing above threshold,
NOT firing at/below threshold, returning None for irrelevant packets,
and correct alert dict fields.
"""

from datetime import datetime

from freezegun import freeze_time

from src.detector.rules import (
    check_port_scan,
    check_syn_flood,
    check_icmp_flood,
    check_dns_tunneling,
    check_malicious_ip,
    check_malicious_port,
    ALL_RULES,
)


class TestPortScan:

    def test_fires_above_threshold(self, analyzer, make_config, make_packet):
        config = make_config(overrides={
            "detection": {"port_scan": {"unique_ports_threshold": 2, "time_window_seconds": 10}}
        })
        with freeze_time(datetime(2026, 1, 1, 12, 0, 0)):
            for port in [80, 443, 8080]:  # 3 unique ports, threshold is 2
                pkt = make_packet(src_ip="1.2.3.4", dst_port=port)
                analyzer.process(pkt)

            result = check_port_scan(pkt, analyzer, config)

        assert result is not None
        assert result["type"] == "PORT_SCAN"
        assert result["severity"] == "HIGH"
        assert result["src_ip"] == "1.2.3.4"
        assert "3 unique ports" in result["description"]

    def test_does_not_fire_at_threshold(self, analyzer, make_config, make_packet):
        config = make_config(overrides={
            "detection": {"port_scan": {"unique_ports_threshold": 3, "time_window_seconds": 10}}
        })
        with freeze_time(datetime(2026, 1, 1, 12, 0, 0)):
            for port in [80, 443, 8080]:  # exactly 3, threshold is 3 (rule uses >)
                pkt = make_packet(src_ip="1.2.3.4", dst_port=port)
                analyzer.process(pkt)

            result = check_port_scan(pkt, analyzer, config)

        assert result is None

    def test_returns_none_without_src_ip(self, analyzer, make_config, make_packet):
        config = make_config()
        pkt = make_packet(src_ip=None, dst_port=80)
        assert check_port_scan(pkt, analyzer, config) is None

    def test_returns_none_without_dst_port(self, analyzer, make_config, make_packet):
        config = make_config()
        pkt = make_packet(src_ip="1.2.3.4", dst_port=None)
        assert check_port_scan(pkt, analyzer, config) is None


class TestSynFlood:

    def test_fires_above_threshold(self, analyzer, make_config, make_packet):
        config = make_config(overrides={
            "detection": {"syn_flood": {"syn_count_threshold": 2, "time_window_seconds": 5}}
        })
        with freeze_time(datetime(2026, 1, 1, 12, 0, 0)):
            for _ in range(3):  # 3 SYNs, threshold is 2
                pkt = make_packet(src_ip="1.2.3.4", protocol="TCP", tcp_flags="S")
                analyzer.process(pkt)

            result = check_syn_flood(pkt, analyzer, config)

        assert result is not None
        assert result["type"] == "SYN_FLOOD"
        assert result["severity"] == "CRITICAL"
        assert result["src_ip"] == "1.2.3.4"

    def test_does_not_fire_at_threshold(self, analyzer, make_config, make_packet):
        config = make_config(overrides={
            "detection": {"syn_flood": {"syn_count_threshold": 3, "time_window_seconds": 5}}
        })
        with freeze_time(datetime(2026, 1, 1, 12, 0, 0)):
            for _ in range(3):
                pkt = make_packet(src_ip="1.2.3.4", protocol="TCP", tcp_flags="S")
                analyzer.process(pkt)

            result = check_syn_flood(pkt, analyzer, config)

        assert result is None

    def test_returns_none_without_src_ip(self, analyzer, make_config, make_packet):
        config = make_config()
        pkt = make_packet(src_ip=None, protocol="TCP", tcp_flags="S")
        assert check_syn_flood(pkt, analyzer, config) is None

    def test_returns_none_for_non_tcp(self, analyzer, make_config, make_packet):
        config = make_config()
        pkt = make_packet(src_ip="1.2.3.4", protocol="UDP")
        assert check_syn_flood(pkt, analyzer, config) is None


class TestIcmpFlood:

    def test_fires_above_threshold(self, analyzer, make_config, make_packet):
        config = make_config(overrides={
            "detection": {"icmp_flood": {"icmp_count_threshold": 2, "time_window_seconds": 5}}
        })
        with freeze_time(datetime(2026, 1, 1, 12, 0, 0)):
            for _ in range(3):
                pkt = make_packet(src_ip="1.2.3.4", protocol="ICMP")
                analyzer.process(pkt)

            result = check_icmp_flood(pkt, analyzer, config)

        assert result is not None
        assert result["type"] == "ICMP_FLOOD"
        assert result["severity"] == "MEDIUM"
        assert result["src_ip"] == "1.2.3.4"

    def test_does_not_fire_at_threshold(self, analyzer, make_config, make_packet):
        config = make_config(overrides={
            "detection": {"icmp_flood": {"icmp_count_threshold": 3, "time_window_seconds": 5}}
        })
        with freeze_time(datetime(2026, 1, 1, 12, 0, 0)):
            for _ in range(3):
                pkt = make_packet(src_ip="1.2.3.4", protocol="ICMP")
                analyzer.process(pkt)

            result = check_icmp_flood(pkt, analyzer, config)

        assert result is None

    def test_returns_none_without_src_ip(self, analyzer, make_config, make_packet):
        config = make_config()
        pkt = make_packet(src_ip=None, protocol="ICMP")
        assert check_icmp_flood(pkt, analyzer, config) is None

    def test_returns_none_for_non_icmp(self, analyzer, make_config, make_packet):
        config = make_config()
        pkt = make_packet(src_ip="1.2.3.4", protocol="TCP")
        assert check_icmp_flood(pkt, analyzer, config) is None


class TestDnsTunneling:

    def test_fires_above_threshold(self, make_config, make_packet):
        config = make_config(overrides={
            "detection": {"dns_tunneling": {"subdomain_length_threshold": 10}}
        })
        long_subdomain = "a" * 20  # 20 chars, threshold is 10
        pkt = make_packet(src_ip="1.2.3.4", dns_query=f"{long_subdomain}.example.com")

        result = check_dns_tunneling(pkt, None, config)

        assert result is not None
        assert result["type"] == "DNS_TUNNELING"
        assert result["severity"] == "MEDIUM"
        assert result["src_ip"] == "1.2.3.4"

    def test_does_not_fire_at_threshold(self, make_config, make_packet):
        config = make_config(overrides={
            "detection": {"dns_tunneling": {"subdomain_length_threshold": 10}}
        })
        subdomain = "a" * 10  # exactly 10, threshold is 10 (rule uses >)
        pkt = make_packet(dns_query=f"{subdomain}.example.com")

        result = check_dns_tunneling(pkt, None, config)
        assert result is None

    def test_returns_none_without_dns_query(self, make_config, make_packet):
        config = make_config()
        pkt = make_packet(dns_query=None)
        assert check_dns_tunneling(pkt, None, config) is None

    def test_handles_trailing_dot_in_query(self, make_config, make_packet):
        config = make_config(overrides={
            "detection": {"dns_tunneling": {"subdomain_length_threshold": 10}}
        })
        long_subdomain = "b" * 20
        # Trailing "." on a fully-qualified DNS name should be stripped
        # before measuring the first label's length.
        pkt = make_packet(dns_query=f"{long_subdomain}.example.com.")

        result = check_dns_tunneling(pkt, None, config)
        assert result is not None


class TestMaliciousIp:

    def test_fires_when_src_ip_matches(self, make_config, make_packet):
        config = make_config(overrides={
            "detection": {"malicious_ips": ["6.6.6.6"]}
        })
        pkt = make_packet(src_ip="6.6.6.6", dst_ip="1.1.1.1")

        result = check_malicious_ip(pkt, None, config)

        assert result is not None
        assert result["type"] == "MALICIOUS_IP"
        assert result["severity"] == "CRITICAL"
        assert "6.6.6.6" in result["description"]

    def test_fires_when_dst_ip_matches(self, make_config, make_packet):
        config = make_config(overrides={
            "detection": {"malicious_ips": ["6.6.6.6"]}
        })
        pkt = make_packet(src_ip="1.1.1.1", dst_ip="6.6.6.6")

        result = check_malicious_ip(pkt, None, config)

        assert result is not None
        assert "6.6.6.6" in result["description"]

    def test_returns_none_when_list_empty(self, make_config, make_packet):
        config = make_config()  # malicious_ips defaults to []
        pkt = make_packet(src_ip="6.6.6.6")
        assert check_malicious_ip(pkt, None, config) is None

    def test_returns_none_when_no_match(self, make_config, make_packet):
        config = make_config(overrides={
            "detection": {"malicious_ips": ["6.6.6.6"]}
        })
        pkt = make_packet(src_ip="1.1.1.1", dst_ip="2.2.2.2")
        assert check_malicious_ip(pkt, None, config) is None


class TestMaliciousPort:

    def test_fires_when_dst_port_matches(self, make_config, make_packet):
        config = make_config(overrides={
            "detection": {"malicious_ports": [4444]}
        })
        pkt = make_packet(src_port=5000, dst_port=4444)

        result = check_malicious_port(pkt, None, config)

        assert result is not None
        assert result["type"] == "MALICIOUS_PORT"
        assert result["severity"] == "HIGH"

    def test_fires_when_src_port_matches(self, make_config, make_packet):
        config = make_config(overrides={
            "detection": {"malicious_ports": [31337]}
        })
        pkt = make_packet(src_port=31337, dst_port=80)

        result = check_malicious_port(pkt, None, config)
        assert result is not None

    def test_returns_none_when_list_empty(self, make_config, make_packet):
        config = make_config()  # malicious_ports defaults to []
        pkt = make_packet(src_port=4444, dst_port=80)
        assert check_malicious_port(pkt, None, config) is None

    def test_returns_none_when_no_match(self, make_config, make_packet):
        config = make_config(overrides={
            "detection": {"malicious_ports": [4444]}
        })
        pkt = make_packet(src_port=5000, dst_port=80)
        assert check_malicious_port(pkt, None, config) is None

    def test_ignores_none_ports(self, make_config, make_packet):
        # src_port/dst_port of None should never accidentally match
        # if 4444 somehow weren't in the list — sanity check for the
        # `- {None}` filtering in the rule.
        config = make_config(overrides={
            "detection": {"malicious_ports": [4444]}
        })
        pkt = make_packet(src_port=None, dst_port=None)
        assert check_malicious_port(pkt, None, config) is None


class TestAllRulesRegistry:

    def test_all_rules_contains_six_functions(self):
        assert len(ALL_RULES) == 6

    def test_all_rules_contains_expected_functions(self):
        assert check_port_scan in ALL_RULES
        assert check_syn_flood in ALL_RULES
        assert check_icmp_flood in ALL_RULES
        assert check_dns_tunneling in ALL_RULES
        assert check_malicious_ip in ALL_RULES
        assert check_malicious_port in ALL_RULES