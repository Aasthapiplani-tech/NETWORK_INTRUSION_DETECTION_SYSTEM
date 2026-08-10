"""
Tests for DetectionEngine (src/detector/detection_engine.py).

Covers: aggregating alerts from multiple firing rules, returning an
empty list when nothing fires, and exception isolation — a rule that
raises should not prevent other rules from still being evaluated.
"""

from datetime import datetime

from freezegun import freeze_time

from src.detector.detection_engine import DetectionEngine


class TestEvaluateAggregation:

    def test_returns_empty_list_when_nothing_fires(self, analyzer, make_config, make_packet):
        config = make_config()  # default thresholds, ordinary packet won't trip anything
        engine = DetectionEngine(analyzer, config)

        pkt = make_packet(src_ip="1.2.3.4", protocol="TCP", dst_port=80, tcp_flags="A")
        analyzer.process(pkt)

        alerts = engine.evaluate(pkt)
        assert alerts == []

    def test_single_rule_fires(self, analyzer, make_config, make_packet):
        config = make_config(overrides={
            "detection": {"malicious_ports": [4444]}
        })
        engine = DetectionEngine(analyzer, config)

        pkt = make_packet(src_ip="1.2.3.4", dst_port=4444)
        analyzer.process(pkt)

        alerts = engine.evaluate(pkt)
        assert len(alerts) == 1
        assert alerts[0]["type"] == "MALICIOUS_PORT"

    def test_multiple_rules_fire_on_same_packet(self, analyzer, make_config, make_packet):
        # Craft a packet + config so BOTH check_malicious_ip and
        # check_malicious_port fire on the same single packet.
        config = make_config(overrides={
            "detection": {
                "malicious_ips": ["6.6.6.6"],
                "malicious_ports": [4444],
            }
        })
        engine = DetectionEngine(analyzer, config)

        pkt = make_packet(src_ip="6.6.6.6", dst_ip="1.1.1.1", dst_port=4444)
        analyzer.process(pkt)

        alerts = engine.evaluate(pkt)
        types = {a["type"] for a in alerts}
        assert "MALICIOUS_IP" in types
        assert "MALICIOUS_PORT" in types
        assert len(alerts) == 2

    def test_port_scan_and_malicious_port_can_both_fire(self, analyzer, make_config, make_packet):
        config = make_config(overrides={
            "detection": {
                "port_scan": {"unique_ports_threshold": 2, "time_window_seconds": 10},
                "malicious_ports": [8080],
            }
        })
        engine = DetectionEngine(analyzer, config)

        with freeze_time(datetime(2026, 1, 1, 12, 0, 0)):
            for port in [80, 443, 8080]:
                pkt = make_packet(src_ip="1.2.3.4", dst_port=port)
                analyzer.process(pkt)

            alerts = engine.evaluate(pkt)  # last packet: dst_port=8080

        types = {a["type"] for a in alerts}
        assert "PORT_SCAN" in types
        assert "MALICIOUS_PORT" in types


class TestExceptionIsolation:

    def test_one_broken_rule_does_not_block_others(self, analyzer, make_config, make_packet, monkeypatch):
        """
        Injects a deliberately broken rule into ALL_RULES (via monkeypatch
        on the engine's own .rules list, not the shared module-level list)
        and confirms DetectionEngine.evaluate() still returns alerts from
        the other, working rules — matching the try/except per rule in
        DetectionEngine.evaluate().
        """
        config = make_config(overrides={
            "detection": {"malicious_ports": [4444]}
        })
        engine = DetectionEngine(analyzer, config)

        def broken_rule(parsed_packet, analyzer, config):
            raise ValueError("simulated rule failure")

        # Replace the engine's own rule list (does not affect the shared
        # ALL_RULES used by other tests/modules).
        engine.rules = [broken_rule] + engine.rules

        pkt = make_packet(src_ip="1.2.3.4", dst_port=4444)
        analyzer.process(pkt)

        alerts = engine.evaluate(pkt)

        # The broken rule contributed nothing, but the working
        # check_malicious_port rule still fired.
        assert len(alerts) == 1
        assert alerts[0]["type"] == "MALICIOUS_PORT"

    def test_all_rules_broken_returns_empty_list_not_exception(self, analyzer, make_config, make_packet):
        config = make_config()
        engine = DetectionEngine(analyzer, config)

        def broken_rule(parsed_packet, analyzer, config):
            raise RuntimeError("simulated failure")

        engine.rules = [broken_rule, broken_rule]

        pkt = make_packet(src_ip="1.2.3.4")
        # Should not raise — DetectionEngine.evaluate() must swallow all
        # per-rule exceptions and simply return an empty list.
        alerts = engine.evaluate(pkt)
        assert alerts == []


class TestEngineUsesRealRuleRegistry:

    def test_engine_defaults_to_all_rules(self, analyzer, make_config):
        from src.detector.rules import ALL_RULES
        config = make_config()
        engine = DetectionEngine(analyzer, config)
        assert engine.rules == ALL_RULES