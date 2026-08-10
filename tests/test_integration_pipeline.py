"""
Integration tests for the detection pipeline (src/analyzer/traffic_analyzer.py
-> src/detector/detection_engine.py -> src/alerts/AlertHistory), using
synthetic ParsedPacket-like objects. No live packet capture, no Scapy
sniffing, no real network interface — fully deterministic and isolated.

These tests exercise the SAME wiring used in src/main.py's
processing_loop(): analyzer.process(parsed) -> engine.evaluate(parsed)
-> alert_history.record(alert) for each returned alert.
"""

from datetime import datetime

from freezegun import freeze_time

from src.detector.detection_engine import DetectionEngine


def run_packet_through_pipeline(pkt, analyzer, engine, alert_history):
    """
    Mirrors main.py's processing_loop() body for a single packet:
    update the analyzer, run detection, record any alerts.
    """
    analyzer.process(pkt)
    alerts = engine.evaluate(pkt)
    for alert in alerts:
        alert_history.record(alert)
    return alerts


class TestPortScanEndToEnd:

    def test_simulated_port_scan_burst_triggers_alerts(
        self, analyzer, alert_history, make_config, make_packet
    ):
        config = make_config(overrides={
            "detection": {"port_scan": {"unique_ports_threshold": 5, "time_window_seconds": 10}}
        })
        engine = DetectionEngine(analyzer, config)

        all_alerts = []
        with freeze_time(datetime(2026, 1, 1, 12, 0, 0)):
            # Simulate a single source scanning 8 distinct ports rapidly —
            # crosses the threshold of 5 partway through the burst.
            for port in range(20, 28):  # 8 ports: 20..27
                pkt = make_packet(src_ip="192.168.1.50", dst_port=port, protocol="TCP", tcp_flags="S")
                alerts = run_packet_through_pipeline(pkt, analyzer, engine, alert_history)
                all_alerts.extend(alerts)

        # At least one PORT_SCAN alert should have fired once the 6th
        # unique port was contacted (crossing threshold of 5).
        port_scan_alerts = [a for a in all_alerts if a["type"] == "PORT_SCAN"]
        assert len(port_scan_alerts) > 0
        assert all(a["src_ip"] == "192.168.1.50" for a in port_scan_alerts)

    def test_alert_history_reflects_the_scan(
        self, analyzer, alert_history, make_config, make_packet
    ):
        config = make_config(overrides={
            "detection": {"port_scan": {"unique_ports_threshold": 5, "time_window_seconds": 10}}
        })
        engine = DetectionEngine(analyzer, config)

        with freeze_time(datetime(2026, 1, 1, 12, 0, 0)):
            for port in range(20, 28):
                pkt = make_packet(src_ip="192.168.1.50", dst_port=port, protocol="TCP", tcp_flags="S")
                run_packet_through_pipeline(pkt, analyzer, engine, alert_history)

        assert alert_history.total_count() > 0
        severity_counts = alert_history.count_by_severity()
        assert severity_counts.get("HIGH", 0) > 0

        recent = alert_history.get_recent(5)
        assert all(a["type"] == "PORT_SCAN" for a in recent)

    def test_normal_traffic_does_not_trigger_alerts(
        self, analyzer, alert_history, make_config, make_packet
    ):
        # Same default thresholds as real config.yaml — a handful of
        # ordinary packets to a few different ports should stay well
        # under the port_scan threshold of 15.
        config = make_config()
        engine = DetectionEngine(analyzer, config)

        with freeze_time(datetime(2026, 1, 1, 12, 0, 0)):
            for port in [80, 443, 22]:
                pkt = make_packet(src_ip="192.168.1.50", dst_port=port, protocol="TCP", tcp_flags="A")
                run_packet_through_pipeline(pkt, analyzer, engine, alert_history)

        assert alert_history.total_count() == 0


class TestSynFloodEndToEnd:

    def test_simulated_syn_flood_triggers_alert(
        self, analyzer, alert_history, make_config, make_packet
    ):
        config = make_config(overrides={
            "detection": {"syn_flood": {"syn_count_threshold": 4, "time_window_seconds": 5}}
        })
        engine = DetectionEngine(analyzer, config)

        all_alerts = []
        with freeze_time(datetime(2026, 1, 1, 12, 0, 0)):
            for _ in range(6):  # 6 unmatched SYNs, threshold is 4
                pkt = make_packet(src_ip="10.0.0.99", protocol="TCP", tcp_flags="S", dst_port=443)
                alerts = run_packet_through_pipeline(pkt, analyzer, engine, alert_history)
                all_alerts.extend(alerts)

        syn_alerts = [a for a in all_alerts if a["type"] == "SYN_FLOOD"]
        assert len(syn_alerts) > 0
        assert all(a["severity"] == "CRITICAL" for a in syn_alerts)


class TestMixedTrafficEndToEnd:

    def test_multiple_sources_isolated_correctly(
        self, analyzer, alert_history, make_config, make_packet
    ):
        """
        Two source IPs generate traffic concurrently (in simulated time);
        only the scanning IP should trigger alerts, confirming per-source
        isolation holds across the full pipeline, not just in isolated
        TrafficAnalyzer unit tests.
        """
        config = make_config(overrides={
            "detection": {"port_scan": {"unique_ports_threshold": 5, "time_window_seconds": 10}}
        })
        engine = DetectionEngine(analyzer, config)

        with freeze_time(datetime(2026, 1, 1, 12, 0, 0)):
            # Attacker: scans 8 ports.
            for port in range(20, 28):
                pkt = make_packet(src_ip="192.168.1.66", dst_port=port, protocol="TCP", tcp_flags="S")
                run_packet_through_pipeline(pkt, analyzer, engine, alert_history)

            # Innocent host: normal traffic to 2 ports only.
            for port in [80, 443]:
                pkt = make_packet(src_ip="192.168.1.10", dst_port=port, protocol="TCP", tcp_flags="A")
                run_packet_through_pipeline(pkt, analyzer, engine, alert_history)

        recent = alert_history.get_recent(50)
        offending_ips = {a["src_ip"] for a in recent}
        assert offending_ips == {"192.168.1.66"}

    def test_malicious_ip_and_port_scan_both_recorded(
        self, analyzer, alert_history, make_config, make_packet
    ):
        config = make_config(overrides={
            "detection": {
                "port_scan": {"unique_ports_threshold": 5, "time_window_seconds": 10},
                "malicious_ips": ["192.168.1.66"],
            }
        })
        engine = DetectionEngine(analyzer, config)

        with freeze_time(datetime(2026, 1, 1, 12, 0, 0)):
            for port in range(20, 28):
                pkt = make_packet(src_ip="192.168.1.66", dst_ip="1.1.1.1", dst_port=port,
                                   protocol="TCP", tcp_flags="S")
                run_packet_through_pipeline(pkt, analyzer, engine, alert_history)

        recent_types = {a["type"] for a in alert_history.get_recent(50)}
        assert "PORT_SCAN" in recent_types
        assert "MALICIOUS_IP" in recent_types


class TestPipelineSummaryConsistency:

    def test_analyzer_summary_matches_processed_packet_count(
        self, analyzer, alert_history, make_config, make_packet
    ):
        config = make_config()
        engine = DetectionEngine(analyzer, config)

        with freeze_time(datetime(2026, 1, 1, 12, 0, 0)):
            for i in range(10):
                pkt = make_packet(src_ip=f"10.0.0.{i}", protocol="TCP", dst_port=80, tcp_flags="A")
                run_packet_through_pipeline(pkt, analyzer, engine, alert_history)

        summary = analyzer.get_summary()
        assert summary["total_packets"] == 10
        assert summary["unique_sources"] == 10