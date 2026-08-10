"""
Tests for TrafficAnalyzer (src/analyzer/traffic_analyzer.py).

Covers: packet/protocol/talker counting, unique port tracking, SYN/ICMP
sliding-window counting, window expiry, top talkers, and get_summary().

Sliding-window expiry is tested deterministically using freezegun to
control datetime.now() — TrafficAnalyzer.process() stores each packet's
own .timestamp field, while get_unique_ports/get_syn_count/get_icmp_count
compare against datetime.now() at call time (see _prune()). Freezing time
lets us simulate "time passing" without any real sleep().
"""

from datetime import datetime, timedelta
import threading

from freezegun import freeze_time


class TestPacketCounting:

    def test_total_packets_increments(self, analyzer, make_packet):
        analyzer.process(make_packet())
        analyzer.process(make_packet())
        assert analyzer.total_packets == 2

    def test_protocol_counts_tracks_by_protocol(self, analyzer, make_packet):
        analyzer.process(make_packet(protocol="TCP"))
        analyzer.process(make_packet(protocol="TCP"))
        analyzer.process(make_packet(protocol="UDP"))
        assert analyzer.protocol_counts["TCP"] == 2
        assert analyzer.protocol_counts["UDP"] == 1

    def test_protocol_counts_ignores_falsy_protocol(self, analyzer, make_packet):
        analyzer.process(make_packet(protocol=None))
        assert dict(analyzer.protocol_counts) == {}

    def test_talker_counts_tracks_source_ips(self, analyzer, make_packet):
        analyzer.process(make_packet(src_ip="1.1.1.1"))
        analyzer.process(make_packet(src_ip="1.1.1.1"))
        analyzer.process(make_packet(src_ip="2.2.2.2"))
        assert analyzer.talker_counts["1.1.1.1"] == 2
        assert analyzer.talker_counts["2.2.2.2"] == 1

    def test_process_without_src_ip_still_counts_totals(self, analyzer, make_packet):
        analyzer.process(make_packet(src_ip=None, protocol="TCP"))
        assert analyzer.total_packets == 1
        assert analyzer.protocol_counts["TCP"] == 1

    def test_process_without_src_ip_does_not_track_talker(self, analyzer, make_packet):
        analyzer.process(make_packet(src_ip=None, protocol="TCP"))
        assert analyzer.get_top_talkers(10) == []


class TestUniquePorts:

    def test_counts_distinct_ports(self, analyzer, make_packet):
        with freeze_time(datetime(2026, 1, 1, 12, 0, 0)):
            for port in [80, 443, 8080]:
                analyzer.process(make_packet(src_ip="1.2.3.4", dst_port=port))
            assert analyzer.get_unique_ports("1.2.3.4", 10) == 3

    def test_ignores_duplicate_ports(self, analyzer, make_packet):
        with freeze_time(datetime(2026, 1, 1, 12, 0, 0)):
            for _ in range(3):
                analyzer.process(make_packet(src_ip="1.2.3.4", dst_port=80))
            assert analyzer.get_unique_ports("1.2.3.4", 10) == 1

    def test_only_counts_packets_with_dst_port(self, analyzer, make_packet):
        with freeze_time(datetime(2026, 1, 1, 12, 0, 0)):
            analyzer.process(make_packet(src_ip="1.2.3.4", dst_port=None))
            assert analyzer.get_unique_ports("1.2.3.4", 10) == 0

    def test_isolated_per_source_ip(self, analyzer, make_packet):
        with freeze_time(datetime(2026, 1, 1, 12, 0, 0)):
            analyzer.process(make_packet(src_ip="1.1.1.1", dst_port=80))
            analyzer.process(make_packet(src_ip="2.2.2.2", dst_port=443))
            assert analyzer.get_unique_ports("1.1.1.1", 10) == 1
            assert analyzer.get_unique_ports("2.2.2.2", 10) == 1

    def test_unseen_source_ip_returns_zero(self, analyzer):
        assert analyzer.get_unique_ports("9.9.9.9", 10) == 0

    def test_window_expiry_prunes_old_entries(self, analyzer, make_packet):
        start = datetime(2026, 1, 1, 12, 0, 0)
        with freeze_time(start) as frozen:
            analyzer.process(make_packet(src_ip="1.2.3.4", dst_port=80))
            frozen.move_to(start + timedelta(seconds=15))
            # 15s have passed; window is 10s, so the entry should be pruned.
            assert analyzer.get_unique_ports("1.2.3.4", 10) == 0

    def test_within_window_not_pruned(self, analyzer, make_packet):
        start = datetime(2026, 1, 1, 12, 0, 0)
        with freeze_time(start) as frozen:
            analyzer.process(make_packet(src_ip="1.2.3.4", dst_port=80))
            frozen.move_to(start + timedelta(seconds=5))
            # Only 5s have passed against a 10s window — still counted.
            assert analyzer.get_unique_ports("1.2.3.4", 10) == 1


class TestSynCount:

    def test_counts_unmatched_syn(self, analyzer, make_packet):
        with freeze_time(datetime(2026, 1, 1, 12, 0, 0)):
            analyzer.process(make_packet(src_ip="1.2.3.4", protocol="TCP", tcp_flags="S"))
            assert analyzer.get_syn_count("1.2.3.4", 5) == 1

    def test_ignores_syn_ack(self, analyzer, make_packet):
        with freeze_time(datetime(2026, 1, 1, 12, 0, 0)):
            analyzer.process(make_packet(src_ip="1.2.3.4", protocol="TCP", tcp_flags="SA"))
            assert analyzer.get_syn_count("1.2.3.4", 5) == 0

    def test_ignores_ack_only(self, analyzer, make_packet):
        with freeze_time(datetime(2026, 1, 1, 12, 0, 0)):
            analyzer.process(make_packet(src_ip="1.2.3.4", protocol="TCP", tcp_flags="A"))
            assert analyzer.get_syn_count("1.2.3.4", 5) == 0

    def test_ignores_non_tcp_protocol(self, analyzer, make_packet):
        with freeze_time(datetime(2026, 1, 1, 12, 0, 0)):
            analyzer.process(make_packet(src_ip="1.2.3.4", protocol="UDP", tcp_flags="S"))
            assert analyzer.get_syn_count("1.2.3.4", 5) == 0

    def test_ignores_missing_tcp_flags(self, analyzer, make_packet):
        with freeze_time(datetime(2026, 1, 1, 12, 0, 0)):
            analyzer.process(make_packet(src_ip="1.2.3.4", protocol="TCP", tcp_flags=None))
            assert analyzer.get_syn_count("1.2.3.4", 5) == 0

    def test_window_expiry(self, analyzer, make_packet):
        start = datetime(2026, 1, 1, 12, 0, 0)
        with freeze_time(start) as frozen:
            analyzer.process(make_packet(src_ip="1.2.3.4", protocol="TCP", tcp_flags="S"))
            frozen.move_to(start + timedelta(seconds=10))
            assert analyzer.get_syn_count("1.2.3.4", 5) == 0


class TestIcmpCount:

    def test_counts_icmp_packets(self, analyzer, make_packet):
        with freeze_time(datetime(2026, 1, 1, 12, 0, 0)):
            analyzer.process(make_packet(src_ip="1.2.3.4", protocol="ICMP"))
            analyzer.process(make_packet(src_ip="1.2.3.4", protocol="ICMP"))
            assert analyzer.get_icmp_count("1.2.3.4", 5) == 2

    def test_ignores_non_icmp(self, analyzer, make_packet):
        with freeze_time(datetime(2026, 1, 1, 12, 0, 0)):
            analyzer.process(make_packet(src_ip="1.2.3.4", protocol="TCP"))
            assert analyzer.get_icmp_count("1.2.3.4", 5) == 0

    def test_window_expiry(self, analyzer, make_packet):
        start = datetime(2026, 1, 1, 12, 0, 0)
        with freeze_time(start) as frozen:
            analyzer.process(make_packet(src_ip="1.2.3.4", protocol="ICMP"))
            frozen.move_to(start + timedelta(seconds=10))
            assert analyzer.get_icmp_count("1.2.3.4", 5) == 0


class TestTopTalkers:

    def test_returns_sorted_descending(self, analyzer, make_packet):
        for _ in range(3):
            analyzer.process(make_packet(src_ip="1.1.1.1"))
        for _ in range(5):
            analyzer.process(make_packet(src_ip="2.2.2.2"))
        for _ in range(1):
            analyzer.process(make_packet(src_ip="3.3.3.3"))

        top = analyzer.get_top_talkers(10)
        assert top[0] == ("2.2.2.2", 5)
        assert top[1] == ("1.1.1.1", 3)
        assert top[2] == ("3.3.3.3", 1)

    def test_respects_n_limit(self, analyzer, make_packet):
        for ip in ["1.1.1.1", "2.2.2.2", "3.3.3.3"]:
            analyzer.process(make_packet(src_ip=ip))
        assert len(analyzer.get_top_talkers(2)) == 2

    def test_empty_when_no_traffic(self, analyzer):
        assert analyzer.get_top_talkers(10) == []


class TestSummary:

    def test_summary_reflects_processed_traffic(self, analyzer, make_packet):
        analyzer.process(make_packet(src_ip="1.1.1.1", protocol="TCP"))
        analyzer.process(make_packet(src_ip="2.2.2.2", protocol="UDP"))

        summary = analyzer.get_summary()
        assert summary["total_packets"] == 2
        assert summary["protocol_counts"] == {"TCP": 1, "UDP": 1}
        assert summary["unique_sources"] == 2

    def test_summary_on_empty_analyzer(self, analyzer):
        summary = analyzer.get_summary()
        assert summary["total_packets"] == 0
        assert summary["protocol_counts"] == {}
        assert summary["unique_sources"] == 0


class TestThreadSafety:

    def test_concurrent_process_calls_do_not_lose_updates(self, analyzer, make_packet):
        """
        Sanity check that TrafficAnalyzer's internal lock actually
        prevents lost updates under concurrent access, matching its
        docstring claim of being thread-safe.
        """
        def worker(ip):
            for _ in range(200):
                analyzer.process(make_packet(src_ip=ip, protocol="TCP"))

        threads = [
            threading.Thread(target=worker, args=(f"10.0.0.{i}",))
            for i in range(10)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert analyzer.total_packets == 2000
        assert analyzer.protocol_counts["TCP"] == 2000