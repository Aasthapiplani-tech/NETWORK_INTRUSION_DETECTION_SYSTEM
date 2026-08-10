"""
TrafficAnalyzer: Maintains sliding-window traffic statistics per source IP —
unique ports contacted, SYN counts, ICMP counts, and overall traffic stats.
Thread-safe, since it's written to by the capture/processing thread and
read from by the detection engine and dashboard.
"""

import logging
import threading
from collections import defaultdict, deque
from datetime import datetime

logger = logging.getLogger(__name__)


class TrafficAnalyzer:
    """
    Tracks traffic patterns using sliding time windows, keyed by source IP.
    All public methods are thread-safe.
    """

    def __init__(self):
        self._lock = threading.Lock()

        # Overall stats
        self.total_packets = 0
        self.protocol_counts = defaultdict(int)          # {"TCP": 120, "UDP": 45, ...}
        self.talker_counts = defaultdict(int)             # {src_ip: packet_count}

        # Sliding-window trackers: src_ip -> deque of (timestamp, extra_data)
        self._port_scan_tracker = defaultdict(deque)      # (timestamp, dst_port)
        self._syn_tracker = defaultdict(deque)             # timestamp only
        self._icmp_tracker = defaultdict(deque)            # timestamp only

    def process(self, parsed_packet):
        """
        Updates all tracked statistics with one parsed packet.

        Args:
            parsed_packet: A ParsedPacket instance from PacketParser.
        """
        with self._lock:
            self.total_packets += 1

            if parsed_packet.protocol:
                self.protocol_counts[parsed_packet.protocol] += 1

            if parsed_packet.src_ip:
                self.talker_counts[parsed_packet.src_ip] += 1
                now = parsed_packet.timestamp

                # Track for port scan detection
                if parsed_packet.dst_port is not None:
                    self._port_scan_tracker[parsed_packet.src_ip].append(
                        (now, parsed_packet.dst_port)
                    )

                # Track for SYN flood detection (SYN set, ACK not set)
                if parsed_packet.protocol == "TCP" and parsed_packet.tcp_flags:
                    if "S" in parsed_packet.tcp_flags and "A" not in parsed_packet.tcp_flags:
                        self._syn_tracker[parsed_packet.src_ip].append(now)

                # Track for ICMP flood detection
                if parsed_packet.protocol == "ICMP":
                    self._icmp_tracker[parsed_packet.src_ip].append(now)

    def _prune(self, dq: deque, window_seconds: int, now: datetime):
        """Removes entries older than the sliding window from the left of a deque."""
        while dq and (now - (dq[0][0] if isinstance(dq[0], tuple) else dq[0])).total_seconds() > window_seconds:
            dq.popleft()

    def get_unique_ports(self, src_ip: str, window_seconds: int) -> int:
        """Returns the count of unique destination ports contacted by src_ip within the window."""
        with self._lock:
            now = datetime.now()
            dq = self._port_scan_tracker[src_ip]
            self._prune(dq, window_seconds, now)
            return len({port for _, port in dq})

    def get_syn_count(self, src_ip: str, window_seconds: int) -> int:
        """Returns the count of unmatched SYN packets from src_ip within the window."""
        with self._lock:
            now = datetime.now()
            dq = self._syn_tracker[src_ip]
            self._prune(dq, window_seconds, now)
            return len(dq)

    def get_icmp_count(self, src_ip: str, window_seconds: int) -> int:
        """Returns the count of ICMP packets from src_ip within the window."""
        with self._lock:
            now = datetime.now()
            dq = self._icmp_tracker[src_ip]
            self._prune(dq, window_seconds, now)
            return len(dq)

    def get_top_talkers(self, n: int = 10):
        """Returns the top N source IPs by packet count, as a list of (ip, count) tuples."""
        with self._lock:
            return sorted(self.talker_counts.items(), key=lambda x: x[1], reverse=True)[:n]

    def get_summary(self) -> dict:
        """Returns a snapshot of overall traffic stats for the dashboard."""
        with self._lock:
            return {
                "total_packets": self.total_packets,
                "protocol_counts": dict(self.protocol_counts),
                "unique_sources": len(self.talker_counts),
            }