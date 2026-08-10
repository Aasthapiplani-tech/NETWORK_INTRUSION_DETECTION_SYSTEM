"""
PacketParser: Extracts structured fields from raw Scapy packets across
Ethernet, IP, TCP, UDP, ICMP, and DNS layers.
"""

import logging
from datetime import datetime
from scapy.all import Ether, IP, TCP, UDP, ICMP, DNS, DNSQR

logger = logging.getLogger(__name__)


class ParsedPacket:
    """
    A plain, structured representation of a captured packet.
    Every field defaults to None if that protocol layer isn't present.
    """

    def __init__(self):
        self.timestamp = datetime.now()

        # Layer 2 — Ethernet
        self.src_mac = None
        self.dst_mac = None

        # Layer 3 — IP
        self.src_ip = None
        self.dst_ip = None
        self.protocol = None  # "TCP", "UDP", "ICMP", or "OTHER"
        self.ttl = None
        self.length = None

        # Layer 4 — TCP/UDP
        self.src_port = None
        self.dst_port = None
        self.tcp_flags = None  # e.g. "S", "SA", "A", "FA"

        # Layer 7 — DNS
        self.dns_query = None

    def __repr__(self):
        return (
            f"ParsedPacket({self.protocol}, {self.src_ip}:{self.src_port} "
            f"-> {self.dst_ip}:{self.dst_port})"
        )


class PacketParser:
    """
    Parses raw Scapy packets into ParsedPacket objects with clean,
    accessible fields — so downstream code never touches raw Scapy layers.
    """

    def parse(self, packet) -> ParsedPacket:
        """
        Args:
            packet: A raw Scapy packet (as pulled from PacketCapture's queue).

        Returns:
            A ParsedPacket with whatever fields could be extracted.
            Fields for layers not present in the packet stay None.
        """
        parsed = ParsedPacket()

        try:
            if packet.haslayer(Ether):
                parsed.src_mac = packet[Ether].src
                parsed.dst_mac = packet[Ether].dst

            if packet.haslayer(IP):
                ip_layer = packet[IP]
                parsed.src_ip = ip_layer.src
                parsed.dst_ip = ip_layer.dst
                parsed.ttl = ip_layer.ttl
                parsed.length = ip_layer.len

                if packet.haslayer(TCP):
                    parsed.protocol = "TCP"
                    tcp_layer = packet[TCP]
                    parsed.src_port = tcp_layer.sport
                    parsed.dst_port = tcp_layer.dport
                    parsed.tcp_flags = str(tcp_layer.flags)

                elif packet.haslayer(UDP):
                    parsed.protocol = "UDP"
                    udp_layer = packet[UDP]
                    parsed.src_port = udp_layer.sport
                    parsed.dst_port = udp_layer.dport

                elif packet.haslayer(ICMP):
                    parsed.protocol = "ICMP"

                else:
                    parsed.protocol = "OTHER"

            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                try:
                    parsed.dns_query = packet[DNSQR].qname.decode(errors="ignore")
                except Exception:
                    parsed.dns_query = None

        except Exception as e:
            logger.error("Failed to parse packet: %s", e)

        return parsed