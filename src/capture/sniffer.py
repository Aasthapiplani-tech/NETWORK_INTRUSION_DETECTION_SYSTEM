"""
PacketCapture: Sniffs live packets from a network interface in a background
thread and pushes them into a thread-safe queue for downstream processing.
"""

import logging
import threading
import queue
from scapy.all import sniff, conf

logger = logging.getLogger(__name__)


class PacketCapture:
    """
    Captures live packets from a specified network interface on a background
    thread and pushes each raw packet onto a thread-safe queue.

    Usage:
        capture = PacketCapture(interface="Wi-Fi", packet_queue=my_queue)
        capture.start()
        ...
        capture.stop()
    """

    def __init__(self, interface: str, packet_queue: queue.Queue):
        """
        Args:
            interface: Name of the network interface to sniff on (must match
                       Scapy's interface list exactly, e.g. "Wi-Fi").
            packet_queue: A thread-safe queue.Queue that captured packets
                          are pushed into for the processing thread to consume.
        """
        self.interface = interface
        self.packet_queue = packet_queue
        self._stop_event = threading.Event()
        self._thread = None

    def _packet_handler(self, packet):
        """Callback invoked by Scapy for every captured packet."""
        try:
            self.packet_queue.put(packet, block=False)
        except queue.Full:
            logger.warning("Packet queue is full — dropping packet.")

    def _capture_loop(self):
        """Runs Scapy's sniff() loop until stop() is called."""
        logger.info("Starting packet capture on interface: %s", self.interface)
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                stop_filter=lambda pkt: self._stop_event.is_set(),
                store=False,
            )
        except Exception as e:
            logger.error("Packet capture failed on interface '%s': %s", self.interface, e)
        logger.info("Packet capture stopped.")

    def start(self):
        """Starts packet capture on a background thread."""
        if self._thread and self._thread.is_alive():
            logger.warning("Capture already running.")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Signals the capture thread to stop and waits for it to exit."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
