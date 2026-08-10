"""
Temporary end-to-end test: captures traffic, self-scans to trigger a port
scan alert, and verifies the detection pipeline works — all in one script.
"""

import queue
import time
import threading
import socket

from src.capture.sniffer import PacketCapture
from src.parser.packet_parser import PacketParser
from src.analyzer.traffic_analyzer import TrafficAnalyzer
from src.detector.detection_engine import DetectionEngine
from src.config.config_manager import ConfigManager


def run_self_scan(target_ip):
    """Scans ourselves to generate real port-scan traffic."""
    for port in range(20, 50):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        s.connect_ex((target_ip, port))
        s.close()


def main():
    config = ConfigManager("config/config.yaml")
    q = queue.Queue()

    capture = PacketCapture(config.get("network", "interface"), q)
    parser = PacketParser()
    analyzer = TrafficAnalyzer()
    engine = DetectionEngine(analyzer, config)

    capture.start()
    time.sleep(1)  # let capture spin up before scanning

    # Scan the router/gateway instead of ourselves — real external target,
    # guarantees traffic actually traverses the NIC.
    import subprocess
    result = subprocess.run(["ipconfig"], capture_output=True, text=True)
    print("Find your Default Gateway below, then edit target_ip manually if needed:")
    for line in result.stdout.splitlines():
        if "Default Gateway" in line or "Wireless LAN" in line:
            print(line.strip())

    target_ip = "192.168.110.1"  # <-- CHANGE THIS to your actual Default Gateway if different
    print(f"\nScanning target: {target_ip}")

    scan_thread = threading.Thread(target=run_self_scan, args=(target_ip,))
    scan_thread.start()
    scan_thread.join()

    time.sleep(2)
    capture.stop()

    all_alerts = []
    while not q.empty():
        parsed = parser.parse(q.get())
        analyzer.process(parsed)
        all_alerts.extend(engine.evaluate(parsed))

    print(f"Total packets captured: {analyzer.total_packets}")
    print(f"Unique ports for {target_ip} (last 10s, from target's replies): {analyzer.get_unique_ports(target_ip, 10)}")
    print(f"\nTotal alerts triggered: {len(all_alerts)}")
    for a in all_alerts[:10]:
        print(a)
    


if __name__ == "__main__":
    main()