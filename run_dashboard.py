"""
run_dashboard.py — Standalone runner for Milestone 11 (Dashboard).

Wires together the existing capture/parse/analyze/detect pipeline with
the new Dashboard, using ONE shared TrafficAnalyzer and ONE shared
AlertHistory instance throughout — so the dashboard reflects real,
live traffic and real, live alerts.

This is a temporary standalone entry point for testing the dashboard.
It will be superseded by main.py in Milestone 12 (Integration).

Usage:
    python run_dashboard.py
"""

import logging
import queue
import threading
import time

from src.capture.sniffer import PacketCapture
from src.parser.packet_parser import PacketParser
from src.analyzer.traffic_analyzer import TrafficAnalyzer
from src.detector.detection_engine import DetectionEngine
from src.config.config_manager import ConfigManager
from src.alerts import AlertHistory
from src.dashboard.dashboard import Dashboard
from src.logger.log_config import setup_logging

logger = logging.getLogger(__name__)


def processing_loop(pkt_queue, parser, analyzer, engine, alert_history, stop_event):
    """
    Background thread target: continuously pulls raw packets off the
    queue, parses them, feeds the shared TrafficAnalyzer, runs detection,
    and records any alerts into the shared AlertHistory.

    Args:
        pkt_queue: The queue.Queue shared with PacketCapture.
        parser: A PacketParser instance.
        analyzer: The shared TrafficAnalyzer instance (also read by Dashboard).
        engine: A DetectionEngine instance (wraps the same analyzer + config).
        alert_history: The shared AlertHistory instance (also read by Dashboard).
        stop_event: A threading.Event signaling this loop to exit.
    """
    while not stop_event.is_set():
        try:
            raw_packet = pkt_queue.get(timeout=0.5)
        except queue.Empty:
            continue

        parsed = parser.parse(raw_packet)
        analyzer.process(parsed)

        alerts = engine.evaluate(parsed)
        for alert in alerts:
            alert_history.record(alert)


def main():
    config = ConfigManager("config/config.yaml")

    setup_logging(
        log_dir=config.get("logging", "log_dir", default="logs"),
        log_file=config.get("logging", "log_file", default="nids.log"),
        log_level=config.get("logging", "log_level", default="INFO"),
    )

    # Shared instances — created ONCE, passed to both the pipeline and the dashboard.
    analyzer = TrafficAnalyzer()
    alert_history = AlertHistory(max_size=200)

    pkt_queue = queue.Queue()
    parser = PacketParser()
    engine = DetectionEngine(analyzer, config)

    capture = PacketCapture(config.get("network", "interface"), pkt_queue)
    stop_event = threading.Event()

    processing_thread = threading.Thread(
        target=processing_loop,
        args=(pkt_queue, parser, analyzer, engine, alert_history, stop_event),
        daemon=True,
    )

    print("Starting packet capture and processing thread...")
    capture.start()
    processing_thread.start()

    time.sleep(1)  # let capture spin up before the dashboard takes over the screen

    dashboard = Dashboard(analyzer, alert_history, config)

    try:
        dashboard.run()  # blocks until Ctrl+C
    finally:
        print("Shutting down...")
        stop_event.set()
        capture.stop()
        processing_thread.join(timeout=2)
        print("Stopped cleanly.")


if __name__ == "__main__":
    main()