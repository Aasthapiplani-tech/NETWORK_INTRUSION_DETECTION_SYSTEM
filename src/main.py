"""
main.py — Single entry point for the NIDS application.

Subcommands:
    run      Starts the full NIDS: capture, parsing, analysis, detection,
             alert management, AND the live dashboard.
    monitor  Starts the full NIDS engine (capture through alerting) with
             NO dashboard — alerts and status go to the console/log only.

Future subcommands (e.g. "dashboard" to view a running instance separately,
or "replay" to feed a pcap file instead of live capture) can be added by
registering a new subparser and a new cmd_*() function, without touching
the existing ones.

Usage:
    python src/main.py run
    python src/main.py monitor
"""

import argparse
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
        analyzer: The shared TrafficAnalyzer instance.
        engine: A DetectionEngine instance (wraps the same analyzer + config).
        alert_history: The shared AlertHistory instance.
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
            logger.warning(
                "ALERT [%s/%s] %s",
                alert["type"], alert["severity"], alert["description"]
            )


def build_pipeline(config: ConfigManager):
    """
    Creates all shared pipeline components using the given config.
    Both 'run' and 'monitor' modes call this — the ONLY place these
    objects are constructed, so there is no duplication between modes.

    Args:
        config: A loaded ConfigManager instance.

    Returns:
        A dict containing: analyzer, alert_history, pkt_queue, parser,
        engine, capture, stop_event — everything needed to start and
        stop the pipeline.
    """
    analyzer = TrafficAnalyzer()
    alert_history = AlertHistory(max_size=200)
    pkt_queue = queue.Queue()
    parser = PacketParser()
    engine = DetectionEngine(analyzer, config)
    capture = PacketCapture(config.get("network", "interface"), pkt_queue)
    stop_event = threading.Event()

    return {
        "analyzer": analyzer,
        "alert_history": alert_history,
        "pkt_queue": pkt_queue,
        "parser": parser,
        "engine": engine,
        "capture": capture,
        "stop_event": stop_event,
    }


def start_pipeline(components: dict) -> threading.Thread:
    """
    Starts packet capture and the background processing thread.

    Args:
        components: The dict returned by build_pipeline().

    Returns:
        The started processing thread (daemon, already running).
    """
    processing_thread = threading.Thread(
        target=processing_loop,
        args=(
            components["pkt_queue"],
            components["parser"],
            components["analyzer"],
            components["engine"],
            components["alert_history"],
            components["stop_event"],
        ),
        daemon=True,
    )

    components["capture"].start()
    processing_thread.start()
    time.sleep(1)  # let capture spin up before returning control

    return processing_thread


def stop_pipeline(components: dict, processing_thread: threading.Thread):
    """
    Signals shutdown and waits for capture + processing to stop cleanly.

    Args:
        components: The dict returned by build_pipeline().
        processing_thread: The thread returned by start_pipeline().
    """
    components["stop_event"].set()
    components["capture"].stop()
    processing_thread.join(timeout=2)


def load_config_and_logging() -> ConfigManager:
    """
    Loads config.yaml and initializes logging. Shared by every subcommand.

    Returns:
        A loaded ConfigManager instance.
    """
    config = ConfigManager("config/config.yaml")
    setup_logging(
        log_dir=config.get("logging", "log_dir", default="logs"),
        log_file=config.get("logging", "log_file", default="nids.log"),
        log_level=config.get("logging", "log_level", default="INFO"),
    )
    return config


def cmd_run(args):
    """
    Handler for: python src/main.py run
    Starts the full NIDS pipeline AND the live dashboard.
    """
    config = load_config_and_logging()
    components = build_pipeline(config)

    print("Starting NIDS (full mode with dashboard)...")
    processing_thread = start_pipeline(components)

    dashboard = Dashboard(components["analyzer"], components["alert_history"], config)

    try:
        dashboard.run()  # blocks until Ctrl+C
    finally:
        print("Shutting down...")
        stop_pipeline(components, processing_thread)
        print("Stopped cleanly.")


def cmd_monitor(args):
    """
    Handler for: python src/main.py monitor
    Starts the full NIDS pipeline with NO dashboard. Alerts and status
    are visible via the console/log (through logger.warning in
    processing_loop). Runs until Ctrl+C.
    """
    config = load_config_and_logging()
    components = build_pipeline(config)

    print("Starting NIDS (monitor mode, no dashboard). Press Ctrl+C to stop.")
    processing_thread = start_pipeline(components)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping (Ctrl+C received)...")
    finally:
        stop_pipeline(components, processing_thread)
        summary = components["analyzer"].get_summary()
        print(f"Total packets processed: {summary['total_packets']}")
        print(f"Total alerts retained: {components['alert_history'].total_count()}")
        print("Stopped cleanly.")


def main():
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="NIDS — Network Intrusion Detection System",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser(
        "run", help="Start the full NIDS with the live dashboard."
    )
    run_parser.set_defaults(func=cmd_run)

    monitor_parser = subparsers.add_parser(
        "monitor", help="Start the full NIDS engine with no dashboard."
    )
    monitor_parser.set_defaults(func=cmd_monitor)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()