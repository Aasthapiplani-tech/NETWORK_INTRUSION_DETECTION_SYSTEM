"""
DetectionEngine: Runs each parsed packet through all registered detection
rules and returns any alerts that fire.
"""

import logging
from src.detector.rules import ALL_RULES

logger = logging.getLogger(__name__)


class DetectionEngine:
    """
    Orchestrates threat detection by running every parsed packet through
    the full set of rules defined in rules.ALL_RULES.

    Usage:
        engine = DetectionEngine(analyzer, config)
        alerts = engine.evaluate(parsed_packet)
    """

    def __init__(self, analyzer, config):
        """
        Args:
            analyzer: A TrafficAnalyzer instance (already receiving packets).
            config: A ConfigManager instance with detection thresholds loaded.
        """
        self.analyzer = analyzer
        self.config = config
        self.rules = ALL_RULES

    def evaluate(self, parsed_packet) -> list:
        """
        Runs one parsed packet through every detection rule.

        Args:
            parsed_packet: A ParsedPacket instance from PacketParser.

        Returns:
            A list of alert dicts (possibly empty) for any rules that fired.
        """
        triggered_alerts = []

        for rule in self.rules:
            try:
                result = rule(parsed_packet, self.analyzer, self.config)
                if result:
                    triggered_alerts.append(result)
                    logger.info(
                        "ALERT [%s/%s] %s",
                        result["type"], result["severity"], result["description"]
                    )
            except Exception as e:
                logger.error("Rule '%s' raised an exception: %s", rule.__name__, e)

        return triggered_alerts