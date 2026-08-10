"""
AlertHistory: Maintains a thread-safe, timestamped, in-memory record of
recent alerts, so the dashboard (and any other consumer) can display
recent threat activity without re-parsing log files.

This does NOT replace logging — DetectionEngine still logs every alert
via logger.info() as before. AlertHistory is an additional, separate
record kept purely in memory for live display purposes.
"""

import threading
from collections import deque
from datetime import datetime


class AlertHistory:
    """
    Stores the most recent alerts in a fixed-size, thread-safe deque.

    Usage:
        history = AlertHistory(max_size=200)
        history.record(alert_dict)          # called once per alert generated
        recent = history.get_recent(10)      # called by the dashboard
    """

    def __init__(self, max_size: int = 200):
        """
        Args:
            max_size: Maximum number of alerts to retain. Oldest alerts
                      are automatically dropped once this limit is exceeded.
        """
        self._lock = threading.Lock()
        self._alerts = deque(maxlen=max_size)

    def record(self, alert: dict):
        """
        Adds an alert to the history, attaching a timestamp.

        Args:
            alert: An alert dict as produced by DetectionEngine.evaluate()
                   (must contain at least "type", "severity", "src_ip",
                   "description").
        """
        with self._lock:
            timestamped_alert = {
                "timestamp": datetime.now(),
                **alert,
            }
            self._alerts.append(timestamped_alert)

    def get_recent(self, n: int = 10) -> list:
        """
        Returns the N most recent alerts, newest first.

        Args:
            n: Number of alerts to return.

        Returns:
            A list of timestamped alert dicts, most recent first.
        """
        with self._lock:
            return list(self._alerts)[-n:][::-1]

    def count_by_severity(self) -> dict:
        """
        Returns a count of currently retained alerts grouped by severity.
        Useful for a dashboard summary panel (e.g. "3 CRITICAL, 5 HIGH").
        """
        with self._lock:
            counts = {}
            for alert in self._alerts:
                sev = alert.get("severity", "UNKNOWN")
                counts[sev] = counts.get(sev, 0) + 1
            return counts

    def total_count(self) -> int:
        """Returns the total number of alerts currently retained (bounded by max_size)."""
        with self._lock:
            return len(self._alerts)