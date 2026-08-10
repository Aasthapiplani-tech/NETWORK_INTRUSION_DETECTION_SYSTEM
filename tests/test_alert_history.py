"""
Tests for AlertHistory (src/alerts/__init__.py).

Covers: record() timestamping, get_recent() ordering and limit,
max_size eviction (bounded deque), count_by_severity(), and
total_count().
"""

from datetime import datetime

from freezegun import freeze_time

from src.alerts import AlertHistory


def make_alert(alert_type="PORT_SCAN", severity="HIGH", src_ip="1.2.3.4", description="test alert"):
    """Local helper — builds a plain alert dict matching rules.py's shape."""
    return {
        "type": alert_type,
        "severity": severity,
        "src_ip": src_ip,
        "description": description,
    }


class TestRecord:

    def test_record_adds_timestamp(self, alert_history):
        with freeze_time(datetime(2026, 1, 1, 12, 0, 0)):
            alert_history.record(make_alert())

        recent = alert_history.get_recent(1)
        assert recent[0]["timestamp"] == datetime(2026, 1, 1, 12, 0, 0)

    def test_record_preserves_original_alert_fields(self, alert_history):
        alert_history.record(make_alert(
            alert_type="SYN_FLOOD", severity="CRITICAL",
            src_ip="9.9.9.9", description="flood detected"
        ))
        recent = alert_history.get_recent(1)
        assert recent[0]["type"] == "SYN_FLOOD"
        assert recent[0]["severity"] == "CRITICAL"
        assert recent[0]["src_ip"] == "9.9.9.9"
        assert recent[0]["description"] == "flood detected"

    def test_record_does_not_mutate_original_dict(self, alert_history):
        original = make_alert()
        alert_history.record(original)
        # AlertHistory.record() builds a new dict via {**alert}, so the
        # caller's original dict must remain untouched (no "timestamp" key).
        assert "timestamp" not in original

    def test_total_count_increments(self, alert_history):
        alert_history.record(make_alert())
        alert_history.record(make_alert())
        assert alert_history.total_count() == 2

    def test_total_count_zero_when_empty(self, alert_history):
        assert alert_history.total_count() == 0


class TestGetRecent:

    def test_returns_newest_first(self, alert_history):
        with freeze_time(datetime(2026, 1, 1, 12, 0, 0)):
            alert_history.record(make_alert(description="first"))
        with freeze_time(datetime(2026, 1, 1, 12, 0, 1)):
            alert_history.record(make_alert(description="second"))
        with freeze_time(datetime(2026, 1, 1, 12, 0, 2)):
            alert_history.record(make_alert(description="third"))

        recent = alert_history.get_recent(3)
        assert [a["description"] for a in recent] == ["third", "second", "first"]

    def test_respects_n_limit(self, alert_history):
        for i in range(5):
            alert_history.record(make_alert(description=f"alert-{i}"))

        recent = alert_history.get_recent(2)
        assert len(recent) == 2
        # Most recent two, newest first.
        assert [a["description"] for a in recent] == ["alert-4", "alert-3"]

    def test_returns_empty_list_when_no_alerts(self, alert_history):
        assert alert_history.get_recent(10) == []

    def test_n_larger_than_available_returns_all(self, alert_history):
        alert_history.record(make_alert())
        alert_history.record(make_alert())
        recent = alert_history.get_recent(100)
        assert len(recent) == 2

    def test_default_n_is_ten(self, alert_history):
        for i in range(15):
            alert_history.record(make_alert(description=f"alert-{i}"))
        recent = alert_history.get_recent()
        assert len(recent) == 10


class TestMaxSizeEviction:

    def test_oldest_alerts_evicted_beyond_max_size(self, alert_history):
        # Fixture provides max_size=200; use a small dedicated instance
        # here to test eviction without recording 200+ alerts.
        small_history = AlertHistory(max_size=3)

        for i in range(5):
            small_history.record(make_alert(description=f"alert-{i}"))

        assert small_history.total_count() == 3
        recent = small_history.get_recent(3)
        # Only the 3 most recent should remain: alert-4, alert-3, alert-2
        assert [a["description"] for a in recent] == ["alert-4", "alert-3", "alert-2"]

    def test_default_max_size_is_200(self):
        default_history = AlertHistory()
        for i in range(250):
            default_history.record(make_alert())
        assert default_history.total_count() == 200


class TestCountBySeverity:

    def test_counts_grouped_correctly(self, alert_history):
        alert_history.record(make_alert(severity="HIGH"))
        alert_history.record(make_alert(severity="HIGH"))
        alert_history.record(make_alert(severity="CRITICAL"))
        alert_history.record(make_alert(severity="MEDIUM"))

        counts = alert_history.count_by_severity()
        assert counts == {"HIGH": 2, "CRITICAL": 1, "MEDIUM": 1}

    def test_empty_when_no_alerts(self, alert_history):
        assert alert_history.count_by_severity() == {}

    def test_missing_severity_key_counted_as_unknown(self, alert_history):
        # Defensive case: an alert dict missing "severity" entirely.
        alert_history.record({"type": "WEIRD", "src_ip": "1.1.1.1", "description": "no severity field"})
        counts = alert_history.count_by_severity()
        assert counts == {"UNKNOWN": 1}

    def test_reflects_eviction(self):
        small_history = AlertHistory(max_size=2)
        small_history.record(make_alert(severity="LOW"))
        small_history.record(make_alert(severity="HIGH"))
        small_history.record(make_alert(severity="CRITICAL"))
        # "LOW" alert was evicted; only HIGH and CRITICAL remain.
        counts = small_history.count_by_severity()
        assert counts == {"HIGH": 1, "CRITICAL": 1}