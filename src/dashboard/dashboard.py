"""
Dashboard: Live terminal display of NIDS traffic statistics and recent
alerts. Reads from a shared TrafficAnalyzer and AlertHistory instance —
does not modify or own any detection/capture logic.
"""

import logging
from datetime import datetime

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

logger = logging.getLogger(__name__)

# Maps alert severity to a rich color name for visual emphasis.
SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "bold orange3",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "UNKNOWN": "white",
}


class Dashboard:
    """
    Renders a live terminal dashboard showing traffic summary, top
    talkers, and recent alerts.

    Usage:
        dashboard = Dashboard(analyzer, alert_history, config)
        dashboard.run()   # blocks, refreshing until Ctrl+C
    """

    def __init__(self, analyzer, alert_history, config):
        """
        Args:
            analyzer: A TrafficAnalyzer instance (shared with the capture
                      pipeline, read-only from the dashboard's perspective).
            alert_history: An AlertHistory instance (shared with the
                      detection pipeline, read-only from here).
            config: A ConfigManager instance, used to read
                      dashboard.refresh_interval_seconds.
        """
        self.analyzer = analyzer
        self.alert_history = alert_history
        self.config = config
        self.console = Console()
        self.refresh_interval = config.get(
            "dashboard", "refresh_interval_seconds", default=3
        )

    def _build_summary_panel(self) -> Panel:
        """Builds the top panel: overall traffic summary."""
        summary = self.analyzer.get_summary()
        severity_counts = self.alert_history.count_by_severity()

        lines = [
            f"[bold]Total Packets:[/bold] {summary['total_packets']}",
            f"[bold]Unique Sources:[/bold] {summary['unique_sources']}",
            f"[bold]Protocols:[/bold] "
            + ", ".join(f"{proto}={count}" for proto, count in summary["protocol_counts"].items())
            if summary["protocol_counts"] else "[bold]Protocols:[/bold] (none yet)",
            "",
            f"[bold]Total Alerts (retained):[/bold] {self.alert_history.total_count()}",
            "  " + "  ".join(
                f"[{SEVERITY_COLORS.get(sev, 'white')}]{sev}: {count}[/{SEVERITY_COLORS.get(sev, 'white')}]"
                for sev, count in severity_counts.items()
            ) if severity_counts else "  (no alerts yet)",
        ]

        return Panel(
            "\n".join(lines),
            title="[bold cyan]Traffic Summary[/bold cyan]",
            border_style="cyan",
        )

    def _build_top_talkers_table(self) -> Table:
        """Builds a table of the top source IPs by packet count."""
        table = Table(title="Top Talkers", expand=True)
        table.add_column("Source IP", style="white")
        table.add_column("Packets", justify="right", style="green")

        for ip, count in self.analyzer.get_top_talkers(10):
            table.add_row(ip, str(count))

        if not self.analyzer.get_top_talkers(1):
            table.add_row("(no traffic yet)", "-")

        return table

    def _build_alerts_table(self) -> Table:
        """Builds a table of the most recent alerts, newest first."""
        table = Table(title="Recent Alerts", expand=True)
        table.add_column("Time", style="dim", width=10)
        table.add_column("Type", style="white")
        table.add_column("Severity", width=10)
        table.add_column("Source IP", style="white")
        table.add_column("Description", style="white", overflow="fold")

        recent = self.alert_history.get_recent(15)

        if not recent:
            table.add_row("-", "-", "-", "-", "(no alerts yet)")
            return table

        for alert in recent:
            ts = alert["timestamp"].strftime("%H:%M:%S")
            severity = alert.get("severity", "UNKNOWN")
            color = SEVERITY_COLORS.get(severity, "white")
            table.add_row(
                ts,
                alert.get("type", "-"),
                Text(severity, style=color),
                alert.get("src_ip") or "-",
                alert.get("description", "-"),
            )

        return table

    def _build_layout(self) -> Layout:
        """Assembles the full dashboard layout for one refresh cycle."""
        layout = Layout()

        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="summary", size=8),
            Layout(name="body"),
        )

        layout["body"].split_row(
            Layout(name="talkers"),
            Layout(name="alerts", ratio=2),
        )

        header_text = Text(
            f" NIDS Live Dashboard — last updated {datetime.now().strftime('%H:%M:%S')} ",
            style="bold white on blue",
            justify="center",
        )
        layout["header"].update(Panel(header_text))
        layout["summary"].update(self._build_summary_panel())
        layout["talkers"].update(self._build_top_talkers_table())
        layout["alerts"].update(self._build_alerts_table())

        return layout

    def run(self):
        """
        Starts the live dashboard loop. Blocks until interrupted
        (Ctrl+C). Refreshes according to dashboard.refresh_interval_seconds
        from config.
        """
        logger.info("Dashboard started (refresh interval: %ss)", self.refresh_interval)
        try:
            with Live(
                self._build_layout(),
                refresh_per_second=1 / self.refresh_interval,
                screen=True,
            ) as live:
                while True:
                    live.update(self._build_layout())
                    import time
                    time.sleep(self.refresh_interval)
        except KeyboardInterrupt:
            logger.info("Dashboard stopped by user (Ctrl+C).")
            self.console.print("\n[bold yellow]Dashboard stopped.[/bold yellow]")