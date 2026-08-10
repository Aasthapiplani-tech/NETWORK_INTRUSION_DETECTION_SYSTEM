# Architecture & Design Notes

This document covers *why* the system is structured the way it is, and the contracts between components — useful for anyone extending the project (including future-you). For setup and usage, see the main [README](../README.md).

## Design Principles

- **Single responsibility per module.** Capture, parsing, analysis, detection, alerting, and presentation are separate components. Each can be tested, reasoned about, and replaced independently.
- **Thread-safety at the boundaries.** `TrafficAnalyzer` and `AlertHistory` are the two objects shared across threads (the background processing thread writes, the dashboard thread reads). Both wrap all state access in an internal `threading.Lock`. Every other component is effectively single-threaded / stateless from the caller's perspective.
- **Duck-typed data contracts, not inheritance.** `ParsedPacket` is a plain container; rules and the analyzer only ever read attributes off it, never call methods. This is why the test suite can use lightweight fake objects (`SimpleNamespace`) instead of real Scapy-derived packets — the contract is "has these attributes," not "is this class."
- **Fail-soft detection.** `DetectionEngine.evaluate()` wraps each rule call in its own try/except. A bug in one rule degrades detection for that rule only — it never takes down the pipeline or hides alerts from other rules.

## Data Contracts

**`ParsedPacket`** (produced by `PacketParser.parse()`, consumed by `TrafficAnalyzer.process()` and every rule in `rules.py`):

| Field | Type | Notes |
|---|---|---|
| `timestamp` | `datetime` | Set at parse time |
| `src_ip`, `dst_ip` | `str` or `None` | `None` if no IP layer |
| `protocol` | `"TCP"` / `"UDP"` / `"ICMP"` / `"OTHER"` / `None` | `None` if no IP layer present |
| `src_port`, `dst_port` | `int` or `None` | Only set for TCP/UDP |
| `tcp_flags` | `str` or `None` | e.g. `"S"`, `"SA"`, `"A"`, `"FA"` — only set for TCP |
| `dns_query` | `str` or `None` | Only set if a DNS query layer is present |

**Alert dict** (produced by any rule function, consumed by `DetectionEngine.evaluate()`, `AlertHistory.record()`, and the dashboard):

```python
{
    "type": str,        # e.g. "PORT_SCAN"
    "severity": str,     # "MEDIUM" | "HIGH" | "CRITICAL"
    "src_ip": str,
    "description": str,  # pre-formatted, human-readable
}
```

Note there is no `timestamp` field at this stage — `AlertHistory.record()` is the point where a timestamp gets attached (via `{"timestamp": datetime.now(), **alert}`), producing a new dict rather than mutating the original. This keeps `rules.py` and `DetectionEngine` free of any time-handling responsibility.

## Threading Model

Main thread Capture thread Processing thread
──────────── ────────────── ──────────────────
main.py: build_pipeline()
main.py: start_pipeline() ──► PacketCapture.start()
(scapy sniff loop)
pushes to queue.Queue
◄── processing_loop()
pulls from queue,
calls analyzer.process(),
engine.evaluate(),
alert_history.record()

Dashboard.run() (run mode, [these two threads run [shared instances:
in main thread) polls concurrently with the TrafficAnalyzer,
TrafficAnalyzer + main thread] AlertHistory —
AlertHistory every both thread-safe]
refresh_interval_seconds

`monitor` mode simply omits the `Dashboard.run()` step — the capture and processing threads behave identically either way. This is why `src/main.py` factors pipeline construction (`build_pipeline`, `start_pipeline`, `stop_pipeline`) out of both `cmd_run` and `cmd_monitor`: the only difference between the two subcommands is what happens in the main thread afterward.

## Extension Points

The codebase was deliberately shaped in Milestone 12 to make future subcommands cheap to add:

- **A `dashboard` subcommand** (attach a dashboard to an already-running instance, e.g. over a socket or shared file) would need a new `cmd_dashboard()` function and a way to reach a running pipeline's `TrafficAnalyzer`/`AlertHistory` — currently these are in-process only, so this would require adding an IPC layer (not needed for a single-machine portfolio deployment).
- **A `replay` subcommand** (feed a `.pcap` file instead of live capture) would only require swapping `PacketCapture` for a new component that reads a pcap file and pushes packets onto the same `queue.Queue` — `PacketParser`, `TrafficAnalyzer`, `DetectionEngine`, and `AlertHistory` would need no changes at all, since they only ever see whatever comes off the queue.
- **New detection rules** are added by writing a new function matching the `(parsed_packet, analyzer, config) -> dict | None` signature and appending it to `ALL_RULES` in `rules.py` — `DetectionEngine` requires no changes.
- **Persisting `AlertHistory` to disk/DB** would be a self-contained change to `src/alerts/__init__.py` — every consumer (`DetectionEngine`'s caller, the dashboard) only relies on `record()` / `get_recent()` / `count_by_severity()` / `total_count()`, so the storage backend could change without touching call sites.

## Known Trade-offs

- **In-memory-only alert history** was chosen over a database for simplicity, matching the project's stated educational/portfolio scope (see README → Known Limitations). The full alert trail still exists in `logs/nids.log` if longer retention is ever needed.
- **`rich`'s alternate screen buffer** (`Live(screen=True)`) was chosen for a clean, self-clearing live view, at the cost of no native scrollback in the dashboard itself — mitigated by `AlertHistory` retaining more (200) than the dashboard displays at once (15), and by `nids.log` retaining everything.