# Network Intrusion Detection System (NIDS)

A lightweight, educational, Python-based Network Intrusion Detection System that captures live traffic, parses it down to the protocol level, applies rule-based and heuristic threat detection, and presents findings through a real-time terminal dashboard.

> **Note:** This is an educational and portfolio project, not a production replacement for tools like Snort, Suricata, or Zeek. It is engineered with production-grade practices — proper architecture, error handling, logging, testing, and documentation — as a learning exercise.

---

## Overview

Most small-to-medium networks have zero visibility into the traffic flowing across them. This project builds that visibility from the ground up: sniffing packets off a live interface, decoding them across multiple protocol layers, tracking traffic patterns and connection state, and flagging suspicious behavior such as port scans, SYN floods, ICMP floods, DNS tunneling, and connections to known-malicious hosts.

This is an **IDS**, not an IPS — it observes and alerts, but does not block traffic.

## Features

- **Live packet capture** from a user-specified network interface (via Scapy)
- **Multi-layer protocol parsing** — Ethernet, IP, TCP, UDP, ICMP, and DNS
- **Rule-based & threshold-based threat detection**:
  - Port scanning
  - SYN flood attacks
  - ICMP floods
  - DNS tunneling (abnormally long subdomain queries)
  - Known malicious IPs
  - Known malicious ports
- **Severity-tagged alerting** — MEDIUM, HIGH, CRITICAL
- **Real-time terminal dashboard** (via [rich](https://github.com/Textualize/rich)) — live traffic stats, protocol distribution, top talkers, and a live-updating recent-alerts table
- **YAML-based configuration** — tune thresholds, rules, and interface selection without touching code
- **Structured logging** — full audit trail of system activity and detections, to both console and a rotating log file
- **Automated test suite** — 105 pytest tests covering configuration, traffic analysis, alerting, detection rules, the detection engine, and end-to-end pipeline behavior

## Tech Stack

| Technology | Role |
|---|---|
| Python 3.10+ | Core language |
| Scapy | Packet capture & parsing |
| rich | Real-time terminal dashboard |
| PyYAML | Configuration |
| threading / queue | Concurrent, non-blocking capture pipeline |
| logging (stdlib) | Structured audit logging |
| pytest / freezegun | Automated, deterministic testing |

## Architecture

Traffic flows through four stages, each a separate, single-responsibility component connected via a thread-safe queue — so the time-critical capture thread never blocks on downstream processing:

PacketCapture (Scapy sniff, background thread)
│ raw packets
▼
queue.Queue
│
▼
PacketParser.parse() → ParsedPacket (structured fields)
│
├──────────────────────────────┐
▼ ▼
TrafficAnalyzer.process() DetectionEngine.evaluate()
(sliding-window stats, (runs all rules in rules.py,
thread-safe, read by reads thresholds from config
both detection & dashboard) and live stats from analyzer)
│ │
│ ▼
│ AlertHistory.record()
│ (timestamped, bounded in-memory
│ history, thread-safe)
│ │
└───────────────┬───────────────┘
▼
Dashboard (rich, polls both
TrafficAnalyzer and AlertHistory
every dashboard.refresh_interval_seconds)

Every alert is also written to the rotating log file (`logs/nids.log`) regardless of whether the dashboard is running, so nothing is lost in `monitor` mode.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for a deeper breakdown of each module's responsibilities, data contracts between components, and extension points.

## Project Status

**Milestones 1–13 complete** (project scaffolding through automated testing). Documentation (Milestone 14) is in progress. See [`docs/`](docs/) for design notes.

## Requirements

- Python 3.10+
- **Windows:** [Npcap](https://npcap.com/) installed with "WinPcap API-Compatible Mode" enabled (required by Scapy)
- **Linux:** libpcap (typically preinstalled or available via package manager)
- Administrator/root privileges (required for raw packet capture)

## Installation

```bash
# Clone the repository
git clone <repo-url>
cd nids

# Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate      # Windows
source venv/bin/activate   # Linux/macOS

# Install dependencies
pip install -r requirements.txt
```

## Configuration

All tunable behavior lives in `config/config.yaml` — no code changes required to retune the system.

| Section | Key | Meaning | Example |
|---|---|---|---|
| `network` | `interface` | Network interface name to sniff on (must match Scapy's interface list exactly) | `"Wi-Fi"` |
| `detection.port_scan` | `unique_ports_threshold` | Alert if a source IP contacts more than this many unique destination ports... | `15` |
| | `time_window_seconds` | ...within this many seconds | `10` |
| `detection.syn_flood` | `syn_count_threshold` | Alert if a source IP sends more than this many unmatched SYN packets... | `50` |
| | `time_window_seconds` | ...within this many seconds | `5` |
| `detection.icmp_flood` | `icmp_count_threshold` | Alert if a source IP sends more than this many ICMP packets... | `30` |
| | `time_window_seconds` | ...within this many seconds | `5` |
| `detection.dns_tunneling` | `subdomain_length_threshold` | Alert if a DNS query's first subdomain label exceeds this many characters | `50` |
| `detection` | `malicious_ips` | List of known-bad IPs to flag on sight (source or destination) | `["1.2.3.4"]` |
| | `malicious_ports` | List of known-bad ports to flag on sight (source or destination) | `[4444, 31337]` |
| `logging` | `log_dir` | Directory where the log file is written | `"logs"` |
| | `log_file` | Log file name | `"nids.log"` |
| | `log_level` | Minimum severity logged: DEBUG, INFO, WARNING, ERROR, CRITICAL | `"INFO"` |
| `dashboard` | `refresh_interval_seconds` | How often the live dashboard redraws | `3` |

`network`, `detection`, `logging`, and `dashboard` are all **required** top-level sections — `ConfigManager` raises a `ConfigError` at startup if any are missing, or if the file is missing, empty, or malformed.

## Usage

The NIDS has a single entry point, `src/main.py`, with two subcommands:

```bash
# Full NIDS: capture + parsing + analysis + detection + alerting + live dashboard
python src/main.py run

# Full NIDS engine only — no dashboard; alerts print to console/log as they fire
python src/main.py monitor
```

Both require an elevated/Administrator terminal (raw packet capture needs it). Stop either with `Ctrl+C` — both shut down capture and the processing thread cleanly.

`monitor` mode prints a summary (total packets processed, total alerts retained) on exit — useful for headless or scripted runs where a live dashboard isn't wanted.

> The standalone scripts `test_detection.py` (manual smoke test) and `run_dashboard.py` (Milestone 11 prototype) are no longer needed for normal operation — `src/main.py` supersedes both — but remain in the repository for reference.

## Running the Test Suite

```bash
pip install -r requirements.txt   # includes pytest and freezegun
pytest tests/ -v
```

The suite is fully deterministic and requires **no live network traffic, no packet capture, and no elevated privileges** — sliding-window and timing behavior is tested using `freezegun` to control time directly, and packets are synthetic (duck-typed fake objects), not real captured traffic.

| Test file | Focus |
|---|---|
| `test_config_manager.py` | Config loading, validation, nested key lookup |
| `test_traffic_analyzer.py` | Packet/protocol counting, sliding-window stats, thread safety |
| `test_alert_history.py` | Alert recording, ordering, bounded history, severity counts |
| `test_rules.py` | All six detection rules, threshold boundaries, edge cases |
| `test_detection_engine.py` | Rule aggregation, exception isolation |
| `test_integration_pipeline.py` | Synthetic end-to-end detection scenarios |

## Detection & Alerting Overview

Every parsed packet is run through six independent rules (`src/detector/rules.py`); each returns an alert dict or `None`:

| Rule | Trigger | Severity |
|---|---|---|
| `check_port_scan` | Source IP contacts more unique destination ports than `unique_ports_threshold` within the time window | HIGH |
| `check_syn_flood` | Source IP sends more unmatched SYN packets than `syn_count_threshold` within the time window | CRITICAL |
| `check_icmp_flood` | Source IP sends more ICMP packets than `icmp_count_threshold` within the time window | MEDIUM |
| `check_dns_tunneling` | A DNS query's first subdomain label exceeds `subdomain_length_threshold` characters | MEDIUM |
| `check_malicious_ip` | Source or destination IP is in the configured `malicious_ips` list | CRITICAL |
| `check_malicious_port` | Source or destination port is in the configured `malicious_ports` list | HIGH |

Every alert dict has the shape `{"type": str, "severity": str, "src_ip": str, "description": str}`. A single rule failing (raising an exception) never prevents the others from running — `DetectionEngine.evaluate()` isolates and logs per-rule errors.

Alerts are:
1. Logged via the standard logger (visible in console and `logs/nids.log`), in both `run` and `monitor` mode
2. Recorded into `AlertHistory` — a thread-safe, timestamped, bounded (default 200) in-memory record, which the dashboard reads from directly

## Project Structure

nids/
├── config/
│ └── config.yaml # All tunable thresholds, interface, logging, dashboard settings
├── docs/ # Architecture & design notes
├── logs/ # Runtime logs (gitignored)
├── src/
│ ├── alerts/ # AlertHistory — thread-safe, timestamped alert record
│ ├── analyzer/ # TrafficAnalyzer — sliding-window traffic statistics
│ ├── capture/ # PacketCapture — Scapy-based live sniffing (background thread)
│ ├── config/ # ConfigManager — YAML loading & validation
│ ├── dashboard/ # Dashboard — live rich-based terminal UI
│ ├── detector/ # DetectionEngine + rules.py — threat detection logic
│ ├── logger/ # Logging setup (console + rotating file handler)
│ ├── parser/ # PacketParser — raw Scapy packet → ParsedPacket
│ └── main.py # Single entry point: run and monitor subcommands
├── tests/ # Automated pytest suite (105 tests)
├── requirements.txt
├── run_dashboard.py # Milestone 11 prototype runner (superseded by main.py)
├── test_detection.py # Manual end-to-end smoke test script
└── README.md

## Known Limitations

- **IDS, not IPS** — traffic is observed and alerted on, never blocked or dropped.
- **In-memory alert history only** — `AlertHistory` retains the most recent 200 alerts per running process; it is not persisted to disk or a database, and resets on restart. Full alert history is still recoverable from `logs/nids.log`.
- **No HTTP-layer parsing** — protocol parsing covers Ethernet, IP, TCP, UDP, ICMP, and DNS only.
- **Single-host scope** — designed to monitor traffic visible to one network interface on one machine; it is not a distributed or multi-sensor system.
- **Fixed rule set** — detection rules are threshold-based and hand-coded in `rules.py`; there is no machine-learning or anomaly-based detection.
- **Terminal dashboard only** — no web UI; `run` mode requires an interactive terminal (it uses an alternate screen buffer, so output isn't meaningfully redirectable to a file).
- **Windows/Npcap and Linux/libpcap only** — platform support is whatever Scapy itself supports; this has been developed and tested primarily on Windows 11.
- **Two independent pipelines if run simultaneously** — running `main.py` alongside `test_detection.py` or `run_dashboard.py` creates separate, uncoordinated `TrafficAnalyzer`/`AlertHistory` instances, each seeing the same live traffic independently. This is expected for testing but not intended as normal operation.

## Disclaimer

This tool is intended for use on networks you own or have explicit authorization to monitor. Unauthorized packet capture on networks you do not control or have permission to monitor may be illegal.

## License

TBD