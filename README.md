# Network Intrusion Detection System (NIDS)

A lightweight, educational, Python-based Network Intrusion Detection System that captures live traffic, parses it down to the protocol level, applies rule-based and heuristic threat detection, and presents findings through a real-time interactive dashboard.

> **Note:** This is an educational and portfolio project, not a production replacement for tools like Snort, Suricata, or Zeek. It is engineered with production-grade practices — proper architecture, error handling, logging, testing, and documentation — as a learning exercise.

---

## Overview

Most small-to-medium networks have zero visibility into the traffic flowing across them. This project builds that visibility from the ground up: sniffing packets off a live interface, decoding them across multiple protocol layers, tracking traffic patterns and connection state, and flagging suspicious behavior such as port scans, SYN floods, ICMP floods, DNS tunneling, and connections to known-malicious hosts.

This is an **IDS**, not an IPS — it observes and alerts, but does not block traffic.

## Features

- **Live packet capture** from a user-specified network interface (via Scapy)
- **Multi-layer protocol parsing** — Ethernet, IP, TCP, UDP, ICMP, DNS, and basic HTTP
- **Rule-based & threshold-based threat detection**:
  - Port scanning
  - SYN flood attacks
  - ICMP floods
  - DNS tunneling (abnormally long subdomain queries)
  - Known malicious IPs/ports
- **Severity-tagged alerting** — LOW, MEDIUM, HIGH, CRITICAL
- **Real-time Streamlit dashboard** — live traffic stats, protocol distribution, top talkers, and filterable alert history
- **YAML-based configuration** — tune thresholds, rules, and interface selection without touching code
- **Structured logging** — full audit trail of system activity and detections

## Tech Stack

| Technology | Role |
|---|---|
| Python 3.10+ | Core language |
| Scapy | Packet capture & parsing |
| Streamlit | Real-time dashboard |
| Plotly | Interactive visualizations |
| pandas | Traffic data aggregation |
| psutil | Cross-platform interface/system info |
| PyYAML | Configuration |
| threading / queue | Concurrent, non-blocking capture pipeline |
| logging (stdlib) | Structured audit logging |

## Architecture

Traffic flows through four planes: **Data** (NIC → Scapy capture) → **Processing** (Parser → Analyzer → Detection Engine) → **Storage** (thread-safe queue, log files, YAML config) → **Presentation** (Streamlit dashboard + Plotly charts).

Capture, parsing, analysis, and detection are deliberately kept as separate components (single responsibility), connected via a thread-safe queue so the time-critical capture thread never blocks on downstream processing.

## Project Status

🚧 **In active development.** This project is being built milestone-by-milestone, from project scaffolding through packet capture, parsing, analysis, detection, alerting, dashboard, integration, and testing. See the implementation plan for the full roadmap.

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

Detection thresholds, the network interface to monitor, and logging settings are controlled via `config/config.yaml` — no code changes required to retune the system.

## Usage

```bash
# Run the capture/detection engine
python src/main.py

# Launch the dashboard
streamlit run src/dashboard/app.py
```

## Project Structure

```
nids/
├── config/          # YAML configuration
├── src/
│   ├── capture/     # Packet capture (Scapy)
│   ├── parser/      # Protocol parsing
│   ├── analyzer/    # Traffic statistics
│   ├── detector/    # Detection engine & rules
│   ├── alerts/      # Alert management
│   ├── config/      # Config loading/validation
│   ├── logger/      # Logging setup
│   └── dashboard/   # Streamlit dashboard
├── tests/           # Unit tests
├── logs/            # Runtime logs (gitignored)
└── docs/            # Architecture & setup docs
```

## Disclaimer

This tool is intended for use on networks you own or have explicit authorization to monitor. Unauthorized packet capture on networks you do not control or have permission to monitor may be illegal.

## License

TBD

