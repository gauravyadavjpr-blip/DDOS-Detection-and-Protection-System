# Advanced DDoS Detection & Protection System

A Python-based DDoS detection and mitigation dashboard built with PyQt5 and Scapy. The project is organized as a lightweight modular package with separate modules for config loading, packet capture, packet analysis, anomaly detection, threat intelligence, alert handling, mitigation, and UI rendering.

## Features

- Live packet capture using Scapy
- Protocol parsing for TCP, UDP, ICMP, and IP traffic
- Source-IP anomaly detection with configurable rate threshold
- Optional malicious IP feed integration via HTTP JSON
- MITM-free local mitigation path using iptables-compatible firewall rules
- Email alert support with SMTP configuration
- PyQt5 dashboard with live table, packet details, protocol charts, and blocked-IP area
- CSV export and PCAP save support
- Modular architecture for easier maintenance and extension

## Project Structure

```text
DDOS-Detection-and-Protection-System/
├── main.py
├── config.ini
├── requirements.txt
├── README.md
└── ddos_detector/
    ├── __init__.py
    ├── app.py
    ├── analyzer.py
    ├── alerts.py
    ├── capture.py
    ├── config.py
    ├── detector.py
    ├── mitigation.py
    ├── threat_intel.py
    └── ui.py
```

## Installation

1. Clone the repository.
2. Create a virtual environment.
3. Install dependencies.

```bash
python -m venv .venv
.\.venv\Scripts\activate
python -m pip install -r requirements.txt
```

## Run

```bash
python main.py
```

## Configuration

The project reads its settings from [config.ini](config.ini). The most important settings are:

- `Network.Interface` — capture interface name, or `auto`
- `Network.Filter` — packet filter such as `tcp`, `udp`, `icmp`, `ip`
- `Detection.RateLimit` — threshold for packet-rate anomalies
- `Mitigation.IptablesChain` — firewall chain used for drop rules
- `ThreatIntel.FeedURL` — optional malicious IP feed

## Notes

- On Linux, `iptables` is the real OS mitigation backend.
- On Windows, packet capture requires a compatible Npcap/Scapy adapter.
- The default configuration is designed for portability and uses `auto` interface selection.

## Testing

```bash
python -m pytest -q
```

