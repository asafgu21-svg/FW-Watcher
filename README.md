# FW Watcher

A desktop GUI for visualising FortiGate firewall configurations as an interactive network topology graph. Load address objects and firewall policies from CSV exports and explore the relationships between subnets, hosts, and rules.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue) ![PyQt6](https://img.shields.io/badge/PyQt6-6.4%2B-green) ![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)

## Features

- **Interactive graph** — subnets as nodes, policies as colour-coded edges (green = accept, red = deny, orange = mixed)
- **Click to inspect** — select any node or edge to see address details, members, and policy rules in the side panel
- **Drill-down view** — double-click a subnet to see all contained address objects and related policies in a table
- **Search** — filter nodes in real time by name
- **ANY node toggle** — show or hide the catch-all `__ANY__` node to reduce clutter
- **Right-click menu** — drill in, copy name, or hide individual nodes
- **Flexible CSV parser** — handles semicolon or comma delimiters and fuzzy column-name matching

## Screenshots

> Load your FortiGate CSV exports and the graph renders automatically.

## Requirements

- Python 3.10+
- PyQt6 >= 6.4
- networkx >= 3.0

## Installation

```bash
git clone https://github.com/asafgu21-svg/FW-Watcher.git
cd FW-Watcher
pip install -r requirements.txt
python main.py
```

## Usage

1. Click **Load Addresses CSV** and select your FortiGate address export.
2. Click **Load Policies CSV** and select your FortiGate policy export.
3. The topology graph renders automatically.
4. **Scroll** to zoom, **middle-drag** to pan.
5. **Click** a node or edge to inspect details in the right panel.
6. **Double-click** a subnet node to drill into its members.

### Exporting CSVs from FortiGate

- **Addresses:** Policy & Objects → Addresses → select all → export to CSV
- **Policies:** Policy & Objects → Firewall Policy → select all → export to CSV

### Test Data

The `input/` folder contains sample CSV files you can use to try the app immediately:

| File | Contents |
|------|----------|
| `input/addresses.csv` | 19 objects — subnets, hosts, IP ranges, FQDN, groups |
| `input/policies.csv` | 15 policies — accept/deny, NAT, disabled rules, inter-zone traffic |

## Project Structure

```
FW-Watcher/
├── main.py          # Main window, toolbar, detail panel, drill-down view
├── models.py        # AddressObject, PolicyObject, NetworkTopology
├── parsers.py       # CSV parsers for addresses and policies
├── graph_view.py    # PyQt6 / QGraphicsScene-based graph renderer
├── requirements.txt
└── input/
    ├── addresses.csv
    └── policies.csv
```

## CSV Format

### Addresses

| Column | Required | Notes |
|--------|----------|-------|
| Name | Yes | Address object name |
| Type | No | `ipmask`, `iprange`, `fqdn`, `group` |
| Subnet | No | `192.168.1.0 255.255.255.0` or CIDR |
| Interface | No | Associated interface |
| Comment | No | |
| Members | No | Space or comma separated (groups only) |

### Policies

| Column | Required | Notes |
|--------|----------|-------|
| # | Yes | Policy sequence number |
| Name | No | |
| From | No | Source interface |
| To | No | Destination interface |
| Source | Yes | Source address name(s) |
| Destination | Yes | Destination address name(s) |
| Service | No | Service name(s) |
| Action | No | `ACCEPT` or `DENY` |
| Status | No | `enable` / `disable` |
| NAT | No | |
| Comment | No | |

## License

MIT
