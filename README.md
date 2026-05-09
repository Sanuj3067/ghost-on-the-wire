# 👻 Ghost on the Wire

> **Layer 2 Attack & Defense Toolkit** — MAC spoofing, ARP poisoning, spoof detection, and real-time network trust mapping in pure Python.

```
⚠️  FOR AUTHORIZED SECURITY TESTING ONLY
    Unauthorized use is illegal. Get written permission first.
```

---

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Launch the TUI dashboard (requires root)
sudo python3 main.py dashboard

# Or use individual modes:
sudo python3 main.py spoof    -i eth0 --random              # Random MAC
sudo python3 main.py spoof    -i eth0 --vendor "Apple"      # Vendor spoof
sudo python3 main.py spoof    -i eth0 --restore             # Restore MAC
sudo python3 main.py detect   -i eth0                       # ARP monitoring
sudo python3 main.py recon    -i eth0                       # Network scan
sudo python3 main.py arp-poison -i eth0 --target 192.168.1.5 --gateway 192.168.1.1
```

## Features

| Module | What it does |
|--------|-------------|
| **MAC Spoofer** | Random / vendor-targeted / specific MAC changes with auto-restore |
| **ARP Poisoner** | Bidirectional MITM with IP forwarding and graceful cache restore |
| **ARP Detector** | 5-heuristic passive detection engine with configurable alerts |
| **Trust Map** | Real-time behavioral trust scoring for every device on the LAN |
| **Recon** | Active ARP scan + passive discovery + OS fingerprinting |
| **TUI Dashboard** | Live Rich terminal UI combining all components |

## Project Structure

```
ghost_on_the_wire/
├── main.py              ← Entry point / CLI
├── requirements.txt
├── core/
│   ├── mac_spoofer.py   ← MAC address manipulation
│   ├── arp_poisoner.py  ← ARP MITM attack
│   ├── arp_detector.py  ← Detection engine
│   ├── trust_map.py     ← Trust scoring
│   └── recon.py         ← Host discovery
├── ui/
│   └── dashboard.py     ← Rich TUI
├── data/
│   └── oui_lookup.py    ← IEEE OUI database
└── docs/
    └── DOCUMENTATION.md ← Full reference
```

## Requirements

- Python 3.10+
- Linux (raw socket support)
- Root / sudo privileges
- `scapy`, `rich`, `netifaces`

## Open in VS Code

```bash
code ghost_on_the_wire/
```

Use the pre-configured `.vscode/launch.json` to run any mode directly from the Run panel.

---

*See `docs/DOCUMENTATION.md` for full API reference, concept explanations, and enterprise defense techniques.*
