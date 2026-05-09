# Ghost on the Wire — Bug Fixes & Setup Guide

## Errors Fixed

### Root Cause: `KeyError: 'scope'` on import

All the import errors you saw (across `core/arp_detector.py`, `core/arp_poisoner.py`,
`core/recon.py`, `core/trust_map.py`, `ui/dashboard.py`) shared one root cause —
a **bug in Scapy 2.6+ on Python 3.12 / Linux**.

**Error chain:**
```
from scapy.all import ARP, Ether, sniff ...
  → scapy/layers/inet.py
    → scapy/layers/inet6.py
      → scapy/route6.py
        → scapy/arch/linux/rtnetlink.py  ← BUG HERE
            KeyError: 'scope'
```

**Why it happens:**  
Scapy's `rtnetlink.py` builds address dictionaries and only adds a `'scope'`
key for IPv6 entries (`af_family == 10`). Two places later in the same file
access `x["scope"]` unconditionally — crashing on any IPv4 address entry.

**The fix** (two lines in scapy's source):
```python
# Before (broken):
x["address"], x["scope"]
ip["address"], ip["scope"]

# After (fixed):
x["address"], x.get("scope", 0)
ip["address"], ip.get("scope", 0)
```

---

## How to Apply the Fix on Your Machine

### Option A — Run the included patcher (recommended)

```bash
python3 fix_scapy_scope_bug.py
```

This automatically finds and patches your installed Scapy.

### Option B — Manual patch

1. Find the file:
   ```bash
   python3 -c "import scapy.arch.linux.rtnetlink; print(scapy.arch.linux.rtnetlink.__file__)"
   ```

2. Open that file and replace **both** occurrences:
   - `x["address"], x["scope"]`  →  `x["address"], x.get("scope", 0)`
   - `ip["address"], ip["scope"]`  →  `ip["address"], ip.get("scope", 0)`

### Option C — Downgrade Scapy

If you prefer not to patch system files:
```bash
pip install "scapy==2.5.0"
```
Version 2.5.0 predates the bug.

---

## Install Dependencies

```bash
pip install scapy>=2.5.0 rich>=13.0.0 netifaces>=0.11.0
```

---

## Running the Tool

**All modes require root/sudo** (raw packet operations):

```bash
# Full TUI dashboard
sudo python3 main.py dashboard

# MAC spoofing
sudo python3 main.py spoof -i eth0 --random
sudo python3 main.py spoof -i eth0 --vendor "Apple"
sudo python3 main.py spoof -i eth0 --restore

# ARP poisoning (MITM) — authorized testing only
sudo python3 main.py arp-poison -i eth0 --target 192.168.1.5 --gateway 192.168.1.1

# ARP spoof detection
sudo python3 main.py detect -i eth0

# Network recon scan
sudo python3 main.py recon -i eth0 --subnet 192.168.1.0/24
```

---

## VS Code Setup

Add this to your `.vscode/settings.json` to suppress the Pylance false positives
caused by scapy's dynamic imports:

```json
{
  "python.analysis.ignore": ["**/scapy/**"],
  "python.linting.enabled": true
}
```

The existing `.vscode/launch.json` is already configured correctly.

---

⚠️ **Legal reminder:** Use only on networks you own or have explicit written
permission to test. Unauthorized use is illegal under the CFAA and equivalent laws.
