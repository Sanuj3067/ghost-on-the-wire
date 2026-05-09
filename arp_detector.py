"""
ARP Spoof Detection Engine
===========================
Passively monitors the network for signs of ARP cache poisoning.

Detection heuristics:
  1. IP-MAC conflict      — Same IP claiming a different MAC than previously seen
  2. MAC-IP conflict      — Same MAC claiming multiple IP addresses
  3. ARP reply flood      — High-rate unsolicited ARP replies (>10/sec from one host)
  4. Gratuitous ARP burst — Repeated gratuitous ARPs in a short window
  5. Gateway impersonation — Anyone claiming the gateway's IP with a different MAC

Approach: build a baseline of trusted IP→MAC bindings from the first N seconds,
then alert on deviations. New devices are marked UNKNOWN until confirmed.
"""

import time
import threading
import collections
from dataclasses import dataclass, field
from typing import Optional, Callable

try:
    from scapy.all import ARP, Ether, sniff, conf
except ImportError:
    raise ImportError("Scapy is required: pip install scapy")

from data.oui_lookup import get_vendor


# ------------------------------------------------------------------ #
# Data structures                                                     #
# ------------------------------------------------------------------ #

@dataclass
class ARPEntry:
    """Tracks what we know about an IP address on the network."""
    ip: str
    mac: str
    vendor: str = ""
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    arp_count: int = 0
    mac_history: list[str] = field(default_factory=list)
    is_trusted: bool = False


@dataclass
class ARPAlert:
    """Represents a detected ARP anomaly."""
    timestamp: float
    alert_type: str       # e.g. "IP_MAC_CONFLICT", "ARP_FLOOD"
    severity: str         # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    source_ip: str
    source_mac: str
    detail: str
    mitre_technique: str = "T1557.002"   # MITRE ATT&CK: ARP Cache Poisoning

    def __str__(self):
        ts = time.strftime("%H:%M:%S", time.localtime(self.timestamp))
        return f"[{ts}] [{self.severity:8s}] {self.alert_type}: {self.detail}"


# ------------------------------------------------------------------ #
# Detector                                                            #
# ------------------------------------------------------------------ #

class ARPDetector:
    """
    Real-time ARP spoof detection engine.

    Usage:
        detector = ARPDetector("eth0", gateway_ip="192.168.1.1")
        detector.start()   # blocks; Ctrl+C to stop
    """

    BASELINE_PERIOD = 30           # seconds to build initial trust baseline
    FLOOD_THRESHOLD = 10           # ARP replies/sec to trigger flood alert
    FLOOD_WINDOW = 5               # seconds to measure flood rate
    GRATUITOUS_THRESHOLD = 3       # repeated gratuitous ARPs within window

    def __init__(
        self,
        interface: str,
        gateway_ip: Optional[str] = None,
        alert_callback: Optional[Callable[[ARPAlert], None]] = None,
        verbose: bool = True,
    ):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.alert_callback = alert_callback or self._default_alert
        self.verbose = verbose

        # State
        self._arp_table: dict[str, ARPEntry] = {}   # IP → ARPEntry
        self._mac_to_ips: dict[str, set[str]] = {}  # MAC → set of IPs
        self._alerts: list[ARPAlert] = []
        self._recent_replies: dict[str, list[float]] = collections.defaultdict(list)  # MAC → timestamps
        self._gratuitous_seen: dict[str, list[float]] = collections.defaultdict(list)

        self._start_time = 0.0
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._packet_count = 0

    # ------------------------------------------------------------------ #
    # Alert handling                                                      #
    # ------------------------------------------------------------------ #

    def _default_alert(self, alert: ARPAlert):
        print(f"\n{'='*70}")
        print(f"  ⚠️  ARP ALERT DETECTED")
        print(f"{'='*70}")
        print(str(alert))
        print(f"{'='*70}")

    def _raise_alert(
        self,
        alert_type: str,
        severity: str,
        src_ip: str,
        src_mac: str,
        detail: str,
    ):
        alert = ARPAlert(
            timestamp=time.time(),
            alert_type=alert_type,
            severity=severity,
            source_ip=src_ip,
            source_mac=src_mac,
            detail=detail,
        )
        with self._lock:
            self._alerts.append(alert)
        self.alert_callback(alert)
        return alert

    # ------------------------------------------------------------------ #
    # Packet analysis                                                      #
    # ------------------------------------------------------------------ #

    def _is_gratuitous(self, pkt) -> bool:
        """
        A gratuitous ARP is a reply where sender IP == target IP,
        or a request where psrc == pdst (used for cache update announcements).
        """
        arp = pkt[ARP]
        return arp.psrc == arp.pdst or (arp.op == 2 and arp.psrc == arp.pdst)

    def _analyze_packet(self, pkt):
        """Process a single captured ARP packet."""
        if not pkt.haslayer(ARP):
            return

        self._packet_count += 1
        arp = pkt[ARP]
        src_ip = arp.psrc
        src_mac = arp.hwsrc.lower()
        op = arp.op   # 1=request, 2=reply

        # Ignore broadcast/empty
        if src_ip == "0.0.0.0" or src_mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return

        now = time.time()
        in_baseline = (now - self._start_time) < self.BASELINE_PERIOD

        with self._lock:
            entry = self._arp_table.get(src_ip)

            if entry is None:
                # New device
                entry = ARPEntry(
                    ip=src_ip,
                    mac=src_mac,
                    vendor=get_vendor(src_mac),
                    is_trusted=in_baseline,
                )
                self._arp_table[src_ip] = entry
                if self.verbose and not in_baseline:
                    print(f"[NEW] {src_ip} → {src_mac} ({entry.vendor})")

            # Update timestamps
            entry.last_seen = now
            entry.arp_count += 1

            # Track MAC changes
            if src_mac not in entry.mac_history:
                entry.mac_history.append(src_mac)

            # Check 1: IP-MAC conflict
            if src_mac != entry.mac and entry.is_trusted:
                old_mac = entry.mac
                old_vendor = get_vendor(old_mac)
                new_vendor = get_vendor(src_mac)
                severity = "CRITICAL" if src_ip == self.gateway_ip else "HIGH"
                self._raise_alert(
                    "IP_MAC_CONFLICT",
                    severity,
                    src_ip, src_mac,
                    f"{src_ip} previously used MAC {old_mac} ({old_vendor}), "
                    f"now claiming {src_mac} ({new_vendor}) — possible ARP spoofing!"
                )
                entry.mac = src_mac
                entry.vendor = new_vendor

            # Check 2: Gateway impersonation
            if self.gateway_ip and src_ip == self.gateway_ip and entry.is_trusted:
                if src_mac != entry.mac:
                    self._raise_alert(
                        "GATEWAY_IMPERSONATION",
                        "CRITICAL",
                        src_ip, src_mac,
                        f"Gateway IP {src_ip} is now responding with MAC {src_mac} "
                        f"(expected {entry.mac}) — likely ARP MITM attack!"
                    )

            # Check 3: MAC claiming multiple IPs (one MAC → many IPs)
            ips_for_mac = self._mac_to_ips.setdefault(src_mac, set())
            if src_ip not in ips_for_mac:
                ips_for_mac.add(src_ip)
                if len(ips_for_mac) > 3 and entry.is_trusted:
                    self._raise_alert(
                        "MAC_IP_CONFLICT",
                        "MEDIUM",
                        src_ip, src_mac,
                        f"MAC {src_mac} is claiming {len(ips_for_mac)} IPs: {sorted(ips_for_mac)} "
                        "— may indicate IP spoofing or DHCP exhaustion."
                    )

        # Check 4: ARP reply flood (outside lock to avoid blocking)
        if op == 2:   # ARP reply
            timestamps = self._recent_replies[src_mac]
            timestamps.append(now)
            # Keep only last FLOOD_WINDOW seconds
            cutoff = now - self.FLOOD_WINDOW
            self._recent_replies[src_mac] = [t for t in timestamps if t > cutoff]
            rate = len(self._recent_replies[src_mac]) / self.FLOOD_WINDOW
            if rate > self.FLOOD_THRESHOLD:
                self._raise_alert(
                    "ARP_REPLY_FLOOD",
                    "HIGH",
                    src_ip, src_mac,
                    f"{src_mac} is sending {rate:.1f} ARP replies/sec "
                    f"(threshold: {self.FLOOD_THRESHOLD}) — likely poisoning tool active."
                )
                # Throttle flood alerts (reset counter to avoid spam)
                self._recent_replies[src_mac] = []

        # Check 5: Gratuitous ARP burst
        if self._is_gratuitous(pkt):
            gtimes = self._gratuitous_seen[src_mac]
            gtimes.append(now)
            cutoff = now - 10  # 10-second window
            self._gratuitous_seen[src_mac] = [t for t in gtimes if t > cutoff]
            if len(self._gratuitous_seen[src_mac]) >= self.GRATUITOUS_THRESHOLD:
                self._raise_alert(
                    "GRATUITOUS_ARP_BURST",
                    "MEDIUM",
                    src_ip, src_mac,
                    f"{src_mac} sent {len(self._gratuitous_seen[src_mac])} gratuitous ARPs "
                    "in 10 seconds — may be ARP cache poisoning or misbehaving NIC."
                )
                self._gratuitous_seen[src_mac] = []

    # ------------------------------------------------------------------ #
    # Public API                                                          #
    # ------------------------------------------------------------------ #

    def start(self):
        """Start passive ARP monitoring. Blocks until Ctrl+C."""
        self._start_time = time.time()
        self._stop_event.clear()

        print(f"[*] ARP Spoof Detector started on {self.interface}")
        print(f"[*] Building trust baseline for {self.BASELINE_PERIOD}s...")
        if self.gateway_ip:
            print(f"[*] Watching gateway: {self.gateway_ip}")
        print("[*] Listening for ARP packets. Press Ctrl+C to stop.\n")

        try:
            sniff(
                iface=self.interface,
                filter="arp",
                prn=self._analyze_packet,
                stop_filter=lambda _: self._stop_event.is_set(),
                store=False,
            )
        except KeyboardInterrupt:
            pass

        print(f"\n[+] Detection stopped. Analyzed {self._packet_count} ARP packets.")
        print(f"[+] Total alerts: {len(self._alerts)}")
        self._print_summary()

    def stop(self):
        self._stop_event.set()

    def get_arp_table(self) -> dict[str, ARPEntry]:
        with self._lock:
            return dict(self._arp_table)

    def get_alerts(self) -> list[ARPAlert]:
        with self._lock:
            return list(self._alerts)

    def _print_summary(self):
        if not self._alerts:
            print("[+] No alerts triggered. Network appears clean.")
            return
        print(f"\n{'='*60}")
        print("  ALERT SUMMARY")
        print(f"{'='*60}")
        for alert in self._alerts[-20:]:  # Last 20
            print(str(alert))
