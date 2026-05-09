"""
Layer 2 Network Trust Map
==========================
Maintains a real-time map of all devices on the local network with:
- IP/MAC address tracking
- Vendor identification (OUI)
- First/last seen timestamps
- Behavioral trust scoring
- Anomaly flagging

Trust Score (0–100):
  Starts at 80 (unknown device).
  Increases with consistent, long-term presence.
  Decreases with suspicious behavior (MAC changes, ARP floods, etc.).
  Devices scoring <30 are marked SUSPICIOUS, <10 marked HOSTILE.
"""

import time
import threading
import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

try:
    from scapy.all import ARP, Ether, srp, sniff, get_if_addr
    import netifaces
except ImportError:
    raise ImportError("pip install scapy netifaces")

from data.oui_lookup import get_vendor


class TrustLevel(Enum):
    TRUSTED   = "TRUSTED"
    KNOWN     = "KNOWN"
    UNKNOWN   = "UNKNOWN"
    SUSPICIOUS = "SUSPICIOUS"
    HOSTILE   = "HOSTILE"

    @property
    def color(self) -> str:
        """Rich markup color for this trust level."""
        return {
            "TRUSTED":    "bright_green",
            "KNOWN":      "green",
            "UNKNOWN":    "yellow",
            "SUSPICIOUS": "orange1",
            "HOSTILE":    "bold red",
        }[self.value]

    @classmethod
    def from_score(cls, score: float) -> "TrustLevel":
        if score >= 80:   return cls.TRUSTED
        if score >= 60:   return cls.KNOWN
        if score >= 30:   return cls.UNKNOWN
        if score >= 10:   return cls.SUSPICIOUS
        return cls.HOSTILE


@dataclass
class DeviceRecord:
    """Complete profile of a device observed on the network."""
    ip: str
    mac: str
    vendor: str = ""

    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    arp_request_count: int = 0
    arp_reply_count: int = 0
    mac_changes: list[tuple[str, float]] = field(default_factory=list)  # (old_mac, timestamp)

    trust_score: float = 80.0
    trust_level: TrustLevel = TrustLevel.UNKNOWN
    flags: list[str] = field(default_factory=list)  # e.g. ["ARP_FLOOD", "MAC_CHANGED"]

    is_gateway: bool = False
    is_local_device: bool = False  # This machine
    hostname: str = ""

    def update_trust(self):
        """Recompute trust level from current score."""
        self.trust_level = TrustLevel.from_score(self.trust_score)

    def penalize(self, reason: str, amount: float):
        """Lower trust score and record a flag."""
        self.trust_score = max(0.0, self.trust_score - amount)
        if reason not in self.flags:
            self.flags.append(reason)
        self.update_trust()

    def reward(self, amount: float = 0.5):
        """Slowly increase trust for consistent, stable behavior."""
        self.trust_score = min(100.0, self.trust_score + amount)
        self.update_trust()

    @property
    def uptime_seconds(self) -> float:
        return self.last_seen - self.first_seen

    @property
    def summary(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "vendor": self.vendor,
            "trust_score": round(self.trust_score, 1),
            "trust_level": self.trust_level.value,
            "flags": self.flags,
            "is_gateway": self.is_gateway,
            "arp_replies": self.arp_reply_count,
            "mac_changes": len(self.mac_changes),
        }


class NetworkTrustMap:
    """
    Continuously builds and maintains a Layer 2 trust map.

    Combines passive sniffing (ARP observation) with active scanning
    (ARP requests to enumerate hosts). Computes behavioral trust scores
    for every observed device.

    Example:
        trust_map = NetworkTrustMap("eth0", gateway_ip="192.168.1.1")
        trust_map.start_passive()   # background thread
        time.sleep(60)
        for device in trust_map.get_all_devices():
            print(device.summary)
    """

    SCORE_MAC_CHANGE        = 40.0   # Trust penalty for MAC address change
    SCORE_GATEWAY_IMPERSONATE = 60.0  # Gateway IP with wrong MAC
    SCORE_ARP_FLOOD         = 25.0
    SCORE_MULTI_IP          = 15.0
    SCORE_GRATUITOUS        = 10.0
    REWARD_STABLE_SEEN      = 0.1    # Per observation when stable

    def __init__(
        self,
        interface: str,
        gateway_ip: Optional[str] = None,
    ):
        self.interface = interface
        self.gateway_ip = gateway_ip

        self._devices: dict[str, DeviceRecord] = {}   # IP → DeviceRecord
        self._mac_to_ips: dict[str, set[str]] = {}
        self._lock = threading.Lock()
        self._packet_count = 0
        self._scan_count = 0

        # Detect local IP/MAC
        try:
            self._local_ip = get_if_addr(interface)
        except Exception:
            self._local_ip = None

    # ------------------------------------------------------------------ #
    # Internal                                                             #
    # ------------------------------------------------------------------ #

    def _upsert_device(self, ip: str, mac: str, op: int) -> DeviceRecord:
        """Insert or update a device record. Returns the record."""
        mac = mac.lower()
        now = time.time()

        record = self._devices.get(ip)

        if record is None:
            record = DeviceRecord(
                ip=ip,
                mac=mac,
                vendor=get_vendor(mac),
                is_gateway=(ip == self.gateway_ip),
                is_local_device=(ip == self._local_ip),
            )
            self._devices[ip] = record
        else:
            # Detect MAC change
            if record.mac != mac:
                old_mac = record.mac
                record.mac_changes.append((old_mac, now))
                record.mac = mac
                record.vendor = get_vendor(mac)

                penalty = self.SCORE_GATEWAY_IMPERSONATE if record.is_gateway else self.SCORE_MAC_CHANGE
                record.penalize("MAC_CHANGED", penalty)
            else:
                record.reward(self.REWARD_STABLE_SEEN)

        record.last_seen = now
        if op == 1:
            record.arp_request_count += 1
        elif op == 2:
            record.arp_reply_count += 1

        # Update MAC→IPs index
        self._mac_to_ips.setdefault(mac, set()).add(ip)
        if len(self._mac_to_ips[mac]) > 3:
            record.penalize("MULTI_IP_CLAIM", self.SCORE_MULTI_IP)

        record.update_trust()
        return record

    def _process_packet(self, pkt):
        """Scapy callback for each captured ARP packet."""
        if not pkt.haslayer(ARP):
            return

        self._packet_count += 1
        arp = pkt[ARP]
        src_ip  = arp.psrc
        src_mac = arp.hwsrc

        if src_ip == "0.0.0.0" or src_mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return

        with self._lock:
            self._upsert_device(src_ip, src_mac, arp.op)

    # ------------------------------------------------------------------ #
    # Active scanning                                                      #
    # ------------------------------------------------------------------ #

    def scan_subnet(self, subnet: Optional[str] = None, timeout: int = 3) -> list[DeviceRecord]:
        """
        Active ARP scan of the entire subnet to discover all hosts.

        Args:
            subnet: CIDR notation. If None, auto-detected from interface.
            timeout: Seconds to wait for responses.

        Returns:
            List of DeviceRecord for discovered hosts.
        """
        if subnet is None:
            subnet = self._auto_subnet()
        if subnet is None:
            return []

        from scapy.all import ARP, Ether, srp
        print(f"[*] Active ARP scan: {subnet}")
        arp_req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
        ans, _ = srp(arp_req, iface=self.interface, timeout=timeout, verbose=False)

        results = []
        with self._lock:
            for _, rcv in ans:
                ip  = rcv[ARP].psrc
                mac = rcv[Ether].src
                rec = self._upsert_device(ip, mac, op=2)
                results.append(rec)

        self._scan_count += 1
        print(f"[+] Scan complete. Found {len(results)} hosts.")
        return results

    def _auto_subnet(self) -> Optional[str]:
        """Attempt to determine the local subnet from the interface."""
        try:
            addrs = netifaces.ifaddresses(self.interface)
            info = addrs.get(netifaces.AF_INET, [{}])[0]
            ip   = info.get("addr")
            mask = info.get("netmask")
            if ip and mask:
                iface = ipaddress.IPv4Interface(f"{ip}/{mask}")
                return str(iface.network)
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------ #
    # Passive monitoring thread                                            #
    # ------------------------------------------------------------------ #

    def start_passive(self) -> threading.Thread:
        """Start background ARP sniffing. Returns the thread."""
        t = threading.Thread(
            target=lambda: sniff(
                iface=self.interface,
                filter="arp",
                prn=self._process_packet,
                store=False,
            ),
            daemon=True,
            name="arp-sniffer",
        )
        t.start()
        return t

    # ------------------------------------------------------------------ #
    # Queries                                                              #
    # ------------------------------------------------------------------ #

    def get_all_devices(self) -> list[DeviceRecord]:
        """Return all tracked devices, sorted by IP."""
        with self._lock:
            records = list(self._devices.values())
        try:
            return sorted(records, key=lambda r: ipaddress.ip_address(r.ip))
        except Exception:
            return sorted(records, key=lambda r: r.ip)

    def get_suspicious_devices(self) -> list[DeviceRecord]:
        return [d for d in self.get_all_devices()
                if d.trust_level in (TrustLevel.SUSPICIOUS, TrustLevel.HOSTILE)]

    def get_device(self, ip: str) -> Optional[DeviceRecord]:
        with self._lock:
            return self._devices.get(ip)

    def get_stats(self) -> dict:
        devices = self.get_all_devices()
        return {
            "total_devices": len(devices),
            "trusted": sum(1 for d in devices if d.trust_level == TrustLevel.TRUSTED),
            "suspicious": sum(1 for d in devices if d.trust_level in (TrustLevel.SUSPICIOUS, TrustLevel.HOSTILE)),
            "packets_analyzed": self._packet_count,
            "active_scans": self._scan_count,
        }
