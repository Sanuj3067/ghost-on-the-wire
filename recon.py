"""
Network Reconnaissance Module
==============================
Provides both passive and active host discovery techniques at Layer 2.

Techniques:
  - Passive: Listen for ARP broadcasts (zero packets sent, stealthy)
  - Active: Send ARP requests to enumerate all hosts on a subnet
  - OS fingerprinting: Infer OS from ARP timing and field characteristics
  - Switch/router detection: Identify network infrastructure by vendor OUI
"""

import time
import statistics
import threading
import ipaddress
from dataclasses import dataclass, field
from typing import Optional

try:
    from scapy.all import (
        ARP, Ether, srp, sniff, get_if_addr, conf
    )
    import netifaces
except ImportError:
    raise ImportError("pip install scapy netifaces")

from data.oui_lookup import get_vendor


# OUI prefixes commonly associated with network infrastructure
ROUTER_VENDORS = ["Cisco", "Juniper", "Aruba", "Netgear", "TP-Link", "Ubiquiti", "MikroTik", "D-Link"]
SWITCH_VENDORS = ["Cisco", "Juniper", "HP", "Aruba", "Extreme", "Brocade", "Foundry"]


@dataclass
class HostInfo:
    ip: str
    mac: str
    vendor: str = ""
    os_guess: str = "Unknown"
    device_type: str = "Host"       # Host / Router / Switch / AP / VM
    response_time_ms: float = 0.0
    arp_ttl: int = 0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    is_infrastructure: bool = False

    def __str__(self):
        return (
            f"{self.ip:<17} {self.mac:<19} {self.vendor:<25} "
            f"{self.device_type:<10} {self.os_guess}"
        )


class NetworkRecon:
    """
    Layer 2 network reconnaissance toolkit.

    Example:
        recon = NetworkRecon("eth0")
        hosts = recon.scan()
        for host in hosts:
            print(host)
    """

    def __init__(
        self,
        interface: str,
        subnet: Optional[str] = None,
        verbose: bool = True,
    ):
        self.interface = interface
        self.subnet = subnet or self._detect_subnet()
        self.verbose = verbose
        self._hosts: dict[str, HostInfo] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    # Subnet detection                                                    #
    # ------------------------------------------------------------------ #

    def _detect_subnet(self) -> Optional[str]:
        """Auto-detect the local subnet from the interface."""
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
    # OS fingerprinting heuristics                                        #
    # ------------------------------------------------------------------ #

    def _fingerprint_os(self, host: HostInfo) -> str:
        """
        Make educated guesses about the OS based on:
        - ARP response timing (fast < 2ms = usually Linux/embedded)
        - Vendor OUI (Apple, Dell, etc.)
        - ARP field values (hwlen, plen, op)

        This is imprecise — treat as a hint, not a fact.
        """
        vendor = host.vendor.lower()

        # Vendor-based guesses
        if any(v in vendor for v in ["apple"]):
            return "macOS / iOS"
        if any(v in vendor for v in ["microsoft"]):
            return "Windows"
        if any(v in vendor for v in ["raspberry"]):
            return "Linux (Raspberry Pi)"
        if any(v in vendor for v in ["vmware", "virtualbox", "parallels", "hyper-v", "xen"]):
            return "Virtual Machine"
        if any(v in vendor for v in ["cisco", "juniper", "aruba", "ubiquiti", "mikrotik"]):
            return "Network OS (IOS/JunOS/etc)"
        if any(v in vendor for v in ["samsung", "huawei", "xiaomi", "oppo"]):
            return "Android / Embedded Linux"

        # Timing heuristics
        if host.response_time_ms < 1.5:
            return "Linux / Embedded"
        if host.response_time_ms < 5:
            return "Linux / macOS (likely)"
        if host.response_time_ms < 15:
            return "Windows (likely)"
        if host.response_time_ms > 50:
            return "Slow / Embedded Device"

        return "Unknown"

    def _classify_device(self, host: HostInfo) -> str:
        """Classify device type based on vendor OUI."""
        vendor = host.vendor.lower()
        if any(v.lower() in vendor for v in ROUTER_VENDORS):
            return "Router/SW"
        if any(v.lower() in vendor for v in ["vmware", "virtualbox", "parallels"]):
            return "VM"
        if any(v.lower() in vendor for v in ["apple"]):
            return "Apple"
        if any(v.lower() in vendor for v in ["samsung", "huawei", "xiaomi", "oneplus"]):
            return "Mobile"
        if any(v.lower() in vendor for v in ["raspberry"]):
            return "SBC"
        if any(v.lower() in vendor for v in ["cisco", "juniper", "aruba"]):
            return "Infra"
        return "Host"

    # ------------------------------------------------------------------ #
    # Active scan                                                         #
    # ------------------------------------------------------------------ #

    def scan(self, timeout: int = 3) -> list[HostInfo]:
        """
        Active ARP scan of the configured subnet.

        Sends ARP requests to every address in the subnet and collects
        responses to build a host inventory. Also records response timing
        for OS fingerprinting.

        Returns:
            List of HostInfo for all responding hosts.
        """
        if not self.subnet:
            print("[!] Cannot determine subnet. Specify with --subnet.")
            return []

        print(f"\n{'='*60}")
        print(f"  ACTIVE ARP SCAN")
        print(f"{'='*60}")
        print(f"  Interface : {self.interface}")
        print(f"  Subnet    : {self.subnet}")
        print(f"  Timeout   : {timeout}s")
        print(f"{'='*60}\n")

        arp_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.subnet)
        t_start = time.time()
        ans, _ = srp(arp_pkt, iface=self.interface, timeout=timeout, verbose=False)
        scan_duration = time.time() - t_start

        hosts = []
        response_times = []

        for sent, rcvd in ans:
            ip  = rcvd[ARP].psrc
            mac = rcvd[Ether].src.lower()
            rt  = (rcvd.time - sent.time) * 1000   # ms

            host = HostInfo(
                ip=ip,
                mac=mac,
                vendor=get_vendor(mac),
                response_time_ms=rt,
            )
            host.os_guess    = self._fingerprint_os(host)
            host.device_type = self._classify_device(host)
            host.is_infrastructure = host.device_type in ("Router/SW", "Infra")

            with self._lock:
                self._hosts[ip] = host
            hosts.append(host)
            response_times.append(rt)

            if self.verbose:
                flag = "  [INFRA]" if host.is_infrastructure else ""
                print(
                    f"  {ip:<17} {mac:<19} {host.vendor:<22} "
                    f"[{rt:.1f}ms] {host.os_guess}{flag}"
                )

        # Sort by IP
        try:
            hosts.sort(key=lambda h: ipaddress.ip_address(h.ip))
        except Exception:
            hosts.sort(key=lambda h: h.ip)

        print(f"\n{'='*60}")
        print(f"  SCAN RESULTS")
        print(f"{'='*60}")
        print(f"  Hosts found   : {len(hosts)}")
        print(f"  Scan duration : {scan_duration:.2f}s")
        if response_times:
            print(f"  Avg RTT       : {statistics.mean(response_times):.2f}ms")
            print(f"  Min/Max RTT   : {min(response_times):.2f}ms / {max(response_times):.2f}ms")
        print(f"  Infrastructure: {sum(1 for h in hosts if h.is_infrastructure)}")
        print(f"{'='*60}\n")

        return hosts

    # ------------------------------------------------------------------ #
    # Passive discovery                                                   #
    # ------------------------------------------------------------------ #

    def passive_listen(self, duration: int = 60) -> list[HostInfo]:
        """
        Passively discover hosts by sniffing ARP broadcasts.
        Sends zero packets — completely stealthy.

        Args:
            duration: How many seconds to listen.

        Returns:
            List of discovered HostInfo.
        """
        print(f"[*] Passive ARP discovery on {self.interface} for {duration}s (sending NO packets)...")

        def _handle(pkt):
            if pkt.haslayer(ARP):
                ip  = pkt[ARP].psrc
                mac = pkt[Ether].src.lower() if pkt.haslayer(Ether) else pkt[ARP].hwsrc.lower()
                if ip == "0.0.0.0" or mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                    return
                with self._lock:
                    if ip not in self._hosts:
                        host = HostInfo(ip=ip, mac=mac, vendor=get_vendor(mac))
                        host.device_type = self._classify_device(host)
                        host.os_guess = self._fingerprint_os(host)
                        self._hosts[ip] = host
                        if self.verbose:
                            print(f"  [PASSIVE] {ip:<17} {mac:<19} {host.vendor}")

        sniff(
            iface=self.interface,
            filter="arp",
            prn=_handle,
            timeout=duration,
            store=False,
        )

        hosts = list(self._hosts.values())
        print(f"[+] Passive discovery complete. Found {len(hosts)} hosts.")
        return hosts

    # ------------------------------------------------------------------ #
    # Queries                                                             #
    # ------------------------------------------------------------------ #

    def get_hosts(self) -> list[HostInfo]:
        with self._lock:
            return sorted(self._hosts.values(), key=lambda h: h.ip)

    def get_infrastructure(self) -> list[HostInfo]:
        return [h for h in self.get_hosts() if h.is_infrastructure]

    def print_table(self):
        """Print a formatted summary table."""
        hosts = self.get_hosts()
        if not hosts:
            print("[*] No hosts discovered yet.")
            return
        print(f"\n{'IP':<17} {'MAC':<19} {'Vendor':<25} {'Type':<10} OS Guess")
        print("-" * 90)
        for h in hosts:
            print(str(h))
