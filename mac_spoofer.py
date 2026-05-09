"""
MAC Address Spoofer
===================
Changes the MAC address of a network interface on Linux.
Supports random MAC generation, vendor OUI-based spoofing, and hardware restore.

Requires root privileges and operates on Linux only.
"""

import re
import subprocess
import time
from pathlib import Path

from data.oui_lookup import get_vendor, vendor_mac, random_mac, get_vendors_by_name


class MACSpooferError(Exception):
    pass


class MACSpoofer:
    """
    Manages MAC address changes for a network interface.

    Example:
        spoofer = MACSpoofer("eth0")
        spoofer.spoof_random()
        # ... do things ...
        spoofer.restore()
    """

    ORIG_MAC_DIR = Path.home() / ".ghost_on_the_wire" / "original_macs"

    def __init__(self, interface: str):
        self.interface = interface
        self._validate_interface()
        self.ORIG_MAC_DIR.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    def _validate_interface(self):
        result = subprocess.run(
            ["ip", "link", "show", self.interface],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            raise MACSpooferError(f"Interface '{self.interface}' not found.")

    def _get_current_mac(self) -> str:
        """Read the current MAC from sysfs."""
        addr_file = Path(f"/sys/class/net/{self.interface}/address")
        if addr_file.exists():
            return addr_file.read_text().strip()
        # Fallback: parse ip link output
        result = subprocess.run(
            ["ip", "link", "show", self.interface],
            capture_output=True, text=True
        )
        match = re.search(r"link/ether ([0-9a-f:]{17})", result.stdout)
        return match.group(1) if match else "00:00:00:00:00:00"

    def _get_permanent_mac(self) -> str | None:
        """
        Attempt to retrieve the hardware/burned-in MAC using ethtool.
        Falls back to None if unavailable.
        """
        try:
            result = subprocess.run(
                ["ethtool", "-P", self.interface],
                capture_output=True, text=True
            )
            match = re.search(r"Permanent address:\s*([0-9a-f:]{17})", result.stdout, re.I)
            if match:
                return match.group(1).lower()
        except FileNotFoundError:
            pass
        return None

    def _save_original(self, mac: str):
        """Persist the original MAC so it can be restored later."""
        cache = self.ORIG_MAC_DIR / self.interface
        if not cache.exists():
            cache.write_text(mac)

    def _load_original(self) -> str | None:
        """Load the saved original MAC address."""
        cache = self.ORIG_MAC_DIR / self.interface
        return cache.read_text().strip() if cache.exists() else None

    def _set_mac(self, new_mac: str):
        """
        Apply a MAC address change by cycling the interface down/up.
        This is the standard Linux method and works for most drivers.
        """
        cmds = [
            ["ip", "link", "set", self.interface, "down"],
            ["ip", "link", "set", self.interface, "address", new_mac],
            ["ip", "link", "set", self.interface, "up"],
        ]
        for cmd in cmds:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise MACSpooferError(
                    f"Command failed: {' '.join(cmd)}\n{result.stderr.strip()}"
                )
            time.sleep(0.1)

        # Verify
        actual = self._get_current_mac()
        if actual.lower() != new_mac.lower():
            raise MACSpooferError(
                f"MAC change verification failed. Expected {new_mac}, got {actual}. "
                "Your driver may not support MAC spoofing, or NetworkManager may have reset it."
            )

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    @property
    def current_mac(self) -> str:
        return self._get_current_mac()

    @property
    def current_vendor(self) -> str:
        return get_vendor(self.current_mac)

    def spoof_random(self) -> str:
        """
        Apply a randomly generated locally-administered MAC address.
        Returns the new MAC address.
        """
        original = self._get_current_mac()
        self._save_original(original)
        new_mac = random_mac()
        print(f"[*] Interface  : {self.interface}")
        print(f"[*] Original   : {original} ({get_vendor(original)})")
        print(f"[*] New MAC    : {new_mac} (randomly generated)")
        self._set_mac(new_mac)
        print(f"[+] MAC changed successfully to {new_mac}")
        return new_mac

    def spoof_vendor(self, vendor_name: str) -> str:
        """
        Apply a MAC address that appears to belong to a specific vendor.

        Args:
            vendor_name: Partial vendor name to search for (e.g. "Apple", "Cisco").

        Returns:
            The new MAC address.
        """
        result = vendor_mac(vendor_name)
        if result is None:
            # Try listing similar vendors
            matches = get_vendors_by_name(vendor_name)
            if not matches:
                raise MACSpooferError(
                    f"No OUI entries found for vendor '{vendor_name}'. "
                    "Try fetching the full database: from data.oui_lookup import fetch_oui_database; fetch_oui_database()"
                )
            suggestion = matches[0][1]
            raise MACSpooferError(f"No exact match. Did you mean: '{suggestion}'?")

        new_mac, matched_vendor = result
        original = self._get_current_mac()
        self._save_original(original)
        print(f"[*] Interface  : {self.interface}")
        print(f"[*] Original   : {original} ({get_vendor(original)})")
        print(f"[*] New MAC    : {new_mac} (impersonating: {matched_vendor})")
        self._set_mac(new_mac)
        print(f"[+] MAC changed successfully to {new_mac}")
        return new_mac

    def spoof_specific(self, mac: str) -> str:
        """
        Apply a specific MAC address.

        Args:
            mac: Target MAC address in any common format.

        Returns:
            The normalized MAC address applied.
        """
        # Normalize
        clean = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
        if len(clean) != 12:
            raise MACSpooferError(f"Invalid MAC address: {mac}")
        new_mac = ":".join(clean[i:i+2] for i in range(0, 12, 2)).lower()

        original = self._get_current_mac()
        self._save_original(original)
        print(f"[*] Interface  : {self.interface}")
        print(f"[*] Original   : {original} ({get_vendor(original)})")
        print(f"[*] New MAC    : {new_mac} ({get_vendor(new_mac)})")
        self._set_mac(new_mac)
        print(f"[+] MAC changed successfully to {new_mac}")
        return new_mac

    def restore(self) -> str:
        """
        Restore the original MAC address.
        First tries the saved original; falls back to ethtool permanent address.

        Returns:
            The restored MAC address.
        """
        # Try ethtool first (most authoritative)
        original = self._get_permanent_mac() or self._load_original()
        if original is None:
            raise MACSpooferError(
                "No original MAC found. Cannot restore.\n"
                "Try: ip link set <interface> address <original_mac>"
            )

        current = self._get_current_mac()
        print(f"[*] Interface  : {self.interface}")
        print(f"[*] Current    : {current} ({get_vendor(current)})")
        print(f"[*] Restoring  : {original} ({get_vendor(original)})")
        self._set_mac(original)

        # Remove cache
        cache = self.ORIG_MAC_DIR / self.interface
        if cache.exists():
            cache.unlink()

        print(f"[+] MAC restored to {original}")
        return original

    def get_status(self) -> dict:
        """Return a dict summarising current spoofing state."""
        current = self._get_current_mac()
        original = self._load_original()
        is_spoofed = original is not None and original.lower() != current.lower()
        return {
            "interface": self.interface,
            "current_mac": current,
            "current_vendor": get_vendor(current),
            "original_mac": original,
            "is_spoofed": is_spoofed,
        }
