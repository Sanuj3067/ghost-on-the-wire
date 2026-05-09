#!/usr/bin/env python3
"""
fix_scapy_scope_bug.py
======================
Patches a known Scapy bug (KeyError: 'scope') that affects Scapy >= 2.6
on Linux when Python 3.12 is used.

Root cause:
  scapy/arch/linux/rtnetlink.py builds address dicts that only include
  a 'scope' key for IPv6 (af_family == 10) entries.  Two places later
  in the same file access x["scope"] unconditionally, raising KeyError
  for any IPv4 address entry that lacks the key.

Fix:
  Change x["scope"] -> x.get("scope", 0)  (two occurrences)

Run with:
  python3 fix_scapy_scope_bug.py
"""

import sys
import re
from pathlib import Path


def find_rtnetlink() -> Path | None:
    try:
        import scapy.arch.linux.rtnetlink as m
        return Path(m.__file__)
    except ImportError:
        return None


def patch(path: Path) -> bool:
    original = path.read_text(encoding="utf-8")
    patched = original

    # Fix 1: line with x["scope"] in devaddrs generator (read_routes6)
    patched = patched.replace(
        'x["address"], x["scope"]',
        'x["address"], x.get("scope", 0)',
    )
    # Fix 2: line with ip["scope"] in in6_getifaddr
    patched = patched.replace(
        'ip["address"], ip["scope"]',
        'ip["address"], ip.get("scope", 0)',
    )

    if patched == original:
        return False  # Nothing changed — already patched or different version

    path.write_text(patched, encoding="utf-8")
    return True


def main():
    print("[*] Scapy scope-bug patcher")

    rtnetlink = find_rtnetlink()
    if rtnetlink is None:
        print("[!] Scapy not found. Install it first:  pip install scapy")
        sys.exit(1)

    print(f"[*] Target file: {rtnetlink}")

    if patch(rtnetlink):
        print("[+] Patch applied successfully.")
        print("[+] Re-run your imports — the KeyError: 'scope' should be gone.")
    else:
        print("[*] File appears already patched (or uses a different Scapy version).")
        print("    If you still see errors, try:  pip install --upgrade scapy")


if __name__ == "__main__":
    main()
