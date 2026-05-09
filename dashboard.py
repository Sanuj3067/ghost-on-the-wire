"""
Ghost on the Wire — TUI Dashboard
===================================
Real-time terminal user interface built with Rich.

Panels:
  ┌─────────────────────────────────────────────────────┐
  │  GHOST ON THE WIRE   [MODE: DEFEND]  iface: eth0   │
  ├──────────────────────┬──────────────────────────────┤
  │  NETWORK TRUST MAP   │  ALERTS LOG                  │
  │  (live device table) │  (scrolling alert feed)      │
  ├──────────────────────┴──────────────────────────────┤
  │  STATS BAR          │  ACTIVE OPERATIONS            │
  └─────────────────────────────────────────────────────┘

Modes:
  DEFEND  — passive ARP detection + trust map
  RECON   — active subnet scan + passive discovery
  ATTACK  — ARP poisoning session (red team)
"""

import time
import threading
import os
import sys
from typing import Optional

try:
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.columns import Columns
    from rich.align import Align
    from rich.rule import Rule
    from rich import box
    from rich.prompt import Prompt, Confirm
    from rich.status import Status
    from rich.progress import Progress, SpinnerColumn, TextColumn
except ImportError:
    print("[!] Rich not installed. Run: pip install rich")
    sys.exit(1)

try:
    import netifaces
except ImportError:
    print("[!] netifaces not installed. Run: pip install netifaces")
    sys.exit(1)

from core.trust_map import NetworkTrustMap, TrustLevel, DeviceRecord
from core.arp_detector import ARPDetector, ARPAlert
from core.arp_poisoner import ARPPoisoner, get_mac
from core.recon import NetworkRecon
from core.mac_spoofer import MACSpoofer
from data.oui_lookup import get_vendor, fetch_oui_database


console = Console()

# ─── Color palette ───────────────────────────────────────────────────────────
COLORS = {
    "brand":      "bright_cyan",
    "header_bg":  "on grey11",
    "panel_title":"bright_white",
    "danger":     "bold red",
    "warn":       "yellow",
    "ok":         "bright_green",
    "dim":        "grey50",
    "accent":     "bright_magenta",
}


def detect_interfaces() -> list[str]:
    """Return non-loopback interfaces."""
    try:
        return [i for i in netifaces.interfaces() if i != "lo"]
    except Exception:
        return []


def detect_gateway(interface: str) -> Optional[str]:
    """Try to find the default gateway IP."""
    try:
        gws = netifaces.gateways()
        gw = gws.get("default", {}).get(netifaces.AF_INET)
        if gw:
            return gw[0]
    except Exception:
        pass
    return None


# ─── Trust level → Rich styling ──────────────────────────────────────────────
TRUST_STYLE = {
    TrustLevel.TRUSTED:    ("bright_green",  "✓ TRUSTED  "),
    TrustLevel.KNOWN:      ("green",         "◉ KNOWN    "),
    TrustLevel.UNKNOWN:    ("yellow",        "? UNKNOWN  "),
    TrustLevel.SUSPICIOUS: ("orange1",       "⚠ SUSPIC.  "),
    TrustLevel.HOSTILE:    ("bold red",      "✗ HOSTILE  "),
}


# ─── Dashboard ───────────────────────────────────────────────────────────────
class Dashboard:
    """Main TUI controller."""

    MODE_DEFEND = "DEFEND"
    MODE_RECON  = "RECON"
    MODE_ATTACK = "ATTACK"

    MAX_ALERTS = 50

    def __init__(self, interface: Optional[str] = None):
        self.interface = interface
        self.mode = self.MODE_DEFEND
        self.gateway_ip: Optional[str] = None

        # Components (initialized in run())
        self.trust_map: Optional[NetworkTrustMap] = None
        self.detector: Optional[ARPDetector] = None
        self.recon: Optional[NetworkRecon] = None
        self.poisoner: Optional[ARPPoisoner] = None
        self.spoofer: Optional[MACSpoofer] = None

        self._alerts: list[ARPAlert] = []
        self._alerts_lock = threading.Lock()
        self._op_log: list[str] = []
        self._poisoning = False
        self._stop_event = threading.Event()

    # ------------------------------------------------------------------ #
    # Setup                                                                #
    # ------------------------------------------------------------------ #

    def _pick_interface(self) -> str:
        interfaces = detect_interfaces()
        if not interfaces:
            console.print("[red]No network interfaces found.[/red]")
            sys.exit(1)
        if self.interface and self.interface in interfaces:
            return self.interface
        if len(interfaces) == 1:
            return interfaces[0]

        console.print(Panel(
            "\n".join(f"  [{i+1}] {iface}" for i, iface in enumerate(interfaces)),
            title="[bright_cyan]Select Interface[/bright_cyan]",
            border_style="cyan"
        ))
        choice = Prompt.ask(
            "Interface number",
            choices=[str(i+1) for i in range(len(interfaces))],
            default="1",
        )
        return interfaces[int(choice) - 1]

    def _print_banner(self):
        console.print()
        console.rule("[bright_cyan]  ◈  GHOST ON THE WIRE  ◈  [/bright_cyan]")
        console.print(
            Align.center(
                "[grey50]Layer 2 Attack & Defense Toolkit[/grey50]\n"
                "[red bold]FOR AUTHORIZED USE ONLY — Unauthorized use is illegal[/red bold]"
            )
        )
        console.print()

    def _print_legal(self):
        console.print(Panel(
            "[yellow]⚠  LEGAL WARNING[/yellow]\n\n"
            "This toolkit is for [bold]authorized security testing ONLY[/bold].\n"
            "Using these tools on networks without explicit written permission\n"
            "is illegal under the Computer Fraud and Abuse Act (CFAA), the UK\n"
            "Computer Misuse Act, EU Directive 2013/40/EU, and equivalent laws\n"
            "worldwide. You may face criminal charges and civil liability.\n\n"
            "[dim]By continuing, you confirm you have authorization to test this network.[/dim]",
            border_style="red",
            title="[red]⚠ LEGAL DISCLAIMER[/red]",
        ))
        if not Confirm.ask("Do you have authorization to test this network?", default=False):
            console.print("[yellow]Exiting. Stay legal.[/yellow]")
            sys.exit(0)

    # ------------------------------------------------------------------ #
    # Alert callback                                                       #
    # ------------------------------------------------------------------ #

    def _on_alert(self, alert: ARPAlert):
        with self._alerts_lock:
            self._alerts.append(alert)
            if len(self._alerts) > self.MAX_ALERTS:
                self._alerts.pop(0)

    # ------------------------------------------------------------------ #
    # Rich rendering helpers                                               #
    # ------------------------------------------------------------------ #

    def _render_header(self) -> Panel:
        mode_color = {
            self.MODE_DEFEND: "bright_green",
            self.MODE_RECON:  "bright_yellow",
            self.MODE_ATTACK: "bright_red",
        }.get(self.mode, "white")

        ts = time.strftime("%H:%M:%S")
        iface = self.interface or "?"
        gw = self.gateway_ip or "unknown"

        content = (
            f"[bright_cyan]◈ GHOST ON THE WIRE ◈[/bright_cyan]   "
            f"Mode: [{mode_color}]{self.mode}[/{mode_color}]   "
            f"Interface: [white]{iface}[/white]   "
            f"Gateway: [white]{gw}[/white]   "
            f"[dim]{ts}[/dim]"
        )
        return Panel(Align.center(content), border_style="cyan", padding=(0, 1))

    def _render_trust_map(self) -> Panel:
        table = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold bright_cyan",
            border_style="grey35",
            expand=True,
        )
        table.add_column("IP Address",   min_width=16)
        table.add_column("MAC",          min_width=18)
        table.add_column("Vendor",       min_width=18, no_wrap=True)
        table.add_column("Trust",        min_width=12)
        table.add_column("Score",        min_width=7, justify="right")
        table.add_column("Flags",        min_width=20)
        table.add_column("Packets",      min_width=8, justify="right")

        if self.trust_map:
            devices = self.trust_map.get_all_devices()
        else:
            devices = []

        for dev in devices:
            color, label = TRUST_STYLE.get(dev.trust_level, ("white", dev.trust_level.value))
            score_color = "green" if dev.trust_score >= 60 else "yellow" if dev.trust_score >= 30 else "red"
            flags_str = ", ".join(dev.flags[:3]) if dev.flags else "[dim]—[/dim]"
            ip_str = dev.ip
            if dev.is_gateway:
                ip_str += " [dim](gw)[/dim]"
            if dev.is_local_device:
                ip_str += " [dim](me)[/dim]"
            table.add_row(
                ip_str,
                f"[dim]{dev.mac}[/dim]",
                dev.vendor[:20] if dev.vendor else "[dim]Unknown[/dim]",
                f"[{color}]{label}[/{color}]",
                f"[{score_color}]{dev.trust_score:.0f}[/{score_color}]",
                f"[yellow]{flags_str}[/yellow]",
                str(dev.arp_reply_count + dev.arp_request_count),
            )

        if not devices:
            table.add_row("[dim]Scanning...[/dim]", "", "", "", "", "", "")

        count = len(devices)
        susp  = sum(1 for d in devices if d.trust_level in (TrustLevel.SUSPICIOUS, TrustLevel.HOSTILE))
        title = (
            f"[bright_cyan]NETWORK TRUST MAP[/bright_cyan]  "
            f"[dim]{count} devices[/dim]"
            + (f"  [red]{susp} suspicious[/red]" if susp else "")
        )
        return Panel(table, title=title, border_style="cyan", padding=(0, 0))

    def _render_alerts(self) -> Panel:
        with self._alerts_lock:
            alerts = list(self._alerts[-20:])

        severity_color = {
            "CRITICAL": "bold red",
            "HIGH":     "red",
            "MEDIUM":   "yellow",
            "LOW":      "dim yellow",
        }

        text = Text()
        if not alerts:
            text.append("  No alerts yet — network appears clean.\n", style="dim green")
        else:
            for alert in reversed(alerts[-15:]):
                ts = time.strftime("%H:%M:%S", time.localtime(alert.timestamp))
                color = severity_color.get(alert.severity, "white")
                text.append(f"  [{ts}] ", style="dim")
                text.append(f"[{alert.severity:8s}] ", style=color)
                text.append(f"{alert.alert_type}: ", style="bright_white")
                text.append(f"{alert.detail[:80]}\n", style="white")

        title = (
            f"[bright_cyan]ALERTS[/bright_cyan]  "
            f"[dim]{len(alerts)} total[/dim]"
            + (f"  [red blink]{sum(1 for a in alerts if a.severity=='CRITICAL')} CRITICAL[/red blink]"
               if any(a.severity == "CRITICAL" for a in alerts) else "")
        )
        return Panel(text, title=title, border_style="red" if alerts else "grey35", padding=(0, 0))

    def _render_stats(self) -> Panel:
        stats_parts = []
        if self.trust_map:
            s = self.trust_map.get_stats()
            stats_parts.append(f"Devices: [white]{s['total_devices']}[/white]")
            stats_parts.append(f"Trusted: [green]{s['trusted']}[/green]")
            stats_parts.append(f"Suspicious: [red]{s['suspicious']}[/red]")
            stats_parts.append(f"Packets: [dim]{s['packets_analyzed']}[/dim]")

        if self._poisoning:
            stats_parts.append("[red blink]● ARP POISONING ACTIVE[/red blink]")

        content = "   ".join(stats_parts) if stats_parts else "[dim]Starting...[/dim]"
        return Panel(content, title="[bright_cyan]STATS[/bright_cyan]", border_style="grey35", padding=(0, 1))

    def _render_ops_log(self) -> Panel:
        text = Text()
        for line in self._op_log[-15:]:
            text.append(f"  {line}\n", style="dim")
        if not self._op_log:
            text.append("  Operations will appear here.\n", style="dim grey50")
        return Panel(text, title="[bright_cyan]OPS LOG[/bright_cyan]", border_style="grey35", padding=(0, 0))

    def _render_help(self) -> Panel:
        help_text = (
            "[bright_cyan]Commands:[/bright_cyan] "
            "[white]m[/white]=mode  "
            "[white]s[/white]=scan  "
            "[white]p[/white]=poison  "
            "[white]d[/white]=detect  "
            "[white]o[/white]=OUI update  "
            "[white]q[/white]=quit"
        )
        return Panel(help_text, border_style="grey35", padding=(0, 1))

    def _build_layout(self) -> Layout:
        layout = Layout(name="root")
        layout.split_column(
            Layout(name="header",  size=3),
            Layout(name="body"),
            Layout(name="footer",  size=5),
            Layout(name="help",    size=3),
        )
        layout["body"].split_row(
            Layout(name="trust_map", ratio=2),
            Layout(name="alerts",    ratio=1),
        )
        layout["footer"].split_row(
            Layout(name="stats",  ratio=1),
            Layout(name="ops_log", ratio=2),
        )
        return layout

    def _update_layout(self, layout: Layout):
        layout["header"].update(self._render_header())
        layout["trust_map"].update(self._render_trust_map())
        layout["alerts"].update(self._render_alerts())
        layout["stats"].update(self._render_stats())
        layout["ops_log"].update(self._render_ops_log())
        layout["help"].update(self._render_help())

    # ------------------------------------------------------------------ #
    # Command handlers                                                    #
    # ------------------------------------------------------------------ #

    def _cmd_scan(self):
        self._log("Running active ARP scan...")
        def _scan():
            if self.recon:
                hosts = self.recon.scan()
                self._log(f"Scan complete: {len(hosts)} hosts found.")
        threading.Thread(target=_scan, daemon=True).start()

    def _cmd_mode(self):
        console.print("\n[1] DEFEND (passive detection)\n[2] RECON (active scan)\n[3] ATTACK (ARP poison)")
        choice = Prompt.ask("Mode", choices=["1","2","3"], default="1")
        self.mode = [self.MODE_DEFEND, self.MODE_RECON, self.MODE_ATTACK][int(choice)-1]
        self._log(f"Mode switched to {self.mode}")

    def _cmd_poison(self):
        if self._poisoning:
            console.print("[yellow]Already poisoning. Stop first.[/yellow]")
            return
        target = Prompt.ask("Target IP")
        gw     = Prompt.ask("Gateway IP", default=self.gateway_ip or "")
        if not target or not gw:
            return
        self._log(f"Starting ARP poison: target={target} gw={gw}")
        self._poisoning = True
        def _run():
            try:
                p = ARPPoisoner(self.interface, target, gw, verbose=False)
                self.poisoner = p
                p.start(duration=0)
            except Exception as e:
                self._log(f"[ERROR] Poisoner: {e}")
            finally:
                self._poisoning = False
        threading.Thread(target=_run, daemon=True).start()

    def _cmd_detect(self):
        self._log("Starting dedicated ARP detection listener...")
        gw = Prompt.ask("Gateway IP (optional)", default=self.gateway_ip or "")
        def _run():
            d = ARPDetector(
                self.interface,
                gateway_ip=gw or None,
                alert_callback=self._on_alert,
                verbose=False,
            )
            self.detector = d
            d.start()
        threading.Thread(target=_run, daemon=True).start()

    def _log(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        self._op_log.append(f"[{ts}] {msg}")
        if len(self._op_log) > 100:
            self._op_log.pop(0)

    # ------------------------------------------------------------------ #
    # Main entry                                                          #
    # ------------------------------------------------------------------ #

    def run(self):
        self._print_banner()
        self._print_legal()

        self.interface = self._pick_interface()
        self.gateway_ip = detect_gateway(self.interface)
        console.print(f"\n[*] Interface : [bright_cyan]{self.interface}[/bright_cyan]")
        console.print(f"[*] Gateway   : [bright_cyan]{self.gateway_ip or 'not detected'}[/bright_cyan]\n")

        with Status("[bright_cyan]Initializing components...[/bright_cyan]", console=console):
            # Trust map
            self.trust_map = NetworkTrustMap(self.interface, gateway_ip=self.gateway_ip)
            self.trust_map.start_passive()

            # Detection
            self.detector = ARPDetector(
                self.interface,
                gateway_ip=self.gateway_ip,
                alert_callback=self._on_alert,
                verbose=False,
            )
            threading.Thread(target=self.detector.start, daemon=True).start()

            # Recon
            self.recon = NetworkRecon(self.interface, verbose=False)

            # Initial scan
            self._log("Initial ARP scan starting...")
            threading.Thread(target=self._cmd_scan, daemon=True).start()

        self._log(f"Interface: {self.interface} | Gateway: {self.gateway_ip}")
        self._log("Dashboard active. Use commands below.")

        layout = self._build_layout()

        with Live(layout, console=console, refresh_per_second=2, screen=True):
            while not self._stop_event.is_set():
                self._update_layout(layout)
                time.sleep(0.5)

                # Non-blocking keyboard input
                if sys.stdin in self._readable():
                    char = sys.stdin.read(1).lower()
                    if char == "q":
                        self._stop_event.set()
                    elif char == "m":
                        self._cmd_mode()
                    elif char == "s":
                        self._cmd_scan()
                    elif char == "p":
                        self._cmd_poison()
                    elif char == "d":
                        self._cmd_detect()
                    elif char == "o":
                        self._log("Fetching OUI database...")
                        threading.Thread(
                            target=lambda: fetch_oui_database(force=True),
                            daemon=True
                        ).start()

        console.print("\n[bright_cyan]Ghost on the Wire — Session ended.[/bright_cyan]")

    def _readable(self) -> list:
        """Non-blocking check for stdin readability."""
        import select
        try:
            return select.select([sys.stdin], [], [], 0)[0]
        except Exception:
            return []
