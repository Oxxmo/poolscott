"""
scanner.py - WiFi network discovery and enumeration
"""

import csv
import io
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich import box

from utils import console, get_logger, oui_lookup, run_command

log = get_logger()


@dataclass
class AccessPoint:
    bssid: str
    ssid: str
    channel: int
    frequency: str
    signal: int          # dBm
    encryption: str      # WPA3/WPA2/WPA/WEP/OPN
    cipher: str
    auth: str
    wps: bool = False
    clients: list[str] = field(default_factory=list)
    vendor: str = "Unknown"

    @property
    def risk(self) -> str:
        if self.encryption in ("OPN", ""):
            return "CRITICAL"
        if self.encryption == "WEP":
            return "CRITICAL"
        if self.wps:
            return "HIGH"
        if self.encryption == "WPA":
            return "HIGH"
        return "MEDIUM"

    @property
    def risk_color(self) -> str:
        colors = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "green"}
        return colors.get(self.risk, "white")


def _parse_airodump_csv(csv_data: str) -> list[AccessPoint]:
    """Parse the AP section of an airodump-ng CSV dump."""
    aps: list[AccessPoint] = []
    lines = csv_data.splitlines()

    # Find AP section
    ap_section = True
    client_start = -1
    for i, line in enumerate(lines):
        if line.strip().startswith("Station MAC"):
            client_start = i
            break

    ap_lines = lines[2:client_start] if client_start > 0 else lines[2:]

    for line in ap_lines:
        line = line.strip()
        if not line:
            continue
        try:
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 14:
                continue
            bssid = parts[0]
            if not re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", bssid):
                continue
            channel = int(parts[3]) if parts[3].lstrip("-").isdigit() else 0
            signal = int(parts[8]) if parts[8].lstrip("-").isdigit() else -100
            encryption = parts[5].strip()
            cipher = parts[6].strip()
            auth = parts[7].strip()
            ssid = parts[13].strip() if len(parts) > 13 else "<hidden>"

            ap = AccessPoint(
                bssid=bssid,
                ssid=ssid if ssid else "<hidden>",
                channel=channel,
                frequency="2.4GHz" if channel <= 14 else "5GHz",
                signal=signal,
                encryption=encryption,
                cipher=cipher,
                auth=auth,
                vendor=oui_lookup(bssid),
            )
            aps.append(ap)
        except (ValueError, IndexError):
            continue

    return aps


def _parse_nmcli_output(output: str) -> list[AccessPoint]:
    """Parse nmcli -f output into AccessPoint list."""
    aps: list[AccessPoint] = []
    seen: set[str] = set()

    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("IN-USE"):
            continue
        # nmcli columns: IN-USE BSSID SSID MODE CHAN FREQ RATE SIGNAL BARS SECURITY
        parts = line.split()
        if len(parts) < 8:
            continue
        try:
            # Handle the IN-USE marker (*) that may or may not be present
            offset = 1 if parts[0] == "*" else 0
            bssid = parts[offset]
            if not re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", bssid):
                continue
            if bssid in seen:
                continue
            seen.add(bssid)

            # SSID may be multi-word; grab everything between BSSID and MODE
            ssid_parts = []
            idx = offset + 1
            while idx < len(parts) and parts[idx] not in ("Infra", "AP", "Ad-Hoc"):
                ssid_parts.append(parts[idx])
                idx += 1
            ssid = " ".join(ssid_parts) or "<hidden>"

            chan_idx = idx + 1
            signal_idx = idx + 4
            security_idx = idx + 6

            channel = int(parts[chan_idx]) if chan_idx < len(parts) and parts[chan_idx].isdigit() else 0
            signal_raw = int(parts[signal_idx]) if signal_idx < len(parts) and parts[signal_idx].isdigit() else 50
            # nmcli reports signal 0-100; convert to approx dBm
            signal_dbm = int((signal_raw / 2) - 100)
            encryption = " ".join(parts[security_idx:]) if security_idx < len(parts) else "OPN"

            ap = AccessPoint(
                bssid=bssid,
                ssid=ssid,
                channel=channel,
                frequency="2.4GHz" if channel <= 14 else "5GHz",
                signal=signal_dbm,
                encryption=encryption,
                cipher="",
                auth="",
                vendor=oui_lookup(bssid),
            )
            aps.append(ap)
        except (ValueError, IndexError):
            continue

    return aps


def build_ap_table(aps: list[AccessPoint], title: str = "Detected WiFi Networks") -> Table:
    """Build a rich Table from a list of AccessPoint objects."""
    table = Table(
        title=title,
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold magenta",
    )
    table.add_column("#", style="bold dim", width=4)
    table.add_column("SSID", style="bold cyan", min_width=16)
    table.add_column("BSSID", style="dim", min_width=17)
    table.add_column("CH", justify="right", width=4)
    table.add_column("Band", width=6)
    table.add_column("Signal", justify="right", width=8)
    table.add_column("Security", min_width=10)
    table.add_column("WPS", justify="center", width=5)
    table.add_column("Vendor", min_width=12)
    table.add_column("Risk", justify="center", width=8)

    for idx, ap in enumerate(aps, 1):
        wps_str = "[red]YES[/red]" if ap.wps else "[green]no[/green]"
        risk_str = f"[{ap.risk_color}]{ap.risk}[/{ap.risk_color}]"
        enc_color = "red" if ap.encryption in ("OPN", "WEP", "") else "yellow" if ap.encryption == "WPA" else "green"
        enc_str = f"[{enc_color}]{ap.encryption or 'OPEN'}[/{enc_color}]"
        table.add_row(
            str(idx),
            ap.ssid,
            ap.bssid,
            str(ap.channel),
            ap.frequency,
            f"{ap.signal} dBm",
            enc_str,
            wps_str,
            ap.vendor,
            risk_str,
        )
    return table


def scan_with_nmcli(iface: str, duration: int = 5) -> list[AccessPoint]:
    """Use nmcli to perform a quick passive scan (no monitor mode required)."""
    console.print(f"[cyan]Scanning with nmcli on {iface} ...[/cyan]")
    try:
        # Trigger a rescan
        run_command(["nmcli", "dev", "wifi", "rescan", "ifname", iface], timeout=15)
        time.sleep(duration)
        result = run_command(
            ["nmcli", "-f", "IN-USE,BSSID,SSID,MODE,CHAN,FREQ,RATE,SIGNAL,BARS,SECURITY",
             "dev", "wifi", "list", "ifname", iface],
            timeout=15,
        )
        if result.returncode == 0:
            return _parse_nmcli_output(result.stdout)
    except (subprocess.SubprocessError, FileNotFoundError) as exc:
        log.warning("nmcli scan failed: %s", exc)
    return []


def scan_with_airodump(iface: str, duration: int = 15, output_prefix: str = "/tmp/wifi_scan") -> list[AccessPoint]:
    """
    Use airodump-ng for an active passive scan in monitor mode.
    Writes a CSV then parses it.
    """
    import tempfile, shutil
    csv_path = f"{output_prefix}-01.csv"

    # Ensure output file doesn't exist from a previous run
    for ext in ["-01.csv", "-01.cap", "-01.kismet.csv", "-01.kismet.netxml", "-01.log.csv"]:
        try:
            os.remove(output_prefix + ext)
        except FileNotFoundError:
            pass

    console.print(f"[cyan]Scanning with airodump-ng on {iface} for {duration}s ...[/cyan]")
    try:
        proc = subprocess.Popen(
            ["airodump-ng", "--write", output_prefix, "--output-format", "csv", iface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(duration)
        proc.terminate()
        proc.wait(timeout=5)
    except FileNotFoundError:
        console.print("[red]airodump-ng not found.[/red]")
        return []

    try:
        with open(csv_path, encoding="utf-8", errors="ignore") as fh:
            data = fh.read()
        return _parse_airodump_csv(data)
    except FileNotFoundError:
        log.warning("airodump-ng CSV not created: %s", csv_path)
        return []


def scan_networks(iface: str, duration: int = 15, use_monitor: bool = False) -> list[AccessPoint]:
    """
    High-level scan: tries airodump-ng if monitor mode requested,
    otherwise falls back to nmcli.
    """
    if use_monitor:
        aps = scan_with_airodump(iface, duration)
    else:
        aps = scan_with_nmcli(iface, duration)

    if not aps:
        console.print("[yellow]No networks found. Try increasing duration or enabling monitor mode.[/yellow]")
        return []

    aps.sort(key=lambda a: a.signal, reverse=True)
    log.info("Scan found %d networks", len(aps))
    for ap in aps:
        log.info("  %s [%s] ch=%s enc=%s signal=%sdBm wps=%s",
                 ap.ssid, ap.bssid, ap.channel, ap.encryption, ap.signal, ap.wps)
    return aps


def select_target(aps: list[AccessPoint]) -> Optional[AccessPoint]:
    """Display the AP table and prompt the user to select a target."""
    if not aps:
        return None

    console.print(build_ap_table(aps))
    from rich.prompt import Prompt
    choice = Prompt.ask(
        "\nSelect target network number (or 'q' to quit)",
        default="q",
    )
    if choice.lower() == "q":
        return None
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(aps):
            return aps[idx]
    except ValueError:
        pass
    console.print("[red]Invalid selection.[/red]")
    return None
