"""
utils.py - Shared utilities for WiFi Security Audit Tool
Handles: root check, tool availability, interface detection, authorization prompt, logging
"""

import os
import sys
import subprocess
import shutil
import logging
import json
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich import box

console = Console()

DISCLAIMER = """
╔══════════════════════════════════════════════════════════════════════╗
║          PROFESSIONAL WiFi SECURITY AUDIT TOOL                      ║
║                                                                      ║
║  LEGAL WARNING - AUTHORIZED USE ONLY                                ║
║                                                                      ║
║  This tool is intended EXCLUSIVELY for cybersecurity professionals  ║
║  with explicit written authorization to audit target networks.       ║
║                                                                      ║
║  Unauthorized use is illegal and constitutes a criminal offense      ║
║  under the Computer Fraud and Abuse Act (CFAA) 18 U.S.C. § 1030,   ║
║  UK Computer Misuse Act 1990, and equivalent laws worldwide.         ║
║                                                                      ║
║  By continuing, you certify that you have written authorization      ║
║  from the network owner and are operating within a legal scope       ║
║  of work (SOW) or engagement letter.                                 ║
╚══════════════════════════════════════════════════════════════════════╝
"""

REQUIRED_TOOLS = {
    'airmon-ng': 'aircrack-ng',
    'airodump-ng': 'aircrack-ng',
    'aireplay-ng': 'aircrack-ng',
    'aircrack-ng': 'aircrack-ng',
    'iwconfig': 'wireless-tools',
    'iw': 'iw',
    'nmcli': 'network-manager',
}

OPTIONAL_TOOLS = {
    'hashcat': 'hashcat',
    'hcxdumptool': 'hcxdumptool',
    'hcxpcapngtool': 'hcxtools',
    'wash': 'reaver',
    'reaver': 'reaver',
}

# Global session state
SESSION: dict = {}
_logger: logging.Logger | None = None


def setup_logging(log_dir: str = "/tmp/wifi_audit_logs") -> logging.Logger:
    """Configure file and console logging for the session."""
    global _logger
    if _logger is not None:
        return _logger

    Path(log_dir).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = Path(log_dir) / f"wifi_audit_{timestamp}.log"

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(log_file),
        ],
    )
    _logger = logging.getLogger("wifi_audit")
    _logger.info("WiFi Audit session started - log file: %s", log_file)
    SESSION["log_file"] = str(log_file)
    return _logger


def get_logger() -> logging.Logger:
    """Return the module-level logger, initializing if needed."""
    global _logger
    if _logger is None:
        return setup_logging()
    return _logger


def check_root() -> bool:
    """Verify the process is running as root (required for raw socket / monitor mode)."""
    if os.geteuid() != 0:
        console.print(
            Panel(
                "[bold red]This tool requires root privileges.[/bold red]\n\n"
                "Run with: [bold]sudo python3 main.py ...[/bold]",
                title="[red]Permission Error[/red]",
                border_style="red",
            )
        )
        return False
    return True


def check_tools(required: bool = True) -> dict[str, bool]:
    """
    Check availability of required and optional tools.

    Returns a dict mapping tool name -> available (bool).
    Prints a colour-coded table to the terminal.
    """
    tools_map = REQUIRED_TOOLS if required else OPTIONAL_TOOLS
    all_tools = {**REQUIRED_TOOLS, **OPTIONAL_TOOLS}

    results: dict[str, bool] = {}
    table = Table(title="Tool Availability Check", box=box.ROUNDED, show_lines=True)
    table.add_column("Tool", style="bold cyan")
    table.add_column("Package", style="dim")
    table.add_column("Status", justify="center")
    table.add_column("Type", justify="center")

    for tool, package in all_tools.items():
        found = shutil.which(tool) is not None
        results[tool] = found
        status_str = "[green]Found[/green]" if found else "[red]Missing[/red]"
        tool_type = "[yellow]Required[/yellow]" if tool in REQUIRED_TOOLS else "[dim]Optional[/dim]"
        table.add_row(tool, package, status_str, tool_type)

    console.print(table)

    missing_required = [t for t in REQUIRED_TOOLS if not results.get(t, False)]
    if missing_required:
        console.print(
            f"\n[bold red]Missing required tools:[/bold red] {', '.join(missing_required)}\n"
            "Install with: [bold]sudo apt-get install aircrack-ng wireless-tools iw network-manager[/bold]\n"
        )

    get_logger().info("Tool check: %s", json.dumps(results))
    return results


def detect_wireless_interfaces() -> list[str]:
    """
    Return a list of wireless interface names detected on the system.
    Tries iw, then falls back to /proc/net/wireless.
    """
    interfaces: list[str] = []

    # Method 1 — iw dev
    try:
        out = subprocess.check_output(["iw", "dev"], text=True, timeout=5)
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Interface "):
                interfaces.append(line.split()[1])
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    # Method 2 — /proc/net/wireless fallback
    if not interfaces:
        try:
            with open("/proc/net/wireless") as fh:
                for line in fh.readlines()[2:]:
                    iface = line.split(":")[0].strip()
                    if iface:
                        interfaces.append(iface)
        except OSError:
            pass

    return list(dict.fromkeys(interfaces))  # de-duplicate, preserve order


def select_interface(preferred: str | None = None) -> str | None:
    """
    Resolve the wireless interface to use.
    If *preferred* is given, validate it exists; otherwise prompt interactively.
    """
    ifaces = detect_wireless_interfaces()

    if not ifaces:
        console.print("[bold red]No wireless interfaces detected.[/bold red]")
        console.print(
            "Ensure your WiFi adapter is connected and drivers are loaded.\n"
            "Try: [bold]sudo iw dev[/bold] or [bold]sudo iwconfig[/bold]"
        )
        return None

    if preferred:
        if preferred in ifaces:
            return preferred
        console.print(
            f"[yellow]Warning:[/yellow] Specified interface '[bold]{preferred}[/bold]' "
            f"not found. Available: {', '.join(ifaces)}"
        )

    if len(ifaces) == 1:
        console.print(f"[cyan]Auto-selected interface:[/cyan] [bold]{ifaces[0]}[/bold]")
        return ifaces[0]

    table = Table(title="Detected Wireless Interfaces", box=box.SIMPLE)
    table.add_column("#", style="bold")
    table.add_column("Interface", style="cyan")
    for idx, iface in enumerate(ifaces, 1):
        table.add_row(str(idx), iface)
    console.print(table)

    choice = Prompt.ask(
        "Select interface number",
        choices=[str(i) for i in range(1, len(ifaces) + 1)],
        default="1",
    )
    return ifaces[int(choice) - 1]


def display_disclaimer() -> None:
    """Print the legal disclaimer panel."""
    console.print(Panel(DISCLAIMER, style="bold yellow", border_style="red"))


def authorization_prompt() -> dict:
    """
    Collect and record authorization details before any active attack operation.
    Returns a dict with client_name, target_network, auth_date, tester_name.
    Raises SystemExit if user does not confirm.
    """
    display_disclaimer()

    console.print(
        "\n[bold red]AUTHORIZATION REQUIRED[/bold red]\n"
        "You must confirm you have explicit written authorization before proceeding.\n"
    )

    if not Confirm.ask("[bold]Do you have written authorization to perform this security audit?[/bold]"):
        console.print("\n[red]Authorization not confirmed. Exiting.[/red]")
        sys.exit(1)

    console.print("\n[bold cyan]Please provide engagement details for the audit log:[/bold cyan]\n")
    client_name = Prompt.ask("  Client / Organization name")
    target_network = Prompt.ask("  Target network name (SSID or description)")
    auth_date = Prompt.ask(
        "  Authorization date (date on the signed document)",
        default=datetime.now().strftime("%Y-%m-%d"),
    )
    tester_name = Prompt.ask("  Tester name (your full name)")

    auth_record = {
        "client_name": client_name,
        "target_network": target_network,
        "auth_date": auth_date,
        "tester_name": tester_name,
        "confirmed_at": datetime.now().isoformat(),
    }

    SESSION["authorization"] = auth_record
    get_logger().info("Authorization confirmed: %s", json.dumps(auth_record))

    console.print(
        Panel(
            f"[green]Authorization recorded[/green]\n\n"
            f"Client    : [bold]{client_name}[/bold]\n"
            f"Target    : [bold]{target_network}[/bold]\n"
            f"Auth Date : [bold]{auth_date}[/bold]\n"
            f"Tester    : [bold]{tester_name}[/bold]",
            title="[green]Engagement Details[/green]",
            border_style="green",
        )
    )
    console.print()
    return auth_record


def run_command(
    cmd: list[str],
    timeout: int = 30,
    capture_output: bool = True,
    check: bool = False,
    **kwargs,
) -> subprocess.CompletedProcess:
    """
    Wrapper around subprocess.run with logging and error handling.
    """
    log = get_logger()
    log.debug("Running command: %s", " ".join(str(c) for c in cmd))
    try:
        result = subprocess.run(
            cmd,
            timeout=timeout,
            capture_output=capture_output,
            text=True,
            check=check,
            **kwargs,
        )
        if result.returncode != 0 and result.stderr:
            log.debug("Command stderr: %s", result.stderr[:500])
        return result
    except subprocess.TimeoutExpired:
        log.warning("Command timed out after %ds: %s", timeout, " ".join(str(c) for c in cmd))
        raise
    except FileNotFoundError:
        log.error("Command not found: %s", cmd[0])
        raise


def get_interface_info(iface: str) -> dict:
    """
    Return a dict with physical-layer info for *iface*: mode, channel, frequency, tx_power.
    """
    info: dict = {"interface": iface}
    try:
        out = subprocess.check_output(["iw", "dev", iface, "info"], text=True, timeout=5)
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("type "):
                info["mode"] = line.split(None, 1)[1]
            elif line.startswith("channel "):
                parts = line.split()
                info["channel"] = parts[1]
                if len(parts) >= 4:
                    info["frequency"] = parts[3].lstrip("(")
            elif "txpower" in line.lower():
                info["tx_power"] = line.split()[-2] + " dBm"
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    return info


def oui_lookup(bssid: str) -> str:
    """
    Very lightweight OUI prefix lookup against a small built-in table.
    Returns vendor string or 'Unknown'.
    """
    OUI_TABLE = {
        "00:50:F2": "Microsoft",
        "00:0C:E7": "Asus",
        "18:31:BF": "Asus",
        "10:02:B5": "TP-Link",
        "50:C7:BF": "TP-Link",
        "EC:08:6B": "TP-Link",
        "A0:63:91": "TP-Link",
        "DC:FE:07": "TP-Link",
        "00:1A:2B": "Cisco",
        "00:1B:D4": "Cisco",
        "00:23:EA": "Cisco",
        "F8:72:EA": "Netgear",
        "A0:04:60": "Netgear",
        "C4:04:15": "Netgear",
        "00:09:5B": "Netgear",
        "B0:7F:B9": "Ubiquiti",
        "24:A4:3C": "Ubiquiti",
        "78:8A:20": "Ubiquiti",
        "DC:9F:DB": "Ubiquiti",
        "00:17:88": "Philips (Hue)",
        "B8:27:EB": "Raspberry Pi",
        "DC:A6:32": "Raspberry Pi",
        "E4:5F:01": "Raspberry Pi",
        "00:1C:BF": "D-Link",
        "14:D6:4D": "D-Link",
        "84:C9:B2": "D-Link",
        "34:31:C4": "Huawei",
        "48:AD:08": "Huawei",
        "F8:98:EF": "Apple",
        "AC:BC:32": "Apple",
        "3C:07:54": "Apple",
        "60:F8:1D": "Apple",
        "00:26:B9": "Dell",
        "18:03:73": "Dell",
        "00:21:6A": "Linksys",
        "C0:C1:C0": "Linksys",
    }
    prefix = ":".join(bssid.upper().split(":")[:3])
    return OUI_TABLE.get(prefix, "Unknown")


def print_banner() -> None:
    """Print the tool banner."""
    banner = """
[bold cyan] ██╗    ██╗██╗███████╗██╗      █████╗ ██╗   ██╗██████╗ ██╗████████╗
 ██║    ██║██║██╔════╝██║     ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
 ██║ █╗ ██║██║█████╗  ██║     ███████║██║   ██║██║  ██║██║   ██║
 ██║███╗██║██║██╔══╝  ██║     ██╔══██║██║   ██║██║  ██║██║   ██║
 ╚███╔███╔╝██║██║     ██║     ██║  ██║╚██████╔╝██████╔╝██║   ██║
  ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝[/bold cyan]
[bold yellow]              Professional WiFi Security Audit Tool v1.0[/bold yellow]
[dim]              For authorized penetration testing only[/dim]
"""
    console.print(banner)
