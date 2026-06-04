#!/usr/bin/env python3
"""
main.py - WiFi Security Audit Tool — CLI entry point

Usage:
  sudo python3 main.py scan     --interface wlan0
  sudo python3 main.py capture  --interface wlan0 --bssid AA:BB:CC:DD:EE:FF --channel 6
  sudo python3 main.py crack    --cap /tmp/wifi_audit_captures/cap_OfficeWifi_*.cap --bssid AA:BB:CC:DD:EE:FF --wordlist /usr/share/wordlists/rockyou.txt
  sudo python3 main.py wps      --interface wlan0mon
  sudo python3 main.py report   --client "Acme Corp" --tester "John Doe"
  sudo python3 main.py full     --interface wlan0
"""

import argparse
import sys
from pathlib import Path

# Ensure local imports work regardless of CWD
sys.path.insert(0, str(Path(__file__).parent))

from utils import (
    check_root,
    check_tools,
    select_interface,
    authorization_prompt,
    setup_logging,
    print_banner,
    SESSION,
    console,
)


def cmd_scan(args: argparse.Namespace) -> None:
    from scanner import scan_networks, build_ap_table

    iface = select_interface(args.interface)
    if not iface:
        sys.exit(1)

    aps = scan_networks(iface, duration=args.duration, use_monitor=args.monitor)
    if aps:
        console.print(build_ap_table(aps))
        SESSION["networks"] = aps
    else:
        console.print("[yellow]No networks found.[/yellow]")


def cmd_capture(args: argparse.Namespace) -> None:
    from capture import enable_monitor_mode, disable_monitor_mode, capture_handshake, capture_pmkid

    auth = authorization_prompt()
    SESSION["authorization"] = auth

    iface = select_interface(args.interface)
    if not iface:
        sys.exit(1)

    # Enable monitor mode
    mon_iface = enable_monitor_mode(iface)
    if not mon_iface:
        console.print("[red]Could not enable monitor mode.[/red]")
        sys.exit(1)

    try:
        if args.pmkid:
            cap_file = capture_pmkid(mon_iface, args.bssid, args.ssid or "target", timeout=args.timeout)
            if cap_file:
                from capture import convert_pmkid_to_hashcat
                convert_pmkid_to_hashcat(cap_file)
        else:
            cap_file = capture_handshake(
                mon_iface=mon_iface,
                bssid=args.bssid,
                channel=args.channel,
                ssid=args.ssid or "target",
                timeout=args.timeout,
                deauth_count=args.deauth,
            )
        SESSION["last_cap"] = cap_file
    finally:
        disable_monitor_mode(mon_iface, iface)


def cmd_crack(args: argparse.Namespace) -> None:
    from cracker import (
        crack_with_aircrack,
        crack_with_hashcat,
        generate_targeted_wordlist,
        find_default_wordlist,
        verify_handshake,
    )

    auth = authorization_prompt()
    SESSION["authorization"] = auth

    wordlist = args.wordlist
    if not wordlist:
        wordlist = find_default_wordlist()
        if not wordlist:
            console.print(
                "[yellow]No wordlist found. Generating targeted wordlist...[/yellow]"
            )
            wordlist = "/tmp/wifi_audit_targeted.txt"
            generate_targeted_wordlist(wordlist, company=args.company or "")

    cap_file = args.cap
    bssid = args.bssid

    # Verify handshake
    if not verify_handshake(cap_file, bssid):
        console.print("[red]No valid WPA handshake found in the cap file.[/red]")
        if not args.force:
            sys.exit(1)

    key = None
    if args.hashcat:
        key = crack_with_hashcat(cap_file, wordlist, hash_mode=args.hash_mode)
    else:
        key = crack_with_aircrack(cap_file, bssid, wordlist)

    if not key and not args.hashcat:
        console.print("[dim]Trying hashcat as fallback...[/dim]")
        key = crack_with_hashcat(cap_file, wordlist)

    if key:
        console.print(f"\n[bold green]Key recovered:[/bold green] {key}")
    else:
        console.print("\n[yellow]Key not recovered with provided wordlist.[/yellow]")
        console.print("Tips:")
        console.print("  • Try a larger wordlist (rockyou.txt, SecLists)")
        console.print("  • Generate a targeted wordlist: --company 'AcmeCorp'")
        console.print("  • Use hashcat rules: --hashcat --rules /usr/share/hashcat/rules/best64.rule")


def cmd_wps(args: argparse.Namespace) -> None:
    from wps_audit import scan_wps_networks, pixie_dust_attack, wps_pin_attack

    auth = authorization_prompt()
    SESSION["authorization"] = auth

    iface = select_interface(args.interface)
    if not iface:
        sys.exit(1)

    # Assume already in monitor mode or enable it
    mon_iface = iface
    if not iface.endswith("mon"):
        from capture import enable_monitor_mode, disable_monitor_mode
        mon_iface = enable_monitor_mode(iface)
        if not mon_iface:
            sys.exit(1)

    try:
        networks = scan_wps_networks(mon_iface, duration=args.duration)

        if not networks:
            console.print("[yellow]No WPS networks found.[/yellow]")
            return

        if args.bssid:
            # Attack specific target
            target = next((n for n in networks if n["bssid"].upper() == args.bssid.upper()), None)
            if not target:
                target = {"bssid": args.bssid, "channel": args.channel or 6, "ssid": args.ssid or "target"}
        else:
            # Interactive selection
            from rich.prompt import Prompt
            console.print("\nSelect target number (or 'q' to quit):", end=" ")
            choice = Prompt.ask("", default="q")
            if choice.lower() == "q":
                return
            try:
                target = networks[int(choice) - 1]
            except (ValueError, IndexError):
                console.print("[red]Invalid selection.[/red]")
                return

        if args.attack == "pixie":
            pixie_dust_attack(mon_iface, target["bssid"], target["channel"], target["ssid"])
        elif args.attack == "pin":
            wps_pin_attack(mon_iface, target["bssid"], target["channel"], target["ssid"], timeout=args.timeout)
        else:
            console.print("[yellow]Scan only — no attack. Use --attack pixie or --attack pin.[/yellow]")
    finally:
        if not iface.endswith("mon") and mon_iface != iface:
            from capture import disable_monitor_mode
            disable_monitor_mode(mon_iface, iface)


def cmd_report(args: argparse.Namespace) -> None:
    from reporter import build_report, auto_findings

    auth = {
        "client_name": args.client or SESSION.get("authorization", {}).get("client_name", "N/A"),
        "tester_name": args.tester or SESSION.get("authorization", {}).get("tester_name", "N/A"),
        "auth_date": args.auth_date or SESSION.get("authorization", {}).get("auth_date", "N/A"),
        "target_network": args.scope or SESSION.get("authorization", {}).get("target_network", "N/A"),
    }

    networks = SESSION.get("networks", [])
    findings = auto_findings(networks)
    log_file = SESSION.get("log_file", "")
    build_report(networks, findings, auth, log_file=log_file)


def cmd_full_audit(args: argparse.Namespace) -> None:
    """Full automated audit workflow."""
    from scanner import scan_networks, select_target
    from capture import enable_monitor_mode, disable_monitor_mode, capture_handshake
    from cracker import crack_with_aircrack, find_default_wordlist, generate_targeted_wordlist
    from reporter import build_report, auto_findings

    auth = authorization_prompt()
    SESSION["authorization"] = auth

    iface = select_interface(args.interface)
    if not iface:
        sys.exit(1)

    console.print("\n[bold cyan]Step 1/4 — Network Discovery[/bold cyan]")
    aps = scan_networks(iface, duration=args.duration, use_monitor=False)
    if not aps:
        console.print("[red]No networks found. Exiting.[/red]")
        sys.exit(1)
    SESSION["networks"] = aps

    target = select_target(aps)
    if not target:
        console.print("[yellow]No target selected. Generating report from scan only.[/yellow]")
        findings = auto_findings(aps)
        build_report(aps, findings, auth, log_file=SESSION.get("log_file", ""))
        return

    console.print("\n[bold cyan]Step 2/4 — Monitor Mode & Handshake Capture[/bold cyan]")
    mon_iface = enable_monitor_mode(iface)
    if not mon_iface:
        console.print("[red]Could not enable monitor mode. Report from scan only.[/red]")
        findings = auto_findings(aps)
        build_report(aps, findings, auth, log_file=SESSION.get("log_file", ""))
        return

    cap_file = None
    try:
        cap_file = capture_handshake(
            mon_iface=mon_iface,
            bssid=target.bssid,
            channel=target.channel,
            ssid=target.ssid,
            timeout=args.capture_timeout,
            deauth_count=5,
        )
    finally:
        disable_monitor_mode(mon_iface, iface)

    if cap_file:
        console.print("\n[bold cyan]Step 3/4 — Dictionary Attack[/bold cyan]")
        wordlist = args.wordlist or find_default_wordlist()
        if not wordlist:
            wordlist = "/tmp/wifi_audit_targeted.txt"
            generate_targeted_wordlist(
                wordlist,
                company=auth.get("client_name", ""),
            )
        crack_with_aircrack(cap_file, target.bssid, wordlist)
    else:
        console.print("\n[yellow]Step 3/4 — Skipping crack (no handshake).[/yellow]")

    console.print("\n[bold cyan]Step 4/4 — Generating Report[/bold cyan]")
    findings = auto_findings(aps)
    build_report(aps, findings, auth, log_file=SESSION.get("log_file", ""))


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="wifi_audit",
        description="Professional WiFi Security Audit Tool — Authorized use only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--log-dir", default="/tmp/wifi_audit_logs", help="Log directory")

    sub = parser.add_subparsers(dest="command", required=True)

    # ── scan ──────────────────────────────────────────────────────────────────
    p_scan = sub.add_parser("scan", help="Scan for WiFi networks")
    p_scan.add_argument("-i", "--interface", help="WiFi interface")
    p_scan.add_argument("-d", "--duration", type=int, default=10, help="Scan duration in seconds (default: 10)")
    p_scan.add_argument("--monitor", action="store_true", help="Use monitor mode (requires root + airmon-ng)")

    # ── capture ───────────────────────────────────────────────────────────────
    p_cap = sub.add_parser("capture", help="Capture WPA/WPA2 handshake or PMKID")
    p_cap.add_argument("-i", "--interface", help="WiFi interface (managed mode; monitor enabled automatically)")
    p_cap.add_argument("-b", "--bssid", required=True, help="Target AP BSSID (e.g. AA:BB:CC:DD:EE:FF)")
    p_cap.add_argument("-c", "--channel", type=int, required=True, help="Target AP channel")
    p_cap.add_argument("-s", "--ssid", help="Target AP SSID (for naming output files)")
    p_cap.add_argument("-t", "--timeout", type=int, default=60, help="Capture timeout in seconds (default: 60)")
    p_cap.add_argument("--deauth", type=int, default=5, help="Number of deauth packets to send (default: 5)")
    p_cap.add_argument("--pmkid", action="store_true", help="Use PMKID attack instead of handshake capture")

    # ── crack ─────────────────────────────────────────────────────────────────
    p_crack = sub.add_parser("crack", help="Run dictionary attack on a captured handshake")
    p_crack.add_argument("--cap", required=True, help="Path to the .cap or .hc22000 file")
    p_crack.add_argument("-b", "--bssid", required=True, help="Target AP BSSID")
    p_crack.add_argument("-w", "--wordlist", help="Path to wordlist (auto-detected if omitted)")
    p_crack.add_argument("--company", help="Company name for targeted wordlist generation")
    p_crack.add_argument("--hashcat", action="store_true", help="Use hashcat instead of aircrack-ng")
    p_crack.add_argument("--hash-mode", type=int, default=22000, help="Hashcat hash mode (default: 22000)")
    p_crack.add_argument("--rules", help="Hashcat rules file")
    p_crack.add_argument("--force", action="store_true", help="Continue even if handshake verification fails")

    # ── wps ───────────────────────────────────────────────────────────────────
    p_wps = sub.add_parser("wps", help="WPS vulnerability scan and attack")
    p_wps.add_argument("-i", "--interface", help="WiFi interface (monitor mode preferred)")
    p_wps.add_argument("-b", "--bssid", help="Target AP BSSID (skip scan if provided)")
    p_wps.add_argument("-c", "--channel", type=int, help="Target AP channel")
    p_wps.add_argument("-s", "--ssid", help="Target AP SSID")
    p_wps.add_argument("-d", "--duration", type=int, default=15, help="WPS scan duration (default: 15)")
    p_wps.add_argument("-t", "--timeout", type=int, default=3600, help="Attack timeout in seconds")
    p_wps.add_argument("--attack", choices=["pixie", "pin"], help="Attack type: pixie (Pixie Dust) or pin (brute-force)")

    # ── report ────────────────────────────────────────────────────────────────
    p_rep = sub.add_parser("report", help="Generate audit report from current session")
    p_rep.add_argument("--client", help="Client name")
    p_rep.add_argument("--tester", help="Tester name")
    p_rep.add_argument("--auth-date", help="Authorization date")
    p_rep.add_argument("--scope", help="Scope / target network description")

    # ── full-audit ────────────────────────────────────────────────────────────
    p_full = sub.add_parser("full", help="Full automated audit: scan → capture → crack → report")
    p_full.add_argument("-i", "--interface", help="WiFi interface")
    p_full.add_argument("-d", "--duration", type=int, default=15, help="Scan duration (default: 15)")
    p_full.add_argument("-w", "--wordlist", help="Path to wordlist")
    p_full.add_argument("--capture-timeout", type=int, default=90, help="Handshake capture timeout (default: 90)")

    # ── check ─────────────────────────────────────────────────────────────────
    sub.add_parser("check", help="Check tool availability and wireless interfaces")

    args = parser.parse_args()

    print_banner()
    setup_logging(args.log_dir)

    if args.command == "check":
        check_tools()
        from utils import detect_wireless_interfaces
        ifaces = detect_wireless_interfaces()
        console.print(f"\n[cyan]Detected wireless interfaces:[/cyan] {', '.join(ifaces) or 'none'}")
        return

    if not check_root():
        sys.exit(1)

    dispatch = {
        "scan": cmd_scan,
        "capture": cmd_capture,
        "crack": cmd_crack,
        "wps": cmd_wps,
        "report": cmd_report,
        "full": cmd_full_audit,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
