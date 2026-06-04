"""
cracker.py - Dictionary and rule-based attacks against captured WPA handshakes
"""

import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

from rich.progress import Progress, SpinnerColumn, TimeElapsedColumn, TextColumn, BarColumn
from rich.panel import Panel

from utils import console, get_logger, run_command, SESSION

log = get_logger()

DEFAULT_WORDLISTS = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/rockyou.txt.gz",
    "/usr/share/john/password.lst",
    "/usr/share/metasploit-framework/data/wordlists/common_passwords.txt",
]


def find_default_wordlist() -> Optional[str]:
    """Return the first existing wordlist from the default list."""
    for path in DEFAULT_WORDLISTS:
        if os.path.exists(path):
            return path
    return None


# ─── Aircrack-ng ─────────────────────────────────────────────────────────────

def crack_with_aircrack(
    cap_file: str,
    bssid: str,
    wordlist: str,
) -> Optional[str]:
    """
    Run aircrack-ng against a .cap file.
    Returns the cracked key as a string, or None.
    """
    if not os.path.exists(cap_file):
        console.print(f"[red]Cap file not found:[/red] {cap_file}")
        return None
    if not os.path.exists(wordlist):
        console.print(f"[red]Wordlist not found:[/red] {wordlist}")
        return None
    if not shutil.which("aircrack-ng"):
        console.print("[red]aircrack-ng not found.[/red]")
        return None

    console.print(
        Panel(
            f"[bold]Running aircrack-ng[/bold]\n"
            f"  Cap file : [cyan]{cap_file}[/cyan]\n"
            f"  Wordlist : [cyan]{wordlist}[/cyan]\n"
            f"  Target   : {bssid}",
            border_style="yellow",
        )
    )
    log.info("Starting aircrack-ng: cap=%s wordlist=%s bssid=%s", cap_file, wordlist, bssid)

    try:
        result = subprocess.run(
            ["aircrack-ng", "-a", "2", "-b", bssid, "-w", wordlist, cap_file],
            capture_output=True,
            text=True,
            timeout=3600,
        )
    except subprocess.TimeoutExpired:
        console.print("[red]aircrack-ng timed out.[/red]")
        return None
    except FileNotFoundError:
        console.print("[red]aircrack-ng not found.[/red]")
        return None

    key = _parse_aircrack_result(result.stdout)
    if key:
        _report_success(key, "aircrack-ng", cap_file)
        return key

    if "Passphrase not in dictionary" in result.stdout:
        console.print("[yellow]Key not found in wordlist.[/yellow]")
        log.info("aircrack-ng: passphrase not in dictionary")
    else:
        console.print(f"[red]aircrack-ng failed.[/red]\n{result.stdout[-500:]}")

    return None


def _parse_aircrack_result(output: str) -> Optional[str]:
    """Extract the cracked key from aircrack-ng output."""
    for line in output.splitlines():
        line = line.strip()
        if "KEY FOUND!" in line:
            # Format: KEY FOUND! [ password ]
            start = line.find("[")
            end = line.find("]")
            if start != -1 and end != -1:
                return line[start + 1:end].strip()
    return None


# ─── Hashcat ─────────────────────────────────────────────────────────────────

def cap_to_hccapx(cap_file: str, bssid: str) -> Optional[str]:
    """Convert a .cap file to .hccapx format for hashcat using aircrack-ng."""
    hccapx_file = cap_file.replace(".cap", ".hccapx")
    result = run_command(
        ["aircrack-ng", "-J", hccapx_file.replace(".hccapx", ""), "-b", bssid, cap_file],
        timeout=30,
    )
    if result.returncode == 0 and os.path.exists(hccapx_file):
        log.info("Converted to hccapx: %s", hccapx_file)
        return hccapx_file
    return None


def crack_with_hashcat(
    hash_file: str,
    wordlist: str,
    hash_mode: int = 22000,
    rules: Optional[str] = None,
    use_gpu: bool = True,
) -> Optional[str]:
    """
    Run hashcat against a hash file (mode 22000 for WPA2, or 2500 for .hccapx).
    Returns the cracked key or None.
    """
    if not shutil.which("hashcat"):
        console.print("[red]hashcat not found. Install: sudo apt install hashcat[/red]")
        return None
    if not os.path.exists(hash_file):
        console.print(f"[red]Hash file not found:[/red] {hash_file}")
        return None
    if not os.path.exists(wordlist):
        console.print(f"[red]Wordlist not found:[/red] {wordlist}")
        return None

    potfile = hash_file + ".pot"
    cmd = [
        "hashcat",
        "-m", str(hash_mode),
        "-a", "0",
        "--status",
        "--status-timer", "10",
        "--potfile-path", potfile,
        hash_file,
        wordlist,
    ]

    if rules:
        cmd += ["-r", rules]

    if not use_gpu:
        cmd += ["--force"]  # CPU-only fallback

    console.print(
        Panel(
            f"[bold]Running hashcat (mode {hash_mode})[/bold]\n"
            f"  Hash file: [cyan]{hash_file}[/cyan]\n"
            f"  Wordlist : [cyan]{wordlist}[/cyan]\n"
            f"  Rules    : {rules or 'none'}",
            border_style="yellow",
        )
    )
    log.info("Starting hashcat: cmd=%s", " ".join(cmd))

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)
    except subprocess.TimeoutExpired:
        console.print("[red]hashcat timed out.[/red]")
        return None

    key = _parse_hashcat_result(result.stdout, potfile)
    if key:
        _report_success(key, "hashcat", hash_file)
        return key

    if "Exhausted" in result.stdout:
        console.print("[yellow]hashcat: wordlist exhausted, key not found.[/yellow]")
    else:
        console.print(f"[red]hashcat failed.[/red]\nstdout: {result.stdout[-300:]}")
        log.debug("hashcat stderr: %s", result.stderr[-300:])

    return None


def _parse_hashcat_result(output: str, potfile: str) -> Optional[str]:
    """Parse hashcat output or pot file for the cracked password."""
    # Check potfile first
    if os.path.exists(potfile):
        with open(potfile) as fh:
            for line in fh:
                if ":" in line:
                    return line.strip().rsplit(":", 1)[-1]

    # Parse stdout
    for line in output.splitlines():
        if ":" in line and not line.startswith("["):
            parts = line.strip().split(":")
            if len(parts) >= 2 and len(parts[-1]) >= 8:
                return parts[-1]
    return None


# ─── Wordlist generation ─────────────────────────────────────────────────────

def generate_targeted_wordlist(output_path: str, company: str = "", extra_words: Optional[list] = None) -> str:
    """
    Generate a targeted wordlist based on company name and common corporate patterns.
    Writes to output_path. Returns the path.
    """
    from wordlists import generate_corporate_wordlist
    words = generate_corporate_wordlist(company, extra_words or [])

    with open(output_path, "w") as fh:
        for word in words:
            fh.write(word + "\n")

    console.print(f"[green]Generated targeted wordlist:[/green] {output_path} ({len(words)} entries)")
    log.info("Generated targeted wordlist: %s (%d words)", output_path, len(words))
    return output_path


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _report_success(key: str, tool: str, source: str) -> None:
    console.print(
        Panel(
            f"[bold red]PASSWORD FOUND[/bold red]\n\n"
            f"  Key    : [bold green]{key}[/bold green]\n"
            f"  Tool   : {tool}\n"
            f"  Source : {source}",
            title="[bold red]!! CREDENTIAL RECOVERED !![/bold red]",
            border_style="red",
        )
    )
    log.critical("PASSWORD CRACKED: key=%s tool=%s source=%s", key, tool, source)
    SESSION.setdefault("cracked_keys", []).append({"key": key, "tool": tool, "source": source})


def verify_handshake(cap_file: str, bssid: str) -> bool:
    """Quick check that the cap file contains a valid WPA handshake."""
    if not shutil.which("aircrack-ng"):
        return os.path.exists(cap_file) and os.path.getsize(cap_file) > 0

    result = run_command(
        ["aircrack-ng", "-a", "2", "-b", bssid, cap_file],
        timeout=10,
    )
    return "1 handshake" in result.stdout or "Handshake" in result.stdout
