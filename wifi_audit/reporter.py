"""
reporter.py - Generates professional HTML and JSON audit reports
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from utils import console, get_logger, SESSION

log = get_logger()

REPORT_DIR = Path("/tmp/wifi_audit_reports")
REPORT_DIR.mkdir(parents=True, exist_ok=True)

_RISK_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#d97706",
    "LOW": "#16a34a",
    "INFO": "#2563eb",
}

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Rapport d'Audit Sécurité WiFi — {client}</title>
<style>
  :root {{
    --primary: #1e3a5f;
    --accent: #dc2626;
    --bg: #f8fafc;
    --card: #ffffff;
    --border: #e2e8f0;
    --text: #1e293b;
    --muted: #64748b;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }}

  header {{
    background: var(--primary);
    color: white;
    padding: 40px 60px;
    border-bottom: 4px solid var(--accent);
  }}
  header h1 {{ font-size: 2rem; font-weight: 700; margin-bottom: 4px; }}
  header .subtitle {{ color: #94a3b8; font-size: 0.95rem; }}
  header .meta {{ margin-top: 20px; display: flex; gap: 40px; flex-wrap: wrap; }}
  header .meta-item label {{ display: block; color: #94a3b8; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.05em; }}
  header .meta-item span {{ font-weight: 600; font-size: 0.95rem; }}

  .container {{ max-width: 1100px; margin: 0 auto; padding: 40px 40px; }}

  .section {{ margin-bottom: 40px; }}
  .section h2 {{
    font-size: 1.25rem; font-weight: 700;
    color: var(--primary); border-left: 4px solid var(--accent);
    padding-left: 12px; margin-bottom: 16px;
  }}

  .card {{
    background: var(--card); border: 1px solid var(--border);
    border-radius: 8px; padding: 24px; margin-bottom: 16px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.06);
  }}

  .summary-grid {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px;
  }}
  .summary-card {{
    background: var(--card); border: 1px solid var(--border); border-radius: 8px;
    padding: 20px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.06);
  }}
  .summary-card .number {{ font-size: 2.5rem; font-weight: 800; }}
  .summary-card .label {{ color: var(--muted); font-size: 0.85rem; text-transform: uppercase; }}

  table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
  th {{ background: var(--primary); color: white; padding: 10px 14px; text-align: left; font-weight: 600; }}
  td {{ padding: 10px 14px; border-bottom: 1px solid var(--border); }}
  tr:last-child td {{ border-bottom: none; }}
  tr:nth-child(even) td {{ background: #f8fafc; }}

  .badge {{
    display: inline-block; padding: 2px 10px; border-radius: 12px;
    font-size: 0.78rem; font-weight: 700; color: white;
  }}

  .finding-block {{
    border-left: 4px solid; padding: 16px 20px; margin-bottom: 12px;
    border-radius: 0 8px 8px 0; background: var(--card);
    box-shadow: 0 1px 3px rgba(0,0,0,0.06);
  }}
  .finding-block h3 {{ font-size: 1rem; margin-bottom: 6px; }}
  .finding-block p {{ color: var(--muted); font-size: 0.9rem; }}

  .rec-list {{ list-style: none; }}
  .rec-list li {{
    padding: 12px 16px; margin-bottom: 8px; border-radius: 6px;
    background: var(--card); border: 1px solid var(--border);
    display: flex; gap: 12px; align-items: flex-start;
  }}
  .rec-list li::before {{ content: '→'; color: var(--accent); font-weight: bold; }}

  .credential-block {{
    background: #fef2f2; border: 2px solid var(--accent); border-radius: 8px;
    padding: 20px; font-family: monospace;
  }}
  .credential-block .key {{ font-size: 1.4rem; font-weight: 800; color: var(--accent); }}

  footer {{
    text-align: center; padding: 30px; color: var(--muted); font-size: 0.82rem;
    border-top: 1px solid var(--border); margin-top: 40px;
  }}

  @media print {{
    header {{ break-after: avoid; }}
    .section {{ break-inside: avoid; }}
  }}
</style>
</head>
<body>

<header>
  <h1>Rapport d'Audit — Sécurité WiFi</h1>
  <div class="subtitle">Pentest — Infrastructure sans fil</div>
  <div class="meta">
    <div class="meta-item"><label>Client</label><span>{client}</span></div>
    <div class="meta-item"><label>Auditeur</label><span>{tester}</span></div>
    <div class="meta-item"><label>Date d'autorisation</label><span>{auth_date}</span></div>
    <div class="meta-item"><label>Date du rapport</label><span>{report_date}</span></div>
    <div class="meta-item"><label>Périmètre</label><span>{scope}</span></div>
    <div class="meta-item"><label>Statut</label><span style="color:#fbbf24;">CONFIDENTIEL</span></div>
  </div>
</header>

<div class="container">

<!-- Executive Summary -->
<div class="section">
  <h2>Résumé Exécutif</h2>
  <div class="card">
    <p>{executive_summary}</p>
  </div>
  <div class="summary-grid" style="margin-top:16px;">
    <div class="summary-card">
      <div class="number" style="color:{color_critical};">{count_critical}</div>
      <div class="label">Critique</div>
    </div>
    <div class="summary-card">
      <div class="number" style="color:{color_high};">{count_high}</div>
      <div class="label">Élevé</div>
    </div>
    <div class="summary-card">
      <div class="number" style="color:{color_medium};">{count_medium}</div>
      <div class="label">Moyen</div>
    </div>
    <div class="summary-card">
      <div class="number" style="color:{color_low};">{count_low}</div>
      <div class="label">Faible</div>
    </div>
    <div class="summary-card">
      <div class="number" style="color:#1e3a5f;">{total_networks}</div>
      <div class="label">Réseaux détectés</div>
    </div>
  </div>
</div>

<!-- Networks Table -->
<div class="section">
  <h2>Réseaux WiFi Détectés</h2>
  <div class="card" style="padding:0;overflow:hidden;">
    <table>
      <tr>
        <th>SSID</th><th>BSSID</th><th>Canal</th><th>Signal</th>
        <th>Chiffrement</th><th>WPS</th><th>Fabricant</th><th>Risque</th>
      </tr>
      {networks_rows}
    </table>
  </div>
</div>

<!-- Findings -->
<div class="section">
  <h2>Constats de Sécurité</h2>
  {findings_html}
</div>

<!-- Credentials Recovered -->
{credentials_section}

<!-- Recommendations -->
<div class="section">
  <h2>Recommandations</h2>
  <ul class="rec-list">
    {recommendations_html}
  </ul>
</div>

<!-- Methodology -->
<div class="section">
  <h2>Méthodologie</h2>
  <div class="card">
    <p>
      L'audit a été réalisé en plusieurs phases :
    </p>
    <ol style="margin:12px 0 0 20px; line-height:2;">
      <li><strong>Reconnaissance passive</strong> — inventaire des réseaux WiFi environnants (SSID, BSSID, canal, puissance, protocoles de sécurité, WPS).</li>
      <li><strong>Capture de handshake WPA/WPA2</strong> — interception du processus d'authentification à 4 voies via une attaque de désauthentification ciblée.</li>
      <li><strong>Attaque par dictionnaire</strong> — test de la robustesse de la passphrase à l'aide d'une liste de mots adaptée au contexte de l'entreprise.</li>
      <li><strong>Audit WPS</strong> — détection et exploitation des vulnérabilités WPS (Pixie Dust, brute-force PIN).</li>
      <li><strong>Analyse des risques</strong> — évaluation de l'impact potentiel d'une compromission sur l'infrastructure.</li>
    </ol>
    <p style="margin-top:12px; color:#64748b; font-size:0.88rem;">
      Outils utilisés : aircrack-ng, airodump-ng, aireplay-ng, hashcat, reaver, hcxdumptool.
    </p>
  </div>
</div>

<!-- Log file -->
<div class="section">
  <h2>Fichier de Log</h2>
  <div class="card">
    <p style="font-family:monospace; color:#64748b;">{log_file}</p>
  </div>
</div>

</div><!-- /container -->

<footer>
  Ce rapport est strictement confidentiel. Il est destiné exclusivement au client mentionné ci-dessus
  et ne peut être reproduit ou divulgué sans autorisation écrite.
  <br/>Généré par WiFiAudit Pro — {report_date}
</footer>

</body>
</html>
"""

_FINDING_TEMPLATES = {
    "open_network": {
        "title": "Réseau WiFi ouvert (sans authentification)",
        "risk": "CRITICAL",
        "description": "Le réseau {ssid} n'utilise aucun mécanisme d'authentification. "
                       "N'importe qui à portée peut se connecter et intercepter le trafic réseau.",
        "impact": "Accès complet au réseau local, interception du trafic, attaques MITM, accès aux ressources internes.",
    },
    "wep_encryption": {
        "title": "Chiffrement WEP déprécié",
        "risk": "CRITICAL",
        "description": "Le réseau {ssid} utilise WEP, un protocole cassé depuis 2001. "
                       "La clé peut être récupérée en quelques minutes avec des outils standards.",
        "impact": "Décryptage du trafic réseau en temps réel, accès au réseau local.",
    },
    "wps_enabled": {
        "title": "WPS activé — vecteur d'attaque Pixie Dust / PIN",
        "risk": "HIGH",
        "description": "Le réseau {ssid} a WPS activé. "
                       "L'attaque Pixie Dust peut récupérer la clé WPA en quelques secondes sur les AP vulnérables. "
                       "Le brute-force du PIN WPS (8 chiffres) réduit l'espace de recherche à ~11 000 tentatives.",
        "impact": "Récupération de la clé WiFi sans connaissance préalable. Accès complet au réseau.",
    },
    "wpa_legacy": {
        "title": "Protocole WPA (TKIP) déprécié",
        "risk": "HIGH",
        "description": "Le réseau {ssid} utilise WPA avec TKIP, un protocole présentant des vulnérabilités connues.",
        "impact": "Possibilité d'attaques Beck-Tews/TKIP sur le trafic réseau.",
    },
    "weak_password": {
        "title": "Passphrase WiFi faible ou courante",
        "risk": "CRITICAL",
        "description": "La passphrase du réseau {ssid} a été récupérée par attaque dictionnaire en un temps court. "
                       "Elle figure dans des listes de mots de passe courants.",
        "impact": "Accès complet au réseau WiFi et potentiellement à toute l'infrastructure interne.",
    },
    "pmkid_vulnerable": {
        "title": "Vulnérable à l'attaque PMKID (clientless)",
        "risk": "HIGH",
        "description": "Le réseau {ssid} expose son PMKID dans les trames beacon/probe, "
                       "permettant une attaque sans présence de clients connectés.",
        "impact": "Possibilité d'attaque offline sur la passphrase sans interaction avec les clients.",
    },
}

_RECOMMENDATIONS = [
    "Migrer tous les réseaux WiFi vers WPA3-Personal ou WPA2-Enterprise (802.1X/RADIUS).",
    "Désactiver WPS sur tous les points d'accès — le protocole présente des vulnérabilités structurelles.",
    "Mettre en place une politique de passphrases robustes : minimum 15 caractères, aléatoires, sans rapport avec le nom de l'entreprise.",
    "Segmenter le réseau WiFi en VLAN dédié, isolé du réseau interne (LAN/serveurs).",
    "Déployer un système de détection d'intrusion sans fil (WIDS) pour détecter les attaques de désauthentification.",
    "Remplacer les équipements supportant uniquement WEP ou WPA (TKIP).",
    "Activer PMF (Protected Management Frames / 802.11w) pour se protéger contre les attaques de désauthentification.",
    "Changer régulièrement la passphrase WiFi (tous les 6 à 12 mois) et lors de tout départ d'employé.",
    "Envisager une architecture Zero Trust avec authentification 802.1X par certificat pour les équipements professionnels.",
    "Former les collaborateurs aux risques liés aux réseaux WiFi et aux attaques de type Evil Twin / rogue AP.",
]


def _badge(risk: str) -> str:
    color = _RISK_COLORS.get(risk, "#64748b")
    return f'<span class="badge" style="background:{color};">{risk}</span>'


def build_report(
    networks: list,
    findings: list[dict],
    auth: dict,
    cracked_keys: Optional[list] = None,
    log_file: str = "",
) -> str:
    """Build a full HTML report and return the file path."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    client = auth.get("client_name", "N/A")
    tester = auth.get("tester_name", "N/A")
    auth_date = auth.get("auth_date", "N/A")
    scope = auth.get("target_network", "N/A")
    report_date = datetime.now().strftime("%d/%m/%Y %H:%M")

    cracked_keys = cracked_keys or SESSION.get("cracked_keys", [])

    # Count by risk level
    count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        level = f.get("risk", "MEDIUM")
        count[level] = count.get(level, 0) + 1

    exec_summary = (
        f"L'audit du réseau WiFi de {client} a permis d'identifier {len(findings)} constat(s) de sécurité "
        f"dont {count['CRITICAL']} critique(s) et {count['HIGH']} élevé(s) sur {len(networks)} réseau(x) détecté(s). "
    )
    if cracked_keys:
        exec_summary += (
            f"{len(cracked_keys)} passphrase(s) WiFi ont été récupérées par attaque dictionnaire, "
            "démontrant l'insuffisance de la politique de mots de passe actuelle. "
        )
    exec_summary += (
        "Des mesures correctives sont détaillées en section Recommandations."
    )

    # Networks table rows
    rows = []
    for ap in networks:
        enc = getattr(ap, "encryption", "?") or "OPEN"
        enc_color = _RISK_COLORS["CRITICAL"] if enc in ("OPN", "WEP", "") else (
            _RISK_COLORS["HIGH"] if enc == "WPA" else "#16a34a"
        )
        risk = getattr(ap, "risk", "MEDIUM")
        wps = "YES" if getattr(ap, "wps", False) else "no"
        wps_color = _RISK_COLORS["CRITICAL"] if getattr(ap, "wps", False) else "#16a34a"
        rows.append(
            f"<tr>"
            f"<td><strong>{getattr(ap,'ssid','?')}</strong></td>"
            f"<td style='font-family:monospace;font-size:0.85em;'>{getattr(ap,'bssid','?')}</td>"
            f"<td>{getattr(ap,'channel','?')}</td>"
            f"<td>{getattr(ap,'signal','?')} dBm</td>"
            f"<td><span style='color:{enc_color};font-weight:700;'>{enc}</span></td>"
            f"<td><span style='color:{wps_color};font-weight:700;'>{wps}</span></td>"
            f"<td>{getattr(ap,'vendor','?')}</td>"
            f"<td>{_badge(risk)}</td>"
            f"</tr>"
        )
    networks_rows = "\n".join(rows) if rows else "<tr><td colspan='8' style='text-align:center;color:#64748b;'>Aucun réseau scanné</td></tr>"

    # Findings
    findings_html_parts = []
    for f in findings:
        risk = f.get("risk", "MEDIUM")
        color = _RISK_COLORS.get(risk, "#64748b")
        title = f.get("title", "Constat")
        desc = f.get("description", "")
        impact = f.get("impact", "")
        findings_html_parts.append(
            f'<div class="finding-block" style="border-left-color:{color};">'
            f"<h3>{_badge(risk)} &nbsp; {title}</h3>"
            f"<p><strong>Description :</strong> {desc}</p>"
            f"<p style='margin-top:6px;'><strong>Impact :</strong> {impact}</p>"
            f"</div>"
        )
    findings_html = "\n".join(findings_html_parts) if findings_html_parts else (
        '<div class="card"><p style="color:#64748b;">Aucun constat enregistré.</p></div>'
    )

    # Credentials
    if cracked_keys:
        cred_rows = []
        for item in cracked_keys:
            cred_rows.append(
                f'<div class="credential-block" style="margin-bottom:12px;">'
                f'Réseau : <strong>{item.get("ssid") or item.get("source","?")}</strong><br/>'
                f'<span class="key">{item.get("key","?")}</span><br/>'
                f'<small style="color:#64748b;">Outil : {item.get("tool","?")}</small>'
                f"</div>"
            )
        credentials_section = (
            '<div class="section"><h2 style="color:#dc2626;">Identifiants Récupérés</h2>'
            + "\n".join(cred_rows)
            + "</div>"
        )
    else:
        credentials_section = ""

    # Recommendations
    rec_items = "\n".join(f"<li>{r}</li>" for r in _RECOMMENDATIONS)

    html = _HTML_TEMPLATE.format(
        client=client,
        tester=tester,
        auth_date=auth_date,
        report_date=report_date,
        scope=scope,
        executive_summary=exec_summary,
        count_critical=count["CRITICAL"],
        count_high=count["HIGH"],
        count_medium=count["MEDIUM"],
        count_low=count["LOW"],
        color_critical=_RISK_COLORS["CRITICAL"],
        color_high=_RISK_COLORS["HIGH"],
        color_medium=_RISK_COLORS["MEDIUM"],
        color_low=_RISK_COLORS["LOW"],
        total_networks=len(networks),
        networks_rows=networks_rows,
        findings_html=findings_html,
        credentials_section=credentials_section,
        recommendations_html=rec_items,
        log_file=log_file or "N/A",
    )

    # Write HTML
    html_path = str(REPORT_DIR / f"wifi_audit_{client.replace(' ','_')}_{ts}.html")
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(html)

    # Write JSON
    json_path = html_path.replace(".html", ".json")
    report_data = {
        "metadata": {
            "client": client,
            "tester": tester,
            "auth_date": auth_date,
            "report_date": report_date,
            "scope": scope,
        },
        "summary": {**count, "total_networks": len(networks)},
        "networks": [
            {k: getattr(ap, k, None) for k in
             ("ssid", "bssid", "channel", "signal", "encryption", "cipher", "auth", "wps", "vendor", "risk")}
            for ap in networks
        ],
        "findings": findings,
        "credentials": cracked_keys,
        "recommendations": _RECOMMENDATIONS,
        "log_file": log_file,
    }
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report_data, fh, indent=2, ensure_ascii=False)

    log.info("Report generated: HTML=%s JSON=%s", html_path, json_path)
    console.print(f"\n[bold green]Report saved:[/bold green]")
    console.print(f"  HTML : [cyan]{html_path}[/cyan]")
    console.print(f"  JSON : [cyan]{json_path}[/cyan]")

    return html_path


def auto_findings(networks: list) -> list[dict]:
    """
    Automatically generate findings from the list of scanned AccessPoint objects.
    """
    findings = []
    for ap in networks:
        enc = getattr(ap, "encryption", "") or ""
        ssid = getattr(ap, "ssid", "?")

        if enc in ("OPN", "", "OPEN"):
            f = dict(_FINDING_TEMPLATES["open_network"])
            f["description"] = f["description"].format(ssid=ssid)
            f["ssid"] = ssid
            findings.append(f)
        elif enc == "WEP":
            f = dict(_FINDING_TEMPLATES["wep_encryption"])
            f["description"] = f["description"].format(ssid=ssid)
            f["ssid"] = ssid
            findings.append(f)
        elif enc == "WPA":
            f = dict(_FINDING_TEMPLATES["wpa_legacy"])
            f["description"] = f["description"].format(ssid=ssid)
            f["ssid"] = ssid
            findings.append(f)

        if getattr(ap, "wps", False):
            f = dict(_FINDING_TEMPLATES["wps_enabled"])
            f["description"] = f["description"].format(ssid=ssid)
            f["ssid"] = ssid
            findings.append(f)

    # Add findings for cracked passwords
    for item in SESSION.get("cracked_keys", []):
        f = dict(_FINDING_TEMPLATES["weak_password"])
        target_ssid = item.get("ssid") or item.get("source", "?")
        f["description"] = f["description"].format(ssid=target_ssid)
        f["ssid"] = target_ssid
        findings.append(f)

    return findings
