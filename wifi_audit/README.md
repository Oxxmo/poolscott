# WiFiAudit Pro — Outil d'Audit de Sécurité WiFi

Outil professionnel d'audit de sécurité des réseaux WiFi, destiné aux consultants en cybersécurité réalisant des tests d'intrusion **avec autorisation écrite**.

> **AVERTISSEMENT LÉGAL** : Cet outil est réservé à un usage professionnel autorisé. Toute utilisation non autorisée est illégale (Art. 323-1 du Code Pénal français, CFAA aux USA).

---

## Prérequis

### Système
- Linux (Kali, Parrot OS, Ubuntu recommandé)
- Python 3.10+
- Adaptateur WiFi supportant le mode monitor (Alfa AWUS036ACS, TP-Link Archer T2U, etc.)

### Installation des outils
```bash
sudo apt update
sudo apt install -y aircrack-ng reaver hcxdumptool hcxtools wireless-tools iw network-manager hashcat
pip3 install -r requirements.txt
```

---

## Usage

Toutes les commandes actives nécessitent des **privilèges root** :

```bash
sudo python3 main.py <commande> [options]
```

### Vérification de l'environnement
```bash
python3 main.py check
```

### 1. Scan des réseaux WiFi
```bash
# Scan passif rapide (nmcli, sans mode monitor)
sudo python3 main.py scan --interface wlan0 --duration 10

# Scan actif avec mode monitor (plus complet)
sudo python3 main.py scan --interface wlan0 --monitor --duration 20
```

### 2. Capture de handshake WPA/WPA2
```bash
# Capture classique (4-way handshake + deauth)
sudo python3 main.py capture \
  --interface wlan0 \
  --bssid AA:BB:CC:DD:EE:FF \
  --channel 6 \
  --ssid "OfficeWifi" \
  --timeout 90 \
  --deauth 10

# Attaque PMKID (sans client connecté requis)
sudo python3 main.py capture \
  --interface wlan0 \
  --bssid AA:BB:CC:DD:EE:FF \
  --channel 6 \
  --pmkid
```

### 3. Attaque par dictionnaire
```bash
# Avec aircrack-ng (CPU)
sudo python3 main.py crack \
  --cap /tmp/wifi_audit_captures/cap_OfficeWifi_20241201_143022-01.cap \
  --bssid AA:BB:CC:DD:EE:FF \
  --wordlist /usr/share/wordlists/rockyou.txt

# Avec hashcat (GPU, beaucoup plus rapide)
sudo python3 main.py crack \
  --cap /tmp/wifi_audit_captures/cap_OfficeWifi_20241201_143022-01.cap \
  --bssid AA:BB:CC:DD:EE:FF \
  --hashcat \
  --wordlist /usr/share/wordlists/rockyou.txt

# Avec liste ciblée générée automatiquement (nom de l'entreprise)
sudo python3 main.py crack \
  --cap /tmp/wifi_audit_captures/cap_OfficeWifi_*.cap \
  --bssid AA:BB:CC:DD:EE:FF \
  --company "Acme Corporation"
```

### 4. Audit WPS
```bash
# Scan des réseaux WPS
sudo python3 main.py wps --interface wlan0mon --duration 15

# Attaque Pixie Dust (rapide, quelques secondes si vulnérable)
sudo python3 main.py wps \
  --interface wlan0mon \
  --bssid AA:BB:CC:DD:EE:FF \
  --channel 6 \
  --attack pixie

# Brute-force PIN WPS
sudo python3 main.py wps \
  --interface wlan0mon \
  --bssid AA:BB:CC:DD:EE:FF \
  --channel 6 \
  --attack pin \
  --timeout 7200
```

### 5. Génération de rapport
```bash
sudo python3 main.py report \
  --client "Acme Corporation" \
  --tester "Jean Dupont" \
  --auth-date "2024-11-28" \
  --scope "Réseaux WiFi siège social Paris"
```

### 6. Audit complet automatisé
```bash
# Enchaîne : scan → sélection cible → capture → crack → rapport
sudo python3 main.py full \
  --interface wlan0 \
  --duration 15 \
  --wordlist /usr/share/wordlists/rockyou.txt \
  --capture-timeout 90
```

---

## Fichiers de sortie

| Type | Emplacement |
|------|-------------|
| Logs | `/tmp/wifi_audit_logs/wifi_audit_YYYYMMDD_HHMMSS.log` |
| Captures | `/tmp/wifi_audit_captures/` |
| Rapports HTML | `/tmp/wifi_audit_reports/wifi_audit_<client>_<ts>.html` |
| Rapports JSON | `/tmp/wifi_audit_reports/wifi_audit_<client>_<ts>.json` |

---

## Architecture

```
wifi_audit/
├── main.py          # Point d'entrée CLI (argparse)
├── scanner.py       # Découverte des réseaux (nmcli / airodump-ng)
├── capture.py       # Capture handshake WPA + PMKID
├── cracker.py       # Attaque dictionnaire (aircrack-ng / hashcat)
├── wps_audit.py     # Audit WPS (wash / reaver)
├── wordlists.py     # Génération de listes ciblées
├── reporter.py      # Rapports HTML + JSON
├── utils.py         # Utilitaires partagés (logs, auth, root check)
└── requirements.txt
```

---

## Techniques d'attaque

| Technique | Description | Outils |
|-----------|-------------|--------|
| Handshake capture | Interception du 4-way handshake WPA | airmon-ng, airodump-ng, aireplay-ng |
| PMKID | Extraction du PMKID sans client connecté | hcxdumptool, hcxtools |
| Dictionnaire | Test de passphrases courantes | aircrack-ng, hashcat |
| Pixie Dust | Exploitation d'un défaut d'entropie WPS | reaver |
| PIN WPS | Brute-force du PIN WPS (~11 000 tentatives) | reaver |

---

## Recommandations post-audit

1. Migrer vers **WPA3-Personal** ou **WPA2-Enterprise (802.1X)**
2. **Désactiver WPS** sur tous les AP
3. Passphrases de **15+ caractères** aléatoires
4. Segmenter le WiFi en **VLAN isolé**
5. Déployer un **WIDS** (Wireless Intrusion Detection System)
6. Activer **PMF (802.11w)** contre les attaques de désauthentification
