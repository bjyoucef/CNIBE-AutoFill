import urllib.request
import ssl
import json
import re
import sys

sys.stdout.reconfigure(encoding='utf-8')

print("=" * 70)
print("🔍 INTERROGATION EN DIRECT DU SERVEUR OFFICIEL DU MINISTÈRE")
print("   URL : https://macnibe.interieur.gov.dz/WFReadCardFr.aspx/GET_IDCardControl")
print("=" * 70)

# =====================================================================
# =====================================================================
# INTERROGATION EN DIRECT DU SERVEUR MINISTÈRE
# Compatible avec n'importe quelle carte posée sur le lecteur !
# =====================================================================

import os
import subprocess
import tempfile

# Carte actuellement sur le lecteur
NUM_CARTE = "101859636"
DATE_NAISS = "17/08/1989"
DATE_EXPIR = "10/11/2026"

# Génération 100% automatique du jeton officiel via le composant Windows natif
print(f"[*] Carte ciblée : {NUM_CARTE} (Naissance: {DATE_NAISS}, Expiration: {DATE_EXPIR})")
print("[*] Génération du jeton cryptographique en direct depuis la puce...")

ps_exe = r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
script_token = os.path.join(os.path.dirname(os.path.abspath(__file__)), "get_card_token.ps1")

with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
    tmp_out = tmp.name

cmd = [
    ps_exe, "-ExecutionPolicy", "Bypass", "-File", script_token,
    "-numCarte", NUM_CARTE,
    "-dateNaiss", DATE_NAISS,
    "-dateExpir", DATE_EXPIR,
    "-outputFile", tmp_out
]

subprocess.run(cmd, capture_output=True, timeout=15)
ID_CARD = ""
if os.path.exists(tmp_out):
    with open(tmp_out, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read().strip()
    try:
        os.remove(tmp_out)
    except Exception:
        pass
    if content.startswith("RESP:"):
        ID_CARD = content[5:].strip()

if not ID_CARD:
    print("[-] Impossible d'obtenir le jeton depuis le lecteur. Vérifiez que la carte est bien posée.")
    sys.exit(1)

print(f"[+] Jeton cryptographique généré en direct ({len(ID_CARD)} caractères) !")

url = 'https://macnibe.interieur.gov.dz/WFReadCardFr.aspx/GET_IDCardControl'
payload = json.dumps({'IDCard': ID_CARD, 'NUM_CARTE': NUM_CARTE}).encode('utf-8')

headers = {
    'Host': 'macnibe.interieur.gov.dz',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Content-Type': 'application/json; charset=UTF-8',
    'X-Requested-With': 'XMLHttpRequest',
    'Origin': 'https://macnibe.interieur.gov.dz',
    'Referer': 'https://macnibe.interieur.gov.dz/WFReadCardFr.aspx'
}

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

req = urllib.request.Request(url, data=payload, headers=headers, method='POST')

try:
    with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
        raw_body = resp.read().decode('utf-8')
        print(f"[+] Connexion réussie ! Code HTTP : {resp.status}")
        print(f"[+] Content-Type  : {resp.headers.get('Content-Type')}")
        print(f"[+] Server        : {resp.headers.get('Server')}")
        print(f"[+] Date Serveur  : {resp.headers.get('Date')}")
        print(f"[+] Taille reçue  : {len(raw_body)} octets")
        
        parsed = json.loads(raw_body)
        raw_d = parsed.get('d', '')
        
        print("\n[+] PAYLOAD BRUT REÇU EN DIRECT DU SERVEUR WEB (extrait texte) :")
        # Afficher la chaîne sans la longue photo en base64 pour lisibilité
        parts = raw_d.split('|')
        raw_preview = "|".join(p if len(p) < 100 else f"[IMAGE JPEG BASE64 {len(p)} cars]" for p in parts)
        print(f"    {raw_preview}")
        
        print(f"\n[+] Total des champs reçus dans le payload 'd' : {len(parts)} champs\n")
        
        field_descriptions = [
            "Nom de famille (Arabe)",
            "Nom de famille (Français/Latin)",
            "Prénom (Arabe)",
            "Prénom (Français/Latin)",
            "Date de Naissance (AAAA/MM/JJ)",
            "Genre (Arabe)",
            "Groupe Sanguin & Rhésus",
            "Situation Familiale (Arabe)",
            "Situation Familiale (Français/Latin)",
            "ADRESSE RÉSIDENTIELLE COMPLÈTE (Rue, Quartier, Commune)",
            "Genre (Français/Latin)",
            "Lieu de Naissance (Arabe)",
            "Lieu de Naissance (Français/Latin)",
            "Photo Biométrique Officielle (JPEG Base64)",
            "NIN (Numéro d'Identification National - 18 chiffres)",
            "Nom de l'époux(se) (Arabe)",
            "Nom de l'époux(se) (Français/Latin)",
            "Situation Familiale Bilingue Complète"
        ]
        
        for i, val in enumerate(parts):
            desc = field_descriptions[i] if i < len(field_descriptions) else f"Champ additionnel #{i}"
            if val.startswith('/9j/') or len(val) > 200:
                print(f"  [{i:02d}] {desc:<45} : [IMAGE JPEG Base64 de {len(val)} caractères]")
            else:
                print(f"  [{i:02d}] {desc:<45} : \"{val}\"")
                
except Exception as e:
    print(f"[-] Erreur : {e}")

print("=" * 70)
