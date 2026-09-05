#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cnibe_agent.py - Service Passerelle & API Officielle du Ministère de l'Intérieur
Fournit l'accès aux services officiels pour cartes CNIBE algériennes :
1. Détection passive de l'état du lecteur NFC et de la carte (SCardGetStatusChange).
2. Génération locale du jeton cryptographique officiel via le composant DzaEidCard (ActiveX).
3. Interrogation du service officiel du Ministère de l'Intérieur (macnibe.interieur.gov.dz)
   pour l'extraction de l'adresse certifiée, du NIN et de la situation familiale.

NOTE : Le serveur web HTTP local a été supprimé. Ce module est désormais une bibliothèque
directement intégrée et exploitée par l'application CNIBE AutoFill (Keyboard Wedge).
"""

import sys
import os
import json
import time
import base64
import threading
import subprocess
import tempfile
import urllib.request
import urllib.parse
import ssl
from typing import Optional, Dict, Any

# Assurer l'encodage UTF-8 sous Windows
for stream_name in ('stdout', 'stderr'):
    stream = getattr(sys, stream_name)
    if hasattr(stream, 'reconfigure'):
        try:
            stream.reconfigure(encoding='utf-8')
        except Exception:
            pass

# Import du module PC/SC passif sécurisé
try:
    from read_cnibe_safe import (
        read_cnibe_card,
        SecurityException,
        NoCardException,
        CardConnectionException,
        get_best_reader,
        readers
    )
    from smartcard.scard import (
        SCardEstablishContext,
        SCardReleaseContext,
        SCardListReaders,
        SCardGetStatusChange,
        SCARD_SCOPE_USER,
        SCARD_STATE_UNAWARE,
        SCARD_STATE_PRESENT,
        SCARD_S_SUCCESS
    )
    HAS_SCARD_PASSIVE = True
except ImportError:
    HAS_SCARD_PASSIVE = False


# Verrouillage pour éviter toute interférence concurrente pendant la lecture
scan_lock = threading.Lock()
is_scanning = False


# ==============================================================================
# 1. DÉTECTION PASSIVE DU LECTEUR ET DE LA CARTE (SANS RESET RF)
# ==============================================================================

def get_passive_pcsc_status() -> Dict[str, Any]:
    """
    Vérifie l'état du lecteur et de la carte de manière 100% PASSIVE.
    N'établit aucune connexion et ne transmet aucun signal reset RF à la puce.
    """
    global is_scanning
    if is_scanning:
        return {
            "status": "OK",
            "readers_count": 1,
            "readers": ["Lecteur NFC actif"],
            "selected_reader": "Lecture NFC en cours...",
            "card_present": True,
            "is_scanning": True,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

    if not scan_lock.acquire(blocking=False):
        return {
            "status": "OK",
            "readers_count": 1,
            "readers": ["Lecteur NFC actif"],
            "selected_reader": "Lecture NFC en cours...",
            "card_present": True,
            "is_scanning": True,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

    try:
        if not HAS_SCARD_PASSIVE:
            try:
                r_list = readers()
                return {
                    "status": "OK",
                    "readers_count": len(r_list),
                    "readers": [str(r) for r in r_list],
                    "selected_reader": str(r_list[0]) if r_list else None,
                    "card_present": bool(r_list),
                    "is_scanning": False,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                }
            except Exception:
                return {"status": "OK", "readers_count": 0, "readers": [], "card_present": False, "is_scanning": False}

        hcontext = None
        try:
            hresult, hcontext = SCardEstablishContext(SCARD_SCOPE_USER)
            if hresult != SCARD_S_SUCCESS:
                return {"status": "OK", "readers_count": 0, "readers": [], "selected_reader": None, "card_present": False, "is_scanning": False}

            hresult, reader_list = SCardListReaders(hcontext, [])
            if hresult != SCARD_S_SUCCESS or not reader_list:
                return {
                    "status": "OK",
                    "readers_count": 0,
                    "readers": [],
                    "selected_reader": None,
                    "card_present": False,
                    "is_scanning": False,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                }

            # Sélectionner de préférence le lecteur Contactless / CL / NFC
            target_reader = reader_list[0]
            for r in reader_list:
                r_upper = r.upper()
                if any(kw in r_upper for kw in ("CL", "CONTACTLESS", "NFC", "PICC", "RFID")):
                    target_reader = r
                    break

            # Inspection passive de l'état matériel (SCARD_STATE_UNAWARE)
            readerstates = [(target_reader, SCARD_STATE_UNAWARE)]
            hresult, states = SCardGetStatusChange(hcontext, 0, readerstates)
            card_present = False

            if hresult == SCARD_S_SUCCESS and states:
                _, eventstate, _ = states[0]
                card_present = bool(eventstate & SCARD_STATE_PRESENT)

            return {
                "status": "OK",
                "readers_count": len(reader_list),
                "readers": reader_list,
                "selected_reader": target_reader,
                "card_present": card_present,
                "is_scanning": False,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }

        except Exception as e:
            return {
                "status": "OK",
                "readers_count": 0,
                "readers": [],
                "selected_reader": None,
                "card_present": False,
                "is_scanning": False,
                "message": str(e),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
        finally:
            if hcontext is not None:
                try:
                    SCardReleaseContext(hcontext)
                except Exception:
                    pass
    finally:
        scan_lock.release()


# ==============================================================================
# 2. GESTION DU CACHE LOCAL DES JETONS
# ==============================================================================

LOCAL_DIR = os.path.dirname(os.path.abspath(__file__))
TOKENS_CACHE_FILE = os.path.join(LOCAL_DIR, "tokens_cache.json")
KNOWN_ID_CARDS: Dict[str, str] = {}
tokens_cache_lock = threading.Lock()


def get_known_id_cards() -> Dict[str, str]:
    """Charge les jetons IDCard cryptographiques en cache mémoire ou fichier tokens_cache.json local (Thread-Safe)."""
    global KNOWN_ID_CARDS
    with tokens_cache_lock:
        if os.path.exists(TOKENS_CACHE_FILE):
            try:
                with open(TOKENS_CACHE_FILE, "r", encoding="utf-8") as f:
                    saved = json.load(f)
                    KNOWN_ID_CARDS.update(saved)
            except Exception:
                pass
        return dict(KNOWN_ID_CARDS)


def save_token_to_cache(num: str, token: str):
    """Sauvegarde un jeton généré dans le cache persistant local de manière thread-safe."""
    global KNOWN_ID_CARDS
    with tokens_cache_lock:
        KNOWN_ID_CARDS[num] = token
        try:
            data = {}
            if os.path.exists(TOKENS_CACHE_FILE):
                with open(TOKENS_CACHE_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
            data[num] = token
            with open(TOKENS_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass


def format_to_dmy(d, is_exp=False):
    """Convertit un format de date (YYMMDD, YYYY-MM-DD, etc.) en JJ/MM/AAAA pour le composant officiel."""
    if not d:
        return ""
    d_str = str(d).strip().replace('-', '/').replace('.', '/')
    if len(d_str) == 6 and d_str.isdigit():
        yy = int(d_str[:2])
        mm = d_str[2:4]
        dd = d_str[4:6]
        full_year = 2000 + yy if is_exp or yy < 30 else 1900 + yy
        return f"{dd}/{mm}/{full_year}"
    if '/' in d_str:
        p = d_str.split('/')
        if len(p) == 3:
            if len(p[0]) == 4:  # AAAA/MM/JJ -> JJ/MM/AAAA
                return f"{p[2].zfill(2)}/{p[1].zfill(2)}/{p[0]}"
            return f"{p[0].zfill(2)}/{p[1].zfill(2)}/{p[2]}"
    return d_str


# ==============================================================================
# 3. GÉNÉRATION DU JETON OFFICIEL VIA LE COMPOSANT DZA EIDCARD
# ==============================================================================

def generate_local_token(num_carte: str, date_naiss: str, date_expir: str) -> Optional[str]:
    """
    Génère le jeton cryptographique IDCard en appelant le composant officiel du Ministère
    (npDzaEidCard 0.6.14) via get_card_token.ps1 directement sur le poste de travail.
    """
    num_norm = str(num_carte).strip()
    d_naiss = format_to_dmy(date_naiss)
    d_exp = format_to_dmy(date_expir, is_exp=True)

    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "get_card_token.ps1")
    if not os.path.exists(script_path):
        return None

    ps_candidates = [
        r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "powershell.exe"
    ]
    ps_exe = None
    for p in ps_candidates:
        if os.path.exists(p) or p == "powershell.exe":
            ps_exe = p
            break

    if not ps_exe:
        return None

    tmp_fd, tmp_out = tempfile.mkstemp(suffix=".txt")
    os.close(tmp_fd)

    cmd = [
        ps_exe, "-ExecutionPolicy", "Bypass", "-File", script_path,
        "-numCarte", num_norm,
        "-dateNaiss", d_naiss,
        "-dateExpir", d_exp,
        "-outputFile", tmp_out
    ]

    try:
        print(f"[*] [MINISTÈRE] Génération du jeton officiel pour la carte {num_norm} via le lecteur USB local...")
        subprocess.run(cmd, capture_output=True, timeout=20)
        if os.path.exists(tmp_out):
            with open(tmp_out, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read().strip()
            try:
                os.remove(tmp_out)
            except Exception:
                pass
            if content.startswith("RESP:"):
                token = content[5:].strip()
                if len(token) > 100:
                    print(f"[+] [MINISTÈRE] Jeton officiel généré avec succès ({len(token)} car.) !")
                    return token
                else:
                    print(f"[-] [MINISTÈRE] Réponse inattendue du composant : {token}")
            else:
                print(f"[-] [MINISTÈRE] Sortie non reconnue : '{content}'")
    except Exception as e:
        print(f"[-] [MINISTÈRE] Erreur génération jeton : {e}")
    return None


# ==============================================================================
# 4. API OFFICIELLE DU MINISTÈRE DE L'INTÉRIEUR ALGÉRIEN
# ==============================================================================

def fetch_ministere_data(document_number: str, id_card: str = None) -> Optional[Dict[str, Any]]:
    """
    Interroge le service officiel du Ministère de l'Intérieur algérien :
    https://macnibe.interieur.gov.dz/WFReadCardFr.aspx/GET_IDCardControl
    Retourne les champs certifiés dont l'adresse certifiée (index 9) et la situation familiale.
    """
    doc_norm = str(document_number).strip()
    if not id_card:
        known = get_known_id_cards()
        id_card = known.get(doc_norm)

    if not id_card:
        return None

    url = "https://macnibe.interieur.gov.dz/WFReadCardFr.aspx/GET_IDCardControl"
    payload = json.dumps({"IDCard": id_card, "NUM_CARTE": doc_norm}).encode('utf-8')
    headers = {
        "Host": "macnibe.interieur.gov.dz",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)",
        "Content-Type": "application/json; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": "https://macnibe.interieur.gov.dz",
        "Referer": "https://macnibe.interieur.gov.dz/WFReadCardFr.aspx"
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=8) as resp:
            if resp.status != 200:
                return None
            res_text = resp.read().decode('utf-8')
            parsed = json.loads(res_text)
            d_str = parsed.get("d", "")
            if not d_str or d_str in ("00", "-1", "6300", "91010", "V"):
                return None
            parts = d_str.split('|')
            if len(parts) < 15:
                return None

            return {
                "status": "SUCCESS",
                "source": "MINISTERE_INTERIEUR",
                "nom_arabe": parts[0].strip(),
                "nom_latin": parts[1].strip(),
                "prenom_arabe": parts[2].strip(),
                "prenom_latin": parts[3].strip(),
                "date_naissance": parts[4].strip(),
                "sexe_arabe": parts[5].strip(),
                "groupe_sanguin": parts[6].strip(),
                "situation_familiale_arabe": parts[7].strip(),
                "situation_familiale_latin": parts[8].strip(),
                "adresse": parts[9].strip(),
                "adresse_officielle": parts[9].strip(),
                "sexe_latin": parts[10].strip() if len(parts) > 10 else "",
                "lieu_naissance_arabe": parts[11].strip() if len(parts) > 11 else "",
                "lieu_naissance_latin": parts[12].strip() if len(parts) > 12 else "",
                "has_photo": bool(len(parts) > 13 and parts[13]),
                "photo_base64": parts[13] if len(parts) > 13 else "",
                "nin": parts[14].strip() if len(parts) > 14 else "",
                "nom_epoux_arabe": parts[15].strip() if len(parts) > 15 else "",
                "nom_epoux_latin": parts[16].strip() if len(parts) > 16 else "",
                "situation_familiale": parts[17].strip() if len(parts) > 17 else f"{parts[7]} / {parts[8]}"
            }
    except Exception as e:
        print(f"[-] [MINISTÈRE API ERREUR] {e}", file=sys.stderr)
        return None


# ==============================================================================
# 5. DIAGNOSTIC CLI EN CAS D'EXÉCUTION DIRECTE
# ==============================================================================

def main():
    print("=" * 70)
    print("🛡️  CNIBE - Passerelle & API Ministère de l'Intérieur")
    print("=" * 70)
    print("[*] Vérification du matériel PC/SC...")
    status = get_passive_pcsc_status()
    print(f"[+] Lecteur(s) détecté(s) : {status.get('readers', [])}")
    print(f"[+] Lecteur sélectionné   : {status.get('selected_reader')}")
    print(f"[+] Carte présente        : {'Oui' if status.get('card_present') else 'Non'}")

    cache = get_known_id_cards()
    print(f"[+] Cartes en cache local : {len(cache)}")
    print("\nCe module fournit les services pour l'application CNIBE AutoFill.")
    print("Pour démarrer l'application avec saisie clavier, lancez :")
    print("👉 py -3.11 cnibe_autofill_gui.py  (ou double-cliquez sur lancer_remplisseur.bat)")


if __name__ == "__main__":
    main()
