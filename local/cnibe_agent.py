#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cnibe_agent.py - Agent Client Local pour Lecteur NFC CNIBE
Ce script s'exécute sur le poste de travail (PC Client) où le lecteur NFC USB est branché.
Il écoute sur http://127.0.0.1:5001 et fournit une API REST sécurisée avec support CORS.

OPTIMISATIONS DE STABILITÉ :
1. Détection passive de l'état de la carte via SCardGetStatusChange (aucun reset RF, aucune connexion/déconnexion intrusive).
2. Verrou exclusif de scan (scan_lock) pour empêcher tout conflit ou collision pendant la lecture NFC.
3. Silence complet du polling d'état pendant qu'une lecture de carte est en cours.
"""

import sys
import os
import json
import time
import base64
import threading
from typing import Optional, Dict, Any
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

# Assurer l'encodage UTF-8 sous Windows
for stream_name in ('stdout', 'stderr'):
    stream = getattr(sys, stream_name)
    if hasattr(stream, 'reconfigure'):
        try:
            stream.reconfigure(encoding='utf-8')
        except Exception:
            pass

# Import du module de lecture sécurisé
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

AGENT_PORT = 5001
AGENT_HOST = "127.0.0.1"

# Verrouillage pour éviter toute interférence concurrente pendant la lecture
scan_lock = threading.Lock()
is_scanning = False


def get_passive_pcsc_status() -> Dict[str, Any]:
    """
    Vérifie l'état du lecteur et de la carte de manière 100% PASSIVE.
    N'établit aucune connexion et ne transmet aucun signal reset RF à la puce.
    RÈGLE CRITIQUE : Si un scan NFC est en cours (is_scanning), retourne immédiatement
    un état statique sans JAMAIS toucher aux contextes PC/SC (winscard), pour ne pas
    interférer avec le transfert NFC des gros fichiers (DG2 photo, DG7 signature).
    """
    global is_scanning
    if is_scanning:
        return {
            "status": "OK",
            "agent": "CNIBE Local Client Agent v1.0",
            "readers_count": 1,
            "readers": ["Lecteur NFC actif"],
            "selected_reader": "Lecture NFC en cours...",
            "card_present": True,
            "is_scanning": True,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

    # Tenter d'acquérir le verrou sans bloquer pour éviter toute collision
    # avec un scan qui démarrerait entre le check is_scanning et l'appel SCard
    if not scan_lock.acquire(blocking=False):
        return {
            "status": "OK",
            "agent": "CNIBE Local Client Agent v1.0",
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
                    "agent": "CNIBE Local Client Agent v1.0",
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
                    "agent": "CNIBE Local Client Agent v1.0",
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
                "agent": "CNIBE Local Client Agent v1.0",
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
                "agent": "CNIBE Local Client Agent v1.0",
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


LOCAL_DIR = os.path.dirname(os.path.abspath(__file__))
TOKENS_CACHE_FILE = os.path.join(LOCAL_DIR, "tokens_cache.json")
KNOWN_ID_CARDS: Dict[str, str] = {}


def get_known_id_cards() -> Dict[str, str]:
    """Charge les jetons IDCard cryptographiques en cache mémoire ou fichier tokens_cache.json local."""
    global KNOWN_ID_CARDS
    if os.path.exists(TOKENS_CACHE_FILE):
        try:
            with open(TOKENS_CACHE_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
                KNOWN_ID_CARDS.update(saved)
        except Exception:
            pass
    return KNOWN_ID_CARDS


def save_token_to_cache(num: str, token: str):
    """Sauvegarde un jeton généré dans le cache persistant local."""
    global KNOWN_ID_CARDS
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


def generate_local_token(num_carte: str, date_naiss: str, date_expir: str) -> Optional[str]:
    """
    Génère le jeton cryptographique IDCard en appelant le composant officiel du Ministère
    (npDzaEidCard 0.6.14) via get_card_token.ps1 directement sur le poste client (lecteur USB).
    """
    import subprocess
    import tempfile

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
        print(f"[*] [AGENT TOKEN] Génération du jeton officiel pour la carte {num_norm} via le lecteur USB local...")
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
                    print(f"[+] [AGENT TOKEN] Jeton officiel généré avec succès ({len(token)} car.) !")
                    return token
                else:
                    print(f"[-] [AGENT TOKEN] Réponse inattendue : {token}")
            else:
                print(f"[-] [AGENT TOKEN] Sortie non reconnue : '{content}'")
    except Exception as e:
        print(f"[-] [AGENT TOKEN] Erreur génération jeton : {e}")
    return None


def fetch_ministere_data(document_number: str, id_card: str = None) -> Optional[Dict[str, Any]]:
    """
    Interroge le service officiel du Ministère de l'Intérieur algérien :
    https://macnibe.interieur.gov.dz/WFReadCardFr.aspx/GET_IDCardControl
    Retourne les 18 champs officiels dont l'adresse certifiée (index 9) et la situation familiale.
    Exécuté directement depuis le poste client avec le jeton cryptographique généré localement.
    """
    import urllib.request
    import ssl

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


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Serveur HTTP multi-threadé pour gérer les requêtes concurrentes."""
    daemon_threads = True


class CNIBEAgentHandler(BaseHTTPRequestHandler):
    """Gestionnaire de requêtes HTTP avec support CORS complet."""

    def _send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
        self.send_header("Access-Control-Max-Age", "86400")

    def _send_json(self, status_code: int, data: Dict[str, Any]):
        response_bytes = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(response_bytes)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(response_bytes)

    def do_OPTIONS(self):
        """Réponse aux requêtes preflight CORS du navigateur."""
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self):
        """Routes GET : statut de l'agent et du lecteur."""
        parsed_path = self.path.split('?')[0]

        if parsed_path == "/status":
            self._handle_status()
        elif parsed_path == "/":
            self._handle_home()
        else:
            self._send_json(404, {"status": "ERROR", "message": "Route introuvable"})

    def do_POST(self):
        """Routes POST : déclenchement de la lecture de carte."""
        parsed_path = self.path.split('?')[0]

        if parsed_path == "/scan":
            self._handle_scan()
        elif parsed_path == "/token":
            self._handle_token()
        else:
            self._send_json(404, {"status": "ERROR", "message": "Route introuvable"})

    def _handle_status(self):
        """Retourne l'état sans perturber le lecteur."""
        status_data = get_passive_pcsc_status()
        self._send_json(200, status_data)

    def _handle_token(self):
        """Génère le jeton officiel du Ministère via le lecteur USB local sans lecture NFC complète."""
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length <= 0:
            self._send_json(400, {"status": "ERROR", "message": "Corps JSON manquant"})
            return
        try:
            body_raw = self.rfile.read(content_length).decode('utf-8')
            payload = json.loads(body_raw)
            doc = payload.get("doc", "").strip()
            dob = payload.get("dob", "").strip()
            doe = payload.get("doe", "").strip()
            if not doc or not dob or not doe:
                self._send_json(400, {"status": "ERROR", "message": "Champs 'doc', 'dob' et 'doe' requis"})
                return
            token = generate_local_token(doc, dob, doe)
            if token:
                self._send_json(200, {"status": "SUCCESS", "id_card_token": token})
            else:
                self._send_json(500, {"status": "ERROR", "message": "Échec de génération du jeton local"})
        except Exception as e:
            self._send_json(500, {"status": "ERROR", "message": str(e)})

    def _handle_home(self):
        """Page d'accueil simple."""
        html_content = """<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>CNIBE Client Agent</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; }
        .card { background: #1e293b; border-radius: 12px; padding: 24px; max-width: 600px; margin: auto; box-shadow: 0 10px 25px rgba(0,0,0,0.5); border: 1px solid #334155; }
        h1 { font-size: 22px; color: #38bdf8; margin-top: 0; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 9999px; font-weight: bold; font-size: 13px; }
        .badge-green { background: #065f46; color: #34d399; }
    </style>
</head>
<body>
    <div class="card">
        <h1>🛡️ CNIBE Client Agent (Local)</h1>
        <p><span class="badge badge-green">● AGENT ACTIF</span> Écoute sur port <strong>5001</strong> (CORS actif)</p>
        <p>Cet agent fait le pont entre votre lecteur NFC USB local et l'application web sur le LAN.</p>
    </div>
</body>
</html>"""
        response_bytes = html_content.encode('utf-8')
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(response_bytes)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(response_bytes)

    def _handle_scan(self):
        """Exécute la lecture NFC sécurisée avec exclusion mutuelle absolue."""
        global is_scanning

        # Vérifier si un scan est déjà en cours
        if not scan_lock.acquire(blocking=False):
            self._send_json(429, {
                "status": "ERROR",
                "message": "Une lecture NFC est déjà en cours sur ce lecteur. Veuillez patienter."
            })
            return

        try:
            is_scanning = True
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length <= 0:
                self._send_json(400, {"status": "ERROR", "message": "Corps de requête JSON manquant"})
                return

            body_raw = self.rfile.read(content_length).decode('utf-8')
            payload = json.loads(body_raw)

            doc = payload.get("doc", "").strip()
            dob = payload.get("dob", "").strip()
            doe = payload.get("doe", "").strip()
            req_doc_type = payload.get("doc_type", "").strip().upper()
            wait_sec = int(payload.get("wait", 15))

            if not doc or not dob or not doe:
                self._send_json(400, {
                    "status": "ERROR",
                    "message": "Les champs 'doc', 'dob' et 'doe' sont obligatoires pour l'authentification BAC."
                })
                return

            print(f"\n[AGENT] Demande de scan reçue : Doc={doc}, DoB={dob}, DoE={doe}, Type={req_doc_type or 'AUTO'}...")

            # Exécution de la lecture sécurisée (Mode 100% Mémoire : aucun fichier .jpg sur disque)
            card_data = read_cnibe_card(
                doc=doc,
                dob=dob,
                doe=doe,
                wait_seconds=wait_sec,
                photo_dest=None,
                signature_dest=None,
                include_base64=True
            )

            print(f"[AGENT] Scan réussi avec succès pour Doc={doc} !")
            photo_fn = card_data.get("photo", {}).get("filename", "")
            sig_fn = card_data.get("signature", {}).get("filename", "")
            if photo_fn or sig_fn:
                print(f"[AGENT] Fichiers sauvegardés : Photo={photo_fn or 'N/A'}, Signature={sig_fn or 'N/A'}")
            else:
                print("[AGENT] Confidentialité active : Photo et Signature conservées en mémoire (Base64), aucun fichier physique écrit sur disque.")

            # Détection du type de document (Passeport vs Carte CNIBE)
            dg1_info = card_data.get("dg1_mrz", {})
            mrz_doc_type = dg1_info.get("document_type", "")
            is_passport = (
                card_data.get("is_passport", False) or 
                req_doc_type in ["PASSPORT", "P"] or 
                mrz_doc_type.startswith("P") or 
                dg1_info.get("document_type_category") == "PASSPORT"
            )
            card_data["is_passport"] = is_passport

            if is_passport:
                print(f"[*] [AGENT] Document détecté : PASSEPORT BIOMÉTRIQUE ({mrz_doc_type or 'P'}).")
                print("    Les services locaux CNIBE (ActiveX EidCard & consultation Ministère) sont ignorés car réservés aux Cartes d'Identité.")
            else:
                # Consultation officielle du Ministère de l'Intérieur (spécifique CNIBE)
                # 1. Vérifier si un jeton officiel est déjà disponible dans le cache local
                known = get_known_id_cards()
                doc_norm = dg1_info.get("document_number", doc).strip()
                token = known.get(doc_norm) or known.get(doc)

                # 2. Si absent du cache, tenter la génération via le lecteur USB local
                if not token:
                    time.sleep(0.3)
                    print(f"[*] [AGENT TOKEN] Génération du jeton officiel pour {doc_norm}...")
                    token = generate_local_token(doc_norm, dob, doe)
                    if token:
                        save_token_to_cache(doc_norm, token)

                # 3. Interroger le Ministère avec le jeton
                if token:
                    card_data["id_card_token"] = token
                    try:
                        print(f"[*] [AGENT] Consultation du Ministère de l'Intérieur pour Doc={doc_norm}...")
                        min_data = fetch_ministere_data(doc_norm, token)
                        if min_data:
                            card_data["ministere_data"] = min_data
                            print(f"[+] [AGENT] Données officielles reçues ! Adresse : {min_data.get('adresse')}")
                        else:
                            print(f"[-] [AGENT] Données officielles non disponibles.")
                    except Exception as em:
                        print(f"[-] [AGENT] Exception consultation Ministère : {em}")
                else:
                    min_data = fetch_ministere_data(doc_norm)
                    if min_data:
                        card_data["ministere_data"] = min_data

            self._send_json(200, {
                "status": "SUCCESS",
                "data": card_data
            })

        except SecurityException as e:
            print(f"[AGENT ERREUR SÉCURITÉ] {e}", file=sys.stderr)
            self._send_json(401, {
                "status": "SECURITY_ERROR",
                "message": f"Échec de l'authentification BAC ou arrêt d'urgence : {str(e)}"
            })
        except (NoCardException, CardConnectionException) as e:
            print(f"[AGENT ERREUR CARTE] {e}", file=sys.stderr)
            self._send_json(404, {
                "status": "CARD_NOT_FOUND",
                "message": f"Carte non détectée ou communication NFC interrompue : {str(e)}"
            })
        except Exception as e:
            print(f"[AGENT ERREUR] {e}", file=sys.stderr)
            self._send_json(500, {
                "status": "ERROR",
                "message": f"Erreur lors de la lecture : {str(e)}"
            })
        finally:
            is_scanning = False
            scan_lock.release()

    def log_message(self, format, *args):
        """Silence les logs HTTP habituels pour garder une console propre."""
        pass


def run_agent():
    print("=" * 70)
    print("🛡️  CNIBE LOCAL CLIENT AGENT (Passerelle PC/SC NFC)")
    print("=" * 70)
    print(f"[*] Démarrage de l'agent sur http://{AGENT_HOST}:{AGENT_PORT}")
    print(f"[*] Mode de détection passive actif (aucune interférence avec le canal NFC).")
    print(f"[*] Pour arrêter l'agent, appuyez sur Ctrl+C.\n")

    # Affichage du statut initial
    initial_status = get_passive_pcsc_status()
    if initial_status.get("readers_count", 0) > 0:
        print(f"[+] Lecteur(s) détecté(s) : {initial_status.get('readers')}")
        print(f"[+] Lecteur sélectionné   : {initial_status.get('selected_reader')}")
        print(f"[+] Carte présente        : {'Oui' if initial_status.get('card_present') else 'Non (déposez la carte)'}\n")
    else:
        print(f"[!] Aucun lecteur PC/SC détecté pour le moment (branchez votre lecteur USB).\n")

    server_address = (AGENT_HOST, AGENT_PORT)
    httpd = ThreadedHTTPServer(server_address, CNIBEAgentHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Arrêt de l'agent CNIBE.")
        httpd.server_close()


if __name__ == "__main__":
    run_agent()
