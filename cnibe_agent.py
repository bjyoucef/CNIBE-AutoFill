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
        else:
            self._send_json(404, {"status": "ERROR", "message": "Route introuvable"})

    def _handle_status(self):
        """Retourne l'état sans perturber le lecteur."""
        status_data = get_passive_pcsc_status()
        self._send_json(200, status_data)

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
            wait_sec = int(payload.get("wait", 15))

            if not doc or not dob or not doe:
                self._send_json(400, {
                    "status": "ERROR",
                    "message": "Les champs 'doc', 'dob' et 'doe' sont obligatoires pour l'authentification BAC."
                })
                return

            print(f"\n[AGENT] Demande de scan reçue : Doc={doc}, DoB={dob}, DoE={doe}...")

            # Exécution de la lecture sécurisée
            card_data = read_cnibe_card(
                doc=doc,
                dob=dob,
                doe=doe,
                wait_seconds=wait_sec,
                include_base64=True
            )

            print(f"[AGENT] Scan réussi avec succès pour Doc={doc} !")
            photo_fn = card_data.get("photo", {}).get("filename", "")
            sig_fn = card_data.get("signature", {}).get("filename", "")
            if photo_fn or sig_fn:
                print(f"[AGENT] Fichiers sauvegardés : Photo={photo_fn or 'N/A'}, Signature={sig_fn or 'N/A'}")

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
