#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
server_minimal.py - Serveur Flask Minimal de Test pour CNIBE
Ce serveur s'exécute sur votre machine serveur (ou localement) sur le port 5000 (0.0.0.0:5000).
Il est accessible par tous les postes clients connectés au réseau local (LAN).
Il fournit l'interface web et enregistre les données de cartes scannées par les postes clients.
"""

import sys
import os
import json
import time
import socket
from flask import Flask, render_template, request, jsonify

# Assurer l'encodage UTF-8 sous Windows
for stream_name in ('stdout', 'stderr'):
    stream = getattr(sys, stream_name)
    if hasattr(stream, 'reconfigure'):
        try:
            stream.reconfigure(encoding='utf-8')
        except Exception:
            pass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "templates"))
app.config['TEMPLATES_AUTO_RELOAD'] = True



def get_local_ip() -> str:
    """Détecte l'adresse IP locale de la machine sur le réseau LAN."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Ne crée pas de vraie connexion, permet de déterminer l'interface de sortie LAN
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip




@app.route('/')
def index():
    """Page d'accueil de l'application CNIBE."""
    return render_template('index.html')


@app.route('/api/ping', methods=['GET'])
def ping():
    """Vérification de l'état du serveur Flask."""
    return jsonify({
        "status": "OK",
        "server": "CNIBE Flask Minimal Test Server",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    })


@app.route('/api/save_card', methods=['POST'])
def save_card():
    """
    Réception et enregistrement d'une carte CNIBE envoyée par le poste client.
    Toutes les données (Puce NFC, Photo, Signature, Données certifiées Ministère)
    ont été collectées de manière 100% autonome par le client local.
    """
    try:
        card_data = request.get_json()
        if not card_data:
            return jsonify({"status": "ERROR", "message": "Aucune donnée JSON reçue"}), 400

        dg1 = card_data.get("dg1_mrz", {})
        dg11 = card_data.get("dg11_personnel", {})
        dg12 = card_data.get("dg12_document", {})
        photo = card_data.get("photo", {})
        sig = card_data.get("signature", {})
        ministere = card_data.get("ministere_data") or {}

        doc_num = dg1.get("document_number", "INCONNU")
        dob = dg1.get("date_of_birth", "")
        doe = dg1.get("date_of_expiry", "")

        is_passport = bool(card_data.get("is_passport") or dg1.get("document_type", "").startswith("P") or "TD3" in dg1.get("format", ""))
        doc_kind = "PASSEPORT BIOMÉTRIQUE" if is_passport else "CARTE CNIBE"

        if is_passport:
            nom_lat = dg1.get("nom_latin") or ministere.get("nom_latin") or (dg11.get("nom", {}) or {}).get("latin", "")
            prenom_lat = dg1.get("prenoms_latin") or ministere.get("prenom_latin") or (dg11.get("prenoms", {}) or {}).get("latin", "")
        else:
            nom_lat = ministere.get("nom_latin") or (dg11.get("nom", {}) or {}).get("latin", dg1.get("nom_latin", ""))
            prenom_lat = ministere.get("prenom_latin") or (dg11.get("prenoms", {}) or {}).get("latin", dg1.get("prenoms_latin", ""))
        nom_ar = ministere.get("nom_arabe") or (dg11.get("nom", {}) or {}).get("arabe", "")
        prenom_ar = ministere.get("prenom_arabe") or (dg11.get("prenoms", {}) or {}).get("arabe", "")
        nin = dg11.get("nin") or ministere.get("nin", "")

        # Détermination de l'adresse (priorité Ministère, sinon puce DG11/DG12)
        adresse = ministere.get("adresse")
        source_adresse = "MINISTERE" if adresse else "PUCE_LOCALE"
        if not adresse:
            addr_dg11 = dg11.get("adresse_residence", {})
            if isinstance(addr_dg11, dict):
                adresse = f"{addr_dg11.get('arabe', '')} - {addr_dg11.get('latin', '')}".strip(" -")
            if not adresse:
                aut = dg12.get("autorite_emission", {})
                if isinstance(aut, dict):
                    adresse = f"{aut.get('arabe', '')} - {aut.get('latin', '')}".strip(" -")

        # Situation familiale & conjoint
        situation = ministere.get("situation_familiale")
        if not situation:
            sit = dg11.get("situation_familiale", {})
            situation = f"{sit.get('arabe', '')} / {sit.get('latin', '')}".strip(" /")

        conjoint = ministere.get("nom_epoux_arabe") or ministere.get("nom_epoux_latin")
        if not conjoint:
            cj = dg11.get("conjoint", {})
            conjoint = f"{cj.get('arabe', '')} {cj.get('latin', '')}".strip()

        has_photo = bool(photo.get("base64") or ministere.get("photo_base64"))
        has_sig = bool(sig.get("base64"))
        photo_desc = "Oui (Base64 mémoire)" if has_photo else "Non"
        sig_desc = "Oui (Base64 mémoire)" if has_sig else "Non"

        print("\n" + "=" * 70)
        print(f"📥 [SERVEUR FLASK] NOUVEAU {doc_kind} REÇU DEPUIS LE LAN !")
        print("=" * 70)
        print(f"  - Client IP          : {request.remote_addr}")
        print(f"  - Type Document      : {doc_kind} ({dg1.get('format', 'TD1/TD3')})")
        print(f"  - N° Document        : {doc_num}")
        print(f"  - Pays / Nationalité : {dg1.get('issuing_country', '')} / {dg1.get('nationality', '')}")
        print(f"  - Nom & Prénom       : {nom_lat} {prenom_lat}" + (f" ({nom_ar} {prenom_ar})" if (nom_ar or prenom_ar) else ""))
        print(f"  - Date Naissance     : {dg1.get('date_of_birth', '')}")
        print(f"  - Date Expiration    : {dg1.get('date_of_expiry', '')}")
        if not is_passport:
            print(f"  - NIN                : {nin}")
            print(f"  - Adresse            : {adresse or 'Non renseignée'} ({source_adresse})")
            print(f"  - Situation Famille  : {situation or 'Non renseignée'}")
        else:
            if nin:
                print(f"  - NIN                : {nin}")
            if dg1.get("optional_data"):
                print(f"  - Données Optionn.   : {dg1.get('optional_data')}")
            if dg12.get("autorite_emission"):
                aut = dg12.get("autorite_emission", {})
                aut_str = f"{aut.get('arabe', '')} - {aut.get('latin', '')}".strip(" -")
                if aut_str:
                    print(f"  - Autorité           : {aut_str}")
            if dg12.get("date_emission"):
                print(f"  - Date Délivrance    : {dg12.get('date_emission')}")
        print(f"  - Photo Biométrique  : {photo_desc}")
        print(f"  - Signature          : {sig_desc}")
        print("=" * 70 + "\n")

        return jsonify({
            "status": "SAVED",
            "message": f"{doc_kind} enregistré avec succès sur le serveur Flask",
            "document_number": doc_num,
            "is_passport": is_passport,
            "adresse": adresse,
            "source_adresse": source_adresse,
            "ministere": ministere
        }), 200

    except Exception as e:
        print(f"[SERVEUR ERREUR] {e}", file=sys.stderr)
        return jsonify({"status": "ERROR", "message": str(e)}), 500




if __name__ == '__main__':
    local_ip = get_local_ip()
    port = 5000

    print("=" * 70)
    print("🚀 SERVEUR FLASK TEST CNIBE DÉMARRÉ")
    print("=" * 70)
    print(f"[*] Accès local (sur ce PC)     : http://127.0.0.1:{port}")
    print(f"[*] Accès réseau LAN (autres PC): http://{local_ip}:{port}")
    print("=" * 70)
    print("[*] En attente des connexions du navigateur...")

    app.run(host='0.0.0.0', port=port, debug=False)
