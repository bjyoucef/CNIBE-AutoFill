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

app = Flask(__name__, template_folder="templates")

STORAGE_FILE = "test_saved_cards.json"


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


def load_saved_records():
    """Charge l'historique des cartes sauvegardées."""
    if not os.path.exists(STORAGE_FILE):
        return []
    try:
        with open(STORAGE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def save_record(record_data):
    """Enregistre une nouvelle carte dans le fichier local."""
    records = load_saved_records()
    records.insert(0, record_data)
    # Garder au max les 100 dernières cartes
    records = records[:100]
    with open(STORAGE_FILE, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)


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
    Réception et enregistrement d'une carte CNIBE envoyée par le navigateur client.
    """
    try:
        card_data = request.get_json()
        if not card_data:
            return jsonify({"status": "ERROR", "message": "Aucune donnée JSON reçue"}), 400

        dg1 = card_data.get("dg1_mrz", {})
        dg11 = card_data.get("dg11_personnel", {})
        photo = card_data.get("photo", {})

        doc_num = dg1.get("document_number", "INCONNU")
        nom_lat = (dg11.get("nom", {}) or {}).get("latin", dg1.get("nom_latin", ""))
        prenom_lat = (dg11.get("prenoms", {}) or {}).get("latin", dg1.get("prenoms_latin", ""))
        nom_ar = (dg11.get("nom", {}) or {}).get("arabe", "")
        prenom_ar = (dg11.get("prenoms", {}) or {}).get("arabe", "")
        nin = dg11.get("nin", "")

        print("\n" + "=" * 70)
        print("📥 [SERVEUR FLASK] NOUVELLE CARTE CNIBE REÇUE DEPUIS LE LAN !")
        print("=" * 70)
        print(f"  - Client IP        : {request.remote_addr}")
        print(f"  - N° Document      : {doc_num}")
        print(f"  - NIN              : {nin}")
        print(f"  - Nom & Prénom     : {nom_lat} {prenom_lat} ({nom_ar} {prenom_ar})")
        print(f"  - Date Naissance   : {dg1.get('date_of_birth', '')}")
        print(f"  - Photo Biométrique: {'Oui' if photo.get('base64') else 'Non'}")
        print("=" * 70 + "\n")

        # Résumé pour l'historique
        summary_entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "client_ip": request.remote_addr,
            "document_number": doc_num,
            "nin": nin,
            "nom_latin": nom_lat,
            "prenom_latin": prenom_lat,
            "nom_arabe": nom_ar,
            "prenom_arabe": prenom_ar,
            "date_naissance": dg1.get("date_of_birth", ""),
            "has_photo": bool(photo.get("base64")),
            "full_data": card_data
        }

        save_record(summary_entry)

        return jsonify({
            "status": "SAVED",
            "message": "Données enregistrées avec succès sur le serveur Flask",
            "document_number": doc_num
        }), 200

    except Exception as e:
        print(f"[SERVEUR ERREUR] {e}", file=sys.stderr)
        return jsonify({"status": "ERROR", "message": str(e)}), 500


@app.route('/api/history', methods=['GET'])
def history():
    """Retourne la liste des cartes enregistrées sur le serveur."""
    records = load_saved_records()
    # Retourne les champs principaux sans le payload brut lourd
    summaries = []
    for r in records:
        summaries.append({
            "timestamp": r.get("timestamp"),
            "document_number": r.get("document_number"),
            "nin": r.get("nin"),
            "nom_latin": r.get("nom_latin"),
            "prenom_latin": r.get("prenom_latin"),
            "nom_arabe": r.get("nom_arabe"),
            "prenom_arabe": r.get("prenom_arabe"),
            "date_naissance": r.get("date_naissance"),
            "has_photo": r.get("has_photo")
        })
    return jsonify(summaries)


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
