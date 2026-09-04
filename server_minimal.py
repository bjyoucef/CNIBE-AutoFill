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


# Cache et registres des jetons IDCard connus pour le Ministère
KNOWN_ID_CARDS = {}

def get_known_id_cards():
    """Charge les jetons IDCard cryptographiques découverts dans les fichiers du projet."""
    global KNOWN_ID_CARDS
    if KNOWN_ID_CARDS:
        return KNOWN_ID_CARDS
    import re
    search_files = ["site ali.md", "ste de minister AKLI.md", "ste de minister.md"]
    for fn in search_files:
        if os.path.exists(fn):
            try:
                with open(fn, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                m_card = re.search(r'IDCard\s*:\s*"([^"]+)"', content)
                m_num = re.search(r'NUM_CARTE\s*:\s*"([^"]+)"', content)
                if m_card and m_num:
                    num = m_num.group(1).strip()
                    card = m_card.group(1).strip()
                    KNOWN_ID_CARDS[num] = card
            except Exception:
                pass
    return KNOWN_ID_CARDS


def fetch_ministere_data(document_number: str, id_card: str = None):
    """
    Interroge le service officiel du Ministère de l'Intérieur algérien :
    https://macnibe.interieur.gov.dz/WFReadCardFr.aspx/GET_IDCardControl
    Retourne les 18 champs officiels dont l'adresse exacte (index 9) et la situation familiale.
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
                "adresse": parts[9].strip(),  # Adresse officielle (ex: "شارع الخير أمبارك دواودة")
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
        print(f"[MINISTÈRE API ERREUR] {e}", file=sys.stderr)
        return None


@app.route('/api/minister_lookup', methods=['POST'])
def minister_lookup():
    """
    Endpoint pour interroger le Ministère de l'Intérieur algérien (macnibe.interieur.gov.dz).
    Permet d'extraire l'adresse officielle de rue, la situation familiale et le conjoint.
    """
    try:
        req_data = request.get_json() or {}
        doc_num = str(req_data.get("document_number", "")).strip()
        id_card = req_data.get("id_card", "").strip() or None

        if not doc_num:
            return jsonify({"status": "ERROR", "message": "Numéro de document requis"}), 400

        data = fetch_ministere_data(doc_num, id_card)
        if not data:
            return jsonify({
                "status": "NOT_FOUND",
                "message": "Données non disponibles sur le serveur du Ministère ou carte non répertoriée."
            }), 404

        return jsonify({
            "status": "SUCCESS",
            "ministere": data
        }), 200

    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500


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
        dg12 = card_data.get("dg12_document", {})
        photo = card_data.get("photo", {})
        sig = card_data.get("signature", {})
        ministere = card_data.get("ministere_data") or {}

        doc_num = dg1.get("document_number", "INCONNU")
        nom_lat = ministere.get("nom_latin") or (dg11.get("nom", {}) or {}).get("latin", dg1.get("nom_latin", ""))
        prenom_lat = ministere.get("prenom_latin") or (dg11.get("prenoms", {}) or {}).get("latin", dg1.get("prenoms_latin", ""))
        nom_ar = ministere.get("nom_arabe") or (dg11.get("nom", {}) or {}).get("arabe", "")
        prenom_ar = ministere.get("prenom_arabe") or (dg11.get("prenoms", {}) or {}).get("arabe", "")
        nin = ministere.get("nin") or dg11.get("nin", "")

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

        photo_desc = photo.get("filename") or ("Oui" if photo.get("base64") else "Non")
        sig_desc = sig.get("filename") or ("Oui" if sig.get("base64") else "Non")

        print("\n" + "=" * 70)
        print("📥 [SERVEUR FLASK] NOUVELLE CARTE CNIBE REÇUE DEPUIS LE LAN !")
        print("=" * 70)
        print(f"  - Client IP          : {request.remote_addr}")
        print(f"  - N° Document        : {doc_num}")
        print(f"  - NIN                : {nin}")
        print(f"  - Nom & Prénom       : {nom_lat} {prenom_lat} ({nom_ar} {prenom_ar})")
        print(f"  - Date Naissance     : {dg1.get('date_of_birth', '')}")
        print(f"  - Adresse            : {adresse or 'Non renseignée'} ({source_adresse})")
        print(f"  - Situation Famille  : {situation or 'Non renseignée'}")
        print(f"  - Photo Biométrique  : {photo_desc}")
        print(f"  - Signature          : {sig_desc}")
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
            "adresse": adresse or "",
            "source_adresse": source_adresse,
            "situation_familiale": situation or "",
            "conjoint": conjoint or "",
            "has_photo": bool(photo.get("base64")),
            "photo_filename": photo.get("filename", ""),
            "signature_filename": sig.get("filename", ""),
            "full_data": card_data
        }

        save_record(summary_entry)

        return jsonify({
            "status": "SAVED",
            "message": "Données enregistrées avec succès sur le serveur Flask",
            "document_number": doc_num,
            "adresse": adresse,
            "source_adresse": source_adresse
        }), 200

    except Exception as e:
        print(f"[SERVEUR ERREUR] {e}", file=sys.stderr)
        return jsonify({"status": "ERROR", "message": str(e)}), 500


@app.route('/api/history', methods=['GET'])
def history():
    """Retourne la liste des cartes enregistrées sur le serveur."""
    records = load_saved_records()
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
            "adresse": r.get("adresse", ""),
            "source_adresse": r.get("source_adresse", "PUCE_LOCALE"),
            "situation_familiale": r.get("situation_familiale", ""),
            "conjoint": r.get("conjoint", ""),
            "has_photo": r.get("has_photo"),
            "photo_filename": r.get("photo_filename", ""),
            "signature_filename": r.get("signature_filename", "")
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
