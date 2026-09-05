# 🌐 CNIBE - Guide de Déploiement & Administration (Serveur Web)

Ce dossier contient l'application web centralisée (Flask) accessible par les postes clients via le réseau local d'entreprise (LAN) ou en local.

---

## 📦 Contenu du Dossier `serveur/`

- **`server_minimal.py`** : Application Flask principale (écoute sur `0.0.0.0:5000`).
- **`templates/index.html`** : Interface utilisateur Web moderne (affichage temps réel de l'agent client, formulaire d'identité, photo d'identité et signature manuscrite numérisée).
- **`requirements.txt`** : Dépendances Python nécessaires (`Flask`, `requests`).
- **`lancer_serveur.bat`** : Fichier lanceur 1-clic pour démarrer le serveur sous Windows.

---

## ⚙️ Prérequis

1. **Python 3.10 ou 3.11** installé sur la machine serveur.
2. Port **5000 (TCP)** ouvert dans le pare-feu Windows pour autoriser les connexions entrantes des postes clients du réseau LAN.

---

## 🚀 Installation Rapide

Dans ce dossier `serveur/`, ouvrez un terminal et tapez :

```powershell
py -3.11 -m pip install -r requirements.txt
```

*(Note : le fichier `lancer_serveur.bat` installe automatiquement Flask s'il n'est pas déjà présent).*

---

## ▶️ Démarrage du Serveur

Double-cliquez sur **`lancer_serveur.bat`**.

La console s'affiche et indique :
- L'adresse d'accès locale : `http://127.0.0.1:5000`
- L'adresse d'accès réseau LAN pour les clients : `http://192.168.x.x:5000`

Les utilisateurs sur leurs postes clients ouvrent simplement cette adresse LAN dans leur navigateur web (Google Chrome, Edge, Firefox).

---

## 🛡️ Fonctionnement avec les Postes Clients

1. Le client navigue sur l'URL du serveur Flask (`http://192.168.x.x:5000`).
2. Le navigateur du client communique en direct avec son agent local (`http://127.0.0.1:5001`) pour lire la puce NFC de la carte insérée sur son propre lecteur USB.
3. Les données extraites (texte, photo, signature) sont ensuite transmises en mémoire par le navigateur au serveur Flask (`/api/save_card`) sans conservation de fichier physique sur le disque pour garantir la confidentialité.
