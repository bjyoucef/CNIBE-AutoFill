# CNIBE & Passport Reader - Système Client / Serveur pour Titres d'Identité Biométriques (eMRTD)

Architecture client/serveur pour la lecture sans contact (NFC) et la centralisation des données de **Cartes d'Identité Biométriques (CNIBE TD1)** et de **Passeports Biométriques (TD3)** conformes aux normes internationales **ICAO Doc 9303 Part 11** et **ISO 7816-4**.

---

## 📁 Organisation du Projet

Le projet est structuré en modules indépendants et spécialisés :

```
CNIBE Reader/
│
├── 🖥️ local/                                # POSTE CLIENT (Opérateur avec lecteur USB)
│   ├── cnibe_agent.py                      # Passerelle locale HTTP (127.0.0.1:5001) : Puce NFC + Jeton + Ministère
│   ├── read_cnibe_safe.py                  # Moteur PC/SC passif sécurisé (ICAO BAC / ASN.1)
│   ├── get_card_token.ps1                  # Pont ActiveX 32-bit pour composant officiel
│   ├── tokens_cache.json                   # Cache local des jetons d'authentification
│   ├── uid.py                              # Outil diagnostic de détection du lecteur et carte
│   ├── requirements.txt                    # Dépendances (pyscard, pycryptodome)
│   ├── lancer_agent.bat                    # Lanceur 1-clic Windows pour le client
│   └── README_CLIENT.md                    # Guide d'installation sur poste client
│
├── 🌐 serveur/                              # SERVEUR WEB CENTRAL (Réseau LAN)
│   ├── server_minimal.py                   # Application Flask pure stockage/affichage (0.0.0.0:5000)
│   ├── templates/
│   │   └── index.html                      # Interface web (formulaire, photo, signature)
│   ├── requirements.txt                    # Dépendances serveur (Flask, requests)
│   ├── lancer_serveur.bat                  # Lanceur 1-clic Windows pour le serveur
│   └── README_SERVEUR.md                   # Guide d'administration et déploiement
│
├── 🛠️ .dev/                                 # OUTILS DE DÉVELOPPEMENT & DIAGNOSTIC
│   ├── inspect_endpoints.py                # Analyse des endpoints ministériels
│   ├── inspect_live_ministere.py           # Diagnostic réseau HTTP
│   └── README.md                           # Documentation des scripts de dev
│
├── .vscode/                                # Configurations VS Code (Launch & Settings)
└── .gitignore                              # Règles de protection des données sensibles
```

---

## 🌐 Fonctionnement Réseau

```
[ POSTE CLIENT (Opérateur) ]                       [ SERVEUR DISTANT (LAN) ]
  ├── Lecteur NFC USB (Identiv)                      └── Application Flask (0.0.0.0:5000)
  ├── Agent local (127.0.0.1:5001)                         (Traitement & affichage en mémoire)
  │     ├── 1. Lecture NFC puce (safe)
  │     ├── 2. Calcul Jeton (get_card_token.ps1)
  │     └── 3. Récupération adresse officielle
  │            (macnibe.interieur.gov.dz)
  │
  └── Navigateur Web (Chrome / Edge)
        │
        ├── A. Charge l'interface web ──────────────► [Serveur Flask:5000]
        ├── B. Demande de scan 127.0.0.1:5001/scan   (Collecte 100% autonome sur le PC Client)
        │
        └── C. Envoi du dossier complet ────────────► [POST /api/save_card -> Traitement centralisé]
```

---

## 🚀 Démarrage Rapide

### 1. Sur le Poste Client (où est branché le lecteur USB) :
1. Allez dans le dossier **`local/`**.
2. Double-cliquez sur **`lancer_agent.bat`**.
3. L'agent démarre et écoute sur `http://127.0.0.1:5001`.

### 2. Sur le Serveur Central :
1. Allez dans le dossier **`serveur/`**.
2. Double-cliquez sur **`lancer_serveur.bat`**.
3. Le serveur Flask démarre sur `0.0.0.0:5000` et affiche son adresse IP sur le LAN.

### 3. Utilisation :
L'opérateur ouvre son navigateur sur l'adresse du serveur (ex: `http://192.168.1.50:5000`), pose la carte sur son lecteur et clique sur **Lire la Carte (NFC)**. Les données sont extraites et enregistrées sur le serveur instantanément !
