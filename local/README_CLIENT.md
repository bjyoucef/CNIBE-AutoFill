# 🖥️ CNIBE - Guide d'Installation & Utilisation (Poste Client)

Ce dossier contient les fichiers nécessaires pour faire fonctionner le lecteur de carte d'identité biométrique (NFC) sur le **poste de travail de l'utilisateur (client)**.

---

## 📦 Contenu du Dossier `local/`

- **`cnibe_agent.py`** : Agent local HTTP (`http://127.0.0.1:5001`) qui assure 100% de la collecte : lecture de la puce NFC, génération du jeton officiel et consultation directe du Ministère de l'Intérieur pour l'adresse certifiée.
- **`read_cnibe_safe.py`** : Moteur cryptographique conforme aux normes ICAO Doc 9303 Part 11 (lecture passive sécurisée sans altération de la puce).
- **`get_card_token.ps1`** : Script PowerShell 32-bit pour la communication avec le composant officiel de la carte (ActiveX).
- **`tokens_cache.json`** : Cache local des jetons d'authentification pour des consultations instantanées.
- **`uid.py`** : Script de test rapide pour vérifier la détection matérielle du lecteur et le numéro de série (CSN/UID) de la carte.
- **`requirements.txt`** : Dépendances Python nécessaires (`pyscard`, `pycryptodome`).
- **`lancer_agent.bat`** : Fichier lanceur pour démarrer l'agent d'un simple double-clic.

---

## ⚙️ Prérequis Matériel & Logiciel

1. **Lecteur NFC PC/SC USB** branché sur l'ordinateur (ex: *Identiv uTrust 4701 F*, *ACS ACR122U*, ou équivalent).
2. **Pilote du lecteur installé** et service Windows *Carte à puce* (`SCardSvr`) actif.
3. **Python 3.10 ou 3.11** installé sur Windows (avec l'option *"Add Python to PATH"* cochée).

---

## 🚀 Installation Rapide (1ère fois)

Ouvrez un terminal dans ce dossier `local/` et exécutez :

```powershell
py -3.11 -m pip install -r requirements.txt
```

*(Note : le fichier `lancer_agent.bat` installe automatiquement ces dépendances s'il détecte qu'elles manquent).*

---

## ▶️ Démarrage Quotidien

1. Branchez votre lecteur NFC USB.
2. Double-cliquez sur **`lancer_agent.bat`**.
3. Une fenêtre noire s'affiche confirmant :
   ```
   🛡️ CNIBE LOCAL CLIENT AGENT
   [*] Démarrage de l'agent sur http://127.0.0.1:5001
   [+] Lecteur sélectionné : Identiv uTrust 4701 F CL Reader
   ```
4. **Laissez cette fenêtre ouverte en arrière-plan pendant votre travail.**
5. Ouvrez votre navigateur et accédez à l'adresse de l'application web fournie par votre administrateur (ex: `http://192.168.1.50:5000` ou `http://127.0.0.1:5000`).

---

## 🔍 Test de Diagnostic Rapide

Pour vérifier que le lecteur et la carte sont bien reconnus sans lancer l'agent :
```powershell
py -3.11 uid.py
```
Ce script doit afficher le nom de votre lecteur et l'UID de la carte dès que celle-ci est posée dessus.
