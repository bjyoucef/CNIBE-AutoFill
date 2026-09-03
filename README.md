# CNIBE Reader - Lecteur NFC Ultra-Sécurisé pour Cartes d'Identité Biométriques (eMRTD)

Script Python autonome conforme aux normes internationales **ICAO Doc 9303 Part 11** et **ISO 7816-4** pour la lecture sécurisée des cartes d'identité biométriques (CNIBE) via un lecteur PC/SC sans contact (NFC).

---

## 🛡️ Architecture de Sécurité Anti-Blocage

Le script intègre un **garde-fou passif** strict (`PassiveSafetyGuard`) pour protéger la puce de la carte :
1. **Zéro Écriture** : Aucune commande modifiante (`0xD6 UPDATE BINARY`, `0xD0 WRITE BINARY`, `0x0E ERASE BINARY`). Seules les commandes de lecture passive sont autorisées (`0xA4 SELECT FILE`, `0x84 GET CHALLENGE`, `0x82 EXTERNAL AUTHENTICATE`, `0xB0 READ BINARY`).
2. **Zéro PIN** : Aucune commande `0x20 VERIFY PIN` n'est présente dans le code.
3. **Tentative BAC unique** : Si la carte retourne un code d'erreur (`SW=6300`, `SW=6982` ou tout code différent de `9000`), le script déclenche un **arrêt d'urgence immédiat sans retry**, évitant de décrémenter le compteur d'essais de la puce.
4. **Vecteur d'Initialisation Nul (IV)** : Pour le chiffrement 3DES-CBC en Secure Messaging selon ICAO Doc 9303 Part 11 / ISO 11568-2, le vecteur d'initialisation est obligatoirement `b"\x00" * 8`.
5. **Compteur de Séquence (SSC)** : Initialisé selon `RND.ICC[4:8] || RND.IFD[4:8]` et incrémenté de `1` avant chaque commande émise et avant chaque déballage de réponse.

---

## 📋 Prérequis & Installation

- Python 3.10, 3.11 ou supérieur avec les modules `pyscard` et `pycryptodome` :
```bash
py -3.11 -m pip install -r requirements.txt
```
- Lecteur NFC PC/SC branché (ex: *Identiv uTrust 4701 F CL Reader*). Le script sélectionne automatiquement le canal Contactless (NFC).

---

## 🚀 Utilisation

### 1. Commande standard (avec dates AAMMJJ)
```bash
py -3.11 read_cnibe_safe.py --doc 100689622 --dob 780908 --doe 260420
```

### 2. Formats de dates alternatifs (JJ/MM/AAAA ou AAAA-MM-JJ)
```bash
py -3.11 read_cnibe_safe.py --doc 100689622 --dob 08/09/1978 --doe 20/04/2026
```

### 3. Options disponibles
- `--photo <fichier.jpg>` : Chemin d'enregistrement de la photo extraite (par défaut : `photo.jpg`).
- `--output <resultat.json>` : Enregistrement du résultat JSON dans un fichier.
- `--wait <secondes>` : Temps d'attente max de la présentation de la carte (défaut : 15 secondes).
- `--reader <nom>` : Spécifier manuellement un lecteur (optionnel, détection auto par défaut).
- `--test-vectors` : Exécuter la suite de tests mathématiques officiels ICAO Doc 9303 Appendix D.

---

## 📂 Données Extraites

| Fichier LDS | Contenu extrait |
|---|---|
| **EF.COM** | Version LDS et liste des Data Groups présents (`DG1`, `DG2`, `DG11`...) |
| **EF.DG1** | MRZ TD1 (3 lignes x 30 car.) : N° Document, Date Naissance, Date Expiration, Sexe, Nationalité, Nom et Prénoms latins |
| **EF.DG2** | Photo biométrique faciale complète (détection JPEG / JPEG2000, enregistrée dans `photo.jpg`) |
| **EF.DG11** | Détails personnels étendus avec décodage **ISO-8859-6** pour l'arabe :<br>• `0x5F0E` : Nom (Latin & Arabe)<br>• `0x5F0F` : Prénom (Latin & Arabe)<br>• `0x5F10` : NIN (18 chiffres)<br>• `0x5F11` : Lieu de naissance (Latin & Arabe)<br>• `0x5F42` : Sexe & Groupe Sanguin |
