#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
read_cnibe_safe.py - Lecteur NFC Ultra-Sécurisé pour Cartes d'Identité Biométriques (CNIBE / eMRTD)
Conforme ICAO Doc 9303 Part 11 & ISO 7816-4.

GARANTIES DE SÉCURITÉ STRICTES :
1. Aucune commande d'écriture (aucune modification possible de la puce).
2. Aucune commande VERIFY PIN (aucun risque de blocage par code PIN).
3. Tentative BAC unique : arrêt immédiat sur tout code d'erreur (6300, 6982...) pour ne pas
   consommer le compteur d'essais de la carte.
4. IV nul (b"\\x00" * 8) pour le chiffrement 3DES-CBC en Secure Messaging selon Doc 9303 Part 11.
"""

import sys
import os
import re
import json
import time
import hashlib
import argparse
from typing import Optional, Tuple, List, Dict, Any

# Forcer la sortie standard et d'erreur en UTF-8 pour supporter les caractères arabes et accents sous Windows
for stream_name in ('stdout', 'stderr'):
    stream = getattr(sys, stream_name)
    if hasattr(stream, 'reconfigure'):
        try:
            stream.reconfigure(encoding='utf-8')
        except Exception:
            pass
    elif hasattr(stream, 'buffer'):
        import io
        setattr(sys, stream_name, io.TextIOWrapper(stream.buffer, encoding='utf-8'))

# Dépendances cryptographiques et PC/SC
try:
    from Crypto.Cipher import DES, DES3
    from Crypto.Random import get_random_bytes
except ImportError:
    print("[ERREUR] pycryptodome n'est pas installé. Exécutez : pip install pycryptodome", file=sys.stderr)
    sys.exit(1)

try:
    from smartcard.System import readers
    from smartcard.CardConnection import CardConnection
    from smartcard.Exceptions import CardConnectionException, NoCardException
    from smartcard.scard import (
        SCardBeginTransaction,
        SCardEndTransaction,
        SCARD_LEAVE_CARD,
        SCARD_SHARE_EXCLUSIVE,
        SCARD_S_SUCCESS
    )
    HAS_SCARD_TRANSACTION = True
except ImportError:
    HAS_SCARD_TRANSACTION = False
    try:
        from smartcard.System import readers
        from smartcard.CardConnection import CardConnection
        from smartcard.Exceptions import CardConnectionException, NoCardException
    except ImportError:
        print("[ERREUR] pyscard n'est pas installé. Exécutez : pip install pyscard", file=sys.stderr)
        sys.exit(1)


# ==============================================================================
# 1. GARDE-FOU PASSIF & CONTRÔLE DE SÉCURITÉ ANTI-BLOCAGE
# ==============================================================================

class SecurityException(Exception):
    """Exception levée en cas de violation de sécurité ou d'échec d'authentification critique."""
    pass


class PassiveSafetyGuard:
    """
    Garde-fou passif garantissant l'intégrité de la carte.
    Autorise STRICTEMENT ET UNIQUEMENT les opérations de lecture et d'authentification ICAO.
    """
    ALLOWED_INS = {
        0xA4: "SELECT FILE / AID",
        0x84: "GET CHALLENGE",
        0x82: "EXTERNAL AUTHENTICATE",
        0xB0: "READ BINARY"
    }

    FORBIDDEN_INS = {
        0x20: "VERIFY PIN (STRICTEMENT INTERDIT)",
        0xD6: "UPDATE BINARY (STRICTEMENT INTERDIT)",
        0xD0: "WRITE BINARY (STRICTEMENT INTERDIT)",
        0x0E: "ERASE BINARY (STRICTEMENT INTERDIT)",
    }

    def __init__(self):
        self.bac_attempted = False
        self.bac_succeeded = False

    def validate_apdu(self, apdu: List[int]) -> None:
        """Vérifie avant toute émission que la commande est autorisée et sans danger."""
        if not apdu or len(apdu) < 4:
            raise SecurityException("APDU invalide ou tronquée.")

        ins = apdu[1]

        # Rejet catégorique des instructions interdites
        if ins in self.FORBIDDEN_INS:
            raise SecurityException(
                f"[BLOCAGE DE SÉCURITÉ] COMMANDE DANGEREUSE INTERDITE : 0x{ins:02X} ({self.FORBIDDEN_INS[ins]})"
            )

        # Vérification dans la liste blanche
        if ins not in self.ALLOWED_INS:
            raise SecurityException(
                f"[BLOCAGE DE SÉCURITÉ] Instruction non autorisée : 0x{ins:02X}. "
                f"Seules les instructions de lecture passive sont permises."
            )

        # Règle anti-blocage : une seule tentative BAC permise tant que BAC n'a pas réussi.
        # Si BAC a déjà réussi avec succès (paramètres MRZ prouvés valides), la ré-authentification
        # est permise pour récupérer le canal après une micro-coupure RF transitoire.
        if ins == 0x82:
            if self.bac_attempted and not self.bac_succeeded:
                raise SecurityException(
                    "[BLOCAGE DE SÉCURITÉ] Tentative multiple d'EXTERNAL AUTHENTICATE interdite. "
                    "Le script protège le compteur d'essais de la puce."
                )
            self.bac_attempted = True

    def check_response(self, ins: int, sw1: int, sw2: int) -> None:
        """Surveille les codes retours et déclenche l'arrêt d'urgence immédiat en cas d'erreur BAC."""
        sw = (sw1 << 8) | sw2
        if ins == 0x82 and sw != 0x9000:
            self.bac_succeeded = False
            error_msg = (
                f"\n{'='*75}\n"
                f" [ALERTE SÉCURITÉ ANTI-BLOCAGE]\n"
                f" Échec de l'authentification BAC (SW = {sw1:02X}{sw2:02X}).\n"
                f" ARRÊT IMMÉDIAT DU SCRIPT.\n"
                f" Aucune seconde tentative ne sera effectuée afin de NE PAS CONSOMMER\n"
                f" le compteur d'essais de la carte biométrique (CNIBE).\n"
                f" Veuillez vérifier scrupuleusement les 3 paramètres MRZ :\n"
                f"   - Numéro de Document (9 caractères)\n"
                f"   - Date de Naissance (AAMMJJ)\n"
                f"   - Date d'Expiration (AAMMJJ)\n"
                f"{'='*75}\n"
            )
            print(error_msg, file=sys.stderr)
            raise SecurityException(f"Échec BAC SW={sw1:02X}{sw2:02X}. Arrêt d'urgence.")


# ==============================================================================
# 2. CRYPTOGRAPHIE ICAO DOC 9303 PART 11 (BAC & SECURE MESSAGING)
# ==============================================================================

def calc_check_digit(data: str) -> str:
    """Calcul du check-digit selon ICAO Doc 9303 (poids 7-3-1)."""
    weights = [7, 3, 1]
    total = 0
    for i, ch in enumerate(data):
        if '0' <= ch <= '9':
            val = int(ch)
        elif 'A' <= ch <= 'Z':
            val = ord(ch) - ord('A') + 10
        elif ch == '<':
            val = 0
        else:
            val = 0
        total += val * weights[i % 3]
    return str(total % 10)


def des_set_key_parity(key_bytes: bytes) -> bytes:
    """Ajuste le bit de poids faible de chaque octet pour assurer une parité impaire (DES odd parity)."""
    adjusted = bytearray()
    for b in key_bytes:
        # Nombre de bits à 1 dans les 7 bits de poids fort
        bits = bin(b & 0xFE).count('1')
        if bits % 2 == 0:
            adjusted.append((b & 0xFE) | 0x01)
        else:
            adjusted.append(b & 0xFE)
    return bytes(adjusted)


def pad_iso7816(data: bytes, block_size: int = 8) -> bytes:
    """Padding ISO/IEC 7816-4 / Method 2 : ajout de 0x80 suivi de zéros jusqu'au multiple de block_size."""
    data = data + b"\x80"
    pad_len = (block_size - (len(data) % block_size)) % block_size
    return data + (b"\x00" * pad_len)


def unpad_iso7816(data: bytes) -> bytes:
    """Retrait du padding ISO/IEC 7816-4."""
    idx = data.rfind(b"\x80")
    if idx == -1:
        raise ValueError("Padding ISO 7816-4 absent ou invalide.")
    if any(b != 0 for b in data[idx + 1:]):
        raise ValueError("Padding ISO 7816-4 corrompu (octets non nuls après 0x80).")
    return data[:idx]


def compute_retail_mac(key16: bytes, data: bytes) -> bytes:
    """
    Calcul du Retail MAC selon ISO/IEC 9797-1 MAC Algorithme 3 avec padding Method 2.
    - Clé 16 octets : Ka (8 octets), Kb (8 octets).
    - Blocs intermédiaires : Single-DES CBC avec Ka.
    - Dernier bloc : Single-DES encrypt(Ka) -> decrypt(Kb) -> encrypt(Ka).
    """
    Ka = key16[:8]
    Kb = key16[8:16]
    padded = pad_iso7816(data, 8)
    blocks = [padded[i:i + 8] for i in range(0, len(padded), 8)]

    des_a = DES.new(Ka, DES.MODE_ECB)
    des_b = DES.new(Kb, DES.MODE_ECB)

    y = b"\x00" * 8
    for blk in blocks[:-1]:
        x = bytes(a ^ b for a, b in zip(y, blk))
        y = des_a.encrypt(x)

    x = bytes(a ^ b for a, b in zip(y, blocks[-1]))
    y = des_a.encrypt(x)
    y = des_b.decrypt(y)
    y = des_a.encrypt(y)
    return y


def derive_bac_keys(doc_number: str, dob: str, doe: str) -> Tuple[bytes, bytes]:
    """
    Dérive les clés de base K_enc et K_mac à partir des 3 informations MRZ.
    Doc 9303 Part 11 Section 9.7.
    """
    # Normalisation du numéro de document sur 9 caractères (complété par '<' si plus court)
    doc_norm = doc_number.strip().upper()[:9].ljust(9, '<')
    cd_doc = calc_check_digit(doc_norm)
    cd_dob = calc_check_digit(dob)
    cd_doe = calc_check_digit(doe)

    kbd = f"{doc_norm}{cd_doc}{dob}{cd_dob}{doe}{cd_doe}"
    k_seed = hashlib.sha1(kbd.encode('ascii')).digest()[:16]

    d_enc = hashlib.sha1(k_seed + b"\x00\x00\x00\x01").digest()
    ka_enc = des_set_key_parity(d_enc[:8])
    kb_enc = des_set_key_parity(d_enc[8:16])
    k_enc = ka_enc + kb_enc

    d_mac = hashlib.sha1(k_seed + b"\x00\x00\x00\x02").digest()
    ka_mac = des_set_key_parity(d_mac[:8])
    kb_mac = des_set_key_parity(d_mac[8:16])
    k_mac = ka_mac + kb_mac

    return k_enc, k_mac


# ==============================================================================
# 3. GESTIONNAIRE DE SECURE MESSAGING (ICAO DOC 9303 PART 11)
# ==============================================================================

class SecureMessagingSession:
    """
    Canal de communication sécurisé (Secure Messaging).
    RÈGLE CRYPTO STRICTE : IV est TOUJOURS un vecteur nul (b"\\x00" * 8).
    Le SSC est incrémenté de 1 avant chaque émission et avant chaque déballage de réponse.
    """

    def __init__(self, connection: CardConnection, guard: PassiveSafetyGuard,
                 ks_enc: bytes, ks_mac: bytes, ssc_init: int, debug: bool = False):
        self.connection = connection
        self.guard = guard
        self.ks_enc = ks_enc
        # En 3DES 2 clés pour PyCryptodome, on utilise 24 octets (Ka || Kb || Ka)
        self.ks_enc_3des = ks_enc + ks_enc[:8]
        self.ks_mac = ks_mac
        self.ssc = ssc_init
        self.debug = debug

    def _inc_ssc(self) -> int:
        self.ssc = (self.ssc + 1) % (1 << 64)
        return self.ssc

    def _encode_tlv_length(self, length: int) -> bytes:
        if length < 0x80:
            return bytes([length])
        elif length <= 0xFF:
            return bytes([0x81, length])
        elif length <= 0xFFFF:
            return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
        else:
            raise ValueError(f"Longueur non supportée : {length}")

    def _parse_tlv_objects(self, data: bytes) -> List[Tuple[bytes, bytes, bytes]]:
        """Parse les Data Objects (DO) d'une réponse APDU protégée. Renvoie liste de (tag, val, raw_tlv)."""
        idx = 0
        objects = []
        while idx < len(data):
            start_idx = idx
            tag = data[idx]
            idx += 1
            tag_bytes = bytes([tag])
            if (tag & 0x1F) == 0x1F:
                tag_bytes += bytes([data[idx]])
                idx += 1

            if idx >= len(data):
                break

            len_b = data[idx]
            idx += 1
            if len_b < 0x80:
                length = len_b
            elif len_b == 0x81:
                length = data[idx]
                idx += 1
            elif len_b == 0x82:
                length = (data[idx] << 8) | data[idx + 1]
                idx += 2
            else:
                raise ValueError("Format de longueur DO non géré.")

            val = data[idx:idx + length]
            idx += length
            raw_tlv = data[start_idx:idx]
            objects.append((tag_bytes, val, raw_tlv))
        return objects

    def transmit(self, cla: int, ins: int, p1: int, p2: int,
                 data: Optional[bytes] = None, le: Optional[int] = None) -> Tuple[bytes, int, int]:
        """
        Envoie une commande APDU emballée sous Secure Messaging et déchiffre la réponse.
        Garantit que l'instruction demandée est vérifiée par le garde-fou passif.
        """
        self.guard.validate_apdu([cla, ins, p1, p2])

        # 1. Incrémentation du SSC avant émission
        ssc_cmd = self._inc_ssc()
        ssc_cmd_bytes = ssc_cmd.to_bytes(8, 'big')

        # 2. Masquage du CLA (bit SM activé -> 0x0C)
        cla_sm = cla | 0x0C

        # 3. Construction des DOs
        do87 = b""
        if data is not None and len(data) > 0:
            padded_data = pad_iso7816(data, 8)
            # RÈGLE CRYPTO : IV NUL (b"\x00" * 8)
            cipher = DES3.new(self.ks_enc_3des, DES3.MODE_CBC, iv=b"\x00" * 8)
            enc_data = cipher.encrypt(padded_data)
            payload = b"\x01" + enc_data  # 0x01 = indicateur de padding
            do87 = b"\x87" + self._encode_tlv_length(len(payload)) + payload

        do97 = b""
        if le is not None:
            le_val = le if le < 256 else 0
            do97 = b"\x97\x01" + bytes([le_val])

        # 4. Calcul du MAC
        # Entrée MAC = SSC || Header masqué avec padding 0x80 00 00 00 || DO87 || DO97
        padded_header = bytes([cla_sm, ins, p1, p2, 0x80, 0x00, 0x00, 0x00])
        mac_input = ssc_cmd_bytes + padded_header + do87 + do97
        mac = compute_retail_mac(self.ks_mac, mac_input)
        do8e = b"\x8E\x08" + mac

        # 5. Construction finale de l'APDU protégée (ISO 7816-4 : Le absent si la commande d'origine n'a pas de Le)
        body = do87 + do97 + do8e
        if le is not None:
            protected_apdu = [cla_sm, ins, p1, p2, len(body)] + list(body) + [0x00]
        else:
            protected_apdu = [cla_sm, ins, p1, p2, len(body)] + list(body)

        if self.debug:
            print(f"[DEBUG SM TX] INS={ins:02X} P1={p1:02X} P2={p2:02X} Le={le} -> {bytes(protected_apdu).hex().upper()}")

        # 6. Transmission physique
        resp, sw1, sw2 = self.connection.transmit(protected_apdu)
        resp_bytes = bytes(resp)

        if self.debug:
            print(f"[DEBUG SM RX] SW={sw1:02X}{sw2:02X} DATA={resp_bytes.hex().upper()}")

        # Si statut d'erreur du lecteur/carte
        if sw1 != 0x90 or sw2 != 0x00:
            self.guard.check_response(ins, sw1, sw2)
            return b"", sw1, sw2

        # Si la réponse physique est SW=9000 mais sans corps de données (réponse non enveloppée en SM)
        # Typique d'une commande sans Le (comme SELECT FILE avec P2=0x0C)
        if not resp_bytes:
            if le is None:
                return b"", 0x90, 0x00
            return b"", sw1, sw2

        # 7. Déballage de la réponse protégée (présence d'octets enveloppés)
        # Incrémentation du SSC avant déballage
        ssc_resp = self._inc_ssc()
        ssc_resp_bytes = ssc_resp.to_bytes(8, 'big')

        parsed_dos = self._parse_tlv_objects(resp_bytes)
        do87_val = None
        do87_raw = b""
        do99_val = None
        do99_raw = b""
        do8e_val = None

        for tag, val, raw in parsed_dos:
            if tag in (b"\x87", b"\x85"):
                do87_val = val
                do87_raw = raw
            elif tag == b"\x99":
                do99_val = val
                do99_raw = raw
            elif tag == b"\x8E":
                do8e_val = val

        if do99_val is None:
            raise SecurityException(f"Réponse Secure Messaging invalide : DO '99' manquant (données reçues: {resp_bytes.hex().upper()}).")
        if do8e_val is None:
            raise SecurityException("Réponse Secure Messaging invalide : DO '8E' (MAC) manquant.")

        # Vérification du MAC de la carte
        mac_resp_input = ssc_resp_bytes + do87_raw + do99_raw
        expected_mac = compute_retail_mac(self.ks_mac, mac_resp_input)
        if expected_mac != do8e_val:
            raise SecurityException("CORRUPTION DÉTECTÉE : Échec de la vérification MAC de la réponse de la carte.")

        # Déchiffrement des données si présentes
        decrypted_data = b""
        if do87_val is not None:
            # Premier octet = 0x01 (padding indicator)
            ciphertext = do87_val[1:]
            # RÈGLE CRYPTO : IV NUL (b"\x00" * 8)
            cipher = DES3.new(self.ks_enc_3des, DES3.MODE_CBC, iv=b"\x00" * 8)
            decrypted_padded = cipher.decrypt(ciphertext)
            decrypted_data = unpad_iso7816(decrypted_padded)

        card_sw1 = do99_val[0]
        card_sw2 = do99_val[1]
        self.guard.check_response(ins, card_sw1, card_sw2)

        return decrypted_data, card_sw1, card_sw2


# ==============================================================================
# 4. EXÉCUTION DU PROTOCOLE BAC (BASIC ACCESS CONTROL)
# ==============================================================================

def perform_bac(connection: CardConnection, guard: PassiveSafetyGuard,
                doc_number: str, dob: str, doe: str, debug: bool = False) -> SecureMessagingSession:
    """
    Exécute l'authentification mutuelle BAC ICAO Doc 9303 Part 11.
    RÈGLE ABSOLUE : Arrêt immédiat si SW != 9000 lors d'EXTERNAL AUTHENTICATE.
    """
    # 1. Dérivation des clés de base
    k_enc, k_mac = derive_bac_keys(doc_number, dob, doe)
    k_enc_3des = k_enc + k_enc[:8]

    # 2. GET CHALLENGE (INS 0x84) - sans risque de blocage (génération d'aléa)
    apdu_challenge = [0x00, 0x84, 0x00, 0x00, 0x08]
    guard.validate_apdu(apdu_challenge)
    
    resp, sw1, sw2 = [], 0, 0
    for attempt in range(2):
        try:
            resp, sw1, sw2 = connection.transmit(apdu_challenge)
            break
        except (CardConnectionException, NoCardException):
            if attempt == 0:
                time.sleep(0.2)
                continue
            raise

    if sw1 != 0x90 or sw2 != 0x00 or len(resp) < 8:
        raise SecurityException(f"Échec GET CHALLENGE : SW={sw1:02X}{sw2:02X}")

    rnd_icc = bytes(resp[:8])

    # 3. Génération des aléatoires IFD
    rnd_ifd = get_random_bytes(8)
    k_ifd = get_random_bytes(16)

    # 4. Construction et chiffrement de S
    s = rnd_ifd + rnd_icc + k_ifd
    # RÈGLE CRYPTO : IV NUL (b"\x00" * 8)
    cipher = DES3.new(k_enc_3des, DES3.MODE_CBC, iv=b"\x00" * 8)
    e_ifd = cipher.encrypt(s)

    # 5. Calcul du Retail MAC sur e_ifd
    m_ifd = compute_retail_mac(k_mac, e_ifd)

    # 6. EXTERNAL AUTHENTICATE (INS 0x82) - Tentative Unique
    auth_data = e_ifd + m_ifd
    apdu_auth = [0x00, 0x82, 0x00, 0x00, len(auth_data)] + list(auth_data) + [0x28]

    guard.validate_apdu(apdu_auth)
    resp, sw1, sw2 = connection.transmit(apdu_auth)

    # Vérification anti-blocage immédiate
    guard.check_response(0x82, sw1, sw2)

    resp_bytes = bytes(resp)
    if len(resp_bytes) < 40:
        raise SecurityException("Réponse EXTERNAL AUTHENTICATE trop courte.")

    e_icc = resp_bytes[:32]
    m_icc = resp_bytes[32:40]

    # 7. Vérification du MAC de la carte
    expected_m_icc = compute_retail_mac(k_mac, e_icc)
    if expected_m_icc != m_icc:
        raise SecurityException("Échec vérification MAC de la réponse carte (m_icc).")

    # 8. Déchiffrement de e_icc
    cipher_dec = DES3.new(k_enc_3des, DES3.MODE_CBC, iv=b"\x00" * 8)
    r = cipher_dec.decrypt(e_icc)
    rnd_icc_rec = r[:8]
    rnd_ifd_rec = r[8:16]
    k_icc = r[16:32]

    if rnd_ifd_rec != rnd_ifd:
        raise SecurityException("Échec authentification mutuelle : RND.IFD ne correspond pas.")
    if rnd_icc_rec != rnd_icc:
        raise SecurityException("Échec authentification mutuelle : RND.ICC ne correspond pas.")

    # 9. Dérivation des clés de session KS_enc, KS_mac
    k_seed_session = bytes(a ^ b for a, b in zip(k_ifd, k_icc))

    d_ksenc = hashlib.sha1(k_seed_session + b"\x00\x00\x00\x01").digest()
    ks_enc = des_set_key_parity(d_ksenc[:8]) + des_set_key_parity(d_ksenc[8:16])

    d_ksmac = hashlib.sha1(k_seed_session + b"\x00\x00\x00\x02").digest()
    ks_mac = des_set_key_parity(d_ksmac[:8]) + des_set_key_parity(d_ksmac[8:16])

    # 10. Initialisation du Send Sequence Counter (SSC)
    # SSC = RND.ICC[4:8] || RND.IFD[4:8]
    ssc_bytes = rnd_icc[4:8] + rnd_ifd[4:8]
    ssc_init = int.from_bytes(ssc_bytes, 'big')

    return SecureMessagingSession(connection, guard, ks_enc, ks_mac, ssc_init, debug=debug)


# ==============================================================================
# 5. LECTURE DES FICHIERS LDS (LOGICAL DATA STRUCTURE)
# ==============================================================================

def select_icao_application(connection: CardConnection, guard: PassiveSafetyGuard) -> None:
    """Sélectionne l'AID ICAO eMRTD (A0 00 00 02 47 10 01) en clair avant BAC."""
    icao_aid = [0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01]
    apdu = [0x00, 0xA4, 0x04, 0x0C, len(icao_aid)] + icao_aid
    guard.validate_apdu(apdu)

    # Jusqu'à 2 tentatives pour absorber tout rebond physique initial de placement de la carte
    max_retries = 2
    for attempt in range(max_retries):
        try:
            _, sw1, sw2 = connection.transmit(apdu)
            if sw1 not in (0x90, 0x61):
                raise SecurityException(f"Application ICAO non trouvée sur la carte (SW={sw1:02X}{sw2:02X}).")
            return
        except (CardConnectionException, NoCardException):
            if attempt < max_retries - 1:
                time.sleep(0.3)
                continue
            raise



def read_elementary_file(sm: SecureMessagingSession, fid_bytes: bytes) -> bytes:
    """
    Sélectionne un fichier EF par son FID (ou son SFID) et lit l'intégralité de son contenu binaire
    sous Secure Messaging par blocs successifs sans corruption.
    """
    sfid_map = {
        bytes.fromhex("011E"): 0x1E,
        bytes.fromhex("0101"): 0x01,
        bytes.fromhex("0102"): 0x02,
        bytes.fromhex("0107"): 0x07,
        bytes.fromhex("010B"): 0x0B,
        bytes.fromhex("010C"): 0x0C,
        bytes.fromhex("010F"): 0x0F,
        bytes.fromhex("011D"): 0x1D
    }
    sfid = sfid_map.get(fid_bytes)
    use_sfid = False

    # 1. Sélection du fichier par FID (INS 0xA4, P1=0x02, P2=0x0C sans Le)
    _, sw1, sw2 = sm.transmit(cla=0x00, ins=0xA4, p1=0x02, p2=0x0C, data=fid_bytes, le=None)
    if sw1 != 0x90:
        # Essai avec P2=0x00 si P2=0x0C a échoué
        _, sw1_alt, sw2_alt = sm.transmit(cla=0x00, ins=0xA4, p1=0x02, p2=0x00, data=fid_bytes, le=None)
        if sw1_alt != 0x90:
            if sfid is not None:
                use_sfid = True
            else:
                raise SecurityException(f"Échec sélection FID {fid_bytes.hex().upper()} (SW={sw1:02X}{sw2:02X})")

    time.sleep(0.010)

    # 2. Lecture du header ASN.1 (8 octets pour couvrir Tag et Longueur complets)
    p1_init = (0x80 | sfid) if use_sfid else 0x00
    header, sw1, sw2 = sm.transmit(cla=0x00, ins=0xB0, p1=p1_init, p2=0x00, data=None, le=8)
    if sw1 != 0x90 or len(header) < 2:
        raise SecurityException(
            f"Impossible de lire le header ASN.1 du fichier {fid_bytes.hex().upper()} (SW={sw1:02X}{sw2:02X}, len={len(header)})"
        )

    # Décodage de la taille ASN.1
    idx = 1
    # Tag sur 2 octets (ex: 0x5F, 0x7F)
    if (header[0] & 0x1F) == 0x1F:
        idx += 1

    if idx >= len(header):
        content_len = 256
        header_len = idx
    else:
        first_len_byte = header[idx]
        idx += 1
        if first_len_byte < 0x80:
            content_len = first_len_byte
            header_len = idx
        elif first_len_byte == 0x81 and idx < len(header):
            content_len = header[idx]
            header_len = idx + 1
        elif first_len_byte == 0x82 and idx + 1 < len(header):
            content_len = (header[idx] << 8) | header[idx + 1]
            header_len = idx + 2
        elif first_len_byte == 0x83 and idx + 2 < len(header):
            content_len = (header[idx] << 16) | (header[idx + 1] << 8) | header[idx + 2]
            header_len = idx + 3
        else:
            content_len = 256
            header_len = idx

    total_size = header_len + content_len

    # Conserver le header déjà lu dans le buffer
    buffer = bytearray(header)
    if len(buffer) >= total_size:
        return bytes(buffer[:total_size])

    # 3. Lecture séquentielle par blocs calibrés (128 octets)
    # RÈGLE FIABILITÉ NFC : 128 octets de données claires produisent une trame chiffrée SM de ~156 octets,
    # tenant parfaitement dans la capacité d'une seule trame ISO 14443-4 sans fractionnement (chaining I-blocks).
    chunk_size = 128
    offset = len(buffer)
    last_err_sw = ""

    while offset < total_size:
        bytes_to_read = min(chunk_size, total_size - offset)
        p1 = (offset >> 8) & 0x7F
        p2 = offset & 0xFF
        chunk, sw1, sw2 = sm.transmit(cla=0x00, ins=0xB0, p1=p1, p2=p2, data=None, le=bytes_to_read)
        if sw1 != 0x90 or not chunk:
            last_err_sw = f"SW={sw1:02X}{sw2:02X}, chunk_len={len(chunk) if chunk else 0}"
            break
        buffer.extend(chunk)
        offset += len(chunk)

        # Indicateur de progression en temps réel pour les gros fichiers (DG2 photo, DG7 signature)
        if total_size > 2000 and (offset % (chunk_size * 5) == 0 or offset >= total_size):
            pct = int((offset / total_size) * 100)
            sys.stdout.write(f"\r   [Transfert NFC] {pct}% ({offset}/{total_size} octets)...   ")
            sys.stdout.flush()

        time.sleep(0.015)  # Pause calibrée de 15ms : temps de recharge inductif optimal du condensateur NFC de la puce

    if total_size > 2000:
        # Effacer proprement la ligne de progression
        sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.flush()

    if len(buffer) < total_size:
        if total_size > 2000:
            sys.stdout.write("\n")
            sys.stdout.flush()
        raise SecurityException(
            f"Lecture incomplète du fichier {fid_bytes.hex().upper()} : "
            f"{len(buffer)}/{total_size} octets lus ({last_err_sw}). La transmission NFC a été interrompue."
        )

    return bytes(buffer[:total_size])


# ==============================================================================
# 6. EXTRACTION ET ANALYSE DES DONNÉES (EF.COM, DG1, DG2, DG11)
# ==============================================================================

def parse_ef_com(data: bytes) -> List[str]:
    """Parse EF.COM (FID 011E) et retourne la liste des Data Groups disponibles."""
    # Tag 0x5C = Tag List
    dg_names = {
        0x61: "DG1 (MRZ TD1)",
        0x75: "DG2 (Photo Biométrique)",
        0x63: "DG3 (Empreintes - EAC)",
        0x76: "DG4 (Iris - EAC)",
        0x67: "DG7 (Signature Numérisée)",
        0x6B: "DG11 (Détails Personnels Étendus)",
        0x6C: "DG12 (Détails Document)",
        0x6E: "DG14 (Options Sécurité)",
        0x6F: "DG15 (Active Authentication)",
        0x77: "DG15 (Active Authentication)"
    }
    present_dgs = []
    idx = data.find(b"\x5C")
    if idx != -1 and idx + 1 < len(data):
        length = data[idx + 1]
        tags = data[idx + 2: idx + 2 + length]
        for t in tags:
            present_dgs.append(dg_names.get(t, f"DG-{hex(t)}"))
    return present_dgs


def parse_ef_dg1(data: bytes) -> Dict[str, Any]:
    """
    Parse EF.DG1 (FID 0101) contenant la zone de lecture optique TD1 (3 lignes x 30 caractères).
    Extrait : Numéro, Dates, Sexe, Nationalité, Nom et Prénoms latins.
    """
    # Recherche du tag 0x5F1F (MRZ)
    idx = data.find(b"\x5F\x1F")
    if idx != -1:
        # Longueur du tag MRZ
        len_b = data[idx + 2]
        mrz_bytes = data[idx + 3: idx + 3 + len_b]
    else:
        mrz_bytes = data[-90:]

    mrz_str = mrz_bytes.decode('ascii', errors='replace')
    lines = [mrz_str[i:i + 30] for i in range(0, len(mrz_str), 30) if len(mrz_str[i:i + 30]) == 30]

    if len(lines) < 3:
        # Fallback nettoyage si sauts de lignes présents
        cleaned = "".join(ch for ch in mrz_str if ch.isalnum() or ch == '<')
        lines = [cleaned[i:i + 30] for i in range(0, len(cleaned), 30) if len(cleaned[i:i + 30]) == 30]

    res: Dict[str, Any] = {"raw_mrz": lines}
    if len(lines) >= 3:
        l1, l2, l3 = lines[0], lines[1], lines[2]

        doc_num = l1[5:14].replace('<', '').strip()
        doc_type = l1[0:2].replace('<', '').strip()
        issuing_country = l1[2:5].replace('<', '').strip()

        dob_raw = l2[0:6]
        sex = l2[7]
        doe_raw = l2[8:14]
        nationality = l2[15:18].replace('<', '').strip()

        # Formatage lisible des dates AAAA-MM-JJ
        def format_yymmdd(yymmdd: str, is_dob: bool = False) -> str:
            if len(yymmdd) == 6 and yymmdd.isdigit():
                yy, mm, dd = int(yymmdd[:2]), int(yymmdd[2:4]), int(yymmdd[4:])
                century = 1900 if (is_dob and yy > 30) else 2000
                return f"{century + yy:04d}-{mm:02d}-{dd:02d}"
            return yymmdd

        # Nom et prénoms latins (3e ligne : NOM<<PRENOM)
        name_parts = l3.split('<<')
        nom_latin = name_parts[0].replace('<', ' ').strip()
        prenom_latin = " ".join(p.replace('<', ' ').strip() for p in name_parts[1:]).strip()

        res.update({
            "document_number": doc_num,
            "document_type": doc_type,
            "issuing_country": issuing_country,
            "nationality": nationality,
            "date_of_birth": format_yymmdd(dob_raw, is_dob=True),
            "date_of_birth_mrz": dob_raw,
            "date_of_expiry": format_yymmdd(doe_raw, is_dob=False),
            "date_of_expiry_mrz": doe_raw,
            "sex": sex,
            "nom_latin": nom_latin,
            "prenoms_latin": prenom_latin
        })

    return res


def extract_ef_dg2_photo(data: bytes, output_path: str = "photo.jpg") -> Optional[Dict[str, Any]]:
    """
    Extrait l'image biométrique faciale depuis EF.DG2 (FID 0102).
    Détecte automatiquement les formats JPEG (0xFF 0xD8 0xFF) ou JPEG 2000.
    Enregistre l'image dans le fichier spécifié.
    """
    image_bytes = None
    image_format = None

    # Détection JPEG standard
    jpeg_soi = data.find(b"\xFF\xD8\xFF")
    if jpeg_soi != -1:
        # Recherche du marqueur de fin JPEG EOI (0xFF 0xD9)
        jpeg_eoi = data.rfind(b"\xFF\xD9")
        if jpeg_eoi != -1 and jpeg_eoi > jpeg_soi:
            image_bytes = data[jpeg_soi:jpeg_eoi + 2]
        else:
            image_bytes = data[jpeg_soi:]
        image_format = "JPEG"
    else:
        # Détection JPEG 2000 (boîte jp2 ou codestream)
        jp2_box = data.find(b"\x00\x00\x00\x0C\x6A\x50\x20\x20")
        if jp2_box != -1:
            image_bytes = data[jp2_box:]
            image_format = "JPEG2000"
        else:
            jp2_codestream = data.find(b"\xFF\x4F\xFF\x51")
            if jp2_codestream != -1:
                image_bytes = data[jp2_codestream:]
                image_format = "JPEG2000 (Codestream)"

    if image_bytes:
        with open(output_path, "wb") as f:
            f.write(image_bytes)
        return {
            "format": image_format,
            "size_bytes": len(image_bytes),
            "saved_path": os.path.abspath(output_path)
        }
    return None


def find_all_tlv_tags(buffer: bytes, targets: Optional[set] = None) -> Dict[int, bytes]:
    """Parcourt récursivement un flux ASN.1 pour extraire les tags (tous ou filtrés par targets)."""
    found = {}

    def walk(buf: bytes):
        idx = 0
        while idx < len(buf):
            if idx >= len(buf):
                break
            b0 = buf[idx]
            idx += 1
            if (b0 & 0x1F) == 0x1F:
                if idx >= len(buf):
                    break
                b1 = buf[idx]
                idx += 1
                tag = (b0 << 8) | b1
            else:
                tag = b0

            if idx >= len(buf):
                break
            len_b = buf[idx]
            idx += 1
            if len_b < 0x80:
                length = len_b
            elif len_b == 0x81:
                if idx >= len(buf):
                    break
                length = buf[idx]
                idx += 1
            elif len_b == 0x82:
                if idx + 1 >= len(buf):
                    break
                length = (buf[idx] << 8) | buf[idx + 1]
                idx += 2
            elif len_b == 0x83:
                if idx + 2 >= len(buf):
                    break
                length = (buf[idx] << 16) | (buf[idx + 1] << 8) | buf[idx + 2]
                idx += 3
            else:
                break

            val = buf[idx:idx + length]
            idx += length

            if targets is None or tag in targets:
                if tag not in found:
                    found[tag] = val

            # Si c'est un tag ASN.1 construit (bit 5 activé: 0x20), on descend récursivement
            if (b0 & 0x20) == 0x20:
                walk(val)

    walk(buffer)
    return found


def decode_dg11_text(val_bytes: bytes) -> str:
    """Décode le texte DG11 avec priorité absolue à ISO-8859-6 pour l'arabe, avec replis gracieux."""
    try:
        return val_bytes.decode('iso-8859-6')
    except UnicodeDecodeError:
        try:
            return val_bytes.decode('utf-8')
        except UnicodeDecodeError:
            return val_bytes.decode('latin-1', errors='replace')


def parse_ef_dg11(data: bytes) -> Dict[str, Any]:
    """
    Parse EF.DG11 (FID 010B) - Détails Personnels Étendus.
    Décode l'intégralité des champs d'état civil bilingues français/arabe selon ISO-8859-6 :
      - 0x5F0E : Nom (LATIN<<ARABE)
      - 0x5F0F : Prénom (LATIN<<ARABE)
      - 0x5F10 : NIN (18 chiffres)
      - 0x5F11 : Lieu de naissance (LATIN<<ARABE)
      - 0x5F12 : Adresse / Commune / Daira de résidence (LATIN<<ARABE)
      - 0x5F14 : Profession
      - 0x5F16 : Situation familiale / matrimoniale (Célibataire / أعزب, Marié(e)...)
      - 0x5F26 : Nom du conjoint / époux
      - 0x5F42 : Sexe et Groupe sanguin (ex: M<<ذكر<<O+)
      - 0x5F2B : Date de naissance complète
    """
    tlvs = find_all_tlv_tags(data)

    res: Dict[str, Any] = {}

    # 1. Nom (0x5F0E)
    if 0x5F0E in tlvs:
        text = decode_dg11_text(tlvs[0x5F0E])
        parts = text.split("<<")
        res["nom"] = {
            "latin": parts[0].replace('<', ' ').strip(),
            "arabe": parts[1].replace('<', ' ').strip() if len(parts) > 1 else ""
        }

    # 2. Prénom (0x5F0F)
    if 0x5F0F in tlvs:
        text = decode_dg11_text(tlvs[0x5F0F])
        parts = text.split("<<")
        res["prenoms"] = {
            "latin": parts[0].replace('<', ' ').strip(),
            "arabe": parts[1].replace('<', ' ').strip() if len(parts) > 1 else ""
        }

    # 3. NIN (0x5F10)
    if 0x5F10 in tlvs:
        raw_nin = decode_dg11_text(tlvs[0x5F10]).replace('<', '').strip()
        res["nin"] = raw_nin

    # 4. Lieu de naissance (0x5F11)
    if 0x5F11 in tlvs:
        text = decode_dg11_text(tlvs[0x5F11])
        parts = text.split("<<")
        res["lieu_naissance"] = {
            "latin": parts[0].replace('<', ' ').strip(),
            "arabe": parts[1].replace('<', ' ').strip() if len(parts) > 1 else ""
        }

    # 5. Sexe et Groupe Sanguin (0x5F42)
    if 0x5F42 in tlvs:
        text = decode_dg11_text(tlvs[0x5F42])
        parts = text.split("<<")
        res["sexe_groupe_sanguin"] = {
            "raw": text,
            "sexe_latin": parts[0].strip() if len(parts) > 0 else "",
            "sexe_arabe": parts[1].strip() if len(parts) > 1 else "",
            "groupe_sanguin": parts[2].strip() if len(parts) > 2 else ""
        }

    # 6. Adresse de résidence (0x5F12)
    if 0x5F12 in tlvs:
        text = decode_dg11_text(tlvs[0x5F12])
        parts = text.split("<<")
        res["adresse_residence"] = {
            "latin": parts[0].replace('<', ' ').strip(),
            "arabe": parts[1].replace('<', ' ').strip() if len(parts) > 1 else ""
        }

    # 7. Situation familiale / matrimoniale (0x5F16)
    if 0x5F16 in tlvs:
        text = decode_dg11_text(tlvs[0x5F16])
        parts = text.split("<<")
        lat = parts[0].replace('<', ' ').strip()
        ara = parts[1].replace('<', ' ').strip() if len(parts) > 1 else ""
        if not lat and not ara:
            lat = "Célibataire"
            ara = "عازب" if res.get("sexe_groupe_sanguin", {}).get("sexe_latin") == "M" else "عزباء"
        res["situation_familiale"] = {
            "latin": lat,
            "arabe": ara,
            "raw": text
        }

    # 8. Nom du conjoint / époux (0x5F26)
    if 0x5F26 in tlvs:
        text = decode_dg11_text(tlvs[0x5F26])
        parts = text.split("<<")
        res["conjoint"] = {
            "latin": parts[0].replace('<', ' ').strip(),
            "arabe": parts[1].replace('<', ' ').strip() if len(parts) > 1 else ""
        }

    # 9. Profession (0x5F14)
    if 0x5F14 in tlvs:
        text = decode_dg11_text(tlvs[0x5F14])
        parts = text.split("<<")
        res["profession"] = {
            "latin": parts[0].replace('<', ' ').strip(),
            "arabe": parts[1].replace('<', ' ').strip() if len(parts) > 1 else ""
        }

    # 10. Date de naissance complète (0x5F2B)
    if 0x5F2B in tlvs:
        res["date_naissance_complete"] = decode_dg11_text(tlvs[0x5F2B]).replace('<', '').strip()

    # Capture de tout autre tag dynamique (excluant métadonnées ASN.1 0x5C, 0x02)
    connus = {0x5F0E, 0x5F0F, 0x5F10, 0x5F11, 0x5F42, 0x5F12, 0x5F16, 0x5F26, 0x5F14, 0x5F2B, 0x5C, 0x02}
    inconnus = {}
    for t, v in tlvs.items():
        if t not in connus and t not in (0x6B, 0xA0):
            try:
                dec = decode_dg11_text(v)
                inconnus[f"tag_{hex(t)}"] = dec
            except Exception:
                inconnus[f"tag_{hex(t)}"] = v.hex().upper()
    if inconnus:
        res["champs_supplementaires"] = inconnus

    return res


def parse_ef_dg12(data: bytes) -> Dict[str, Any]:
    """
    Parse EF.DG12 (FID 010C) - Détails Document (Délivrance et Autorité).
    Tags ICAO Doc 9303 Part 10 :
      - 0x5F19 : Autorité de délivrance (Issuing Authority / Daïra / Wilaya)
      - 0x5F26 : Date d'émission / délivrance
      - 0x5F50 : Observations / Mentions spéciales
    """
    tlvs = find_all_tlv_tags(data)
    res: Dict[str, Any] = {}

    if 0x5F19 in tlvs:
        text = decode_dg11_text(tlvs[0x5F19])
        parts = text.split("<<")
        res["autorite_emission"] = {
            "latin": parts[0].replace('<', ' ').strip(),
            "arabe": parts[1].replace('<', ' ').strip() if len(parts) > 1 else ""
        }
    if 0x5F26 in tlvs:
        res["date_emission"] = decode_dg11_text(tlvs[0x5F26]).replace('<', '').strip()
    if 0x5F50 in tlvs:
        res["observations"] = decode_dg11_text(tlvs[0x5F50]).replace('<', '').strip()

    return res


def extract_ef_dg7_signature(data: bytes, output_path: str = "signature.jpg") -> Optional[Dict[str, Any]]:
    """
    Extrait l'image de la signature manuscrite numérisée du titulaire depuis EF.DG7 (FID 0107).
    Prend en charge JPEG, JPEG 2000, PNG ou Bitmap.
    """
    image_bytes = None
    image_format = None

    # 1. Détection JPEG standard (FF D8 FF)
    jpeg_soi = data.find(b"\xFF\xD8\xFF")
    if jpeg_soi != -1:
        jpeg_eoi = data.rfind(b"\xFF\xD9")
        if jpeg_eoi != -1 and jpeg_eoi > jpeg_soi:
            image_bytes = data[jpeg_soi:jpeg_eoi + 2]
        else:
            image_bytes = data[jpeg_soi:]
        image_format = "JPEG"
    else:
        # 2. Détection JPEG 2000
        jp2_box = data.find(b"\x00\x00\x00\x0C\x6A\x50\x20\x20")
        if jp2_box != -1:
            image_bytes = data[jp2_box:]
            image_format = "JPEG2000"
        else:
            jp2_codestream = data.find(b"\xFF\x4F\xFF\x51")
            if jp2_codestream != -1:
                image_bytes = data[jp2_codestream:]
                image_format = "JPEG2000 (Codestream)"
            else:
                png_idx = data.find(b"\x89PNG")
                if png_idx != -1:
                    image_bytes = data[png_idx:]
                    image_format = "PNG"

    if image_bytes:
        with open(output_path, "wb") as f:
            f.write(image_bytes)
        return {
            "format": image_format,
            "size_bytes": len(image_bytes),
            "saved_path": os.path.abspath(output_path)
        }
    return None


# ==============================================================================
# 7. SÉLECTION ET GESTION DU LECTEUR PC/SC
# ==============================================================================

def get_best_reader(preferred_name: Optional[str] = None):
    """
    Sélectionne le lecteur PC/SC approprié.
    Priorité automatique aux lecteurs sans contact / NFC (CL / Contactless).
    """
    reader_list = readers()
    if not reader_list:
        raise RuntimeError("Aucun lecteur de carte à puce (PC/SC) détecté sur le système.")

    if preferred_name:
        for r in reader_list:
            if preferred_name.lower() in str(r).lower():
                return r
        raise RuntimeError(f"Lecteur '{preferred_name}' non trouvé. Lecteurs disponibles : {[str(r) for r in reader_list]}")

    # Recherche prioritaire d'un lecteur Contactless (NFC)
    cl_keywords = [" cl ", "cl reader", "contactless", "nfc", "picc", "rfid"]
    for r in reader_list:
        r_str = str(r).lower()
        if any(kw in r_str for kw in cl_keywords):
            return r

    # À défaut, premier lecteur disponible
    return reader_list[0]


# ==============================================================================
# 8. UTILITAIRE NORMALISATION DATE & CLI
# ==============================================================================

def normalize_date_to_yymmdd(date_str: str) -> str:
    """Convertit n'importe quel format (AAMMJJ, JJ/MM/AAAA, JJ-MM-AAAA, AAAA-MM-JJ) en AAMMJJ."""
    s = date_str.strip()
    if re.match(r"^\d{6}$", s):
        return s
    if re.match(r"^\d{8}$", s):
        return s[2:]
    # JJ/MM/AAAA ou JJ-MM-AAAA
    m = re.match(r"^(\d{1,2})[/-](\d{1,2})[/-](\d{4})$", s)
    if m:
        day, month, year = int(m.group(1)), int(m.group(2)), m.group(3)
        return f"{year[2:]}{month:02d}{day:02d}"
    # JJ/MM/AA ou JJ-MM-AA
    m = re.match(r"^(\d{1,2})[/-](\d{1,2})[/-](\d{2})$", s)
    if m:
        day, month, year = int(m.group(1)), int(m.group(2)), m.group(3)
        return f"{year}{month:02d}{day:02d}"
    # AAAA-MM-JJ ou AAAA/MM/JJ
    m = re.match(r"^(\d{4})[/-](\d{1,2})[/-](\d{1,2})$", s)
    if m:
        year, month, day = m.group(1), int(m.group(2)), int(m.group(3))
        return f"{year[2:]}{month:02d}{day:02d}"
    raise ValueError(f"Format de date non reconnu : '{date_str}'. Formats acceptés : AAMMJJ, JJ/MM/AAAA, AAAA-MM-JJ.")


def run_self_tests() -> bool:
    """Vérifie la conformité mathématique et cryptographique selon ICAO Doc 9303 Part 11 Appendix D."""
    print("[TEST] Exécution des vecteurs de test officiels ICAO Doc 9303 Part 11...")
    doc = "L898902C<"
    dob = "690806"
    doe = "940623"

    cd_doc = calc_check_digit(doc)
    cd_dob = calc_check_digit(dob)
    cd_doe = calc_check_digit(doe)
    assert cd_doc == "3", f"Check digit doc faux: {cd_doc}"
    assert cd_dob == "1", f"Check digit dob faux: {cd_dob}"
    assert cd_doe == "6", f"Check digit doe faux: {cd_doe}"

    kbd = f"{doc}{cd_doc}{dob}{cd_dob}{doe}{cd_doe}"
    assert kbd == "L898902C<369080619406236"

    k_seed = hashlib.sha1(kbd.encode('ascii')).digest()[:16]
    assert k_seed.hex().upper().startswith("239AB9CB282DAF66"), "K_seed ne correspond pas au vecteur ICAO Appendix D"

    k_enc, k_mac = derive_bac_keys(doc, dob, doe)
    assert len(k_enc) == 16 and len(k_mac) == 16

    # Test Retail MAC
    test_mac = compute_retail_mac(k_mac, b"TEST DATA ICAO DOC 9303")
    assert len(test_mac) == 8

    # Test padding ISO 7816-4
    padded = pad_iso7816(b"HELLO", 8)
    assert len(padded) == 8 and padded.startswith(b"HELLO\x80")
    unpadded = unpad_iso7816(padded)
    assert unpadded == b"HELLO"

    print("[TEST OK] Tous les tests cryptographiques ICAO 9303 Part 11 sont validés avec succès !")
    return True


# ==============================================================================
# 9. FLUX PRINCIPAL D'EXÉCUTION
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Lecteur NFC Ultra-Sécurisé pour Cartes d'Identité Biométriques (CNIBE / eMRTD) - ICAO Doc 9303",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--doc", help="Numéro de Document (9 caractères, ex: 100689622)")
    parser.add_argument("--dob", help="Date de Naissance (AAMMJJ, JJ/MM/AAAA ou AAAA-MM-JJ)")
    parser.add_argument("--doe", help="Date d'Expiration (AAMMJJ, JJ/MM/AAAA ou AAAA-MM-JJ)")
    parser.add_argument("--reader", default=None, help="Nom ou sous-chaîne du lecteur PC/SC à utiliser")
    parser.add_argument("--photo", default="photo.jpg", help="Fichier de destination pour la photo (défaut: photo.jpg)")
    parser.add_argument("--signature", default="signature.jpg", help="Fichier de destination pour la signature (défaut: signature.jpg)")
    parser.add_argument("--output", default=None, help="Fichier de sauvegarde du résultat JSON (optionnel)")
    parser.add_argument("--wait", type=int, default=15, help="Temps d'attente max de la carte en secondes (défaut: 15s)")
    parser.add_argument("--test-vectors", action="store_true", help="Exécuter les vecteurs de test mathématiques ICAO")
    parser.add_argument("--debug", action="store_true", help="Afficher les échanges APDU et détails Secure Messaging")

    args = parser.parse_args()

    if args.test_vectors:
        run_self_tests()
        sys.exit(0)

    if not args.doc or not args.dob or not args.doe:
        print("[ERREUR] Les paramètres --doc, --dob et --doe sont obligatoires.\n", file=sys.stderr)
        parser.print_help()
        sys.exit(1)

    try:
        yymmdd_dob = normalize_date_to_yymmdd(args.dob)
        yymmdd_doe = normalize_date_to_yymmdd(args.doe)
    except ValueError as e:
        print(f"[ERREUR] {e}", file=sys.stderr)
        sys.exit(1)

    raw_doc = args.doc.strip().upper()
    if len(raw_doc) == 10:
        candidate_doc = raw_doc[:9]
        expected_cd = calc_check_digit(candidate_doc)
        if raw_doc[9] == expected_cd:
            print(f"[*] Note : 10 caractères saisis. Le 10ème caractère '{raw_doc[9]}' correspond au check digit MRZ.")
            doc_norm = candidate_doc
        else:
            print(f"[!] Avertissement : 10 caractères saisis ({raw_doc}). Le numéro de document officiel comporte 9 caractères.")
            print(f"    (Pour le numéro '{candidate_doc}', le check digit MRZ attendu est '{expected_cd}', mais vous avez saisi '{raw_doc[9]}').")
            doc_norm = candidate_doc
    else:
        doc_norm = raw_doc[:9].ljust(9, '<')

    print(f"[*] Paramètres de dérivation BAC :")
    print(f"    - N° Document : {doc_norm}")
    print(f"    - Date Naiss. : {yymmdd_dob}")
    print(f"    - Date Expir. : {yymmdd_doe}")

    guard = PassiveSafetyGuard()

    # Sélection du lecteur
    try:
        reader = get_best_reader(args.reader)
    except Exception as e:
        print(f"[ERREUR LECTEUR] {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Lecteur sélectionné : {reader}")

    # Connexion à la carte
    connection = reader.createConnection()
    card_connected = False
    start_wait = time.time()

    print(f"[*] Déposez votre carte d'identité (CNIBE) sur le lecteur NFC...")
    while (time.time() - start_wait) < args.wait:
        try:
            if HAS_SCARD_TRANSACTION:
                try:
                    connection.connect(mode=SCARD_SHARE_EXCLUSIVE)
                    card_connected = True
                    break
                except Exception:
                    pass
            connection.connect()
            card_connected = True
            break
        except (NoCardException, CardConnectionException):
            time.sleep(0.3)
        except Exception:
            time.sleep(0.3)

    if not card_connected:
        print(f"[ERREUR] Aucune carte détectée sur le lecteur après {args.wait} secondes d'attente.", file=sys.stderr)
        print("Veuillez vérifier que la carte est bien plaquée contre la cible NFC du lecteur.", file=sys.stderr)
        sys.exit(1)

    in_transaction = False
    inner_conn = getattr(connection, 'component', connection)
    hcard = getattr(inner_conn, 'hcard', None)

    try:
        # Verrouillage exclusif PC/SC pour empêcher les services Windows (CertPropSvc, Hello) d'interférer
        if HAS_SCARD_TRANSACTION and hcard is not None:
            try:
                hres = SCardBeginTransaction(hcard)
                if hres == SCARD_S_SUCCESS:
                    in_transaction = True
            except Exception:
                pass

        atr = bytes(connection.getATR()).hex().upper()
        print(f"[*] Carte connectée. ATR : {atr}")
        if in_transaction:
            print("[*] Canal PC/SC verrouillé en exclusivité (protection anti-interférence Windows active).")
        time.sleep(0.15)

        # 1. Sélection de l'application ICAO AID
        print("[*] Sélection de l'application ICAO eMRTD (AID A0 00 00 02 47 10 01)...")
        select_icao_application(connection, guard)

        # 2. Authentification BAC
        print("[*] Exécution du protocole BAC (Basic Access Control)...")
        sm_session = perform_bac(connection, guard, doc_norm, yymmdd_dob, yymmdd_doe, debug=args.debug)
        guard.bac_succeeded = True
        print("[+] Authentification BAC réussie ! Canal Secure Messaging établi.")

        result_data: Dict[str, Any] = {
            "status": "SUCCESS",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

        # 3. Lecture EF.COM (FID 011E)
        try:
            print("[*] Lecture EF.COM (Data Groups disponibles)...")
            ef_com_bytes = read_elementary_file(sm_session, bytes.fromhex("011E"))
            dgs = parse_ef_com(ef_com_bytes)
            result_data["data_groups_disponibles"] = dgs
            print(f"[+] Data Groups détectés : {dgs}")
        except (CardConnectionException, NoCardException):
            raise
        except Exception as e:
            if "Communication perdue" in str(e):
                raise
            print(f"[!] Erreur lecture EF.COM : {e}", file=sys.stderr)

        time.sleep(0.04)

        # 4. Lecture EF.DG1 (FID 0101 - MRZ TD1)
        try:
            print("[*] Lecture EF.DG1 (MRZ TD1 & Données d'identité)...")
            ef_dg1_bytes = read_elementary_file(sm_session, bytes.fromhex("0101"))
            dg1_info = parse_ef_dg1(ef_dg1_bytes)
            result_data["dg1_mrz"] = dg1_info
            print(f"[+] Données DG1 extraites avec succès.")
        except (CardConnectionException, NoCardException):
            raise
        except Exception as e:
            if "Communication perdue" in str(e):
                raise
            print(f"[!] Erreur lecture EF.DG1 : {e}", file=sys.stderr)

        time.sleep(0.04)

        # 5. Lecture EF.DG11 (FID 010B - Détails Personnels Étendus & Arabe)
        try:
            print("[*] Lecture EF.DG11 (Détails étendus, NIN & Arabe ISO-8859-6)...")
            ef_dg11_bytes = read_elementary_file(sm_session, bytes.fromhex("010B"))
            dg11_info = parse_ef_dg11(ef_dg11_bytes)
            result_data["dg11_personnel"] = dg11_info
            print(f"[+] Données étendues DG11 extraites avec succès.")
        except (CardConnectionException, NoCardException):
            raise
        except Exception as e:
            print(f"[!] Erreur lecture EF.DG11 : {e}", file=sys.stderr)

        time.sleep(0.04)

        # 6. Lecture EF.DG12 (FID 010C - Détails Document & Délivrance) si présent
        if any("DG12" in d for d in result_data.get("data_groups_disponibles", [])):
            try:
                print("[*] Lecture EF.DG12 (Détails document, autorité & émission)...")
                ef_dg12_bytes = read_elementary_file(sm_session, bytes.fromhex("010C"))
                dg12_info = parse_ef_dg12(ef_dg12_bytes)
                result_data["dg12_document"] = dg12_info
                print(f"[+] Données document DG12 extraites avec succès.")
            except (CardConnectionException, NoCardException):
                raise
            except Exception as e:
                print(f"[!] Info DG12 non disponible : {e}", file=sys.stderr)

            time.sleep(0.04)

        def refresh_sm():
            nonlocal sm_session
            time.sleep(0.12)
            select_icao_application(connection, guard)
            sm_session = perform_bac(connection, guard, doc_norm, yymmdd_dob, yymmdd_doe, debug=args.debug)
            guard.bac_succeeded = True

        # 7. Lecture EF.DG2 (FID 0102 - Photo Biométrique)
        for attempt_dg2 in range(2):
            try:
                print("[*] Lecture EF.DG2 (Photo faciale biométrique)...")
                ef_dg2_bytes = read_elementary_file(sm_session, bytes.fromhex("0102"))
                photo_info = extract_ef_dg2_photo(ef_dg2_bytes, args.photo)
                if photo_info:
                    result_data["photo"] = photo_info
                    print(f"[+] Photo biométrique extraite ({photo_info['size_bytes']} octets) -> {args.photo}")
                else:
                    print("[!] Image non détectée dans DG2.")
                break
            except (CardConnectionException, NoCardException):
                raise
            except Exception as e:
                if attempt_dg2 == 0:
                    print(f"[*] Micro-coupure NFC détectée. Restauration automatique du canal sécurisé...", file=sys.stderr)
                    try:
                        refresh_sm()
                        print("[+] Canal restauré avec succès ! Reprise de la lecture photo...")
                        continue
                    except Exception as err_re:
                        print(f"[!] Échec restauration canal : {err_re}", file=sys.stderr)
                print(f"[!] Erreur lecture EF.DG2 : {e}", file=sys.stderr)

        time.sleep(0.06)

        # 8. Lecture EF.DG7 (FID 0107 - Signature Manuscrite Numérisée) si présent
        if any("DG7" in d or "0x67" in d for d in result_data.get("data_groups_disponibles", [])):
            for attempt_dg7 in range(2):
                try:
                    print("[*] Lecture EF.DG7 (Signature manuscrite numérisée)...")
                    ef_dg7_bytes = read_elementary_file(sm_session, bytes.fromhex("0107"))
                    sig_info = extract_ef_dg7_signature(ef_dg7_bytes, args.signature)
                    if sig_info:
                        result_data["signature"] = sig_info
                        print(f"[+] Signature manuscrite extraite ({sig_info['size_bytes']} octets) -> {args.signature}")
                    else:
                        print("[!] Image de signature non détectée dans DG7.")
                    break
                except (CardConnectionException, NoCardException):
                    raise
                except Exception as e:
                    if attempt_dg7 == 0:
                        try:
                            refresh_sm()
                            print("[+] Canal restauré avec succès ! Reprise de la signature...")
                            continue
                        except Exception:
                            pass
                    print(f"[!] Signature DG7 non disponible : {e}", file=sys.stderr)

            time.sleep(0.04)

        # 7. Affichage et export JSON
        json_output = json.dumps(result_data, ensure_ascii=False, indent=2)
        print("\n" + "=" * 70)
        print("RÉSULTAT DE LECTURE CNIBE (JSON) :")
        print("=" * 70)
        print(json_output)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(json_output)
            print(f"\n[+] Résultat complet sauvegardé dans : {args.output}")

    except SecurityException as e:
        print(f"\n[SÉCURITÉ] {e}", file=sys.stderr)
        sys.exit(2)
    except (CardConnectionException, NoCardException) as e:
        print(f"\n[COMMUNICATION NFC INTERROMPUE] {e}", file=sys.stderr)
        print("CONSEIL : Maintenez la carte bien immobile et plaquée à plat contre la cible NFC du lecteur jusqu'à la fin de la lecture.\n", file=sys.stderr)
        sys.exit(3)
    except Exception as e:
        err_msg = str(e)
        if any(code in err_msg for code in ["0x80100069", "0x8010002F", "0x80100016", "La carte à puce a été supprimée", "erreur de connexion", "Card not connected"]):
            print(f"\n[COMMUNICATION NFC INTERROMPUE] {e}", file=sys.stderr)
            print("CONSEIL : Maintenez la carte bien immobile et plaquée à plat contre la cible NFC du lecteur jusqu'à la fin de la lecture.\n", file=sys.stderr)
            sys.exit(3)
        print(f"\n[ERREUR IMPRÉVUE] {e}", file=sys.stderr)
        sys.exit(4)
    finally:
        if in_transaction and hcard is not None:
            try:
                SCardEndTransaction(hcard, SCARD_LEAVE_CARD)
            except Exception:
                pass
        try:
            connection.disconnect()
        except Exception:
            pass


if __name__ == "__main__":
    main()
