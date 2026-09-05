#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
keyboard_wedge.py - Moteur d'émulation clavier et collage direct pour injection sous Windows.
Permet d'injecter des données (NIN, Noms, Prénoms, Dates, Adresses en Français et Arabe)
dans n'importe quel logiciel tiers actif (Word, Excel, logiciel médical, ERP, etc.)
avec navigation par touche Tabulation.
"""

import sys
import time
import ctypes
from ctypes import wintypes
from typing import List, Dict, Any, Optional, Callable

# Modules Windows natifs pour injection fiable
try:
    import win32api
    import win32con
    import win32clipboard
    HAS_PYWIN32 = True
except ImportError:
    HAS_PYWIN32 = False


# ==============================================================================
# 1. GESTION DU PRESSE-PAPIER & SIMULATION CLAVIER ROBUSTE
# ==============================================================================

def set_clipboard_text(text: str):
    """Place le texte dans le presse-papier Windows au format Unicode UTF-16."""
    if HAS_PYWIN32:
        try:
            win32clipboard.OpenClipboard()
            win32clipboard.EmptyClipboard()
            win32clipboard.SetClipboardText(text, win32clipboard.CF_UNICODETEXT)
            win32clipboard.CloseClipboard()
            return True
        except Exception as e:
            try:
                win32clipboard.CloseClipboard()
            except Exception:
                pass
            print(f"[!] Erreur presse-papier pywin32: {e}", file=sys.stderr)

    # Secours via ctypes direct
    try:
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        if not user32.OpenClipboard(0):
            return False
        user32.EmptyClipboard()
        text_utf16 = text.encode('utf-16-le') + b'\x00\x00'
        h_mem = kernel32.GlobalAlloc(0x0042, len(text_utf16))  # GMEM_MOVEABLE | GMEM_ZEROINIT
        if h_mem:
            p_mem = kernel32.GlobalLock(h_mem)
            ctypes.memmove(p_mem, text_utf16, len(text_utf16))
            kernel32.GlobalUnlock(h_mem)
            user32.SetClipboardData(13, h_mem)  # CF_UNICODETEXT = 13
        user32.CloseClipboard()
        return True
    except Exception as e:
        print(f"[!] Erreur presse-papier ctypes: {e}", file=sys.stderr)
        return False


def paste_clipboard():
    """Simule la combinaison de touches Ctrl+V pour coller instantanément dans le champ cible."""
    if HAS_PYWIN32:
        win32api.keybd_event(win32con.VK_CONTROL, 0, 0, 0)
        time.sleep(0.01)
        win32api.keybd_event(ord('V'), 0, 0, 0)
        time.sleep(0.02)
        win32api.keybd_event(ord('V'), 0, win32con.KEYEVENTF_KEYUP, 0)
        time.sleep(0.01)
        win32api.keybd_event(win32con.VK_CONTROL, 0, win32con.KEYEVENTF_KEYUP, 0)
    else:
        user32 = ctypes.windll.user32
        VK_CONTROL = 0x11
        VK_V = 0x56
        KEYEVENTF_KEYUP = 0x0002
        user32.keybd_event(VK_CONTROL, 0, 0, 0)
        time.sleep(0.01)
        user32.keybd_event(VK_V, 0, 0, 0)
        time.sleep(0.02)
        user32.keybd_event(VK_V, 0, KEYEVENTF_KEYUP, 0)
        time.sleep(0.01)
        user32.keybd_event(VK_CONTROL, 0, KEYEVENTF_KEYUP, 0)


def press_tab():
    """Simule l'appui sur la touche Tabulation (passage au champ suivant)."""
    if HAS_PYWIN32:
        win32api.keybd_event(win32con.VK_TAB, 0, 0, 0)
        time.sleep(0.02)
        win32api.keybd_event(win32con.VK_TAB, 0, win32con.KEYEVENTF_KEYUP, 0)
    else:
        user32 = ctypes.windll.user32
        VK_TAB = 0x09
        KEYEVENTF_KEYUP = 0x0002
        user32.keybd_event(VK_TAB, 0, 0, 0)
        time.sleep(0.02)
        user32.keybd_event(VK_TAB, 0, KEYEVENTF_KEYUP, 0)


def press_separator(separator_name: str = "TAB"):
    """Appuie sur la touche de séparation sélectionnée (TAB, ENTER, DOWN, NONE)."""
    sep = (separator_name or "").upper().strip()
    if sep in ("TAB", ""):
        press_tab()
    elif sep in ("ENTER", "ENTREE", "RETURN"):
        if HAS_PYWIN32:
            win32api.keybd_event(win32con.VK_RETURN, 0, 0, 0)
            time.sleep(0.02)
            win32api.keybd_event(win32con.VK_RETURN, 0, win32con.KEYEVENTF_KEYUP, 0)
        else:
            ctypes.windll.user32.keybd_event(0x0D, 0, 0, 0)
            time.sleep(0.02)
            ctypes.windll.user32.keybd_event(0x0D, 0, 0x0002, 0)
    elif sep == "DOWN":
        if HAS_PYWIN32:
            win32api.keybd_event(win32con.VK_DOWN, 0, win32con.KEYEVENTF_EXTENDEDKEY, 0)
            time.sleep(0.02)
            win32api.keybd_event(win32con.VK_DOWN, 0, win32con.KEYEVENTF_EXTENDEDKEY | win32con.KEYEVENTF_KEYUP, 0)
        else:
            ctypes.windll.user32.keybd_event(0x28, 0, 1, 0)
            time.sleep(0.02)
            ctypes.windll.user32.keybd_event(0x28, 0, 1 | 2, 0)
    elif sep in ("NONE", "AUCUN"):
        pass
    else:
        press_tab()


def press_char_key(char: str):
    """Simule la frappe d'une lettre (A-Z) ou d'une touche de contrôle pour naviguer dans une liste déroulante."""
    k = str(char).upper().strip()
    if k == "DOWN":
        press_separator("DOWN")
        return
    if k == "UP":
        if HAS_PYWIN32:
            win32api.keybd_event(win32con.VK_UP, 0, win32con.KEYEVENTF_EXTENDEDKEY, 0)
            time.sleep(0.02)
            win32api.keybd_event(win32con.VK_UP, 0, win32con.KEYEVENTF_EXTENDEDKEY | win32con.KEYEVENTF_KEYUP, 0)
        else:
            ctypes.windll.user32.keybd_event(0x26, 0, 1, 0)
            time.sleep(0.02)
            ctypes.windll.user32.keybd_event(0x26, 0, 1 | 2, 0)
        time.sleep(0.03)
        return

    if len(k) == 1 and k.isalnum():
        vk = ord(k)
        if HAS_PYWIN32:
            win32api.keybd_event(vk, 0, 0, 0)
            time.sleep(0.02)
            win32api.keybd_event(vk, 0, win32con.KEYEVENTF_KEYUP, 0)
        else:
            ctypes.windll.user32.keybd_event(vk, 0, 0, 0)
            time.sleep(0.02)
            ctypes.windll.user32.keybd_event(vk, 0, 2, 0)
        time.sleep(0.04)


SELECT_FIELD_IDS = {
    "civilite", "titre",
    "sexe", "sexe_texte", "sexe_complet", "sexe_latin",
    "situation", "situation_familiale", "situation_familiale_latin"
}


def select_combobox_item(field_id: str, value: str, card_data: Dict[str, Any]):
    """
    Sélectionne la valeur appropriée dans un menu déroulant (ComboBox / Select)
    selon la valeur extraite de la carte CNIBE.
    """
    fid = field_id.lower().strip()
    val_upper = str(value).upper().strip()

    # 1. Sexe : 'Non défini' (défaut), 'Masculin' (touche M), 'Féminin' (touche F)
    if fid in ("sexe", "sexe_texte", "sexe_complet", "sexe_latin"):
        if val_upper.startswith("F"):
            press_char_key("F")
        elif val_upper.startswith("M"):
            press_char_key("M")
        return

    # 2. Situation familiale : '-', 'Célibataire' (C), 'Marié(e)' (M), 'Divorcé(e)' (D), 'Veuf(ve)' (V)
    if fid in ("situation", "situation_familiale", "situation_familiale_latin"):
        if "MARI" in val_upper or "EPOUS" in val_upper:
            press_char_key("M")
        elif "DIVORC" in val_upper:
            press_char_key("D")
        elif "VEUF" in val_upper or "VEUVE" in val_upper:
            press_char_key("V")
        else:
            press_char_key("C")
        return

    # 3. Civilité : '', 'M', 'Mme', 'Mlle', 'Garçon', 'Fille', 'Nouveau-né(e)'
    if fid in ("civilite", "titre"):
        sexe = extract_field_value("sexe", card_data).upper()
        sit = extract_field_value("situation_familiale", card_data).upper()

        if sexe.startswith("F"):
            if "MARI" in sit or "EPOUS" in sit:
                # Mme : M puis flèche bas
                press_char_key("M")
                time.sleep(0.05)
                press_char_key("DOWN")
            else:
                # Mlle : M puis 2 fois flèche bas
                press_char_key("M")
                time.sleep(0.05)
                press_char_key("DOWN")
                time.sleep(0.05)
                press_char_key("DOWN")
        else:
            # M direct
            press_char_key("M")
        return

    # Autre select générique : frappe de la première lettre
    if value:
        c = value.strip()[0].upper()
        if c.isalnum():
            press_char_key(c)


# Définition SendInput 40 octets sous Windows 64-bit pour compatibilité
ULONG_PTR = ctypes.c_size_t

class MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ('dx', wintypes.LONG),
        ('dy', wintypes.LONG),
        ('mouseData', wintypes.DWORD),
        ('dwFlags', wintypes.DWORD),
        ('time', wintypes.DWORD),
        ('dwExtraInfo', ULONG_PTR),
    ]

class KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ('wVk', wintypes.WORD),
        ('wScan', wintypes.WORD),
        ('dwFlags', wintypes.DWORD),
        ('time', wintypes.DWORD),
        ('dwExtraInfo', ULONG_PTR),
    ]

class HARDWAREINPUT(ctypes.Structure):
    _fields_ = [
        ('uMsg', wintypes.DWORD),
        ('wParamL', wintypes.WORD),
        ('wParamH', wintypes.WORD),
    ]

class _INPUT_UNION(ctypes.Union):
    _fields_ = [
        ('mi', MOUSEINPUT),
        ('ki', KEYBDINPUT),
        ('hi', HARDWAREINPUT),
    ]

class INPUT(ctypes.Structure):
    _fields_ = [
        ('type', wintypes.DWORD),
        ('u', _INPUT_UNION),
    ]


def type_text_paste(text: str):
    """Injecte une valeur dans le champ actif via presse-papier Ctrl+V (support total Arabe/Français)."""
    if not text:
        return
    set_clipboard_text(text)
    time.sleep(0.02)
    paste_clipboard()


# Alias pour rétrocompatibilité
type_text = type_text_paste


# ==============================================================================
# 2. FORMATAGE DES VALEURS SELON LE PROFIL
# ==============================================================================

def format_date_value(raw_date: str, target_format: str = "DD/MM/YYYY") -> str:
    """
    Formate une date brute (YYYY-MM-DD, YYMMDD, DD/MM/YYYY) selon le format cible :
    - DD/MM/YYYY (ex: 15/01/1985)
    - YYYY-MM-DD (ex: 1985-01-15)
    - DD-MM-YYYY (ex: 15-01-1985)
    """
    if not raw_date:
        return ""
    d_str = str(raw_date).strip().replace('-', '/').replace('.', '/')
    parts = d_str.split('/')
    day, month, year = "", "", ""

    if len(parts) == 3:
        if len(parts[0]) == 4:  # YYYY/MM/DD
            year, month, day = parts[0], parts[1].zfill(2), parts[2].zfill(2)
        else:  # DD/MM/YYYY
            day, month, year = parts[0].zfill(2), parts[1].zfill(2), parts[2]
    elif len(raw_date.strip()) == 8 and raw_date.strip().isdigit():
        year = raw_date[:4]
        month = raw_date[4:6]
        day = raw_date[6:8]
    elif len(raw_date.strip()) == 6 and raw_date.strip().isdigit():
        yy = int(raw_date[:2])
        year = str(2000 + yy if yy < 50 else 1900 + yy)
        month = raw_date[2:4]
        day = raw_date[4:6]
    else:
        return raw_date

    target_upper = target_format.upper()
    if target_upper == "YYYY-MM-DD":
        return f"{year}-{month}-{day}"
    elif target_upper == "DD-MM-YYYY":
        return f"{day}-{month}-{year}"
    elif target_upper in ("DD/MM/YYYY", "DD.MM.YYYY"):
        return f"{day}/{month}/{year}"
    elif target_upper in ("YYYY/MM/DD", "YYYY.MM.DD"):
        return f"{year}/{month}/{day}"
    elif target_upper == "YYYYMMDD":
        return f"{year}{month}{day}"
    elif target_upper == "DDMMYYYY":
        return f"{day}{month}{year}"
    return f"{day}/{month}/{year}"


def extract_field_value(field_id: str, card_data: Dict[str, Any], date_format: str = "DD/MM/YYYY") -> str:
    """
    Extrait et normalise la valeur d'un champ depuis le dictionnaire résultant de la lecture CNIBE.
    Combine les données de DG1, DG11, DG12 et les données officielles du Ministère si disponibles.
    """
    dg1 = card_data.get("dg1_mrz", {})
    dg11 = card_data.get("dg11_personnel", {})
    dg12 = card_data.get("dg12_document", {})
    ministere = card_data.get("ministere_data") or {}

    fid = field_id.lower().strip()

    # 0. Sauts de champs (pour passer les champs non renseignés ou auto-calculés dans l'application cible)
    if fid in ("skip", "saut", "vide", "tab_only", "passer"):
        return ""

    # 1. Civilité
    elif fid in ("civilite", "titre"):
        s = extract_field_value("sexe", card_data).upper()
        sit = extract_field_value("situation_familiale", card_data).upper()
        if s == "M":
            return "M"
        elif s == "F":
            return "Mme" if ("MARI" in sit or "EPOUSE" in sit) else "Mlle"
        return "M"

    elif fid == "civilite_long":
        s = extract_field_value("sexe", card_data).upper()
        return "Monsieur" if s == "M" else "Madame"

    # 2. Numéro d'Identification National (NIN - 18 chiffres)
    elif fid in ("nin", "id_national", "national_id"):
        val = ministere.get("nin") or dg11.get("nin") or dg1.get("optional_data") or ""
        digits = "".join(c for c in str(val) if c.isdigit())
        return digits if len(digits) >= 18 else str(val).strip()

    # 3. Noms et Prénoms (Latin)
    elif fid in ("nom_latin", "nom", "last_name", "nom_fr"):
        return (ministere.get("nom_latin") or dg1.get("nom_latin") or dg11.get("nom_latin") or "").strip()

    elif fid in ("prenom_latin", "prenom", "prenoms_latin", "first_name", "prenom_fr"):
        return (ministere.get("prenom_latin") or dg1.get("prenoms_latin") or dg11.get("prenoms_latin") or "").strip()

    elif fid == "nom_complet_latin":
        nom = extract_field_value("nom_latin", card_data)
        prenom = extract_field_value("prenom_latin", card_data)
        return f"{nom} {prenom}".strip()

    # 4. Noms et Prénoms (Arabe)
    elif fid in ("nom_arabe", "last_name_ar"):
        return (ministere.get("nom_arabe") or dg11.get("nom_arabe") or "").strip()

    elif fid in ("prenom_arabe", "first_name_ar", "prenoms_arabe"):
        return (ministere.get("prenom_arabe") or dg11.get("prenoms_arabe") or "").strip()

    elif fid == "nom_complet_arabe":
        nom = extract_field_value("nom_arabe", card_data)
        prenom = extract_field_value("prenom_arabe", card_data)
        return f"{prenom} {nom}".strip()

    # 5. Date de Naissance et Expiration
    elif fid in ("date_naissance", "dob", "birth_date", "date_naiss"):
        raw = ministere.get("date_naissance") or dg1.get("date_of_birth") or ""
        return format_date_value(raw, date_format)

    elif fid in ("date_expiration", "doe", "expiry_date"):
        raw = dg1.get("date_of_expiry") or ""
        return format_date_value(raw, date_format)

    # 6. Sexe
    elif fid in ("sexe", "sexe_lettre", "sexe_latin", "sexe_initiale", "sex"):
        s = ministere.get("sexe_latin") or dg1.get("sex") or ""
        s = s.strip().upper()
        if s.startswith("M"):
            return "M"
        elif s.startswith("F"):
            return "F"
        return s

    elif fid in ("sexe_complet", "sexe_texte"):
        s = extract_field_value("sexe", card_data).upper()
        return "Masculin" if s == "M" else ("Féminin" if s == "F" else s)

    elif fid == "sexe_arabe":
        return ministere.get("sexe_arabe") or ("ذكر" if extract_field_value("sexe", card_data) == "M" else "أنثى")

    # 7. Groupe Sanguin
    elif fid in ("groupe_sanguin", "blood_group"):
        return ministere.get("groupe_sanguin") or ""

    # 8. Situation Familiale
    elif fid in ("situation_familiale", "situation_familiale_latin"):
        return ministere.get("situation_familiale_latin") or ministere.get("situation_familiale") or ""

    elif fid == "situation_familiale_arabe":
        return ministere.get("situation_familiale_arabe") or ""

    # 9. Adresse
    elif fid in ("adresse", "adresse_officielle"):
        return ministere.get("adresse") or ministere.get("adresse_officielle") or dg11.get("adresse") or ""

    # 10. Lieu de Naissance
    elif fid in ("lieu_naissance", "lieu_naissance_latin"):
        return ministere.get("lieu_naissance_latin") or dg11.get("lieu_naissance") or ""

    elif fid == "lieu_naissance_arabe":
        return ministere.get("lieu_naissance_arabe") or dg11.get("lieu_naissance_arabe") or ""

    # 11. Document / N° Carte ID (Format complet : Id: <N° Document> NIN: <NIN>)
    elif fid in ("num_carte_id", "carte_id", "no_carte_id", "n_carte_id", "carte_id_nin"):
        doc_num = (dg1.get("document_number") or card_data.get("doc") or "").strip()
        nin = extract_field_value("nin", card_data).strip()
        if doc_num and nin:
            return f"Id: {doc_num} NIN: {nin}"
        elif doc_num:
            return f"Id: {doc_num}"
        elif nin:
            return f"NIN: {nin}"
        return ""

    elif fid in ("num_document", "num_carte", "doc_number", "document_number"):
        return dg1.get("document_number") or card_data.get("doc") or ""

    elif fid == "nationalite":
        return dg1.get("nationality") or "DZA"

    return ""


# ==============================================================================
# 3. EXÉCUTEUR DE SÉQUENCE DE REMPLISSAGE (WEDGE RUNNER)
# ==============================================================================

def execute_autofill(
    card_data: Dict[str, Any],
    fields_config: List[Dict[str, Any]],
    separator: str = "TAB",
    delay_between_fields_ms: int = 130,
    date_format: str = "DD/MM/YYYY",
    on_field_typed: Optional[Callable[[int, str, str], None]] = None
) -> int:
    """
    Exécute la séquence de saisie/collage pour tous les champs activés dans le profil.
    Retourne le nombre total de champs traités.
    """
    delay_s = max(50, delay_between_fields_ms) / 1000.0
    count_typed = 0

    active_fields = [f for f in fields_config if f.get("enabled", True)]
    total = len(active_fields)

    print(f"\n[*] [AUTOFILL] Démarrage de l'injection ({total} champs configurés)...")

    for idx, f_cfg in enumerate(active_fields):
        f_id = f_cfg.get("id", "")
        f_label = f_cfg.get("label", f_id)
        f_date_fmt = f_cfg.get("format", date_format)

        val = extract_field_value(f_id, card_data, date_format=f_date_fmt)
        
        if on_field_typed:
            try:
                on_field_typed(idx, f_label, val)
            except Exception:
                pass

        is_select = (f_id.lower().strip() in SELECT_FIELD_IDS) or (f_cfg.get("type") == "select")

        if is_select and val:
            print(f"    -> [MENU DÉROULANT] Champ {idx+1}/{total} [{f_label}] : '{val}'")
            select_combobox_item(f_id, val, card_data)
            count_typed += 1
            time.sleep(0.06)
        elif val:
            # Champ texte standard ou date
            print(f"    -> Champ {idx+1}/{total} [{f_label}] : '{val}'")
            type_text_paste(val)
            count_typed += 1
            time.sleep(0.04)
        else:
            # Champ vide ou saut de champ
            print(f"    -> Saut de champ {idx+1}/{total} [{f_label}] (Tabulation)")
            count_typed += 1

        # Séparateur pour passer au champ suivant
        sep = f_cfg.get("separator", separator)
        if idx < total - 1 or f_cfg.get("final_separator", False):
            press_separator(sep)

        time.sleep(delay_s)

    print(f"[+] [AUTOFILL] Injection terminée avec succès ({count_typed} étapes effectuées) !\n")
    return count_typed
