#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cnibe_autofill_gui.py - Interface Ultra-Compacte & Moderne PyQt6 pour CNIBE AutoFill.
Conçu pour flotter discrètement à côté de tout logiciel médical, bureautique ou ERP.
"""

import sys
import os
import re
import json
import time
import winsound
import threading
import copy
from typing import Dict, Any, List, Optional

# Assurer l'encodage UTF-8 sous Windows
for stream_name in ('stdout', 'stderr'):
    stream = getattr(sys, stream_name)
    if hasattr(stream, 'reconfigure'):
        try:
            stream.reconfigure(encoding='utf-8')
        except Exception:
            pass

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize
from PyQt6.QtGui import QFont, QIcon, QColor, QPalette, QAction, QCursor
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QLabel, QPushButton, QLineEdit, QComboBox, QTabWidget,
    QListWidget, QListWidgetItem, QSpinBox, QTextEdit, QGroupBox,
    QCheckBox, QMenu, QMessageBox, QFrame, QSizePolicy, QInputDialog
)

# Modules du projet
from read_cnibe_safe import (
    read_cnibe_card,
    SecurityException,
    NoCardException,
    CardConnectionException
)
from cnibe_agent import (
    get_passive_pcsc_status,
    generate_local_token,
    fetch_ministere_data,
    get_known_id_cards,
    save_token_to_cache
)
from keyboard_wedge import (
    execute_autofill,
    extract_field_value,
    format_date_value
)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(APP_DIR, "autofill_config.json")


def load_config() -> Dict[str, Any]:
    """Charge la configuration des profils et paramètres."""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "active_profile": "Formulaire Standard (Nom, Prénom, Date, Adresse)",
        "countdown_seconds": 3,
        "delay_between_fields_ms": 130,
        "separator": "TAB",
        "date_format": "DD/MM/YYYY",
        "enable_ministere": True,
        "sound_enabled": True,
        "profiles": {
            "Formulaire Standard (Nom, Prénom, Date, Adresse)": {
                "description": "Modèle universel pour Word, Excel, formulaires web et logiciels de gestion",
                "fields": [
                    {"id": "nom_latin", "label": "1. Nom (Latin)", "enabled": True},
                    {"id": "prenom_latin", "label": "2. Prénom (Latin)", "enabled": True},
                    {"id": "date_naissance", "label": "3. Date de naissance", "enabled": True, "format": "DD/MM/YYYY"},
                    {"id": "skip", "label": "4. [SAUT DE CHAMP] Sauter Âge / Présumé", "enabled": True},
                    {"id": "lieu_naissance", "label": "5. Né(e) à (Lieu de naissance)", "enabled": True},
                    {"id": "situation_familiale", "label": "6. Situation (Familiale)", "enabled": True},
                    {"id": "skip", "label": "7. [SAUT DE CHAMP] Sauter Nom du père", "enabled": True},
                    {"id": "skip", "label": "8. [SAUT DE CHAMP] Sauter Nom de la mère", "enabled": True},
                    {"id": "adresse", "label": "9. Adresse (Résidence)", "enabled": True}
                ]
            }
        }
    }


def save_config(cfg: Dict[str, Any]):
    """Sauvegarde la configuration de manière persistante."""
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[!] Erreur sauvegarde config: {e}", file=sys.stderr)


def play_beep_async(freq: int, dur: int):
    """Joue un bip sans bloquer le thread principal."""
    threading.Thread(target=winsound.Beep, args=(freq, dur), daemon=True).start()


# ==============================================================================
# WORKERS THREADS (PyQt6 QThread)
# ==============================================================================

class PCSCWatcherThread(QThread):
    """Surveillance continue de l'état du lecteur et de la carte sans geler l'UI."""
    status_updated = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self._running = True
        self.paused = False

    def run(self):
        while self._running:
            if not self.paused:
                try:
                    st = get_passive_pcsc_status()
                    self.status_updated.emit(st)
                except Exception:
                    pass
            time.sleep(1.5)

    def stop(self):
        self._running = False
        self.wait(1000)


class CardReadThread(QThread):
    """Lecture NFC et interrogation Ministère en arrière-plan."""
    progress = pyqtSignal(str)
    success = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, doc: str, dob: str, doe: str, enable_ministere: bool = True):
        super().__init__()
        self.doc = doc
        self.dob = dob
        self.doe = doe
        self.enable_ministere = enable_ministere

    def run(self):
        try:
            self.progress.emit("Lecture NFC en cours... Maintenez la carte immobile.")
            card_data = read_cnibe_card(
                doc=self.doc,
                dob=self.dob,
                doe=self.doe,
                wait_seconds=15,
                include_base64=False,
                read_photo=False,
                read_signature=False
            )

            if self.enable_ministere:
                self.progress.emit("Consultation Ministère de l'Intérieur...")
                doc_norm = card_data.get("dg1_mrz", {}).get("document_number", self.doc).strip()
                known = get_known_id_cards()
                token = known.get(doc_norm) or known.get(self.doc)

                if not token:
                    token = generate_local_token(doc_norm, self.dob, self.doe)
                    if token:
                        save_token_to_cache(doc_norm, token)

                if token:
                    min_data = fetch_ministere_data(doc_norm, token)
                    if min_data:
                        card_data["ministere_data"] = min_data

            self.success.emit(card_data)

        except SecurityException:
            self.error.emit("Informations de la carte incorrectes.\nVeuillez vérifier le numéro et les dates.")
        except (NoCardException, CardConnectionException):
            self.error.emit("Carte non détectée.\nPosez la carte bien à plat sur le lecteur.")
        except Exception as e:
            self.error.emit(f"Erreur : {e}")


class TypingWorkerThread(QThread):
    """Injection clavier en arrière-plan pour garder l'UI 100% réactive."""
    completed = pyqtSignal(int)

    def __init__(self, card_data: dict, fields_config: list, separator: str, delay_ms: int, date_fmt: str):
        super().__init__()
        self.card_data = card_data
        self.fields_config = fields_config
        self.separator = separator
        self.delay_ms = delay_ms
        self.date_fmt = date_fmt

    def run(self):
        count = execute_autofill(
            card_data=self.card_data,
            fields_config=self.fields_config,
            separator=self.separator,
            delay_between_fields_ms=self.delay_ms,
            date_format=self.date_fmt
        )
        self.completed.emit(count)


# ==============================================================================
# FEUILLE DE STYLE QSS (Obsidian & Cyan Moderne)
# ==============================================================================

MODERN_QSS = """
QWidget {
    background-color: #0b0f19;
    color: #e2e8f0;
    font-family: 'Segoe UI', 'Inter', sans-serif;
    font-size: 11px;
}

/* En-tête et Titres */
QLabel#headerTitle {
    color: #38bdf8;
    font-size: 13px;
    font-weight: bold;
}

QCheckBox#pinCheck {
    color: #94a3b8;
    font-weight: bold;
    font-size: 10px;
    spacing: 5px;
}
QCheckBox#pinCheck:hover {
    color: #38bdf8;
}

/* Cadre de statut matériel */
QFrame#statusCard {
    background-color: #131b2e;
    border: 1px solid #1e293b;
    border-radius: 8px;
    padding: 2px 6px;
}

QLabel#readerStatus, QLabel#cardStatus {
    background-color: transparent;
    font-size: 10px;
    font-weight: bold;
}

/* Groupe d'informations */
QGroupBox {
    background-color: #131b2e;
    border: 1px solid #1e293b;
    border-radius: 8px;
    margin-top: 14px;
    font-weight: bold;
    color: #38bdf8;
    font-size: 10px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 10px;
    padding: 0 4px;
    background-color: #131b2e;
    border-radius: 3px;
}

/* Champs de texte & ComboBox */
QLineEdit {
    background-color: #090d16;
    border: 1px solid #1e293b;
    border-radius: 5px;
    padding: 4px 6px;
    color: #f8fafc;
    font-family: 'Consolas', 'Segoe UI', monospace;
    font-size: 11px;
    selection-background-color: #0284c7;
}
QLineEdit:focus {
    border: 1px solid #38bdf8;
    background-color: #0c1220;
}

QComboBox {
    background-color: #131b2e;
    border: 1px solid #1e293b;
    border-radius: 5px;
    padding: 4px 8px;
    color: #f8fafc;
    font-weight: 500;
}
QComboBox:hover {
    border: 1px solid #334155;
}
QComboBox::drop-down {
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 20px;
    border-left: 1px solid #1e293b;
}
QComboBox QAbstractItemView {
    background-color: #131b2e;
    border: 1px solid #334155;
    selection-background-color: #0284c7;
    selection-color: #ffffff;
    color: #e2e8f0;
    padding: 4px;
}

QSpinBox {
    background-color: #090d16;
    border: 1px solid #1e293b;
    border-radius: 5px;
    padding: 3px 6px;
    color: #f8fafc;
    font-weight: bold;
}

/* Onglets QTabWidget */
QTabWidget::pane {
    border: 1px solid #1e293b;
    background-color: #131b2e;
    border-radius: 8px;
    top: -1px;
}
QTabBar::tab {
    background-color: #0d1424;
    color: #94a3b8;
    border: 1px solid #1e293b;
    border-bottom: none;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    padding: 5px 12px;
    margin-right: 2px;
    font-weight: bold;
    font-size: 10px;
}
QTabBar::tab:selected {
    background-color: #0284c7;
    color: #ffffff;
    border-color: #0284c7;
}
QTabBar::tab:hover:!selected {
    background-color: #1e293b;
    color: #38bdf8;
}

/* Boutons */
QPushButton {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 3px 8px;
    color: #f1f5f9;
    font-weight: bold;
    font-size: 10px;
    min-height: 24px;
}
QPushButton:hover {
    background-color: #334155;
    border-color: #475569;
}
QPushButton:pressed {
    background-color: #0f172a;
}
QPushButton:disabled {
    background-color: #0f172a;
    color: #475569;
    border-color: #1e293b;
}

/* Bouton HERO Principal */
QPushButton#btnHero {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0284c7, stop:1 #0369a1);
    border: 1px solid #38bdf8;
    border-radius: 8px;
    padding: 7px;
    color: #ffffff;
    font-size: 12px;
    font-weight: bold;
    letter-spacing: 0.5px;
    min-height: 32px;
}
QPushButton#btnHero:hover {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0369a1, stop:1 #0284c7);
    border: 1px solid #7dd3fc;
}
QPushButton#btnHero:pressed {
    background-color: #075985;
}
QPushButton#btnHero:disabled {
    background: #1e293b;
    border-color: #334155;
    color: #64748b;
}

/* Boutons Spéciaux */
QPushButton#btnSuccess {
    background-color: #059669;
    border: 1px solid #10b981;
    color: #ffffff;
    font-size: 11px;
    min-height: 26px;
}
QPushButton#btnSuccess:hover {
    background-color: #047857;
}

QPushButton#btnSecondary {
    background-color: #1e293b;
    border: 1px solid #334155;
    color: #cbd5e1;
    min-height: 24px;
}

/* ListBox de configuration des champs */
QListWidget {
    background-color: #090d16;
    border: 1px solid #1e293b;
    border-radius: 6px;
    color: #f8fafc;
    font-size: 10px;
    padding: 3px;
}
QListWidget::item {
    padding: 4px 6px;
    border-radius: 4px;
    margin-bottom: 2px;
}
QListWidget::item:selected {
    background-color: #0284c7;
    color: #ffffff;
}
QListWidget::item:hover:!selected {
    background-color: #131b2e;
}

/* Zone Aperçu / Fiche */
QTextEdit#previewText {
    background-color: #090d16;
    border: 1px solid #1e293b;
    border-radius: 6px;
    color: #38bdf8;
    font-family: 'Consolas', 'Segoe UI', monospace;
    font-size: 10px;
    padding: 8px;
}

/* Menu contextuel */
QMenu {
    background-color: #131b2e;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 4px;
}
QMenu::item {
    padding: 5px 14px;
    border-radius: 4px;
    color: #f1f5f9;
}
QMenu::item:selected {
    background-color: #0284c7;
    color: #ffffff;
}

/* Footer barre d'état */
QLabel#footerStatus {
    color: #94a3b8;
    font-size: 10px;
}
"""


# ==============================================================================
# FENÊTRE PRINCIPALE PYQT6
# ==============================================================================

class CNIBEAutoFillWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CNIBE AutoFill")
        self.setMinimumSize(380, 460)
        self.resize(390, 480)

        # Activer le dark mode Windows pour la barre de titre native si possible
        try:
            import ctypes
            hwnd = int(self.winId())
            # DWMWA_USE_IMMERSIVE_DARK_MODE = 20
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, 20, ctypes.byref(ctypes.c_int(1)), ctypes.sizeof(ctypes.c_int)
            )
        except Exception:
            pass

        self.config_data = load_config()
        self.last_card_data: Optional[Dict[str, Any]] = None
        self.is_reading = False

        # État Always on top
        self.is_topmost = True
        self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, True)

        # Thread de surveillance du lecteur
        self.pcsc_watcher = PCSCWatcherThread()
        self.pcsc_watcher.status_updated.connect(self._on_pcsc_status_updated)

        # Timer pour le compte à rebours
        self.countdown_timer = QTimer(self)
        self.countdown_timer.timeout.connect(self._on_countdown_tick)
        self.remaining_countdown = 0

        # Construction UI
        self._build_ui()
        self.setStyleSheet(MODERN_QSS)

        # Démarrer surveillance
        self.pcsc_watcher.start()

    def _build_ui(self):
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(10, 8, 10, 8)
        main_layout.setSpacing(6)

        # 1. En-tête : Titre + Épingler
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 0)

        self.header_title = QLabel("🛡️ CNIBE AutoFill", self)
        self.header_title.setObjectName("headerTitle")
        header_layout.addWidget(self.header_title)

        header_layout.addStretch()

        self.beep_checkbox = QCheckBox("🔊 Bip", self)
        self.beep_checkbox.setObjectName("pinCheck")
        self.beep_checkbox.setChecked(self.config_data.get("sound_enabled", True))
        self.beep_checkbox.toggled.connect(self._toggle_beep)
        header_layout.addWidget(self.beep_checkbox)

        header_layout.addSpacing(6)

        self.pin_checkbox = QCheckBox("📌 Épingler", self)
        self.pin_checkbox.setObjectName("pinCheck")
        self.pin_checkbox.setChecked(True)
        self.pin_checkbox.toggled.connect(self._toggle_topmost)
        header_layout.addWidget(self.pin_checkbox)

        main_layout.addLayout(header_layout)

        # 2. Barre de statut matériel compacte
        status_frame = QFrame(self)
        status_frame.setObjectName("statusCard")
        status_layout = QHBoxLayout(status_frame)
        status_layout.setContentsMargins(8, 4, 8, 4)

        self.reader_lbl = QLabel("🔍 Recherche lecteur...", self)
        self.reader_lbl.setObjectName("readerStatus")
        self.reader_lbl.setStyleSheet("color: #f59e0b;")
        status_layout.addWidget(self.reader_lbl)

        status_layout.addStretch()

        self.card_lbl = QLabel("⚪ Posez la carte", self)
        self.card_lbl.setObjectName("cardStatus")
        self.card_lbl.setStyleSheet("color: #64748b;")
        status_layout.addWidget(self.card_lbl)

        main_layout.addWidget(status_frame)

        # 3. Onglets
        self.tabs = QTabWidget(self)
        main_layout.addWidget(self.tabs, stretch=1)

        # Tab 1: Saisie
        self.tab_fill = QWidget()
        self._build_fill_tab()
        self.tabs.addTab(self.tab_fill, "⚡ Saisie")

        # Tab 2: Champs & Profils
        self.tab_config = QWidget()
        self._build_config_tab()
        self.tabs.addTab(self.tab_config, "⚙️ Champs")

        # Tab 3: Aperçu / Fiche
        self.tab_preview = QWidget()
        self._build_preview_tab()
        self.tabs.addTab(self.tab_preview, "📋 Fiche")

        # 4. Pied de page (Barre d'état)
        footer_layout = QHBoxLayout()
        footer_layout.setContentsMargins(4, 2, 4, 0)
        self.footer_lbl = QLabel("Prêt pour la saisie.", self)
        self.footer_lbl.setObjectName("footerStatus")
        footer_layout.addWidget(self.footer_lbl)
        main_layout.addLayout(footer_layout)

    # ==========================================================================
    # ONGLET 1 : SAISIE
    # ==========================================================================
    def _build_fill_tab(self):
        layout = QVBoxLayout(self.tab_fill)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        # Profil
        prof_layout = QHBoxLayout()
        lbl_mod = QLabel("Modèle :", self)
        lbl_mod.setStyleSheet("color: #94a3b8; font-weight: bold;")
        prof_layout.addWidget(lbl_mod)

        profiles = list(self.config_data.get("profiles", {}).keys())
        current_p = self.config_data.get("active_profile", profiles[0] if profiles else "")
        self.profile_combo = QComboBox(self)
        self.profile_combo.addItems(profiles)
        self.profile_combo.setCurrentText(current_p)
        self.profile_combo.currentTextChanged.connect(self._on_profile_change)
        prof_layout.addWidget(self.profile_combo, stretch=1)
        layout.addLayout(prof_layout)

        # Carte d'informations
        group = QGroupBox("  Informations de la carte  ", self)
        grp_layout = QVBoxLayout(group)
        grp_layout.setContentsMargins(8, 10, 8, 6)
        grp_layout.setSpacing(5)

        # Ligne 1 : N° Document + Bouton Dernière carte
        row1 = QHBoxLayout()
        lbl_doc = QLabel("N° Carte :", self)
        lbl_doc.setFixedWidth(70)
        lbl_doc.setStyleSheet("color: #cbd5e1;")
        row1.addWidget(lbl_doc)

        self.doc_entry = QLineEdit(self)
        self.doc_entry.setPlaceholderText("Ex: 115200000")
        self.doc_entry.setFont(QFont("Consolas", 10, QFont.Weight.Bold))
        row1.addWidget(self.doc_entry, stretch=1)

        self.btn_last_card = QPushButton("📁 Dernière carte", self)
        self.btn_last_card.setObjectName("btnSecondary")
        self.btn_last_card.clicked.connect(self._load_last_card)
        row1.addWidget(self.btn_last_card)
        grp_layout.addLayout(row1)

        # Ligne 2 : Naissance & Expiration
        row2 = QHBoxLayout()
        lbl_dob = QLabel("Naissance :", self)
        lbl_dob.setFixedWidth(70)
        lbl_dob.setStyleSheet("color: #cbd5e1;")
        row2.addWidget(lbl_dob)

        self.dob_entry = QLineEdit(self)
        self.dob_entry.setPlaceholderText("JJ/MM/AAAA")
        row2.addWidget(self.dob_entry, stretch=1)

        lbl_doe = QLabel("Expiration :", self)
        lbl_doe.setStyleSheet("color: #cbd5e1;")
        row2.addWidget(lbl_doe)

        self.doe_entry = QLineEdit(self)
        self.doe_entry.setPlaceholderText("JJ/MM/AAAA")
        row2.addWidget(self.doe_entry, stretch=1)
        grp_layout.addLayout(row2)

        layout.addWidget(group)

        # Actions Principales
        layout.addSpacing(4)

        self.btn_hero = QPushButton("⚡ LIRE ET REMPLIR (3s)", self)
        self.btn_hero.setObjectName("btnHero")
        self.btn_hero.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_hero.clicked.connect(self._start_read_and_fill)
        layout.addWidget(self.btn_hero)

        self.btn_refill = QPushButton("🔁 Re-remplir la dernière carte", self)
        self.btn_refill.setObjectName("btnSecondary")
        self.btn_refill.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_refill.clicked.connect(self._refill_current_data)
        layout.addWidget(self.btn_refill)

        layout.addStretch()

    # ==========================================================================
    # ONGLET 2 : CONFIGURATION DES PROFILS ET CHAMPS
    # ==========================================================================
    def _build_config_tab(self):
        layout = QVBoxLayout(self.tab_config)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        # Choix du profil
        top_h = QHBoxLayout()
        lbl_p = QLabel("Profil :", self)
        lbl_p.setStyleSheet("color: #cbd5e1; font-weight: bold;")
        top_h.addWidget(lbl_p)

        self.cfg_profile_combo = QComboBox(self)
        self.cfg_profile_combo.addItems(list(self.config_data.get("profiles", {}).keys()))
        self.cfg_profile_combo.setCurrentText(self.config_data.get("active_profile", ""))
        self.cfg_profile_combo.currentTextChanged.connect(self._on_cfg_profile_selected)
        top_h.addWidget(self.cfg_profile_combo, stretch=1)

        self.btn_new_prof = QPushButton("➕", self)
        self.btn_new_prof.setToolTip("Créer un nouveau profil")
        self.btn_new_prof.setFixedWidth(28)
        self.btn_new_prof.clicked.connect(self._create_new_profile)
        top_h.addWidget(self.btn_new_prof)

        self.btn_del_prof = QPushButton("🗑️", self)
        self.btn_del_prof.setToolTip("Supprimer le profil actuel")
        self.btn_del_prof.setFixedWidth(28)
        self.btn_del_prof.clicked.connect(self._delete_current_profile)
        top_h.addWidget(self.btn_del_prof)

        layout.addLayout(top_h)

        # Délais et Décompte
        spin_h = QHBoxLayout()
        lbl_d = QLabel("Délai (ms) :", self)
        lbl_d.setStyleSheet("color: #cbd5e1;")
        spin_h.addWidget(lbl_d)

        self.delay_spin = QSpinBox(self)
        self.delay_spin.setRange(30, 800)
        self.delay_spin.setSingleStep(20)
        self.delay_spin.setValue(int(self.config_data.get("delay_between_fields_ms", 130)))
        spin_h.addWidget(self.delay_spin)

        lbl_c = QLabel("Décompte (s) :", self)
        lbl_c.setStyleSheet("color: #cbd5e1;")
        spin_h.addWidget(lbl_c)

        self.countdown_spin = QSpinBox(self)
        self.countdown_spin.setRange(1, 10)
        self.countdown_spin.setValue(int(self.config_data.get("countdown_seconds", 3)))
        spin_h.addWidget(self.countdown_spin)

        spin_h.addStretch()
        layout.addLayout(spin_h)

        # Boîte de réorganisation des champs
        grp_fields = QGroupBox("  Ordre des Champs (Séquence Clavier)  ", self)
        grp_box_layout = QVBoxLayout(grp_fields)
        grp_box_layout.setContentsMargins(8, 12, 8, 8)
        grp_box_layout.setSpacing(5)

        self.fields_listwidget = QListWidget(self)
        self.fields_listwidget.setMinimumHeight(130)
        grp_box_layout.addWidget(self.fields_listwidget, stretch=1)

        # Ligne d'outils 1 : Déplacement, statut et suppression
        bar1 = QHBoxLayout()
        bar1.setSpacing(4)

        btn_up = QPushButton("⬆ Monter", self)
        btn_up.clicked.connect(self._move_field_up)
        bar1.addWidget(btn_up)

        btn_down = QPushButton("⬇ Descendre", self)
        btn_down.clicked.connect(self._move_field_down)
        bar1.addWidget(btn_down)

        btn_toggle = QPushButton("✓ Actif/Inactif", self)
        btn_toggle.clicked.connect(self._toggle_field)
        bar1.addWidget(btn_toggle)

        btn_del = QPushButton("🗑️ Retirer", self)
        btn_del.clicked.connect(self._remove_field)
        bar1.addWidget(btn_del)
        grp_box_layout.addLayout(bar1)

        # Ligne d'outils 2 : Ajout de champs
        bar2 = QHBoxLayout()
        bar2.setSpacing(4)

        btn_add = QPushButton("➕ Ajouter un champ...", self)
        btn_add.clicked.connect(self._show_add_field_menu)
        bar2.addWidget(btn_add, stretch=2)

        btn_skip = QPushButton("➕ Saut (Tab)", self)
        btn_skip.clicked.connect(self._add_skip_field)
        bar2.addWidget(btn_skip, stretch=1)
        grp_box_layout.addLayout(bar2)

        # Ligne 3 : Enregistrement
        self.btn_save_cfg = QPushButton("💾 Enregistrer ce modèle", self)
        self.btn_save_cfg.setObjectName("btnSuccess")
        self.btn_save_cfg.clicked.connect(self._save_current_config)
        grp_box_layout.addWidget(self.btn_save_cfg)

        layout.addWidget(grp_fields, stretch=1)

        self._refresh_fields_list()

    # ==========================================================================
    # ONGLET 3 : APERÇU / FICHE
    # ==========================================================================
    def _build_preview_tab(self):
        layout = QVBoxLayout(self.tab_preview)
        layout.setContentsMargins(6, 6, 6, 6)

        self.preview_text = QTextEdit(self)
        self.preview_text.setObjectName("previewText")
        self.preview_text.setReadOnly(True)
        self.preview_text.setHtml(
            "<div style='color: #64748b; padding: 10px; text-align: center; font-family: Segoe UI;'>"
            "<i>Déposez une carte sur le lecteur NFC puis cliquez sur <b>LIRE ET REMPLIR</b> "
            "pour afficher sa fiche complète ici.</i></div>"
        )
        layout.addWidget(self.preview_text)

    def _update_preview_display(self, data: Dict[str, Any]):
        dg1 = data.get("dg1_mrz", {})
        dg11 = data.get("dg11_personnel", {})
        min_d = data.get("ministere_data") or {}

        doc_num = dg1.get("document_number", data.get("doc", ""))
        nom_l = min_d.get("nom_latin") or dg1.get("nom_latin", "")
        prenom_l = min_d.get("prenom_latin") or dg1.get("prenoms_latin", "")
        nom_a = min_d.get("nom_arabe") or dg11.get("nom_arabe", "")
        prenom_a = min_d.get("prenom_arabe") or dg11.get("prenoms_arabe", "")
        nin = min_d.get("nin") or dg11.get("nin") or dg1.get("optional_data", "")
        dob = min_d.get("date_naissance") or dg1.get("date_of_birth", "")
        sexe = min_d.get("sexe_latin") or dg1.get("sex", "")
        sang = min_d.get("groupe_sanguin", "")
        adr = min_d.get("adresse") or dg11.get("adresse", "")

        html = f"""
        <div style="font-family: 'Segoe UI', Arial; color: #f1f5f9; font-size: 11px; line-height: 1.5;">
            <div style="font-size: 13px; font-weight: bold; color: #38bdf8; border-bottom: 1px solid #1e293b; padding-bottom: 4px; margin-bottom: 8px;">
                📋 DONNÉES BIOMÉTRIQUES CNIBE
            </div>
            <table style="width: 100%; border-collapse: collapse;">
                <tr><td style="color: #94a3b8; width: 100px;">Nom & Prénom :</td><td><b>{nom_l} {prenom_l}</b></td></tr>
                <tr><td style="color: #94a3b8;">العـربـيـة :</td><td style="color: #6ee7b7; font-size: 12px;"><b>{nom_a} {prenom_a}</b></td></tr>
                <tr><td style="color: #94a3b8;">NIN (18 ch.) :</td><td style="color: #fbbf24; font-family: Consolas;"><b>{nin}</b></td></tr>
                <tr><td style="color: #94a3b8;">N° Document :</td><td style="font-family: Consolas;">{doc_num}</td></tr>
                <tr><td style="color: #94a3b8;">Naissance :</td><td>{dob}</td></tr>
                <tr><td style="color: #94a3b8;">Sexe / Sang :</td><td>{sexe} &nbsp;|&nbsp; Groupe: <b style="color: #f43f5e;">{sang or 'N/A'}</b></td></tr>
                <tr><td style="color: #94a3b8; vertical-align: top;">Adresse :</td><td style="color: #cbd5e1;">{adr or 'N/A'}</td></tr>
            </table>
            <div style="margin-top: 10px; font-size: 9px; color: #10b981; border-top: 1px solid #1e293b; padding-top: 4px;">
                ✓ Données synchronisées et prêtes pour injection.
            </div>
        </div>
        """
        self.preview_text.setHtml(html)

    # ==========================================================================
    # GESTION DES PROFILS ET DES CHAMPS
    # ==========================================================================
    def _refresh_fields_list(self):
        p_name = self.cfg_profile_combo.currentText()
        p_data = self.config_data.get("profiles", {}).get(p_name, {})
        fields = p_data.get("fields", [])

        self.fields_listwidget.clear()
        for f in fields:
            enabled = f.get("enabled", True)
            prefix = "✓ " if enabled else "✗ "
            label = f.get("label", f.get("id"))
            item = QListWidgetItem(f"{prefix}{label}")
            if not enabled:
                item.setForeground(QColor("#64748b"))
            else:
                item.setForeground(QColor("#f8fafc"))
            self.fields_listwidget.addItem(item)

    def _move_field_up(self):
        row = self.fields_listwidget.currentRow()
        if row <= 0:
            return
        p_name = self.cfg_profile_combo.currentText()
        fields = self.config_data["profiles"][p_name]["fields"]
        fields[row - 1], fields[row] = fields[row], fields[row - 1]
        self._refresh_fields_list()
        self.fields_listwidget.setCurrentRow(row - 1)

    def _move_field_down(self):
        row = self.fields_listwidget.currentRow()
        p_name = self.cfg_profile_combo.currentText()
        fields = self.config_data["profiles"][p_name]["fields"]
        if row < 0 or row >= len(fields) - 1:
            return
        fields[row + 1], fields[row] = fields[row], fields[row + 1]
        self._refresh_fields_list()
        self.fields_listwidget.setCurrentRow(row + 1)

    def _toggle_field(self):
        row = self.fields_listwidget.currentRow()
        if row < 0:
            return
        p_name = self.cfg_profile_combo.currentText()
        fields = self.config_data["profiles"][p_name]["fields"]
        fields[row]["enabled"] = not fields[row].get("enabled", True)
        self._refresh_fields_list()
        self.fields_listwidget.setCurrentRow(row)

    def _show_add_field_menu(self):
        choices = [
            ("num_carte_id", "N° Carte ID (Id: ... NIN: ...)"),
            ("num_document", "N° Carte seul (sans NIN)"),
            ("nin", "NIN (18 chiffres)"),
            ("nom_latin", "Nom (Latin)"),
            ("prenom_latin", "Prénom (Latin)"),
            ("date_naissance", "Date de naissance (JJ/MM/AAAA)"),
            ("lieu_naissance", "Né(e) à (Lieu de naissance)"),
            ("situation_familiale", "Situation (Célibataire...)"),
            ("adresse", "Adresse (Résidence)"),
            ("sexe", "Sexe (Masculin / Féminin)"),
            ("civilite", "Civilité (M, Mme, Mlle)"),
            ("groupe_sanguin", "Groupe Sanguin"),
            ("nom_arabe", "Nom (Arabe)"),
            ("prenom_arabe", "Prénom (Arabe)"),
            ("date_expiration", "Date d'expiration"),
            ("skip", "[SAUT DE CHAMP / TAB]")
        ]
        menu = QMenu(self)
        for fid, flbl in choices:
            action = QAction(flbl, self)
            action.triggered.connect(lambda checked, f_id=fid, f_l=flbl: self._insert_field(f_id, f_l))
            menu.addAction(action)
        menu.exec(QCursor.pos())

    def _insert_field(self, field_id: str, label: str):
        p_name = self.cfg_profile_combo.currentText()
        fields = self.config_data["profiles"][p_name]["fields"]
        row = self.fields_listwidget.currentRow()
        insert_idx = row + 1 if row >= 0 else len(fields)
        fields.insert(insert_idx, {"id": field_id, "label": label, "enabled": True})
        self._refresh_fields_list()
        self.fields_listwidget.setCurrentRow(insert_idx)

    def _add_skip_field(self):
        self._insert_field("skip", "[SAUT DE CHAMP / TAB]")

    def _remove_field(self):
        row = self.fields_listwidget.currentRow()
        if row < 0:
            return
        p_name = self.cfg_profile_combo.currentText()
        fields = self.config_data["profiles"][p_name]["fields"]
        del fields[row]
        self._refresh_fields_list()
        new_row = min(row, len(fields) - 1)
        if new_row >= 0:
            self.fields_listwidget.setCurrentRow(new_row)

    def _save_current_config(self):
        p_name = self.cfg_profile_combo.currentText()
        self.config_data["active_profile"] = p_name
        self.config_data["delay_between_fields_ms"] = self.delay_spin.value()
        self.config_data["countdown_seconds"] = self.countdown_spin.value()

        save_config(self.config_data)
        self.profile_combo.setCurrentText(p_name)
        self.footer_lbl.setText("Profil et configuration enregistrés avec succès !")
        QMessageBox.information(self, "Configuration", "Profil enregistré avec succès !")

    def _on_profile_change(self, text: str):
        self.config_data["active_profile"] = text
        self.cfg_profile_combo.setCurrentText(text)
        self._refresh_fields_list()
        save_config(self.config_data)

    def _on_cfg_profile_selected(self, text: str):
        self._refresh_fields_list()

    def _create_new_profile(self):
        name, ok = QInputDialog.getText(
            self, "Nouveau Profil", "Nom du nouveau modèle (ex: Dossier Médical, Excel, ERP) :"
        )
        if not ok or not name.strip():
            return
        name = name.strip()
        if name in self.config_data.get("profiles", {}):
            QMessageBox.warning(self, "Profil existant", f"Le profil '{name}' existe déjà.")
            return

        current_p = self.cfg_profile_combo.currentText()
        current_fields = self.config_data.get("profiles", {}).get(current_p, {}).get("fields", [])

        self.config_data.setdefault("profiles", {})[name] = {
            "description": f"Modèle personnalisé {name}",
            "fields": copy.deepcopy(current_fields)
        }
        self.config_data["active_profile"] = name
        save_config(self.config_data)

        profs = list(self.config_data["profiles"].keys())
        self.profile_combo.blockSignals(True)
        self.cfg_profile_combo.blockSignals(True)
        self.profile_combo.clear()
        self.cfg_profile_combo.clear()
        self.profile_combo.addItems(profs)
        self.cfg_profile_combo.addItems(profs)
        self.profile_combo.setCurrentText(name)
        self.cfg_profile_combo.setCurrentText(name)
        self.profile_combo.blockSignals(False)
        self.cfg_profile_combo.blockSignals(False)

        self._refresh_fields_list()
        self.footer_lbl.setText(f"Nouveau profil '{name}' créé et sélectionné !")
        QMessageBox.information(self, "Profil créé", f"Le profil '{name}' a été créé et activé par défaut !")

    def _delete_current_profile(self):
        profs = list(self.config_data.get("profiles", {}).keys())
        if len(profs) <= 1:
            QMessageBox.warning(self, "Action impossible", "Vous devez conserver au moins un profil dans la liste.")
            return

        current_p = self.cfg_profile_combo.currentText()
        confirm = QMessageBox.question(
            self, "Confirmer la suppression",
            f"Voulez-vous vraiment supprimer le profil '{current_p}' ?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        del self.config_data["profiles"][current_p]
        remaining = list(self.config_data["profiles"].keys())
        self.config_data["active_profile"] = remaining[0]
        save_config(self.config_data)

        self.profile_combo.blockSignals(True)
        self.cfg_profile_combo.blockSignals(True)
        self.profile_combo.clear()
        self.cfg_profile_combo.clear()
        self.profile_combo.addItems(remaining)
        self.cfg_profile_combo.addItems(remaining)
        self.profile_combo.setCurrentText(remaining[0])
        self.cfg_profile_combo.setCurrentText(remaining[0])
        self.profile_combo.blockSignals(False)
        self.cfg_profile_combo.blockSignals(False)

        self._refresh_fields_list()
        self.footer_lbl.setText(f"Profil supprimé. Profil actif : '{remaining[0]}'")

    def _toggle_topmost(self, checked: bool):
        self.is_topmost = checked
        self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, checked)
        self.show()

    def _toggle_beep(self, checked: bool):
        self.config_data["sound_enabled"] = checked
        save_config(self.config_data)

    def _play_beep(self, freq: int, dur: int):
        if hasattr(self, "beep_checkbox") and self.beep_checkbox.isChecked():
            play_beep_async(freq, dur)

    # ==========================================================================
    # SURVEILLANCE DU LECTEUR (PCSC)
    # ==========================================================================
    def _on_pcsc_status_updated(self, st: dict):
        if self.is_reading:
            return
        readers_count = st.get("readers_count", 0)
        card_present = st.get("card_present", False)
        reader_name = st.get("selected_reader") or "Aucun"

        if readers_count > 0:
            r_short = reader_name[:24] + "..." if len(reader_name) > 24 else reader_name
            self.reader_lbl.setText(f"● {r_short}")
            self.reader_lbl.setStyleSheet("color: #34d399; font-weight: bold; font-size: 11px;")
        else:
            self.reader_lbl.setText("● Aucun lecteur USB")
            self.reader_lbl.setStyleSheet("color: #f87171; font-weight: bold; font-size: 11px;")

        if card_present:
            self.card_lbl.setText("● Carte présente")
            self.card_lbl.setStyleSheet("color: #38bdf8; font-weight: bold; font-size: 11px;")
        else:
            self.card_lbl.setText("○ Posez la carte")
            self.card_lbl.setStyleSheet("color: #64748b; font-weight: bold; font-size: 11px;")

    # ==========================================================================
    # CHARGEMENT DE LA CARTE EN CACHE
    # ==========================================================================
    def _load_last_card(self):
        known = get_known_id_cards()
        if not known:
            QMessageBox.information(self, "Cache", "Aucune carte en cache local.")
            return
        last_doc = list(known.keys())[-1]
        self.doc_entry.setText(last_doc)

        token = known.get(last_doc, "")
        # Si le jeton contient les dates en clair (bande MRZ), on remplit automatiquement Naissance et Expiration !
        if token and len(token) >= 60 and token.startswith("IDDZA"):
            try:
                dob_raw = token[30:36]
                doe_raw = token[38:44]
                self.dob_entry.setText(format_date_value(dob_raw, "DD/MM/YYYY"))
                self.doe_entry.setText(format_date_value(doe_raw, "DD/MM/YYYY"))
            except Exception:
                pass

        self.footer_lbl.setText(f"Dernière carte chargée ({last_doc})")

    # ==========================================================================
    # LECTURE DE LA CARTE & COMPTE À REBOURS
    # ==========================================================================
    def _start_read_and_fill(self):
        if self.is_reading:
            return

        doc = self.doc_entry.text().strip()
        dob = self.dob_entry.text().strip()
        doe = self.doe_entry.text().strip()

        if not doc or not dob or not doe:
            QMessageBox.warning(
                self, "Champs requis",
                "Veuillez renseigner le N° Carte, la Date de Naissance et la Date d'Expiration."
            )
            return

        self.is_reading = True
        self.pcsc_watcher.paused = True
        self.btn_hero.setEnabled(False)
        self.btn_hero.setText("⏳ LECTURE NFC EN COURS...")
        self.footer_lbl.setText("Lecture NFC en cours... Maintenez la carte immobile.")

        # Lancer le worker de lecture
        self.read_thread = CardReadThread(
            doc=doc,
            dob=dob,
            doe=doe,
            enable_ministere=self.config_data.get("enable_ministere", True)
        )
        self.read_thread.progress.connect(self._on_read_progress)
        self.read_thread.success.connect(self._on_read_success)
        self.read_thread.error.connect(self._on_read_error)
        self.read_thread.start()

    def _on_read_progress(self, msg: str):
        self.footer_lbl.setText(msg)

    def _on_read_error(self, err_msg: str):
        self.is_reading = False
        self.pcsc_watcher.paused = False
        self.btn_hero.setEnabled(True)
        self.btn_hero.setText("⚡ LIRE ET REMPLIR (3s)")
        self.footer_lbl.setText("Erreur lors de la lecture.")
        QMessageBox.critical(self, "Erreur de Lecture", err_msg)

    def _on_read_success(self, card_data: dict):
        self.is_reading = False
        self.pcsc_watcher.paused = False
        self.btn_hero.setEnabled(True)
        self.btn_hero.setText("⚡ LIRE ET REMPLIR (3s)")
        self.last_card_data = card_data
        self._update_preview_display(card_data)
        self._trigger_countdown_and_fill()

    def _refill_current_data(self):
        if not self.last_card_data:
            QMessageBox.information(self, "Aucune carte", "Aucune carte en mémoire. Effectuez une lecture d'abord.")
            return
        self._trigger_countdown_and_fill()

    def _trigger_countdown_and_fill(self):
        # Désactiver temporairement AlwaysOnTop pour permettre à l'utilisateur de cliquer dans la fenêtre cible
        if self.is_topmost:
            self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, False)
            self.show()

        countdown = int(self.config_data.get("countdown_seconds", 3))
        self.remaining_countdown = countdown
        self.btn_hero.setEnabled(False)

        self._play_beep(1000, 150)
        self._update_countdown_ui()
        self.countdown_timer.start(1000)

    def _on_countdown_tick(self):
        self.remaining_countdown -= 1
        if self.remaining_countdown > 0:
            self._play_beep(1000, 150)
            self._update_countdown_ui()
        else:
            self.countdown_timer.stop()
            self._start_typing_step()

    def _update_countdown_ui(self):
        txt = f"⏳ {self.remaining_countdown}s... CLIQUEZ DANS VOTRE LOGICIEL !"
        self.setWindowTitle(f"[{self.remaining_countdown}s] CLIQUEZ DANS VOTRE LOGICIEL !")
        self.btn_hero.setText(txt)
        self.footer_lbl.setText(f"👉 Placez le curseur dans votre logiciel ({self.remaining_countdown}s)...")

    def _start_typing_step(self):
        self.setWindowTitle("⚡ Saisie en cours dans votre logiciel...")
        self.btn_hero.setText("⚡ SAISIE EN COURS DANS VOTRE LOGICIEL...")
        self.footer_lbl.setText("⚡ Injection des champs en cours...")
        self._play_beep(1800, 300)

        # Recharger la dernière version du fichier de configuration
        try:
            self.config_data = load_config()
        except Exception:
            pass

        p_name = self.config_data.get("active_profile", "")
        p_cfg = self.config_data.get("profiles", {}).get(p_name, {})
        fields = p_cfg.get("fields", [])
        separator = self.config_data.get("separator", "TAB")
        delay_ms = int(self.config_data.get("delay_between_fields_ms", 130))
        date_fmt = self.config_data.get("date_format", "DD/MM/YYYY")

        self.typing_thread = TypingWorkerThread(
            card_data=self.last_card_data,
            fields_config=fields,
            separator=separator,
            delay_ms=delay_ms,
            date_fmt=date_fmt
        )
        self.typing_thread.completed.connect(self._on_typing_complete)
        self.typing_thread.start()

    def _on_typing_complete(self, count: int):
        self.setWindowTitle("CNIBE AutoFill")
        self.btn_hero.setEnabled(True)
        self.btn_hero.setText("⚡ LIRE ET REMPLIR (3s)")
        self.footer_lbl.setText(f"✅ Saisie terminée ({count} champs injectés) !")

        # Restaurer AlwaysOnTop si coché
        if self.is_topmost:
            self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, True)
            self.show()

        if hasattr(self, "beep_checkbox") and self.beep_checkbox.isChecked():
            try:
                winsound.MessageBeep(winsound.MB_ICONASTERISK)
            except Exception:
                pass

    def closeEvent(self, event):
        """Arrêt propre des threads lors de la fermeture."""
        self.pcsc_watcher.stop()
        event.accept()


# ==============================================================================
# POINT D'ENTRÉE PRINCIPAL
# ==============================================================================

def main():
    # Optimisation affichage HiDPI sous Windows
    if hasattr(Qt.ApplicationAttribute, "AA_EnableHighDpiScaling"):
        QApplication.setAttribute(Qt.ApplicationAttribute.AA_EnableHighDpiScaling, True)
    if hasattr(Qt.ApplicationAttribute, "AA_UseHighDpiPixmaps"):
        QApplication.setAttribute(Qt.ApplicationAttribute.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    window = CNIBEAutoFillWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
