#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_autofill_wedge.py - Tests unitaires et d'intégration pour le Keyboard Wedge CNIBE.
"""

import os
import json
import unittest
from keyboard_wedge import (
    format_date_value,
    extract_field_value,
    set_clipboard_text,
    paste_clipboard,
    press_tab,
    press_separator
)


class TestKeyboardWedge(unittest.TestCase):
    def setUp(self):
        self.mock_card_data = {
            "doc": "100689622",
            "dg1_mrz": {
                "document_number": "100689622",
                "date_of_birth": "1990-05-14",
                "date_of_expiry": "2030-05-14",
                "nom_latin": "BENALI",
                "prenoms_latin": "MOHAMED",
                "sex": "M",
                "nationality": "DZA",
                "optional_data": "190100689622000001"
            },
            "dg11_personnel": {
                "nom_arabe": "بن علي",
                "prenoms_arabe": "محمد",
                "nin": "190100689622000001",
                "lieu_naissance": "ALGER",
                "lieu_naissance_arabe": "الجزائر",
                "adresse": "12 RUE DIDOUCHE MOURAD ALGER"
            },
            "ministere_data": {
                "nin": "190100689622000001",
                "nom_latin": "BENALI",
                "prenom_latin": "MOHAMED",
                "nom_arabe": "بن علي",
                "prenom_arabe": "محمد",
                "date_naissance": "14/05/1990",
                "sexe_latin": "MASCULIN",
                "groupe_sanguin": "O+",
                "situation_familiale_latin": "CELIBATAIRE",
                "adresse": "12 RUE DIDOUCHE MOURAD, ALGER-CENTRE"
            }
        }

    def test_date_formatting(self):
        self.assertEqual(format_date_value("1990-05-14", "DD/MM/YYYY"), "14/05/1990")
        self.assertEqual(format_date_value("14/05/1990", "YYYY-MM-DD"), "1990-05-14")
        self.assertEqual(format_date_value("900514", "DD/MM/YYYY"), "14/05/1990")

    def test_field_extraction(self):
        # NIN
        self.assertEqual(extract_field_value("nin", self.mock_card_data), "190100689622000001")
        # Noms
        self.assertEqual(extract_field_value("nom_latin", self.mock_card_data), "BENALI")
        self.assertEqual(extract_field_value("prenom_latin", self.mock_card_data), "MOHAMED")
        self.assertEqual(extract_field_value("nom_arabe", self.mock_card_data), "بن علي")
        self.assertEqual(extract_field_value("prenom_arabe", self.mock_card_data), "محمد")
        # Sexe
        self.assertEqual(extract_field_value("sexe", self.mock_card_data), "M")
        # Groupe sanguin
        self.assertEqual(extract_field_value("groupe_sanguin", self.mock_card_data), "O+")
        # Civilité & Sexe Texte
        self.assertEqual(extract_field_value("civilite", self.mock_card_data), "M")
        self.assertEqual(extract_field_value("sexe_complet", self.mock_card_data), "Masculin")
        self.assertEqual(extract_field_value("sexe_texte", self.mock_card_data), "Masculin")
        # Saut de champ
        self.assertEqual(extract_field_value("skip", self.mock_card_data), "")
        # Adresse
        self.assertIn("DIDOUCHE MOURAD", extract_field_value("adresse", self.mock_card_data))
        # N° Carte ID / Document
        self.assertEqual(extract_field_value("num_carte_id", self.mock_card_data), "Id: 100689622 NIN: 190100689622000001")
        self.assertEqual(extract_field_value("num_carte", self.mock_card_data), "100689622")

    def test_config_file_validity(self):
        config_path = os.path.join(os.path.dirname(__file__), "autofill_config.json")
        self.assertTrue(os.path.exists(config_path))
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        self.assertIn("active_profile", cfg)
        self.assertIn("profiles", cfg)
        self.assertIn(cfg["active_profile"], cfg["profiles"])

    def test_win32_clipboard_and_tab(self):
        try:
            res = set_clipboard_text("Test CNIBE محمد")
            self.assertTrue(res)
            press_tab()
            press_separator("TAB")
        except Exception as e:
            self.fail(f"L'appel presse-papier ou Tab a échoué : {e}")


if __name__ == "__main__":
    unittest.main()
