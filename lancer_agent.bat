@echo off
chcp 65001 >nul
title CNIBE AutoFill - Émulateur Clavier
 
echo ======================================================================
echo    🛡️ CNIBE AUTOFILL - REMPLISSEUR CLAVIER (KEYBOARD WEDGE)
echo ======================================================================
echo Ce script lance le remplisseur automatique de formulaires par frappe clavier.
echo.

cd /d "%~dp0"

:: Détection de la commande Python appropriée (priorité à Python 3.11)
set "PY_CMD="
py -3.11 -V >nul 2>&1
if %errorlevel% equ 0 (
    set "PY_CMD=py -3.11"
) else (
    python -V >nul 2>&1
    if %errorlevel% equ 0 (
        set "PY_CMD=python"
    ) else (
        echo [ERREUR] Python introuvable ! Veuillez installer Python 3.10 ou 3.11.
        pause
        exit /b 1
    )
)

echo [*] Utilisation de Python : %PY_CMD%

:: Vérification rapide des modules indispensables
%PY_CMD% -c "import smartcard; import Crypto" >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Installation des dépendances requises (pyscard, pycryptodome)...
    %PY_CMD% -m pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo [ERREUR] Échec de l'installation des dépendances.
        pause
        exit /b 1
    )
)

echo.
echo [*] Lancement de CNIBE AutoFill (Remplisseur Clavier)...
echo.
%PY_CMD% cnibe_autofill_gui.py

if %errorlevel% neq 0 (
    echo.
    echo [!] L'application s'est arrêtée avec une erreur.
    pause
)

