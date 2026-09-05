@echo off
chcp 65001 >nul
title CNIBE - Agent Client Local (Lecteur NFC)

echo ======================================================================
echo    🛡️ CNIBE - AGENT CLIENT LOCAL (Passerelle PC/SC NFC)
echo ======================================================================
echo Ce script doit tourner en continu sur le PC où le lecteur NFC USB est branché.
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
echo [*] Lancement de l'agent client sur http://127.0.0.1:5001 ...
echo [*] Vous pouvez maintenant ouvrir l'application web dans votre navigateur.
echo.
%PY_CMD% cnibe_agent.py

if %errorlevel% neq 0 (
    echo.
    echo [!] L'agent s'est arrêté avec une erreur.
    pause
)
