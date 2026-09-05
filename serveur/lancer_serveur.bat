@echo off
chcp 65001 >nul
title CNIBE - Serveur Web Central (Port 5000)

echo ======================================================================
echo    🌐 CNIBE - SERVEUR WEB FLASK CENTRAL (LAN)
echo ======================================================================
echo Ce script lance le serveur web central accessible par tous les clients du réseau local.
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

:: Vérification rapide du module Flask
%PY_CMD% -c "import flask" >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Installation des dépendances Flask...
    %PY_CMD% -m pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo [ERREUR] Échec de l'installation des dépendances serveur.
        pause
        exit /b 1
    )
)

echo.
echo [*] Démarrage du serveur web sur 0.0.0.0:5000 ...
echo.
%PY_CMD% server_minimal.py

if %errorlevel% neq 0 (
    echo.
    echo [!] Le serveur s'est arrêté avec une erreur.
    pause
)
