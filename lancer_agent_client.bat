@echo off
chcp 65001 >nul
title Agent Client CNIBE (Port 5001)
echo ======================================================================
echo   DEMARRAGE DE L'AGENT CLIENT CNIBE (POSTE UTILISATEUR)
echo ======================================================================
echo.
echo Cet agent communique avec votre lecteur NFC USB sur ce PC
echo et repond aux requetes de l'application web du serveur.
echo.
py -3.11 cnibe_agent.py
pause
