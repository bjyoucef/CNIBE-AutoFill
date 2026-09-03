@echo off
chcp 65001 >nul
title Serveur Flask Minimal CNIBE (Port 5000)
echo ======================================================================
echo   DEMARRAGE DU SERVEUR FLASK TEST CNIBE (LAN 0.0.0.0:5000)
echo ======================================================================
echo.
py -3.11 server_minimal.py
pause
