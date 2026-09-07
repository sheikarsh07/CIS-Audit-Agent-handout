@echo off
title CIS Audit Agent - Web Dashboard & AI Chatbot
echo =================================================================
echo            CIS AUDIT AGENT v1.0 - ONE CLICK LAUNCHER
echo =================================================================
echo.
echo [*] Starting Web Server & AI Security Assistant at http://localhost:8000 ...
echo [*] Opening your web browser automatically ...
echo.

:: Open default browser after 2 seconds
start "" "http://localhost:8000"

:: Launch main web server
py -3 main.py --web

pause
