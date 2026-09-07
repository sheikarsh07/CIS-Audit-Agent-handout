# CIS Audit Agent 1-Click PowerShell Launcher
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "           CIS AUDIT AGENT v1.0 - ONE CLICK LAUNCHER" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[*] Launching Web Dashboard & AI Chatbot at http://localhost:8000 ..." -ForegroundColor Green

Start-Process "http://localhost:8000"
py -3 main.py --web
