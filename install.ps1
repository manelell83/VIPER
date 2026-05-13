# ViperV2 - Windows Installation Script
# Run as Administrator for Npcap/Nmap features

Write-Host "ViperV2 Network Scanner - Setup" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan

# Backend setup
Write-Host "`n[1/3] Setting up Python backend..." -ForegroundColor Yellow
Set-Location backend

if (-not (Test-Path ".venv")) {
    python -m venv .venv
}

.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

if (-not (Test-Path ".env")) {
    Copy-Item .env.example .env
    Write-Host "  Created .env from .env.example" -ForegroundColor Green
}

Set-Location ..

# Frontend setup
Write-Host "`n[2/3] Setting up Node.js frontend..." -ForegroundColor Yellow
Set-Location frontend

npm install

Set-Location ..

Write-Host "`n[3/3] Done!" -ForegroundColor Green
Write-Host ""
Write-Host "To start the application:" -ForegroundColor Cyan
Write-Host "  Backend:  cd backend && .\.venv\Scripts\Activate.ps1 && python run.py" -ForegroundColor White
Write-Host "  Frontend: cd frontend && npm run dev" -ForegroundColor White
Write-Host ""
Write-Host "Open http://localhost:5173 in your browser." -ForegroundColor Cyan
Write-Host ""
Write-Host "NOTE: For ARP scanning, install Npcap from https://npcap.com" -ForegroundColor Yellow
Write-Host "NOTE: For Nmap port scanning, install Nmap from https://nmap.org" -ForegroundColor Yellow
