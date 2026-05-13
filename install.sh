#!/bin/bash
# ViperV2 - Linux/macOS Installation Script

set -e

echo -e "\033[36mViperV2 Network Scanner - Setup\033[0m"
echo "================================"

# Backend
echo -e "\n\033[33m[1/3] Setting up Python backend...\033[0m"
cd backend

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

if [ ! -f .env ]; then
    cp .env.example .env
    echo "  Created .env from .env.example"
fi

cd ..

# Frontend
echo -e "\n\033[33m[2/3] Setting up Node.js frontend...\033[0m"
cd frontend
npm install
cd ..

echo -e "\n\033[32m[3/3] Done!\033[0m"
echo ""
echo -e "\033[36mTo start the application:\033[0m"
echo "  Backend:  cd backend && source .venv/bin/activate && python run.py"
echo "  Frontend: cd frontend && npm run dev"
echo ""
echo "Open http://localhost:5173 in your browser."
echo ""
echo -e "\033[33mNOTE: ARP scanning requires root (sudo python run.py) or Npcap on Windows\033[0m"
echo -e "\033[33mNOTE: Install nmap: sudo apt install nmap (Linux) or brew install nmap (macOS)\033[0m"
