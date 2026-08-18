#!/bin/bash

# VulnDetectRAG v3.5 — Startup Script for macOS / Linux
# Run: chmod +x Run_VulnDetect.sh && ./Run_VulnDetect.sh

set -e

# Resolve script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
YELLOW='\033[1;33m'
GREEN='\033[1;32m'
RED='\033[1;31m'
CYAN='\033[1;36m'
NC='\033[0m'

clear
echo -e "${CYAN}===================================================${NC}"
echo -e "${CYAN}   VulnDetectRAG v3.5 — Vulnerability Intelligence Platform${NC}"
echo -e "${CYAN}   (Nmap, Nuclei, OpenVAS, Nessus, Burp Suite, OWASP ZAP)${NC}"
echo -e "${CYAN}   AI: Ollama (local) or Groq (cloud)${NC}"
echo -e "${CYAN}===================================================${NC}"
echo

# 1. Check Prerequisites
echo -e "${YELLOW}[*]${NC} Checking for Python..."
if command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1; then
    echo -e "${GREEN}[OK]${NC} Python found."
else
    echo -e "${RED}[ERROR]${NC} Python not found. Please install Python 3.10+"
    exit 1
fi

echo -e "${YELLOW}[*]${NC} Checking for Node.js..."
if command -v npm >/dev/null 2>&1; then
    echo -e "${GREEN}[OK]${NC} Node.js found."
else
    echo -e "${RED}[ERROR]${NC} Node.js not found. Please install Node.js 18+"
    exit 1
fi

echo -e "${YELLOW}[*]${NC} Checking for Nmap..."
if command -v nmap >/dev/null 2>&1; then
    echo -e "${GREEN}[OK]${NC} Nmap found."
else
    echo -e "${CYAN}[INFO]${NC} Nmap not found. Scanners will use mock data."
fi

echo -e "${YELLOW}[*]${NC} Checking for Nuclei..."
if command -v nuclei >/dev/null 2>&1; then
    echo -e "${GREEN}[OK]${NC} Nuclei found."
else
    echo -e "${CYAN}[INFO]${NC} Nuclei not found. Scanner will use mock data."
fi

echo -e "${YELLOW}[*]${NC} Checking for Ollama..."
if command -v ollama >/dev/null 2>&1; then
    echo -e "${GREEN}[OK]${NC} Ollama found."
    echo -e "${YELLOW}[*]${NC} Ensuring qwen2.5-coder:7b model is downloaded..."
    ollama run qwen2.5-coder:7b "/bye" >/dev/null 2>&1 || true
else
    echo -e "${RED}[WARNING]${NC} Ollama not found. AI features will be disabled."
fi

echo
echo -e "${CYAN}Prerequisites check complete.${NC}"
echo

# 2. Backend Setup
echo -e "${YELLOW}[1/4]${NC} Starting FastAPI Backend..."
BACKEND_DIR="$SCRIPT_DIR/backend"
FRONTEND_DIR="$SCRIPT_DIR/frontend"

if [[ ! -d "$BACKEND_DIR" ]]; then
    echo -e "${RED}[ERROR]${NC} backend/ directory not found at $BACKEND_DIR"
    exit 1
fi

if [[ ! -d "$BACKEND_DIR/venv" ]]; then
    echo -e "${YELLOW}[*]${NC} Creating Python virtual environment..."
    if command -v python3 >/dev/null 2>&1; then
        python3 -m venv "$BACKEND_DIR/venv"
    else
        python -m venv "$BACKEND_DIR/venv"
    fi
fi

echo -e "${YELLOW}[*]${NC} Installing Python dependencies..."
source "$BACKEND_DIR/venv/bin/activate"
pip install -r "$BACKEND_DIR/requirements.txt" -q

# Open new terminal window for backend
if [[ "$(uname -s)" == "Darwin" ]]; then
    # macOS
    osascript <<EOF
tell application "Terminal"
    do script "cd \"$BACKEND_DIR\" && source venv/bin/activate && python main.py"
end tell
EOF
elif [[ "$(uname -s)" == "Linux" ]]; then
    if command -v gnome-terminal >/dev/null 2>&1; then
        gnome-terminal -- bash -c "cd '$BACKEND_DIR' && source venv/bin/activate && python main.py; exec bash"
    elif command -v xterm >/dev/null 2>&1; then
        xterm -e "cd '$BACKEND_DIR' && source venv/bin/activate && python main.py" &
    else
        echo -e "${YELLOW}[INFO]${NC} Please run manually in another terminal:"
        echo "  cd $BACKEND_DIR && source venv/bin/activate && python main.py"
    fi
else
    echo -e "${YELLOW}[INFO]${NC} Please run manually: cd backend && source venv/bin/activate && python main.py"
fi

echo
# 3. Frontend Setup
echo -e "${YELLOW}[2/4]${NC} Starting React Frontend..."

if [[ ! -d "$FRONTEND_DIR" ]]; then
    echo -e "${RED}[ERROR]${NC} frontend/ directory not found at $FRONTEND_DIR"
    exit 1
fi

if [[ ! -d "$FRONTEND_DIR/node_modules" ]]; then
    echo -e "${YELLOW}[*]${NC} Installing NPM dependencies..."
    (cd "$FRONTEND_DIR" && npm install)
fi

# Open new terminal window for frontend
if [[ "$(uname -s)" == "Darwin" ]]; then
    osascript <<EOF
tell application "Terminal"
    do script "cd \"$FRONTEND_DIR\" && npm run dev"
end tell
EOF
elif [[ "$(uname -s)" == "Linux" ]]; then
    if command -v gnome-terminal >/dev/null 2>&1; then
        gnome-terminal -- bash -c "cd '$FRONTEND_DIR' && npm run dev; exec bash"
    elif command -v xterm >/dev/null 2>&1; then
        xterm -e "cd '$FRONTEND_DIR' && npm run dev" &
    else
        echo -e "${YELLOW}[INFO]${NC} Please run manually in another terminal:"
        echo "  cd $FRONTEND_DIR && npm run dev"
    fi
else
    echo -e "${YELLOW}[INFO]${NC} Please run manually: cd frontend && npm run dev"
fi

echo
# 4. Seed CVE Knowledge Base
echo -e "${YELLOW}[3/4]${NC} Checking CVE Knowledge Base..."
if [[ -f "$SCRIPT_DIR/scripts/seed_cve_data.py" ]]; then
    if [[ ! -f "$SCRIPT_DIR/scripts/data/vulndetect.db" ]]; then
        echo -e "${YELLOW}[*]${NC} Seeding CVE database (first time setup)..."
        cd "$SCRIPT_DIR/scripts"
        source "$BACKEND_DIR/venv/bin/activate"
        python seed_cve_data.py 2>/dev/null || true
        cd "$SCRIPT_DIR"
    else
        echo -e "${GREEN}[OK]${NC} CVE database already initialized."
    fi
else
    echo -e "${CYAN}[INFO]${NC} Seed script not found, skipping CVE initialization."
fi

echo
# 5. Launch UI
echo -e "${YELLOW}[4/4]${NC} Waiting for services to initialize..."
sleep 5

echo -e "${YELLOW}[*]${NC} Opening browser..."
if [[ "$(uname -s)" == "Darwin" ]]; then
    open http://localhost:5173
elif [[ "$(uname -s)" == "Linux" ]]; then
    xdg-open http://localhost:5173 2>/dev/null || true
fi

echo
echo -e "${CYAN}===================================================${NC}"
echo -e "${GREEN}   VulnDetectRAG is now running!${NC}"
echo -e "${CYAN}===================================================${NC}"
echo
echo "  Frontend:  http://localhost:5173"
echo "  Backend:   http://localhost:8000"
echo "  API Docs:  http://localhost:8000/docs"
echo
echo "  Supported Scanners:"
echo "     - Nmap         (port scanning, vulnerability detection)"
echo "     - Nuclei       (active vulnerability scanning)"
echo "     - OpenVAS      (vulnerability management)"
echo "     - Nessus       (professional vulnerability assessment)"
echo "     - Burp Suite   (web application security testing)"
echo "     - OWASP ZAP    (dynamic application security testing)"
echo
echo "  Leave the terminal windows open."
echo "  To stop: close both windows or press Ctrl+C in each."
echo -e "${CYAN}===================================================${NC}"
echo

read -p "Press Enter to exit this script..."
