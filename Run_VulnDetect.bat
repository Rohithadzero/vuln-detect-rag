@echo off
setlocal enabledelayedexpansion
title VulnDetectRAG v3.5 Startup
color 0b

:: Resolve script directory
cd /d "%~dp0"

echo ===================================================
echo    VulnDetectRAG v3.5 - Vulnerability Intelligence Platform
echo        (Nmap, Nuclei, OpenVAS, Nessus, Burp Suite, OWASP ZAP)
echo        AI: Ollama (local) or Groq (cloud)
echo ===================================================
echo.

:: 1. Check Prerequisites
echo [*] Checking for Python...
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Python is not installed or not in PATH. Please install Python 3.10+
    echo Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [*] Checking for Node.js (npm)...
where npm >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Node.js is not installed or not in PATH. Please install Node.js 18+
    echo Download from: https://nodejs.org/
    pause
    exit /b 1
)

echo [*] Checking for Nmap...
where nmap >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [INFO] Nmap not found. Scanners will use mock data.
) else (
    echo [OK] Nmap found.
)

echo [*] Checking for Nuclei...
where nuclei >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [INFO] Nuclei not found. Scanner will use mock data.
) else (
    echo [OK] Nuclei found.
)

echo [*] Checking LLM Provider configuration...
if defined LLM_PROVIDER (
    if /i "%LLM_PROVIDER%"=="groq" (
        echo [INFO] Using Groq cloud API for LLM.
        if not defined GROQ_API_KEY (
            echo [WARNING] GROQ_API_KEY not set. Set it in backend\.env or environment.
        )
    ) else (
        echo [INFO] Using Ollama local LLM.
    )
) else (
    echo [INFO] LLM_PROVIDER not set, defaulting to Ollama.
)

if not defined LLM_PROVIDER (
    echo [*] Checking for Ollama...
    where ollama >nul 2>nul
    if %ERRORLEVEL% neq 0 (
        echo [WARNING] Ollama is not installed. AI features will be disabled.
        echo Please install Ollama from https://ollama.com/
        echo Or set LLM_PROVIDER=groq to use cloud API.
        echo.
    ) else (
        echo [*] Ensuring Ollama model qwen2.5-coder:7b is downloaded...
        echo Note: This may take a while if downloading for the first time.
        call ollama run qwen2.5-coder:7b "/bye" >nul 2>nul
    )
) else if /i "%LLM_PROVIDER%"=="ollama" (
    echo [*] Checking for Ollama...
    where ollama >nul 2>nul
    if %ERRORLEVEL% neq 0 (
        echo [WARNING] Ollama is not installed. AI features will be disabled.
        echo Please install Ollama from https://ollama.com/
        echo.
    ) else (
        echo [*] Ensuring Ollama model qwen2.5-coder:7b is downloaded...
        echo Note: This may take a while if downloading for the first time.
        call ollama run qwen2.5-coder:7b "/bye" >nul 2>nul
    )
) else (
    echo [INFO] Using Groq API - no local Ollama required.
)

echo.

:: Verify backend and frontend directories exist
if not exist "backend\" (
    echo [ERROR] backend\ directory not found. Make sure you run this from the project root.
    pause
    exit /b 1
)
if not exist "frontend\" (
    echo [ERROR] frontend\ directory not found. Make sure you run this from the project root.
    pause
    exit /b 1
)

:: 2. Backend Setup
echo [1/4] Starting FastAPI Backend...
cd backend
if not exist "venv\" (
    echo [*] Creating Python virtual environment...
    python -m venv venv
    if !ERRORLEVEL! neq 0 (
        echo [ERROR] Failed to create virtual environment.
        cd ..
        pause
        exit /b 1
    )
)
echo [*] Installing Python dependencies...
call venv\Scripts\python.exe -m pip install -r requirements.txt -q
start "VulnDetectRAG Backend (Do not close)" cmd /k "cd /d "%~dp0backend" && call venv\Scripts\activate.bat && python main.py"
cd ..

echo.
:: 3. Frontend Setup
echo [2/4] Starting React Frontend...
cd frontend
if not exist "node_modules\" (
    echo [*] Installing NPM dependencies...
    call npm install
)
start "VulnDetectRAG Frontend (Do not close)" cmd /k "cd /d "%~dp0frontend" && npm run dev"
cd ..

echo.
:: 4. Seed CVE Knowledge Base
echo [3/4] Checking CVE Knowledge Base...
if not exist "scripts\seed_cve_data.py" (
    echo [INFO] Seed script not found, skipping CVE initialization.
) else (
    cd scripts
    if not exist "data\vulndetect.db" (
        echo [*] Seeding CVE database (first time setup)...
        cd ..
        call venv\Scripts\python.exe -m pip install -r requirements.txt -q 2>nul
        cd scripts
    )
    if exist "..\backend\venv" (
        echo [*] Ensuring CVE embeddings are loaded...
        ..\backend\venv\Scripts\python.exe seed_cve_data.py 2>nul || echo [INFO] CVE data may already be loaded.
    )
    cd ..
)

echo.
:: 5. Launch UI
echo [4/4] Waiting for services to initialize (8 seconds)...
timeout /t 8 /nobreak >nul

echo [*] Opening browser to application...
start http://localhost:5173

echo.
echo ===================================================
echo    VulnDetectRAG is now running!
echo.
echo    Frontend:  http://localhost:5173
echo    Backend:   http://localhost:8000
echo    API Docs:  http://localhost:8000/docs
echo.
echo    Supported Scanners:
echo       - Nmap         (port scanning, vulnerability detection)
echo       - Nuclei       (active vulnerability scanning)
echo       - OpenVAS      (vulnerability management)
echo       - Nessus       (professional vulnerability assessment)
echo       - Burp Suite   (web application security testing)
echo       - OWASP ZAP    (dynamic application security testing)
echo.
echo    Leave the two terminal windows open.
echo    To stop: close both windows or press Ctrl+C in each.
echo ===================================================
pause
