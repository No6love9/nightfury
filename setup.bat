@echo off
REM ============================================================================
REM NightFury Framework v2.0 - All-in-One Setup Script (Windows)
REM Automated installation and configuration for Windows
REM ============================================================================

setlocal enabledelayedexpansion

REM Colors and formatting
set "GREEN=[92m"
set "RED=[91m"
set "YELLOW=[93m"
set "BLUE=[94m"
set "NC=[0m"

REM Configuration
set "FRAMEWORK_NAME=NightFury"
set "FRAMEWORK_VERSION=2.0"
set "VENV_NAME=nightfury_env"

echo.
echo ================================
echo %FRAMEWORK_NAME% Framework v%FRAMEWORK_VERSION% - Setup
echo ================================
echo.

REM Check Python installation
echo [*] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo [X] Python is not installed
    echo.
    echo Install Python from: https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('python --version') do set "PYTHON_VERSION=%%i"
echo [+] %PYTHON_VERSION% found
echo.

REM Create virtual environment
echo [*] Creating virtual environment...
if exist "%VENV_NAME%" (
    echo [!] Virtual environment already exists
    set /p "RECREATE=Remove and recreate? (y/n): "
    if /i "!RECREATE!"=="y" (
        rmdir /s /q "%VENV_NAME%"
        python -m venv "%VENV_NAME%"
    )
) else (
    python -m venv "%VENV_NAME%"
)
echo [+] Virtual environment created
echo.

REM Activate virtual environment
echo [*] Activating virtual environment...
call "%VENV_NAME%\Scripts\activate.bat"
echo [+] Virtual environment activated
echo.

REM Upgrade pip
echo [*] Upgrading pip, setuptools, and wheel...
python -m pip install --upgrade pip setuptools wheel
echo [+] pip upgraded
echo.

REM Install requirements
echo [*] Installing Python dependencies...
if not exist "requirements.txt" (
    echo [X] requirements.txt not found
    pause
    exit /b 1
)
pip install -r requirements.txt
echo [+] All dependencies installed
echo.

REM Create directories
echo [*] Creating directories...
if not exist "nightfury_reports" mkdir nightfury_reports
if not exist "nightfury_logs" mkdir nightfury_logs
if not exist "nightfury_data" mkdir nightfury_data
echo [+] Directories created
echo.

REM Create configuration file
echo [*] Creating configuration files...
if not exist "nightfury_config.json" (
    (
        echo {
        echo   "framework": {
        echo     "version": "2.0",
        echo     "mode": "balanced",
        echo     "threads": 8,
        echo     "timeout": 300
        echo   },
        echo   "reporting": {
        echo     "output_dir": "./nightfury_reports",
        echo     "auto_save": true,
        echo     "formats": ["html", "json", "csv"]
        echo   },
        echo   "gui": {
        echo     "theme": "dark",
        echo     "window_width": 1600,
        echo     "window_height": 950
        echo   },
        echo   "security": {
        echo     "proxy_rotation": true,
        echo     "evasion_enabled": true,
        echo     "cache_enabled": true
        echo   }
        echo }
    ) > nightfury_config.json
    echo [+] nightfury_config.json created
)
echo.

REM Setup Gemini AI (optional)
echo [*] Google Gemini AI Setup (Optional)
set /p "SETUP_GEMINI=Do you want to set up Google Gemini AI? (y/n): "
if /i "!SETUP_GEMINI!"=="y" (
    echo.
    echo 1. Visit: https://aistudio.google.com/app/apikeys
    echo 2. Click 'Create API Key'
    echo 3. Copy your API key
    echo.
    set /p "GEMINI_KEY=Enter your Gemini API key (or press Enter to skip): "
    
    if not "!GEMINI_KEY!"=="" (
        setx GEMINI_API_KEY "!GEMINI_KEY!"
        echo [+] Gemini API key saved to environment variables
    )
)
echo.

REM Verify installation
echo [*] Running installation verification...
if exist "verify_installation.py" (
    python verify_installation.py
) else (
    echo [!] verify_installation.py not found
)
echo.

REM Print post-installation info
echo.
echo ================================
echo Installation Complete!
echo ================================
echo.
echo NightFury Framework v2.0 is ready to use!
echo.
echo Next steps:
echo.
echo 1. Activate virtual environment:
echo    %VENV_NAME%\Scripts\activate.bat
echo.
echo 2. Start GUI Dashboard:
echo    python nightfury_gui_gemini.py
echo.
echo 3. Or use quick commands:
echo    python runehall_quick_commands.py list
echo.
echo 4. Generate reports:
echo    python nightfury_reporting_engine.py
echo.
echo Documentation:
echo    - Quick Reference: RUNEHALL_QUICK_REFERENCE.md
echo    - Gemini Setup: GEMINI_SETUP.md
echo    - Installation: INSTALLATION_GUIDE.md
echo    - Pentesting Guide: nightfury_pentesting_guide.md
echo.
echo For more information, see README.md
echo.

pause
