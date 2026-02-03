@echo off
REM ============================================================================
REM NightFury Framework v2.0 - Setup Script (Windows)
REM Automated installation, configuration, and verification
REM ============================================================================

setlocal enabledelayedexpansion

REM Color codes (using ANSI escape sequences)
set "GREEN=[92m"
set "RED=[91m"
set "YELLOW=[93m"
set "BLUE=[94m"
set "CYAN=[96m"
set "NC=[0m"

REM Configuration
set "FRAMEWORK_NAME=NightFury"
set "FRAMEWORK_VERSION=2.0"
set "VENV_NAME=nightfury_env"
set "REPO_URL=https://github.com/No6love9/nightfury.git"

REM Logging functions
setlocal enabledelayedexpansion

:log_info
echo [*] %~1
goto :eof

:log_success
echo [+] %~1
goto :eof

:log_error
echo [X] %~1
goto :eof

:log_warning
echo [!] %~1
goto :eof

:log_section
echo.
echo ================================
echo %~1
echo ================================
echo.
goto :eof

REM Banner
:print_banner
cls
echo.
echo ╔════════════════════════════════════════════════════════════════╗
echo ║                                                                ║
echo ║          %FRAMEWORK_NAME% Framework v%FRAMEWORK_VERSION% - Setup Wizard                    ║
echo ║                                                                ║
echo ║     Professional Penetration Testing Platform                 ║
echo ║     with Google Gemini AI Integration                         ║
echo ║                                                                ║
echo ╚════════════════════════════════════════════════════════════════╝
echo.
goto :eof

REM Check Python installation
:check_python
call :log_section "Python Version Check"

python --version >nul 2>&1
if errorlevel 1 (
    call :log_error "Python is not installed"
    echo.
    echo Install Python from: https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('python --version 2^>^&1') do set "PYTHON_VERSION=%%i"
call :log_success "%PYTHON_VERSION% found"
goto :eof

REM Install system dependencies (Windows-specific)
:install_system_deps
call :log_section "System Dependencies"

call :log_info "Checking for required tools..."

REM Check for Git
git --version >nul 2>&1
if errorlevel 1 (
    call :log_warning "Git not found. Install from: https://git-scm.com/download/win"
) else (
    call :log_success "Git found"
)

REM Check for Visual C++ Build Tools
where cl.exe >nul 2>&1
if errorlevel 1 (
    call :log_warning "Visual C++ Build Tools not found"
    echo Install from: https://visualstudio.microsoft.com/downloads/
    echo Select 'Desktop development with C++'
) else (
    call :log_success "Visual C++ Build Tools found"
)

goto :eof

REM Create virtual environment
:create_venv
call :log_section "Virtual Environment Setup"

if exist "%VENV_NAME%" (
    call :log_warning "Virtual environment already exists"
    set /p "RECREATE=Remove and recreate? (y/n): "
    if /i "!RECREATE!"=="y" (
        rmdir /s /q "%VENV_NAME%"
        call :log_info "Creating new virtual environment..."
        python -m venv "%VENV_NAME%"
    )
) else (
    call :log_info "Creating virtual environment..."
    python -m venv "%VENV_NAME%"
)

call :log_success "Virtual environment created at: %VENV_NAME%"
goto :eof

REM Activate virtual environment
:activate_venv
call :log_info "Activating virtual environment..."
call "%VENV_NAME%\Scripts\activate.bat"
call :log_success "Virtual environment activated"
goto :eof

REM Upgrade pip
:upgrade_pip
call :log_section "Pip Upgrade"

call :log_info "Upgrading pip, setuptools, and wheel..."
python -m pip install --upgrade pip setuptools wheel >nul 2>&1
call :log_success "Pip upgraded"
goto :eof

REM Install dependencies
:install_dependencies
call :log_section "Python Dependencies Installation"

if not exist "requirements.txt" (
    call :log_error "requirements.txt not found"
    pause
    exit /b 1
)

call :log_info "Installing Python packages from requirements.txt..."
pip install -r requirements.txt
if errorlevel 1 (
    call :log_error "Installation failed"
    pause
    exit /b 1
)
call :log_success "All dependencies installed"
goto :eof

REM Create directories
:create_directories
call :log_section "Directory Structure"

call :log_info "Creating directories..."
if not exist "nightfury_reports" mkdir nightfury_reports
if not exist "nightfury_logs" mkdir nightfury_logs
if not exist "nightfury_data" mkdir nightfury_data
call :log_success "Directories created"
goto :eof

REM Create configuration file
:create_config
call :log_section "Configuration Setup"

if exist "nightfury_config.json" (
    call :log_warning "Configuration file already exists"
    goto :eof
)

call :log_info "Creating configuration file..."
(
    echo {
    echo   "framework": {
    echo     "version": "2.0",
    echo     "mode": "balanced",
    echo     "threads": 8,
    echo     "timeout": 300,
    echo     "max_retries": 3
    echo   },
    echo   "reporting": {
    echo     "output_dir": "./nightfury_reports",
    echo     "auto_save": true,
    echo     "formats": ["html", "json", "csv"],
    echo     "include_screenshots": true
    echo   },
    echo   "gui": {
    echo     "theme": "dark",
    echo     "window_width": 1600,
    echo     "window_height": 950,
    echo     "auto_save_interval": 300
    echo   },
    echo   "security": {
    echo     "proxy_rotation": true,
    echo     "evasion_enabled": true,
    echo     "cache_enabled": true,
    echo     "cache_size_mb": 1024,
    echo     "ssl_verify": false
    echo   },
    echo   "logging": {
    echo     "level": "INFO",
    echo     "format": "json",
    echo     "rotation": "10 MB",
    echo     "retention": "30 days"
    echo   },
    echo   "ai": {
    echo     "provider": "gemini",
    echo     "auto_analysis": true,
    echo     "confidence_threshold": 0.85
    echo   }
    echo }
) > nightfury_config.json
call :log_success "Configuration file created"
goto :eof

REM Setup Gemini AI
:setup_gemini
call :log_section "Google Gemini AI Setup (Optional)"

set /p "SETUP_GEMINI=Do you want to set up Google Gemini AI? (y/n): "

if /i "!SETUP_GEMINI!"=="y" (
    echo.
    call :log_info "Getting your Gemini API key:"
    echo   1. Visit: https://aistudio.google.com/app/apikeys
    echo   2. Click 'Create API Key'
    echo   3. Copy your API key
    echo.
    
    set /p "GEMINI_KEY=Enter your Gemini API key (or press Enter to skip): "
    
    if not "!GEMINI_KEY!"=="" (
        setx GEMINI_API_KEY "!GEMINI_KEY!"
        call :log_success "Gemini API key saved to environment variables"
    ) else (
        call :log_warning "Gemini API key skipped"
    )
)
goto :eof

REM Verify installation
:verify_installation
call :log_section "Installation Verification"

if exist "verify_installation.py" (
    call :log_info "Running installation verification..."
    python verify_installation.py
) else (
    call :log_warning "verify_installation.py not found, skipping verification"
)
goto :eof

REM Create startup script
:create_startup_script
call :log_section "Startup Script Creation"

call :log_info "Creating startup script..."
(
    echo @echo off
    echo call %VENV_NAME%\Scripts\activate.bat
    echo python nightfury_gui_gemini.py
) > start_nightfury.bat
call :log_success "Startup script created: start_nightfury.bat"
goto :eof

REM Print post-installation info
:print_post_install
call :log_section "Installation Complete!"

echo NightFury Framework v%FRAMEWORK_VERSION% is ready to use!
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
echo Repository: %REPO_URL%
echo.
goto :eof

REM Main installation flow
:main
call :print_banner
call :check_python
call :install_system_deps
call :create_venv
call :activate_venv
call :upgrade_pip
call :install_dependencies
call :create_directories
call :create_config
call :setup_gemini
call :verify_installation
call :create_startup_script
call :print_post_install

echo [+] Setup completed successfully!
echo.
pause
goto :eof

REM Entry point
call :main
endlocal
