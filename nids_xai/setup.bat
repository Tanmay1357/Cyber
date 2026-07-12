@echo off
REM =============================================================================
REM NIDS with XAI - Setup Script (Windows)
REM =============================================================================
REM This script sets up the virtual environment and installs dependencies.
REM Run by double-clicking or from command prompt: setup.bat
REM =============================================================================

echo ========================================
echo   NIDS with XAI - Setup Script
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python not found. Please install Python 3.8 or higher.
    echo Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Display Python version
python --version

REM Create virtual environment
echo.
echo Creating virtual environment...
python -m venv venv

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Upgrade pip
echo.
echo Upgrading pip...
python -m pip install --upgrade pip

REM Install dependencies
echo.
echo Installing dependencies...
pip install -r requirements.txt

REM Create necessary directories
echo.
echo Creating directories...
if not exist "data\raw" mkdir data\raw
if not exist "data\processed" mkdir data\processed
if not exist "models" mkdir models
if not exist "outputs" mkdir outputs
if not exist "logs" mkdir logs

REM Success message
echo.
echo ========================================
echo   Setup Complete!
echo ========================================
echo.
echo To activate the virtual environment:
echo   venv\Scripts\activate.bat
echo.
echo To run the application:
echo   python main.py
echo.
echo To deactivate the virtual environment:
echo   deactivate
echo.
echo Don't forget to place your dataset files in:
echo   data\raw\
echo.

pause
