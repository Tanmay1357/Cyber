@echo off
REM =============================================================================
REM  NIDS-XAI  -  One-click launcher (Windows)
REM =============================================================================
REM  Starts the backend (FastAPI) FIRST, waits until it is ready, then starts
REM  the dashboard (React) and opens the browser. Starting the backend first
REM  avoids the "http proxy error / ECONNREFUSED" messages that appear when the
REM  dashboard starts before the backend is listening.
REM
REM  Run setup first:  nids_xai\setup.bat  and  (in web\)  npm install
REM =============================================================================

echo ========================================
echo   Starting NIDS-XAI...
echo ========================================
echo.

REM --- 1. Start the backend in its own window ---
if exist "%~dp0nids_xai\venv\Scripts\activate.bat" (
    start "NIDS-XAI Backend" cmd /k "cd /d %~dp0nids_xai && call venv\Scripts\activate.bat && uvicorn api.main:app --host 0.0.0.0 --port 8000"
) else (
    echo WARNING: backend environment not found.
    echo Run nids_xai\setup.bat first.
    echo.
    pause
    exit /b 1
)

REM --- 2. Wait until the backend answers on port 8000 (up to ~60 seconds) ---
echo Waiting for the backend to start (loading the model)...
set /a tries=0
:waitbackend
curl -s -o nul http://localhost:8000/api/status
if not errorlevel 1 goto backendready
set /a tries+=1
if %tries% geq 30 (
    echo Backend did not respond in time; starting the dashboard anyway.
    goto startfrontend
)
timeout /t 2 >nul
goto waitbackend
:backendready
echo Backend is ready.

REM --- 3. Start the dashboard in its own window ---
:startfrontend
start "NIDS-XAI Dashboard" cmd /k "cd /d %~dp0web && npm run dev"

REM --- 4. Give the dashboard a moment, then open the browser ---
timeout /t 5 >nul
start "" http://localhost:5173

echo.
echo NIDS-XAI is starting in two new windows.
echo Dashboard: http://localhost:5173
echo To stop:   press Ctrl + C in each window, then close it.
echo.
