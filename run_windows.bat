@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 (
  echo Python Launcher not found. Install Python 3.11 and enable PATH.
  pause
  exit /b 1
)
py -3.11 --version >nul 2>nul
if errorlevel 1 (
  echo Python 3.11 not found. Install Python 3.11 and enable the Python Launcher.
  pause
  exit /b 1
)
if not exist ".runtime-temp" mkdir ".runtime-temp"
if not exist "pip-cache" mkdir "pip-cache"
set "TEMP=%CD%\.runtime-temp"
set "TMP=%CD%\.runtime-temp"
set "PIP_CACHE_DIR=%CD%\pip-cache"
if not exist ".venv\Scripts\python.exe" (
  py -3.11 -m venv .venv
  if errorlevel 1 (
    echo Failed to create the virtual environment.
    pause
    exit /b 1
  )
)
".venv\Scripts\python.exe" -c "import streamlit" >nul 2>nul
if errorlevel 1 (
  ".venv\Scripts\python.exe" -m pip install -r requirements.txt
  if errorlevel 1 (
    echo Configured package source failed. Retrying with official PyPI.
    ".venv\Scripts\python.exe" -m pip install --index-url https://pypi.org/simple -r requirements.txt
    if errorlevel 1 (
      echo Failed to install dependencies. Check the network and try again.
      pause
      exit /b 1
    )
  )
)
".venv\Scripts\python.exe" -m streamlit run app.py --server.address 127.0.0.1
pause
