@echo off
rem Double-click to start the dashboard. Sets up the virtual environment on first run.
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo First run: creating the Python environment and installing packages...
    python -m venv .venv || goto :error
    ".venv\Scripts\python.exe" -m pip install -r requirements.txt || goto :error
)
".venv\Scripts\streamlit.exe" run streamlit_app.py
goto :eof

:error
echo.
echo Setup failed. Make sure Python 3.10+ is installed and on PATH.
pause
