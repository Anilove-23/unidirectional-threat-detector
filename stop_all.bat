@echo off
setlocal
cd /d "%~dp0"
if not defined PYTHON_EXECUTABLE set "PYTHON_EXECUTABLE=%~dp0.venv\Scripts\python.exe"
"%PYTHON_EXECUTABLE%" pipeline_runtime.py stop
exit /b %errorlevel%
