@echo off
setlocal
cd /d "%~dp0"
if not defined PYTHON_EXECUTABLE set "PYTHON_EXECUTABLE=%~dp0.venv\Scripts\python.exe"
"%PYTHON_EXECUTABLE%" train_pipeline.py %*
exit /b %errorlevel%
