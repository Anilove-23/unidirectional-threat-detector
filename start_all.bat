@echo off
setlocal
cd /d "%~dp0"
if not defined PYTHON_EXECUTABLE set "PYTHON_EXECUTABLE=%~dp0.venv\Scripts\python.exe"
if "%~1"=="--stop" (
  "%PYTHON_EXECUTABLE%" pipeline_runtime.py stop
  exit /b %errorlevel%
)
"%PYTHON_EXECUTABLE%" pipeline_runtime.py start %*
exit /b %errorlevel%
