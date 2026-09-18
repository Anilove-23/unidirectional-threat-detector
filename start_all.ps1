$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$python = $env:PYTHON_EXECUTABLE
if (-not $python) { $python = Join-Path $PSScriptRoot '.venv/Scripts/python.exe' }
if (-not (Test-Path $python)) { throw 'Create .venv and install requirements.txt first.' }
if ($args.Count -gt 0 -and $args[0] -eq '--stop') { & $python pipeline_runtime.py stop } else { & $python pipeline_runtime.py start @args }
exit $LASTEXITCODE
