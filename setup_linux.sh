#!/usr/bin/env bash
set -euo pipefail
PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"
if command -v uv >/dev/null 2>&1; then
  if [[ ! -x .venv_linux/bin/python ]]; then uv venv .venv_linux --python 3.13; fi
  uv pip install --python .venv_linux/bin/python -r requirements.txt
  uv pip check --python .venv_linux/bin/python
else
  if [[ ! -x .venv_linux/bin/python ]]; then python3 -m venv .venv_linux; fi
  .venv_linux/bin/python -m ensurepip --upgrade
  .venv_linux/bin/python -m pip install -r requirements.txt
  .venv_linux/bin/python -m pip check
fi
npm --prefix perosn4/backend install
npm --prefix soc-dashboard install
echo 'Ready. Start services with: bash start_all.sh --sim'
