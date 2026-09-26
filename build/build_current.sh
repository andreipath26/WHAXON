#!/bin/sh
# Build a single-file executable for the OS/architecture where this runs.
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"
python3 -m venv .build-venv
. .build-venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
mkdir -p dist
pyinstaller --noconfirm --clean --onefile --name SecureLab --collect-all paramiko --collect-all flask app/secure_lab.py
printf '\nBuild output: %s/dist/SecureLab*\n' "$ROOT"
