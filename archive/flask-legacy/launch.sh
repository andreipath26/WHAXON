#!/bin/sh
set -eu
BASE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if [ -x "$BASE/runtime/bin/python" ]; then PY="$BASE/runtime/bin/python"; else PY="python3"; fi
exec "$PY" "$BASE/app/secure_lab.py"
