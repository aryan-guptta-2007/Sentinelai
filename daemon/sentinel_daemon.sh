#!/usr/bin/env bash
# Start the whole stack under the Python supervisor. Used directly or by systemd.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON="$ROOT_DIR/.venv/bin/python"
[[ -x "$PYTHON" ]] || PYTHON="python3"
exec "$PYTHON" sentinel.py run "$@"
