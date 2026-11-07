#!/usr/bin/env bash
# The responder is implemented in Python. This wrapper keeps the old path working.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON="$ROOT_DIR/.venv/bin/python"
[[ -x "$PYTHON" ]] || PYTHON="python3"
exec "$PYTHON" -m responder.responder "$@"
