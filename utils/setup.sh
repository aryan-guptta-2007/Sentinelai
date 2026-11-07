#!/usr/bin/env bash
# Set up SentinelAI on Linux. Safe to run more than once.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))'; then
    echo "SentinelAI needs Python 3.11 or newer." >&2
    exit 1
fi

[[ -d .venv ]] || python3 -m venv .venv
.venv/bin/python -m pip install --quiet --upgrade pip
.venv/bin/python -m pip install --quiet -r requirements.txt

mkdir -p data/state logs reporter-output/reports
chmod 700 data logs
chmod +x daemon/*.sh responder/*.sh utils/*.sh

# Blocking your own session is the easiest way to get locked out of a remote host,
# so the address you are connected from goes on the allow-list.
if [[ -n "${SSH_CLIENT:-}" ]]; then
    admin_ip="${SSH_CLIENT%% *}"
    if ! grep -qxF "$admin_ip" config/allowlist_ips.txt; then
        echo "$admin_ip" >>config/allowlist_ips.txt
        echo "Added your SSH address $admin_ip to config/allowlist_ips.txt"
    fi
fi

.venv/bin/python sentinel.py check

cat <<'EOF'

Setup finished. SentinelAI starts in dry-run mode.
  Try it:     .venv/bin/python sentinel.py demo
  Run it:     sudo .venv/bin/python sentinel.py run
  Enforce:    set run_mode = "enforce" in config/sentinelai.toml
EOF
