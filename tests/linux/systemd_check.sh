#!/usr/bin/env bash
# The whole product as a customer would run it: installed by setup.sh, started by the
# shipped systemd unit, in enforce mode, reading the real journal, attacked over real SSH
# from another network namespace. Run through docker/systemd-test.Dockerfile, never on a
# real host, because it creates users, changes the firewall and attacks itself.
set -uo pipefail

APP=/opt/sentinelai
DATA="$APP/data"
EVENTS="$DATA/events.jsonl"
FAILURES=0
ATTACKER_IP=10.99.0.2
HOST_IP=10.99.0.1

pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; FAILURES=$((FAILURES + 1)); }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }

wait_until() {
    local tries=0 limit="${2:-120}"
    until eval "$1"; do
        tries=$((tries + 1))
        (( tries > limit )) && return 1
        sleep 0.5
    done
}

attacker() { ip netns exec attacker "$@"; }
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=4 -o LogLevel=ERROR)

try_password() {
    sshpass -p wrong-password ssh "${SSH_OPTS[@]}" -o PreferredAuthentications=password \
        -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 "$1@$2" true 2>/dev/null
}
key_login() {
    ssh "${SSH_OPTS[@]}" -i /root/victim_key -o PasswordAuthentication=no -o BatchMode=yes "$1@$2" "$3" 2>/dev/null
}

echo "== install"
systemctl start ssh
wait_until "systemctl is-active ssh >/dev/null" 20
cp -r /src "$APP"
cd "$APP" || exit 1
rm -rf .venv venv data logs
bash utils/setup.sh >/tmp/setup.log 2>&1
check "setup.sh runs on a clean host" "[[ $? -eq 0 ]]"
sed -i 's/^run_mode = "dry-run"/run_mode = "enforce"/' config/sentinelai.toml
sed -i -e 's/^interval_sec = 30 /interval_sec = 2 /' -e 's/^integrity_interval_sec = 60 /integrity_interval_sec = 2 /' config/sentinelai.toml
cp daemon/sentinelai.service /etc/systemd/system/sentinelai.service
systemctl daemon-reload
systemctl start sentinelai
wait_until "systemctl is-active sentinelai >/dev/null && [[ -f '$DATA/state/supervisor.json' ]]" 60
check "the shipped unit starts" "systemctl is-active sentinelai >/dev/null"
sleep 3
check "it reads the journal" "$APP/.venv/bin/python sentinel.py check | grep -q 'systemd journal'"
check "every component is running" "! $APP/.venv/bin/python sentinel.py status | grep -v notifier | grep -E 'restarting|unavailable|stopped'"
check "the data folder is private" "[[ \$(stat -c '%a' '$DATA') == 700 ]]"

echo "== a remote attacker"
ip netns add attacker
ip link add veth-host type veth peer name veth-attacker
ip link set veth-attacker netns attacker
ip addr add "$HOST_IP/24" dev veth-host
ip link set veth-host up
attacker ip addr add "$ATTACKER_IP/24" dev veth-attacker
attacker ip link set veth-attacker up
attacker ip link set lo up
check "the attacker can reach the host" "attacker bash -c 'exec 3<>/dev/tcp/$HOST_IP/22'"

useradd -m -s /bin/bash victim
echo 'victim:Correct-Horse-9' | chpasswd
ssh-keygen -q -t ed25519 -N '' -f /root/victim_key
install -d -m 700 -o victim -g victim /home/victim/.ssh
install -m 600 -o victim -g victim /root/victim_key.pub /home/victim/.ssh/authorized_keys

echo "== forged lines"
# Forged as an ordinary account, because root can write anything to the journal anyway.
cp "$(command -v logger)" /tmp/sshd
chmod 755 /tmp/sshd
for attempt in 1 2 3 4 5 6; do
    su -s /bin/sh nobody -c "logger -p auth.info -t sshd 'Failed password for root from 9.9.9.9 port $attempt ssh2'"
    su -s /bin/sh nobody -c "/tmp/sshd -p auth.info -t sshd 'Failed password for root from 9.9.9.8 port $attempt ssh2'"
done
sleep 3
check "the forged lines really are in the journal" "journalctl -t sshd --no-pager | grep -q 9.9.9.9"
check "lines forged with logger are ignored" "! grep -q '9\\.9\\.9\\.9' '$EVENTS'"
check "so are lines from a copy of logger named sshd" "! grep -q '9\\.9\\.9\\.8' '$EVENTS'"
check "nothing forged reached the firewall" "! nft list ruleset 2>/dev/null | grep -q '9\\.9\\.9'"

echo "== brute force over real SSH"
for attempt in 1 2 3 4 5 6 7; do
    attacker bash -c "$(declare -p SSH_OPTS); $(declare -f try_password); try_password root $HOST_IP" || true
done
wait_until "grep -q '\"ip\":\"$ATTACKER_IP\"' '$EVENTS'" 30
check "real sshd failures arrive through the journal" "grep -q '\"ip\":\"$ATTACKER_IP\"' '$EVENTS'"
wait_until "nft list set inet sentinelai blocked4 2>/dev/null | grep -q '$ATTACKER_IP'" 30
check "the attacker's address is blocked in the kernel" "nft list set inet sentinelai blocked4 | grep -q '$ATTACKER_IP'"
check "the attacker really is cut off" "! attacker timeout 4 bash -c 'exec 3<>/dev/tcp/$HOST_IP/22'"

echo "== the firewall is wiped, as a reload or reboot would"
nft flush ruleset
wait_until "nft list set inet sentinelai blocked4 2>/dev/null | grep -q '$ATTACKER_IP'" 150
check "the block comes back without a restart" "nft list set inet sentinelai blocked4 | grep -q '$ATTACKER_IP'"
check "the attacker is cut off again" "! attacker timeout 4 bash -c 'exec 3<>/dev/tcp/$HOST_IP/22'"

echo "== unblock"
"$APP/.venv/bin/python" sentinel.py unblock "$ATTACKER_IP"
check "unblock lifts it" "attacker timeout 4 bash -c 'exec 3<>/dev/tcp/$HOST_IP/22'"

echo "== a compromised account"
# Loopback can never be blocked, so this attacker survives to log in, which is the
# case that matters: only the account lock stands between them and the host.
check "the key works before the attack" "key_login victim 127.0.0.1 true"
key_login victim 127.0.0.1 'exec sleep 300' &
SESSION=$!
sleep 1
check "a live session is running" "pgrep -u victim sleep >/dev/null"
for attempt in 1 2 3 4 5 6; do
    try_password victim 127.0.0.1 || true
done
wait_until "grep -q '\"action\":\"block_ip\"' '$DATA/audit.jsonl' && [[ \$(grep -c '\"ip\":\"127.0.0.1\"' '$EVENTS') -ge 5 ]]" 30
sleep 1
key_login victim 127.0.0.1 true
wait_until "grep -q '\"action\":\"lock_user\"' '$DATA/audit.jsonl'" 30
check "login after brute force locks the account" "grep '\"action\":\"lock_user\"' '$DATA/audit.jsonl' | grep -q '\"status\":\"applied\"'"
sleep 1
check "the lock works under the shipped unit" "passwd -S victim | awk '{print \$2}' | grep -q L"
check "the attacker's live session was ended" "! pgrep -u victim sleep >/dev/null"
check "the SSH key no longer works" "! key_login victim 127.0.0.1 true"
wait "$SESSION" 2>/dev/null

"$APP/.venv/bin/python" sentinel.py unlock victim
check "unlock gives the key back" "key_login victim 127.0.0.1 true"

echo "== persistence"
sleep 3
install -d -m 700 /root/.ssh
echo 'ssh-ed25519 AAAAC3Nza attacker' >>/root/.ssh/authorized_keys
wait_until "grep -q authorized_keys '$EVENTS' && grep -q ssh_key_changed '$DATA/alerts.jsonl'" 30
check "a planted root SSH key is seen, even with ProtectHome on" "grep -q ssh_key_changed '$DATA/alerts.jsonl'"
echo '* * * * * root /tmp/x' >/etc/cron.d/backdoor
wait_until "grep -q cron_file_changed '$DATA/alerts.jsonl'" 30
check "a new cron job is seen" "grep -q cron_file_changed '$DATA/alerts.jsonl'"
rm -f /etc/cron.d/backdoor
check "dashboard needs the token" "[[ \$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/api/threats) == 401 ]]"
TOKEN="$("$APP/.venv/bin/python" -c "import json;print(json.load(open('$DATA/state/dashboard_token.json'))['token'])")"
check "and accepts it" "[[ \$(curl -s -o /dev/null -w '%{http_code}' -H \"Authorization: Bearer \$TOKEN\" http://127.0.0.1:8080/api/incidents) == 200 ]]"
check "the token file is private" "[[ \$(stat -c '%a' '$DATA/state/dashboard_token.json') == 600 ]]"

echo "== lifecycle"
systemctl stop sentinelai
sleep 1
check "stopping leaves nothing running" "! pgrep -f 'collectors\\.|analyzer\\.|responder\\.' >/dev/null"
for attempt in 1 2 3; do
    try_password nosuchuser 127.0.0.1 || true
done
BEFORE=$(grep -c nosuchuser "$EVENTS")
systemctl start sentinelai
wait_until "[[ \$(grep -c nosuchuser '$EVENTS') -gt $BEFORE ]]" 30
check "what happened while stopped is read on return" "[[ \$(grep -c nosuchuser '$EVENTS') -gt $BEFORE ]]"

kill -9 "$(pgrep -f 'analyzer.anomaly_detector' | head -1)"
sleep 4
check "a killed component is restarted" "pgrep -f 'analyzer.anomaly_detector' >/dev/null"
kill -9 "$(pgrep -f 'sentinel.py run' | head -1)"
wait_until "systemctl is-active sentinelai >/dev/null && pgrep -f 'analyzer.rule_engine' >/dev/null" 40
check "systemd restarts a killed supervisor" "systemctl is-active sentinelai >/dev/null"
check "no second copy is left behind" "[[ \$(pgrep -fc 'analyzer.rule_engine') -eq 1 ]]"
check "the audit log verifies" "$APP/.venv/bin/python sentinel.py audit | grep -q intact"

echo
if (( FAILURES > 0 )); then
    echo "--- diagnostics"
    systemctl status sentinelai --no-pager | head -12
    tail -8 "$APP/logs/collectors.log"
    tail -5 "$APP/logs/log_monitor.out.log"
    tail -5 "$APP/logs/supervisor.log"
    journalctl -t sshd -n 6 --no-pager | cut -c1-120
    tail -3 "$EVENTS" | cut -c1-200
    cut -c1-90 "$DATA/state/journal_cursor.json"
    ps -eo args | grep -E '[j]ournalctl' | cut -c1-120
    echo "$FAILURES check(s) failed"
    exit 1
fi
echo "All systemd checks passed"
