#!/usr/bin/env python3
"""Exercise real nftables, iptables, usermod and kill inside a disposable container."""

from __future__ import annotations

import copy
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

home = Path(tempfile.mkdtemp())
shutil.copytree(ROOT / "config", home / "config")
os.environ["SENTINELAI_HOME"] = str(home)
os.environ.pop("SENTINELAI_DATA_DIR", None)

from common.runtime import get_paths, load_config, now_iso  # noqa: E402
from responder.firewall import Firewall  # noqa: E402
from responder.responder import Responder  # noqa: E402
from responder.system import parse_ip  # noqa: E402

failures = 0


def check(label: str, ok: bool, extra: str = "") -> None:
    global failures
    print(f"{'PASS' if ok else 'FAIL'}  {label} {extra}".rstrip())
    failures += 0 if ok else 1


def shell(*argv: str) -> str:
    done = subprocess.run(argv, capture_output=True, text=True, check=False)
    return done.stdout + done.stderr


def responder(firewall: str, **section) -> Responder:
    config = copy.deepcopy(load_config())
    config["modes"]["run_mode"] = "enforce"
    config["responder"]["firewall"] = firewall
    config["responder"].update(section)
    return Responder(config, get_paths(config).ensure())


def threat(action: str, target: str, **event) -> dict:
    return {
        "ts": now_iso(),
        "plan": [{"action": action, "target": target}],
        "alert": {"type": "test", "event": {"ts": now_iso(), **event}},
    }


def run(instance: Responder, item: dict) -> dict:
    return instance.handle(item)[0]


def blocked4() -> str:
    return shell("nft", "list", "set", "inet", "sentinelai", "blocked4")


# ------------------------------------------------------------------- nftables
nft = responder("nft")
entry = run(nft, threat("block_ip", "203.0.113.5"))
check("nft block applied", entry["status"] == "applied", str(entry))
check("nft set holds the address", "203.0.113.5" in blocked4())
check("nft entry has a timeout", "timeout" in blocked4())

entry = run(nft, threat("block_ip", "2001:db8::5"))
check("nft IPv6 block applied", entry["status"] == "applied", str(entry))
check("IPv6 uses the v6 set", "2001:db8::5" in shell("nft", "list", "set", "inet", "sentinelai", "blocked6"))
check("present() reads the kernel", {"203.0.113.5", "2001:db8::5"} <= (nft.firewall.present() or set()))

second = responder("nft")
run(second, threat("block_ip", "203.0.113.6"))
rules = shell("nft", "list", "chain", "inet", "sentinelai", "input")
check("restart does not duplicate rules", rules.count("@blocked4") == 1, rules)
forward = shell("nft", "list", "chain", "inet", "sentinelai", "forward")
check("forwarded traffic is covered", "@blocked4" in forward, forward)

ok, detail = nft.unblock("203.0.113.5")
check("nft unblock", ok, detail)
check("nft set no longer holds it", "203.0.113.5" not in blocked4())

short = Firewall("nft")
short.block(parse_ip("203.0.113.8"), 1)
time.sleep(2.5)
check("nft timeout expires by itself", "203.0.113.8" not in blocked4())
check("unblocking an expired address is not an error", short.unblock(parse_ip("203.0.113.8"))[0])

# Regression: after a firewall reload every block failed until a restart.
shell("nft", "flush", "ruleset")
ok, detail = second.firewall.block(parse_ip("203.0.113.81"), 60)
check("a block after `nft flush ruleset` rebuilds the table", ok, detail)
check("the address really is in the rebuilt set", "203.0.113.81" in blocked4())

# Regression: a reboot left the state saying "already blocked" while the kernel was empty.
run(second, threat("block_ip", "203.0.113.82"))
shell("nft", "flush", "ruleset")
after_reboot = responder("nft")
restored = after_reboot.reconcile()
check("reconcile restores blocks the kernel lost", "203.0.113.82" in restored, str(restored))
check("the restored block is really there", "203.0.113.82" in blocked4())
check("a second reconcile finds nothing to do", responder("nft").reconcile() == [])

shell("nft", "flush", "ruleset")
entry = run(responder("nft"), threat("block_ip", "203.0.113.82"))
check("a returning attacker is put back", "203.0.113.82" in blocked4(), str(entry))
shell("nft", "delete", "table", "inet", "sentinelai")

# ------------------------------------------------------------------- iptables
if shutil.which("iptables") and "Permission denied" not in shell("iptables", "-L", "INPUT"):
    fw = Firewall("iptables")
    ok, detail = fw.block(parse_ip("203.0.113.9"), 60)
    check("iptables block", ok, detail)
    fw.block(parse_ip("203.0.113.9"), 60)
    listing = shell("iptables", "-S", "INPUT")
    check("iptables rule added once", listing.count("203.0.113.9") == 1, listing)
    check("present() reads iptables", "203.0.113.9" in (fw.present() or set()))
    ok, detail = fw.unblock(parse_ip("203.0.113.9"))
    check("iptables unblock", ok and "203.0.113.9" not in shell("iptables", "-S", "INPUT"), detail)
else:
    print("SKIP  iptables is not usable in this container")

# ------------------------------------------------------------------- processes
victim = subprocess.Popen(["sleep", "60"])
time.sleep(0.2)
killer = responder("auto", kill_protected_users=True)
entry = run(killer, threat("kill_process", str(victim.pid), meta={"proc": "wrong-name"}))
check("wrong identity refused", entry["status"] == "refused" and victim.poll() is None, str(entry))
entry = run(killer, threat("kill_process", str(victim.pid), meta={"proc": "sleep"}))
check("real process killed", entry["status"] == "applied", str(entry))
victim.wait(timeout=5)

victim = subprocess.Popen(["sleep", "60"])
time.sleep(0.2)
entry = run(responder("auto"), threat("kill_process", str(victim.pid), meta={"proc": "sleep"}))
check("root-owned process protected by default", entry["status"] == "refused", str(entry))
check("protected process survived", victim.poll() is None)
victim.kill()
victim.wait()

# ------------------------------------------------------------------------ users
subprocess.run(["useradd", "-m", "sentinel-test"], check=True)
subprocess.run(["chpasswd"], input="sentinel-test:Passw0rd!\n", text=True, check=True)
session = subprocess.Popen(["su", "-s", "/bin/sh", "sentinel-test", "-c", "exec sleep 60"])
time.sleep(0.5)

instance = responder("auto")
entry = run(instance, threat("lock_user", "sentinel-test"))
check("real account locked", entry["status"] == "applied", str(entry))
check("shadow shows the lock", shell("passwd", "-S", "sentinel-test").split()[1] == "L")
expiry = shell("chage", "-l", "sentinel-test")
check("the account is expired, which stops key logins", "Jan 02, 1970" in expiry, expiry)
time.sleep(0.5)
left = shell("pgrep", "-u", "sentinel-test", "-a").strip()
check("the account's running processes were ended", left == "", left)
session.wait(timeout=5)

entry = run(instance, threat("lock_user", "no-such-user"))
check("a missing account is reported as failed", entry["status"] == "failed", str(entry))

ok, detail = instance.unlock_user("sentinel-test")
check("unlock works", ok, detail)
check("the password is usable again", shell("passwd", "-S", "sentinel-test").split()[1] == "P")
expiry = shell("chage", "-l", "sentinel-test")
check("the expiry is back to what it was", "Account expires\t\t\t\t\t\t: never" in expiry, expiry)
subprocess.run(["userdel", "-r", "sentinel-test"], check=False, capture_output=True)

sys.exit(1 if failures else 0)
