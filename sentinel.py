#!/usr/bin/env python3
"""SentinelAI command line."""

from __future__ import annotations

import argparse
import ctypes
import os
import shutil
import subprocess
import sys
import threading
from typing import List, Optional

from common.runtime import (
    CODE_ROOT,
    SUPERVISOR_ENV,
    VERSION,
    ConfigError,
    dashboard_token,
    get_paths,
    harden_process,
    load_config,
    read_json,
    run_mode,
    unsafe_data_dir,
)
from common.settings import preflight

DEMO_DATA_DIR = "data/demo"
DEMO_LOGS_DIR = "logs/demo"


def elevated() -> bool:
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    return os.geteuid() == 0


def refuse_on_problems() -> bool:
    """A bad file should stop the stack here, with a clear message, rather than leaving
    each component to crash and restart forever."""
    problems = preflight()
    for problem in problems:
        print(f"config problem: {problem}", file=sys.stderr)
    return bool(problems)


def cmd_run(args: argparse.Namespace) -> int:
    from daemon.supervisor import run_stack

    if refuse_on_problems():
        return 1
    config = load_config()
    print(f"SentinelAI starting in {run_mode(config)} mode. Press Ctrl+C to stop.")
    # The link is not printed here: under systemd this output goes into the journal.
    if not args.no_dashboard:
        print("Dashboard link: run `sentinel.py token`", flush=True)
    return run_stack(not args.no_collectors, not args.no_dashboard, args.duration)


def cmd_demo(args: argparse.Namespace) -> int:
    """Run the pipeline on simulated attacks, isolated from real data and never enforcing."""
    os.environ["SENTINELAI_DATA_DIR"] = DEMO_DATA_DIR
    os.environ["SENTINELAI_LOGS_DIR"] = DEMO_LOGS_DIR
    os.environ["SENTINELAI_RUN_MODE"] = "dry-run"

    from daemon.supervisor import another_instance, run_stack

    if refuse_on_problems():
        return 1
    config = load_config()
    paths = get_paths(config)
    if another_instance(paths):
        print("The demo is already running.", file=sys.stderr)
        return 1
    for path in (paths.data_dir, paths.logs_dir):
        shutil.rmtree(path, ignore_errors=True)
    paths.ensure()

    stopping = threading.Event()
    simulators: List[subprocess.Popen] = []

    def attack() -> None:
        if stopping.wait(2):
            return
        command = [sys.executable, "-m", "utils.simulate_events", "--scenario", "all"]
        if args.duration is None:
            command.append("--loop")
        env = {**os.environ, SUPERVISOR_ENV: str(os.getpid())}
        simulators.append(subprocess.Popen(command, cwd=CODE_ROOT, env=env))

    attacker = threading.Thread(target=attack, daemon=True)
    attacker.start()

    if not args.no_dashboard:
        print(f"Dashboard: {dashboard_link(config)}")
    print("Demo running on simulated data in dry-run mode. Press Ctrl+C to stop.", flush=True)
    try:
        return run_stack(collectors=False, dashboard=not args.no_dashboard, duration=args.duration)
    finally:
        # The simulator is a separate process and would otherwise outlive the demo.
        stopping.set()
        attacker.join(timeout=5)
        for simulator in simulators:
            if simulator.poll() is None:
                simulator.terminate()
                simulator.wait(timeout=5)


def dashboard_link(config: dict) -> str:
    section = config.get("dashboard", {})
    token = dashboard_token(get_paths(config).ensure())
    return f"http://{section.get('host')}:{section.get('port')}/?token={token}"


def cmd_token(_: argparse.Namespace) -> int:
    print(dashboard_link(load_config()))
    return 0


def cmd_dashboard(_: argparse.Namespace) -> int:
    from reporter import web_dashboard

    print(f"Dashboard: {dashboard_link(load_config())}", flush=True)
    web_dashboard.main()
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    from reporter import report_generator

    print(report_generator.generate(hours=args.hours))
    return 0


def cmd_status(_: argparse.Namespace) -> int:
    from daemon.supervisor import another_instance

    config = load_config()
    paths = get_paths(config)
    state = read_json(paths.supervisor, {})
    pid = another_instance(paths)
    print(f"mode:       {run_mode(config)}")
    print(f"supervisor: {'running (pid %d)' % pid if pid else 'not running'}")
    for name, info in (state.get("components") or {}).items():
        extra = f" - {info['detail']}" if info.get("detail") else ""
        state_text = info.get("state") if pid else "stopped"
        print(f"  {name:18} {state_text:12} restarts={info.get('restarts', 0)}{extra}")
    return 0


def describe_auth_source(config: dict) -> str:
    from collectors.log_monitor import pick_source

    source, path = pick_source(config)
    if source == "windows":
        if elevated():
            return "Windows event logs, including Security"
        return "Windows event logs, without Security (needs Administrator)"
    if source == "journal":
        return "systemd journal (forged lines are rejected)"
    if source == "file":
        return f"{path} (local accounts can forge lines here; the journal cannot be forged)"
    return "none readable (run as root, or set auth_log)"


def cmd_check(_: argparse.Namespace) -> int:
    """Validate configuration and report what this host can do."""
    from analyzer.rule_engine import load_rules
    from responder.firewall import Firewall

    problems = preflight()
    for problem in problems:
        print(f"problem:  {problem}", file=sys.stderr)
    if problems:
        return 1

    config = load_config()
    firewall = Firewall(config["responder"].get("firewall", "auto")).backend
    can_enforce = "yes" if elevated() else "no, enforcing needs root or Administrator"
    unsafe = unsafe_data_dir(get_paths(config))
    print(f"version:  {VERSION}")
    print(f"config:   ok ({len(load_rules())} rules)")
    print(f"mode:     {run_mode(config)}")
    print(f"firewall: {firewall or 'none (blocks cannot be enforced on this host)'}")
    print(f"auth log: {describe_auth_source(config)}")
    print(f"elevated: {can_enforce}")
    print(f"platform: {sys.platform}")
    if unsafe:
        print(f"warning:  {unsafe}. Enforcement stays off until this is fixed.")
    if not elevated():
        print("warning:  without root or Administrator, other accounts' sockets cannot be traced")
        print("          to a process, so a backdoor they open cannot be identified or stopped.")
    return 0


def cmd_unblock(args: argparse.Namespace) -> int:
    from responder.responder import Responder

    config = load_config()
    ok, detail = Responder(config, get_paths(config).ensure()).unblock(args.ip)
    print(detail, file=sys.stdout if ok else sys.stderr)
    return 0 if ok else 1


def cmd_unlock(args: argparse.Namespace) -> int:
    from responder.responder import Responder

    config = load_config()
    ok, detail = Responder(config, get_paths(config).ensure()).unlock_user(args.user)
    print(detail, file=sys.stdout if ok else sys.stderr)
    return 0 if ok else 1


def cmd_audit(_: argparse.Namespace) -> int:
    from common.audit import verify_audit

    intact, checked, problem = verify_audit(get_paths(load_config()))
    if intact:
        print(f"audit log intact ({checked} entries)")
        return 0
    print(f"audit log damaged after {checked} entries: {problem}", file=sys.stderr)
    return 1


def cmd_notify_test(_: argparse.Namespace) -> int:
    from reporter.notifier import send_test

    results = send_test(load_config())
    if not results:
        print("Nothing is configured. Fill in [notify] in config/sentinelai.toml.", file=sys.stderr)
        return 1
    for name, ok in results:
        print(f"{name}: {'sent' if ok else 'failed, see logs/notifier.log'}")
    return 0 if all(ok for _, ok in results) else 1


def cmd_rotate(_: argparse.Namespace) -> int:
    from common.maintenance import run_maintenance

    config = load_config()
    rotated = run_maintenance(config, get_paths(config).ensure())
    print(f"rotated: {', '.join(rotated)}" if rotated else "nothing needed rotating")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentinel", description=__doc__)
    parser.add_argument("--version", action="version", version=f"SentinelAI {VERSION}")
    commands = parser.add_subparsers(dest="command", required=True)

    run = commands.add_parser("run", help="start the full stack")
    run.add_argument("--no-collectors", action="store_true")
    run.add_argument("--no-dashboard", action="store_true")
    run.add_argument("--duration", type=float, help="stop after this many seconds")
    run.set_defaults(func=cmd_run)

    demo = commands.add_parser("demo", help="run on simulated attacks, safely isolated")
    demo.add_argument("--no-dashboard", action="store_true")
    demo.add_argument("--duration", type=float, help="stop after this many seconds")
    demo.set_defaults(func=cmd_demo)

    # Handled in main(), which hands every remaining argument to the simulator.
    commands.add_parser("simulate", help="write synthetic events (see simulate --help)")

    commands.add_parser("dashboard", help="serve the dashboard").set_defaults(func=cmd_dashboard)
    commands.add_parser("token", help="print the dashboard sign-in link").set_defaults(func=cmd_token)

    report = commands.add_parser("report", help="write a static HTML report")
    report.add_argument("--hours", type=int, default=24)
    report.set_defaults(func=cmd_report)

    commands.add_parser("status", help="show component status").set_defaults(func=cmd_status)
    commands.add_parser("check", help="validate configuration").set_defaults(func=cmd_check)
    commands.add_parser("audit", help="verify the response log").set_defaults(func=cmd_audit)
    commands.add_parser("rotate", help="rotate oversized files now").set_defaults(func=cmd_rotate)
    commands.add_parser("notify-test", help="send a test alert").set_defaults(func=cmd_notify_test)

    unblock = commands.add_parser("unblock", help="remove an IP block")
    unblock.add_argument("ip")
    unblock.set_defaults(func=cmd_unblock)

    unlock = commands.add_parser("unlock", help="restore an account SentinelAI locked")
    unlock.add_argument("user")
    unlock.set_defaults(func=cmd_unlock)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    harden_process()
    arguments = sys.argv[1:] if argv is None else argv
    try:
        if arguments[:1] == ["simulate"]:
            from utils import simulate_events

            return simulate_events.main(arguments[1:])

        args = build_parser().parse_args(arguments)
        return args.func(args)
    except ConfigError as exc:
        print(f"config problem: {exc}", file=sys.stderr)
        return 1
    except PermissionError as exc:
        print(f"permission denied: {exc.filename or exc}", file=sys.stderr)
        print("If SentinelAI has been run as root here, run this as root too.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
