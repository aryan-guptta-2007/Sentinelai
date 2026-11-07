# SentinelAI

SentinelAI is a host intrusion detection and response system for Linux and Windows. It watches
logins, processes, network listeners and critical files, recognises attacks with rules and anomaly
detection, groups what it finds into incidents, and can respond by blocking addresses, stopping
processes, or locking accounts. It tells you through webhooks, Slack, Discord, email or syslog, and
a live dashboard and HTML reports show what it saw and what it did.

It starts in **dry-run mode**: it records what it would do and changes nothing until you turn
enforcement on.

```
collectors ──> events ──> rule engine ──> alerts ──> scorer ──> threats ──┬──> responder ──> audit log
 logs, processes,         (rules.yml)        (incidents and         │       (guarded)      │
 listeners, files                             Isolation Forest)     └──> notifier          │
                                                                         (you)             │
                                dashboard and reports <────────────────────────────────────┘
```

## Try it

The demo runs on any OS. It generates simulated attacks, keeps its data in `data/demo`, and is
forced to dry-run, so it cannot touch your machine.

```powershell
# Windows
powershell -ExecutionPolicy Bypass -File utils\setup.ps1
.\.venv\Scripts\python.exe sentinel.py demo
```

```bash
# Linux
bash utils/setup.sh
.venv/bin/python sentinel.py demo
```

It prints a link to the dashboard. Open that, and press `Ctrl+C` to stop.

## Run it for real

```bash
# Linux
sudo .venv/bin/python sentinel.py run
```

```powershell
# Windows, from an Administrator prompt
.\.venv\Scripts\python.exe sentinel.py run
```

`sentinel.py check` shows what this host can do. What needs elevation:

| | Normal account | Root or Administrator |
|---|---|---|
| Processes, listeners, resources | Yes, though other accounts' sockets cannot be traced to a process | Yes |
| File integrity | Whatever this account can read | Yes |
| Linux auth logs | Depends on the file's permissions | Yes |
| Windows System and Defender logs | Yes | Yes |
| Windows Security log (logons, account changes) | No | Yes |
| Enforcing responses | No | Yes |

To run it as a service on Linux, copy the project to `/opt/sentinelai`, run `utils/setup.sh`
there, then install `daemon/sentinelai.service` with systemd. `sentinel.py token` prints the
dashboard link.

### Getting told

A detection nobody sees has not protected anything. Fill in any destination under `[notify]` in
`config/sentinelai.toml`, then check it:

```bash
.venv/bin/python sentinel.py notify-test
```

Webhooks, Slack, Discord, email and syslog (CEF, which most SIEMs read directly) are supported.
Webhook addresses are secrets, so `SENTINELAI_WEBHOOK_URL`, `SENTINELAI_SLACK_URL` and
`SENTINELAI_DISCORD_URL` can hold them instead. Repeats within an incident are held back, a flood
is capped by `max_per_minute`, and hostile text cannot ping your channel.

### Before turning on enforcement

1. Add your admin and VPN addresses to `config/allowlist_ips.txt` (single IPs or CIDR ranges).
   `setup.sh` adds your current SSH address automatically.
2. Run in dry-run for a while and read the **Response actions** table to see what would have
   happened.
3. Set `run_mode = "enforce"` in `config/sentinelai.toml` and restart.

## Commands

| Command | What it does |
|---|---|
| `sentinel.py run` | Start everything and restart anything that crashes |
| `sentinel.py demo` | Run on simulated attacks, isolated and dry-run |
| `sentinel.py status` | Show the mode and the state of each component |
| `sentinel.py token` | Print the dashboard sign-in link |
| `sentinel.py check` | Validate configuration and show what this host can do |
| `sentinel.py report --hours 24` | Write a self-contained HTML report |
| `sentinel.py unblock 203.0.113.5` | Remove an IP block |
| `sentinel.py unlock alice` | Restore an account SentinelAI locked |
| `sentinel.py audit` | Verify the response log has not been altered |
| `sentinel.py notify-test` | Send a test alert to every configured destination |
| `sentinel.py rotate` | Rotate oversized files now (this also happens hourly) |
| `sentinel.py simulate --scenario brute` | Write synthetic events for one scenario |
| `sentinel.py dashboard` | Serve only the dashboard |

Scenarios: `brute`, `spray`, `probe`, `compromise`, `port`, `backdoor`, `proc`, `busy`,
`revshell`, `webshell`, `command`, `useradd`, `rootuser`, `group`, `logclear`, `filechange`,
`campaign` (one intrusion from start to finish), or `all`.
Simulated events are marked as such, and the responder never acts on them.

## Detection

Rules live in `config/rules.yml`, and process indicators in `config/indicators.yml`. Both are
checked at startup, so a mistake stops with a clear message instead of quietly disabling a
detection. Edit `rules.yml` while running and the change applies within seconds. If the edit is
bad, the old rules stay active.

| Area | What it catches |
|---|---|
| Authentication | Brute force, password spraying, distributed attacks on one account, username enumeration, probing of key-only servers, logins right after any of these |
| Privilege | Repeated sudo and su failures, sudo refused, additions to privileged groups, root password changes |
| Accounts | New accounts, accounts created or changed to UID 0 |
| Network | Unexpected listeners, with higher severity below port 1024, and backdoor listeners from known tools |
| Processes | Known malicious tools, dual-use tools, reverse shells, web shells, programs running from memory, deleted or temporary binaries, known attack command lines on both platforms |
| Windows | Failed and remote logons, new accounts and privileged group changes, new services and scheduled tasks, Defender detections and Defender being disabled |
| Persistence | SSH keys, sudoers, cron, services, PAM, linker preload and Run keys, from file and registry integrity checks |
| Defence evasion | Cleared logs, on both platforms |
| Behaviour | The host staying outside its own normal range, whether or not any rule fired |

File integrity is configured in `config/integrity.yml`. The first run records a baseline silently,
and hashes are rechecked periodically, so a forged timestamp does not hide a change. These alerts
never act, because a changed file can be an admin at work.

Log lines count only if they come from the program that really writes them. On systemd hosts
the journal is used, because it records who wrote each line, so `logger -t sshd` cannot forge
an attack. Plain log files cannot offer that, and `sentinel.py check` says which you have.

### Scoring and response

The score says how urgent something is. **Severity sets the floor**, and context can only lift
it towards 100, so a quiet host never dilutes a critical alert:

`score = 10 × severity + (100 − 10 × severity) × lift`

Lift comes from three places, and each one is listed beside the alert:

- **Attack chain:** the alert is part of an incident spanning several ATT&CK stages.
- **Repeat activity:** it is one of several alerts in the same incident.
- **Host anomaly:** an Isolation Forest trained on this host's own CPU, memory, load, process,
  connection and network history, plus how far any single measurement is past everything the host
  has recorded. This describes the host when the alert fired, not the alert itself.

### Incidents

An alert with a source address joins the incident for that address, so two attackers stay two
incidents even if they try the same account. Without an address, a named account links it. Events
on the host itself, like a new cron job, carry neither, so they join an incident that has already
reached a compromise. The dashboard shows each incident as one story: what happened, which stages
it reached, each step in order, what was done about it, and what to do next.

**What gets done is decided by the rule, not the score.** Each rule lists its response:

```yaml
respond:
  - {action: block_ip, min_score: 40}
  - {action: lock_user}
```

`min_score` is only allowed on `block_ip`, which is timed and reversible. `kill_process` and
`lock_user` cannot depend on the score at all, so a busy host can never be the reason something
is killed. Only rules specific enough to deserve them use them, and a resource spike alone never
stops anything.

| Response | What it does | Undo |
|---|---|---|
| `block_ip` | Firewall block, doubling each time the same address returns | Expires by itself, or `sentinel.py unblock` |
| `kill_process` | Saves evidence, then stops the process and its children | Cannot be undone |
| `lock_user` | Locks and expires the account, so keys stop working too, and ends its sessions | `sentinel.py unlock` |

## Safety guards

These apply in every mode:

- **Allow-lists:** allow-listed IPs are never blocked, and neither are loopback addresses, the
  host's own addresses or its gateway. Edits apply without a restart, and an address added
  later is unblocked.
- **Process kills:** refused for PID 1, SentinelAI itself, critical system processes on both
  platforms, anything in `protected_processes`, and processes owned by protected users. The PID
  must still belong to the program in the alert, so a reused PID is left alone.
- **Accounts:** root and system accounts are never locked, and neither is the account running
  SentinelAI.
- **Stale threats:** anything older than `max_threat_age_sec` is recorded but not acted on, using
  the time the event really happened, so a restart cannot replay old responses.
- **Flood limit:** at most `max_actions_per_minute` of each action, so a flood of bad data cannot
  become a flood of real actions.
- **Trusted files only:** enforcement stays off if other accounts can write the data folder. Data
  and logs are private to the account running SentinelAI.
- **Untrusted input:** every target is validated, and external commands receive argument lists,
  never shell strings.
- **Honest results:** each action records `applied`, `failed`, `refused`, `skipped`, or `dry_run`,
  in a hash-chained log that `sentinel.py audit` verifies.

## Known limits

- It monitors one host. There is no central server or fleet view.
- The dashboard signs in with one shared token and is read-only. It serves plain HTTP on
  `127.0.0.1`, so to reach it remotely, put a TLS proxy in front of it and set `allowed_hosts`.
- There is no Windows service installer yet, so `sentinel.py run` has to be started by hand or
  from Task Scheduler.
- New processes are found by polling every 2 seconds, so something that starts and exits between
  looks is missed. Only kernel-level tracing would see those.
- Plain log files can be forged by anyone who can write to syslog. The journal rejects that from
  ordinary accounts, but root can write anything to it.
- The Windows firewall, account locking and Security log code has only been tested with the
  commands stubbed out, because it needs an Administrator session. Try it in dry-run first.
- On Linux a root attacker can bypass all of this. That includes the audit log, whose chain they
  could recompute.
- Blocks made with iptables and Windows Firewall need a running responder to expire. nftables
  expires them itself.
- macOS is not tested. Host monitoring should work there, but there is no auth log source.

## Development

```bash
python -m pytest                  # unit and end-to-end tests, any OS
make test-linux                   # real attacks, nftables, iptables and usermod, in Docker
make test-systemd                 # the whole product on a real systemd host, attacked over SSH
```

Both need Docker. On Windows without `make`:

```powershell
docker build -f docker/test.Dockerfile -t sentinelai-test .
docker run --rm --cap-add NET_ADMIN --cap-add SYS_PTRACE sentinelai-test
bash tests/linux/run_systemd.sh
```

To serve the dashboard from Docker, reading the `data` folder read-only, run `sentinel.py token`
once first, so there is a token to read. Then:

```bash
docker compose -f docker/docker-compose.yml up dashboard
```

Data files are private to the account that runs SentinelAI, so set `SENTINELAI_UID` if that is not
root. Otherwise the dashboard will answer that it has no access token.

## Layout

```
sentinel.py   command line entry point
common/       paths, locks, durable files, settings, audit log, housekeeping, ATT&CK data
collectors/   auth logs, Windows event logs, processes, listeners, resources, file integrity
analyzer/     rule engine, scorer, incidents
responder/    guarded response: firewall, accounts, processes
reporter/     dashboard, notifications, static reports, shared analytics
daemon/       process supervisor and systemd unit
utils/        setup and attack simulator
config/       settings, rules, indicators, watched files, allow-lists
tests/        test suite, including real-attack checks in tests/linux
docs/         the bug audit
```

## License

SentinelAI is distributed under the MIT License. See [LICENSE](LICENSE) for details.
