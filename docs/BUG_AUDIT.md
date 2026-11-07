# Bug audit

Every bug found in SentinelAI and how it was fixed. Most have a regression test in `tests/`.
Packaging and platform fixes were checked by running them instead.

The first review covered the original code. The second reviewed the result of the first, at a
point where all 224 tests and 67 Linux checks passed. Each second-review bug was reproduced
against the running code before being listed, so "all tests pass" said very little about them.

## Could not run at all

| Bug | Effect | Fix |
|---|---|---|
| `daemon/sentinel_daemon.sh` was 0 bytes | The README's "start the stack" step did nothing | Python supervisor, with the script as its launcher |
| `utils/setup.sh` was 0 bytes | The README's setup step did nothing | Written, plus `utils/setup.ps1` for Windows |
| `from schemas import ...` in `rule_engine.py` | Crash on import, so the test suite could not start | Real packages with proper imports |
| `report_generator.py` compared naive and aware datetimes | `TypeError` on the first event, so no report could be generated | Timezone-aware time everywhere |
| Dockerfile copied only `web_dashboard.py` | `TemplateNotFound` on the home page | Copies everything the dashboard needs |
| BOM and CRLF in shell scripts | Failed when run directly | All files normalized |
| Compose instructions in the README | Pointed at a file that isn't in the root folder | README corrected |

## Dangerous

| Bug | Effect | Fix |
|---|---|---|
| The responder never read `run_mode` | **The default "dry-run" setting really blocked IPs and killed processes** | Dry-run is honoured, and anything unrecognised also means dry-run |
| Response depended on host load, not evidence | **Legitimate `postgres` at high CPU scored 76 and `nginx` opening a port during a deploy scored 70, both enough to be killed** | Each rule states its response in `rules.yml`. Kill and lock cannot depend on the score, and the rules that use them are specific enough to deserve them |
| Worst alerts could not reach kill or lock on a calm host | A netcat backdoor scored 60 with no response at all, and a UID 0 account scored 54 | Same fix. Severity now sets a floor that context can only raise |
| A brute-forced root login got no response | The only plan was `lock_user root`, which is refused, so the attacker's address was left alone | Plans have several steps, so the block happens whatever the lock does |
| Forged auth lines | `sudo echo Failed password for root from 8.8.8.8 port 22 ssh2` got 8.8.8.8 blocked. Any program name matched | Lines count only if the program field is right, and the journal's trusted fields reject forgeries |
| Attacker could choose the "source" IP via the SSH username | `x from 8.8.8.8 port 1` got 8.8.8.8 blocked, so an attacker could block anyone, including you | Patterns are anchored, so only the address sshd wrote at the end is accepted |
| One bad record stopped a stage forever | `{"base_severity":"high"}` crash-looped the detector and held up every alert behind it | Bad records are set aside in `dead_letters.jsonl`. Disk errors still stop and retry |
| Planted model file ran code | A pickle in `data/models` executed on load, as root | Models stay in memory and nothing is unpickled. Training takes 0.2 seconds |
| `lock_user` left the attacker in | Password lock only: SSH keys still worked and live sessions kept running | The account is also expired, and its processes are ended. `sentinel unlock` restores it exactly |
| Shipped systemd unit broke `lock_user` | `ProtectSystem=full` makes `/etc` read-only, so `usermod` always failed under the service | `ProtectSystem=true`, proven on a real systemd host |
| Stale guard read the scoring time | A 6-hour-old event replayed after downtime was acted on as fresh | The oldest of the event, alert and threat times is used |
| Values were pasted into Python source in `update_json` | Code injection, running as root | Responder rewritten with no generated code |
| `$ip` unquoted in the `nft` command | Command injection | Strict parsing, and argument lists only |
| `kill_process` trusted a bare PID | A reused PID meant killing an innocent process | Checks process name and start time before killing |
| No protection for critical processes | Could kill PID 1, `sshd`, or SentinelAI itself | Guard list for Linux and Windows, plus a check of the owning user |
| The allow-list matched exact strings only | CIDR ranges never matched | Real network matching. Loopback, the host's own addresses and its gateway are always safe |
| Empty allow-list by default | Easy to lock yourself out of a remote host | Seeded with loopback, and `setup.sh` adds your SSH address |
| Stored XSS in the HTML report | An SSH username could run script in your browser | Every value escaped |
| Dashboard bound to `0.0.0.0` with no login | Security data open to the whole network | Binds to `127.0.0.1`, read-only API, strict CSP, and a token is required even locally, because other accounts on the machine could read it otherwise |
| Dashboard open to DNS rebinding | Any web page could read it from a browser on the machine | The `Host` header is checked |
| Security data readable by everyone | Data and logs were 644 and 755, including usernames people typed passwords into | Everything is private, on Linux and Windows. The responder refuses to enforce from a folder others can write |
| Firewall failures hidden by `\|\| true` | Logged "blocked" when nothing was blocked | Real status recorded for every action |

## Silently not working

| Bug | Effect | Fix |
|---|---|---|
| Blocks lost after a reboot | State said "already blocked", so a returning attacker was never blocked again | Blocks are checked against the kernel every minute and restored |
| `nft flush ruleset` broke blocking | Every later block failed until a restart | The table is rebuilt and the block retried |
| Pre-auth attacks were invisible | `Invalid user`, `[preauth]` closes and max-auth-exceeded produced no events, so key-only servers saw nothing | New `auth_probe` events, with their own rules |
| `message repeated 4 times` counted as one failure | A burst could stay under the threshold | Each repeat counts |
| Auth lines written during downtime were lost | `tail -n0` starts at the end of the file | Position is saved, and events keep the time from the log |
| Log parser too slow for a real attack | 175 lines per second in bash | Rewritten in Python, measured at about 19,000 |
| Dashboard totals silently capped | 25,000 events showed as 20,000 with no warning | Counted per minute from the whole file |
| Allow-list read only at startup | Adding an address mid-incident did nothing until restart | Reloaded when it changes, and anything newly listed is unblocked |
| Rule engine forgot everything on restart | A login right after a brute force looked innocent | State is rebuilt from events already processed |
| Bad rule templates passed validation | `reason: "bad {"` crashed the engine on the first matching event | Templates are checked at load |
| `sentinel check` crashed on the files it exists to check | Tracebacks for YAML and TOML typos, because rules loaded at import | Nothing loads at import, and `run` refuses to start on a bad file |
| Two starts at once could both run | The check read a PID file | An exclusive lock the OS releases if the holder dies |
| `IFS=` on the `ps` read loop | The whole process scan was dead | Replaced by the Python collector |
| `rules.yml` was never loaded | Editing rules did nothing | It is now the single source of detection and response |
| `suspicious_proc`, `user_add`, `auth_success` had no rules | Collected, then ignored | Rules added, including brute-force-then-success |
| `block_timeout_sec` had no effect | Blocks were permanent | nft timeouts, and a sweep for iptables and Windows |
| `nft` rule assumed `inet filter input` exists | Blocks failed on most hosts | Creates its own table and sets, covering forwarded traffic too |
| IPv6 went to an IPv4 rule | IPv6 blocks failed | Separate IPv6 set |
| Ports below 1024 were ignored | A backdoor on port 23 raised nothing | Now flagged, at higher severity |
| Anomaly score was badly calibrated | A perfectly normal sample scored 55.7 out of 100 | Calibrated to each host's own history |
| Alerts scored against current metrics | A queued alert picked up later activity | Scored against metrics from when it fired |
| Dashboard chart bucketed by count, not time | Always a flat line | Real time buckets |
| Settings that did nothing | `base_severity_threshold`, `follow_files`, `watch_listen` were unused | All wired in |

## Lost data and noise

| Bug | Effect | Fix |
|---|---|---|
| `rotate_logs.sh` copied then truncated | Anything written or unread at that moment was lost, and nothing ever scheduled it | Built into the supervisor. Files are renamed, and readers finish the old one first |
| Followers started at the end of the file | Anything written while a component was down was lost | Read position saved per component, in batches rather than per line |
| Partial lines were parsed | Half-written events were dropped | Only complete lines are delivered |
| No handling of log rotation | Reading stopped forever after rotation | Rotation and truncation handled, and a log cleared in place raises an alert |
| Burst windows used arrival time | Replayed logs looked like bursts | Event time is used |
| First run reported every listener as new | Alert storm at startup | Silent baseline on first run |
| A service restart counted as a new port | False alert each time a PID changed | Only new ports or a different program alert |
| Every UDP client looked like a new service | False alert for DNS and NTP sockets | Temporary UDP ports are ignored |
| Loopback listeners were treated as exposed | Constant noise from desktop software | Local-only listeners are not reported unless they are a known tool |
| Forked workers reported once each | Duplicate alerts | One report per socket |
| Log lines parsed the config file every time | A TOML parse for each line written | Paths are cached |
| `bash`, `sh` and `python` flagged as suspicious | Constant noise | Replaced with specific behaviour checks |
| Process CPU was a lifetime average | Short spikes in old processes were missed | Measured between scans |
| Windows append is not atomic | Two collectors could overwrite each other's events | Writers are locked on Windows |
| No alert cooldown | Repeated alerts for one source | Cooldown per rule and target |
| Per-IP tracking was never cleaned up | Memory grew with every source IP | Idle state pruned and each window capped |
| Auth log path hard-coded to Debian's | Nothing collected on RHEL or journal-only hosts | Journal, `auth.log`, `secure`, or Windows event logs |

## Mistakes made and caught during this work

These were errors in the rewrites themselves. Testing against real systems caught them.

- `journalctl --follow` implies `--lines=10`, so a catch-up after downtime silently stopped at
  ten lines. Only a real journal showed it: 13 entries existed and 10 arrived.
- High-confidence command patterns could kill everyday commands, including `tar -C`, a
  `/dev/tcp` port check and the official Chocolatey installer. Tests had set the confidence by
  hand, so nothing covered the path from a raw command line. High indicators now have to name
  the program running, and an end-to-end test runs real command lines through to the plan.
- An Isolation Forest barely notices one extreme value among normal ones, so a transfer 700
  times the usual size scored 0. A second measure now scores how far any single value is past
  this host's own history.
- `icacls /T` left files that even their owner could not open. Permissions are now set on the
  folder alone, and children inherit them.
- In a container, root cannot trace another account's socket to a process without
  `SYS_PTRACE`. A real root can, so the test container now has that capability.
- A test asserted the dangerous behaviour itself: that a severity 6 process on a busy host
  should be killed. The new policy test checks both directions with the host calm and frantic.
- `test_dry_run_never_kills` failed as root, where the owner guard answered first. The
  responder was right and the test was wrong.
- `sentinel.py simulate --scenario ...` was rejected by the argument parser.
- The demo left its simulator running after it exited.
- Killing the supervisor on Windows left every component running, including the responder.
  Components now exit on their own when the supervisor disappears.
- The chart drew Alerts and Threats on top of each other, since every alert becomes one
  threat. It now shows Responses instead.
