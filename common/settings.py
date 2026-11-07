"""Check configuration before anything runs, so mistakes show up as one clear message
instead of a traceback, or worse, a setting that quietly does nothing."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from common.runtime import RUN_MODES, ConfigError, load_config

NUMBER = (int, float)
SCHEMA: Dict[str, Dict[str, Any]] = {
    "paths": {"data_dir": str, "logs_dir": str},
    "modes": {"run_mode": str, "follow_files": bool},
    "thresholds": {"base_severity_threshold": int, "ml_weight": NUMBER},
    "ml": {
        "min_training_rows": int, "max_training_rows": int, "retrain_hours": NUMBER,
        "metrics_max_age_sec": int, "anomaly_alert_score": NUMBER,
    },
    "network": {"watch_listen": bool, "allowed_ports": list, "ignored_listeners": list},
    "collectors": {
        "interval_sec": NUMBER, "process_interval_sec": NUMBER, "integrity_interval_sec": NUMBER,
        "auth_source": str, "auth_log": str,
        "cpu_threshold": NUMBER, "mem_threshold": NUMBER, "suspicious_names": list,
        "malicious_names": list,
    },
    "responder": {
        "firewall": str, "block_timeout_sec": int, "max_block_sec": int,
        "max_actions_per_minute": int, "kill_protected_users": bool, "max_threat_age_sec": int,
        "protected_processes": list,
    },
    "retention": {"max_data_mb": NUMBER, "max_log_mb": NUMBER, "archive_days": NUMBER, "max_metric_rows": int},
    "notify": {
        "min_score": int, "cooldown_sec": int, "max_per_minute": int, "webhook_url": str,
        "slack_webhook": str, "discord_webhook": str, "syslog_host": str, "syslog_port": int,
        "email_to": str, "email_from": str, "smtp_host": str, "smtp_port": int, "smtp_tls": bool,
        "smtp_user": str,
    },
    "dashboard": {"host": str, "port": int, "allowed_hosts": list},
}
REQUIRED: List[Tuple[str, str]] = [
    ("thresholds", "base_severity_threshold"),
    ("network", "allowed_ports"),
    ("dashboard", "port"),
]
CHOICES: List[Tuple[str, str, Tuple[str, ...]]] = [
    ("modes", "run_mode", RUN_MODES),
    ("collectors", "auth_source", ("auto", "journal", "file", "none")),
    ("responder", "firewall", ("auto", "nft", "iptables", "netsh")),
]
RANGES: List[Tuple[str, str, float, float]] = [
    ("thresholds", "ml_weight", 0, 1),
    ("thresholds", "base_severity_threshold", 1, 10),
    ("dashboard", "port", 1, 65535),
    ("collectors", "interval_sec", 1, 86400),
    ("collectors", "process_interval_sec", 0.5, 3600),
    ("responder", "max_actions_per_minute", 1, 100000),
    ("ml", "anomaly_alert_score", 1, 100),
    ("collectors", "integrity_interval_sec", 1, 86400),
    ("notify", "min_score", 0, 100),
    ("notify", "max_per_minute", 1, 100000),
]


def _wrong_type(value: Any, expected: Any) -> bool:
    if isinstance(value, bool) and expected is not bool:
        return True  # True is an int in Python, but never what these settings mean
    return not isinstance(value, expected)


def config_problems(config: Dict[str, Any]) -> List[str]:
    problems: List[str] = []
    for section, values in config.items():
        known = SCHEMA.get(section)
        if known is None:
            problems.append(f"unknown section [{section}]")
            continue
        if not isinstance(values, dict):
            problems.append(f"[{section}] must be a table")
            continue
        for key, value in values.items():
            if key not in known:
                problems.append(f"[{section}] unknown setting {key}")
            elif _wrong_type(value, known[key]):
                problems.append(f"[{section}] {key} has the wrong type")
    if problems:
        return problems

    for section, key in REQUIRED:
        if key not in config.get(section, {}):
            problems.append(f"[{section}] {key} is required")
    for section, key, allowed in CHOICES:
        value = config.get(section, {}).get(key)
        if value is not None and value not in allowed:
            problems.append(f"[{section}] {key} must be one of {', '.join(allowed)}")
    for section, key, low, high in RANGES:
        value = config.get(section, {}).get(key)
        if value is not None and not low <= value <= high:
            problems.append(f"[{section}] {key} must be between {low} and {high}")

    for port in config.get("network", {}).get("allowed_ports", []):
        if not isinstance(port, int) or isinstance(port, bool) or not 0 < port < 65536:
            problems.append(f"[network] allowed_ports has an invalid port: {port!r}")
    return problems


def preflight() -> List[str]:
    """Everything that would stop the stack from starting properly."""
    from analyzer.rule_engine import RuleError, load_rules
    from collectors.file_monitor import load_watch_list
    from collectors.process_checks import load_indicators

    try:
        config = load_config()
    except ConfigError as exc:
        return [str(exc)]

    problems = config_problems(config)
    try:
        load_rules()
    except RuleError as exc:
        problems.append(str(exc))
    for check in (lambda: load_indicators(config), load_watch_list):
        try:
            check()
        except ConfigError as exc:
            problems.append(str(exc))
    return problems
