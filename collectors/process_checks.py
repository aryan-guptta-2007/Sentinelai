"""Decide whether a process looks wrong. Pure logic, so every case can be tested
without running anything dangerous. The facts are gathered in host_monitor."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import yaml

from common.runtime import ConfigError, root_dir
from responder.system import process_key

CONFIDENCE_LEVELS = {"high", "medium"}
MAX_COMMAND_SHOWN = 300
VERSION_SUFFIX = re.compile(r"[0-9.]+$")


@dataclass(frozen=True)
class CommandIndicator:
    id: str
    pattern: re.Pattern
    technique: str
    confidence: str
    summary: str
    programs: frozenset = frozenset()


@dataclass(frozen=True)
class Indicators:
    shells: frozenset
    servers: frozenset
    text_tools: frozenset
    temp_dirs: tuple
    system_dirs: tuple
    commands: tuple
    malicious_names: frozenset = frozenset()
    suspicious_names: frozenset = frozenset()


@dataclass
class ProcessFacts:
    pid: int
    name: str
    exe: str = ""
    cmdline: Sequence[str] = field(default_factory=list)
    user: str = ""
    parent: str = ""
    exe_deleted: bool = False
    from_memory: bool = False
    socket_stdio: bool = False
    platform: str = "linux"


def load_indicators(config: Dict[str, Any], path: Optional[Path] = None) -> Indicators:
    source = path or root_dir() / "config" / "indicators.yml"
    try:
        document = yaml.safe_load(source.read_text(encoding="utf-8-sig")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"{source.name}: {' '.join(str(exc).split())}") from exc
    if not isinstance(document, dict):
        raise ConfigError(f"{source.name}: must be a mapping")

    commands = []
    seen = set()
    for item in document.get("commands") or []:
        identifier = item.get("id") if isinstance(item, dict) else None
        if not identifier or identifier in seen:
            raise ConfigError(f"{source.name}: missing or duplicate indicator id: {identifier!r}")
        seen.add(identifier)
        if item.get("confidence") not in CONFIDENCE_LEVELS:
            raise ConfigError(f"{source.name}: {identifier}: confidence must be high or medium")
        programs = frozenset(item.get("programs") or [])
        if item["confidence"] == "high" and not programs:
            # Without this, words in another command's arguments could get it killed.
            raise ConfigError(f"{source.name}: {identifier}: a high indicator must name its programs")
        flags = re.IGNORECASE if item.get("ignore_case") else 0
        try:
            pattern = re.compile(str(item.get("pattern")), flags)
        except re.error as exc:
            raise ConfigError(f"{source.name}: {identifier}: bad pattern: {exc}") from exc
        commands.append(
            CommandIndicator(
                identifier, pattern, str(item.get("technique") or ""), item["confidence"],
                str(item.get("summary") or identifier), programs,
            )
        )

    section = config.get("collectors", {})
    return Indicators(
        shells=frozenset(process_key(name) for name in document.get("shells") or []),
        servers=frozenset(process_key(name) for name in document.get("servers") or []),
        text_tools=frozenset(process_key(name) for name in document.get("text_tools") or []),
        temp_dirs=tuple(document.get("temp_dirs") or ()),
        system_dirs=tuple(document.get("system_dirs") or ()),
        commands=tuple(commands),
        malicious_names=frozenset(process_key(name) for name in section.get("malicious_names", [])),
        suspicious_names=frozenset(process_key(name) for name in section.get("suspicious_names", [])),
    )


def _names(facts: ProcessFacts) -> set:
    names = {process_key(facts.name)}
    if facts.exe:
        names.add(process_key(facts.exe))
    return names


def program_names(cmdline: Sequence[str]) -> set:
    """The program a command line runs, with and without a version, so python3.11 counts
    as python while regsvr32 stays regsvr32."""
    name = process_key(cmdline[0])
    return {name, VERSION_SUFFIX.sub("", name)}


def _matching_command(facts: ProcessFacts, indicators: Indicators) -> Optional[CommandIndicator]:
    if not facts.cmdline or process_key(facts.cmdline[0]) in indicators.text_tools:
        return None
    program = program_names(facts.cmdline)
    command = " ".join(facts.cmdline)
    best: Optional[CommandIndicator] = None
    for indicator in indicators.commands:
        if indicator.programs and not program & indicator.programs:
            continue
        if indicator.pattern.search(command):
            if indicator.confidence == "high":
                return indicator
            best = best or indicator
    return best


def inspect(facts: ProcessFacts, indicators: Indicators) -> List[Dict[str, Any]]:
    """Return one finding per reason this process stands out.

    Each finding is the type and detail of an event. What happens next is up to the
    rules: a finding only says what was seen.
    """
    findings: List[Dict[str, Any]] = []
    names = _names(facts)

    if names & indicators.malicious_names:
        findings.append({"type": "suspicious_proc", "meta": {"flags": ["malicious"]}})
    elif names & indicators.suspicious_names:
        findings.append({"type": "suspicious_proc", "meta": {"flags": ["name"]}})

    is_shell = bool(names & indicators.shells)
    if is_shell and process_key(facts.parent) in indicators.servers:
        findings.append({"type": "webshell_spawn", "meta": {"parent": facts.parent}})
    if is_shell and facts.socket_stdio:
        findings.append({"type": "reverse_shell", "meta": {}})

    if facts.from_memory:
        findings.append({"type": "fileless_process", "meta": {}})
    elif facts.exe_deleted and not facts.exe.startswith(indicators.system_dirs):
        findings.append({"type": "deleted_binary", "meta": {}})
    elif facts.platform == "linux" and facts.exe.startswith(indicators.temp_dirs):
        findings.append({"type": "temp_binary", "meta": {}})

    indicator = _matching_command(facts, indicators)
    if indicator is not None:
        findings.append(
            {
                "type": "malicious_command",
                "meta": {
                    "indicator": indicator.id,
                    "confidence": indicator.confidence,
                    "summary": indicator.summary,
                    "mitre": [indicator.technique] if indicator.technique else [],
                    "command": " ".join(facts.cmdline)[:MAX_COMMAND_SHOWN],
                },
            }
        )
    return findings
