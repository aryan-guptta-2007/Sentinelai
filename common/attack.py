"""MITRE ATT&CK reference data: what each technique is called and which stage it belongs to."""

from __future__ import annotations

from typing import Dict, Iterable, List, Tuple

TECHNIQUES: Dict[str, Tuple[str, str]] = {
    "T1003.001": ("LSASS Memory", "credential-access"),
    "T1027": ("Obfuscated Files or Information", "defense-evasion"),
    "T1037": ("Boot or Logon Initialization Scripts", "persistence"),
    "T1053.003": ("Cron", "persistence"),
    "T1053.005": ("Scheduled Task", "persistence"),
    "T1059": ("Command and Scripting Interpreter", "execution"),
    "T1059.001": ("PowerShell", "execution"),
    "T1059.004": ("Unix Shell", "execution"),
    "T1059.006": ("Python", "execution"),
    "T1070.001": ("Clear Windows Event Logs", "defense-evasion"),
    "T1070.002": ("Clear Linux or Mac System Logs", "defense-evasion"),
    "T1070.003": ("Clear Command History", "defense-evasion"),
    "T1070.004": ("File Deletion", "defense-evasion"),
    "T1071": ("Application Layer Protocol", "command-and-control"),
    "T1078": ("Valid Accounts", "initial-access"),
    "T1098": ("Account Manipulation", "persistence"),
    "T1098.004": ("SSH Authorized Keys", "persistence"),
    "T1105": ("Ingress Tool Transfer", "command-and-control"),
    "T1110": ("Brute Force", "credential-access"),
    "T1110.001": ("Password Guessing", "credential-access"),
    "T1110.003": ("Password Spraying", "credential-access"),
    "T1136.001": ("Create Local Account", "persistence"),
    "T1197": ("BITS Jobs", "defense-evasion"),
    "T1204": ("User Execution", "execution"),
    "T1218.005": ("Mshta", "defense-evasion"),
    "T1218.010": ("Regsvr32", "defense-evasion"),
    "T1218.011": ("Rundll32", "defense-evasion"),
    "T1490": ("Inhibit System Recovery", "impact"),
    "T1496": ("Resource Hijacking", "impact"),
    "T1505.003": ("Web Shell", "persistence"),
    "T1543.002": ("Systemd Service", "persistence"),
    "T1543.003": ("Windows Service", "persistence"),
    "T1547.001": ("Registry Run Keys / Startup Folder", "persistence"),
    "T1548.003": ("Sudo and Sudo Caching", "privilege-escalation"),
    "T1556.003": ("Pluggable Authentication Modules", "credential-access"),
    "T1562.001": ("Disable or Modify Tools", "defense-evasion"),
    "T1565.001": ("Stored Data Manipulation", "impact"),
    "T1571": ("Non-Standard Port", "command-and-control"),
    "T1574.006": ("Dynamic Linker Hijacking", "persistence"),
    "T1589.003": ("Employee Names", "reconnaissance"),
    "T1620": ("Reflective Code Loading", "defense-evasion"),
}

# The order an intrusion usually unfolds in, for displaying a timeline.
TACTIC_ORDER = [
    "reconnaissance", "initial-access", "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "command-and-control", "impact",
]
TACTIC_NAMES = {
    "reconnaissance": "Reconnaissance",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "command-and-control": "Command and Control",
    "impact": "Impact",
}


def technique_name(technique: str) -> str:
    return TECHNIQUES.get(technique, ("", ""))[0]


def tactics_of(techniques: Iterable[str]) -> List[str]:
    found = {TECHNIQUES[item][1] for item in techniques if item in TECHNIQUES}
    return [tactic for tactic in TACTIC_ORDER if tactic in found]
