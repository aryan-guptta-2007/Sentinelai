"""Group alerts into incidents, so a sequence reads as one attack rather than many rows.

An address is the strongest identity there is, so an alert with one joins the incident for
that address or starts its own: two attackers trying the same account are two attackers.
Without an address, a named account links it, as with sudo failures after a login. Events on
the host itself, like a new cron job, carry neither, so they join an incident that has already
reached a compromise. On one host, those are very unlikely to be a coincidence.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set

from common.attack import tactics_of
from common.runtime import parse_ts

OPEN_FOR_SEC = 3600
# Attackers from unrelated addresses all try these, so a shared name proves nothing.
SHARED_ACCOUNTS = {"", "root", "admin", "administrator", "test", "user", "guest", "ubuntu", "oracle", "postgres"}
COMPROMISE_TYPES = {"auth_compromise", "reverse_shell", "web_shell", "fileless_execution", "malicious_command"}
AFTER_COMPROMISE_TACTICS = {
    "execution", "persistence", "privilege-escalation", "defense-evasion", "command-and-control", "impact",
}


@dataclass
class Incident:
    id: str
    opened: float
    updated: float
    ips: Set[str] = field(default_factory=set)
    users: Set[str] = field(default_factory=set)
    tactics: Set[str] = field(default_factory=set)
    alerts: int = 0
    compromised: bool = False


class IncidentTracker:
    def __init__(self) -> None:
        self.open: List[Incident] = []

    def _forget_closed(self, now: float) -> None:
        self.open = [item for item in self.open if now - item.updated <= OPEN_FOR_SEC]

    def _find(self, ip: str, user: str, tactics: Set[str]) -> Optional[Incident]:
        if ip:
            return next((item for item in self.open if ip in item.ips), None)
        if user and user.lower() not in SHARED_ACCOUNTS:
            for item in self.open:
                if user in item.users:
                    return item
        if tactics & AFTER_COMPROMISE_TACTICS:
            for item in reversed(self.open):
                if item.compromised:
                    return item
        return None

    def observe(self, alert: Dict[str, Any], when: Optional[float] = None) -> Incident:
        """Attach an alert to its incident, opening one if nothing fits."""
        moment = time.time() if when is None else when
        self._forget_closed(moment)
        event = alert.get("event") or {}
        ip = str(event.get("ip") or "")
        user = str(event.get("user") or "")
        tactics = set(tactics_of(alert.get("mitre") or []))

        incident = self._find(ip, user, tactics)
        if incident is None:
            incident = Incident(id=self._new_id(moment), opened=moment, updated=moment)
            self.open.append(incident)

        incident.updated = max(incident.updated, moment)
        incident.alerts += 1
        incident.tactics |= tactics
        if ip:
            incident.ips.add(ip)
        if user:
            incident.users.add(user)
        if alert.get("type") in COMPROMISE_TYPES:
            incident.compromised = True
        return incident

    def _new_id(self, moment: float) -> str:
        base = f"INC-{time.strftime('%Y%m%d-%H%M%S', time.gmtime(moment))}"
        used = {item.id for item in self.open}
        candidate, suffix = base, 1
        while candidate in used:
            suffix += 1
            candidate = f"{base}-{suffix}"
        return candidate

    def rebuild(self, threats: Iterable[Dict[str, Any]]) -> None:
        """Restore open incidents after a restart, so an attack in progress stays one attack."""
        for threat in threats:
            alert = threat.get("alert") if isinstance(threat, dict) else None
            if not isinstance(alert, dict):
                continue
            stamp = parse_ts((alert.get("event") or {}).get("ts")) or parse_ts(threat.get("ts"))
            if stamp is not None:
                self.observe(alert, stamp.timestamp())
        self._forget_closed(time.time())


def context_factors(incident: Incident) -> List[Dict[str, Any]]:
    """What being part of this incident says about how urgent an alert is."""
    factors: List[Dict[str, Any]] = []
    stages = len(incident.tactics)
    if stages >= 2:
        factors.append(
            {"name": "attack_chain", "lift": min(0.6, 0.2 * (stages - 1)),
             "detail": f"part of an attack spanning {stages} stages"}
        )
    if incident.alerts >= 2:
        factors.append(
            {"name": "repeat_activity", "lift": min(0.3, 0.05 * (incident.alerts - 1)),
             "detail": f"alert {incident.alerts} in this incident"}
        )
    return factors
