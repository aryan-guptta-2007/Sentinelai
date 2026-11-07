#!/usr/bin/env python3
from typing import Any, Dict, List, TypedDict


class Event(TypedDict, total=False):
    ts: str
    src: str
    type: str
    host: str
    user: str
    pid: int
    ip: str
    port: int
    proto: str
    msg: str
    meta: Dict[str, Any]


class ResponseStep(TypedDict, total=False):
    action: str  # "block_ip" | "kill_process" | "lock_user"
    target: str  # event field in a rule, the resolved value in a plan
    min_score: int


class Alert(TypedDict, total=False):
    ts: str
    event: Event
    type: str
    rule_id: str
    reason: str
    base_severity: int
    mitre: List[str]
    evidence: List[str]
    advice: str
    respond: List[ResponseStep]


class Threat(TypedDict, total=False):
    ts: str
    alert: Alert
    ml_score: float
    threat_score: int
    plan: List[ResponseStep]
    notes: str
