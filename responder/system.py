"""Small operating-system helpers shared by the response modules."""

from __future__ import annotations

import ipaddress
import os
import socket
import struct
import subprocess
from pathlib import Path
from typing import Any, List, Optional, Set, Tuple, Union

import psutil

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

COMMAND_TIMEOUT_SEC = 10
COMM_LENGTH = 15  # Linux truncates process names to 15 characters


def run_command(argv: List[str], stdin: Optional[str] = None) -> Tuple[bool, str]:
    try:
        done = subprocess.run(
            argv,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT_SEC,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    return done.returncode == 0, (done.stderr or done.stdout).strip()


def parse_ip(raw: Any) -> Optional[IPAddress]:
    """Parse an address strictly. IPv4-mapped IPv6 becomes plain IPv4."""
    try:
        address = ipaddress.ip_address(str(raw).strip())
    except ValueError:
        return None
    mapped = getattr(address, "ipv4_mapped", None)
    return mapped or address


def read_list(path: Path) -> List[str]:
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except OSError:
        return []
    cleaned = (line.split("#", 1)[0].strip() for line in lines)
    return [line for line in cleaned if line]


def local_addresses() -> Set[IPAddress]:
    found: Set[IPAddress] = set()
    for entries in psutil.net_if_addrs().values():
        for entry in entries:
            address = parse_ip(entry.address.split("%", 1)[0])
            if address:
                found.add(address)
    return found


def default_gateways() -> Set[IPAddress]:
    """Blocking the gateway can take the whole host off the network."""
    found: Set[IPAddress] = set()
    if os.name == "nt":
        ok, output = run_command(["route", "print", "-4", "0.0.0.0"])
        if ok:
            for line in output.splitlines():
                fields = line.split()
                if len(fields) >= 3 and fields[:2] == ["0.0.0.0", "0.0.0.0"]:
                    address = parse_ip(fields[2])
                    if address:
                        found.add(address)
        return found

    try:
        rows = Path("/proc/net/route").read_text(encoding="ascii").splitlines()[1:]
    except OSError:
        return found
    for row in rows:
        fields = row.split()
        if len(fields) >= 4 and fields[1] == "00000000" and int(fields[3], 16) & 2:
            address = parse_ip(socket.inet_ntoa(struct.pack("<L", int(fields[2], 16))))
            if address:
                found.add(address)
    return found


def process_key(name: Any) -> str:
    """Reduce a process name or path to a form that compares across platforms."""
    base = str(name).replace("\\", "/").rsplit("/", 1)[-1].lower()
    return base.removesuffix(".exe")[:COMM_LENGTH]
