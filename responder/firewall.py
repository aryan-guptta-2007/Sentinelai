"""Blocks addresses through nftables, iptables or Windows Firewall, and reports honestly
when it cannot. Addresses reach this module already parsed, and commands only ever
receive argument lists."""

from __future__ import annotations

import os
import re
import shutil
from typing import Optional, Set, Tuple

from responder import system
from responder.system import IPAddress, parse_ip

NFT_TABLE = "sentinelai"
# Forwarded traffic is covered too, or a blocked address could still reach anything
# published from a container.
NFT_RULESET = f"""
table inet {NFT_TABLE} {{
    set blocked4 {{ type ipv4_addr; flags timeout; }}
    set blocked6 {{ type ipv6_addr; flags timeout; }}
    chain input {{
        type filter hook input priority -10; policy accept;
        ip saddr @blocked4 drop
        ip6 saddr @blocked6 drop
    }}
    chain forward {{
        type filter hook forward priority -10; policy accept;
        ip saddr @blocked4 drop
        ip6 saddr @blocked6 drop
    }}
}}
"""
ADDRESS_TOKEN = re.compile(r"[0-9a-fA-F:.]{2,}")
IPTABLES_RULE = re.compile(r"-s (\S+?)(?:/\d+)? -j DROP")
WINDOWS_RULE_PREFIX = "SentinelAI block"


class Firewall:
    def __init__(self, preference: str):
        self.backend = self._pick(preference)
        self.table_ready = False

    @staticmethod
    def _pick(preference: str) -> Optional[str]:
        if preference == "auto":
            order = ["netsh"] if os.name == "nt" else ["nft", "iptables"]
        else:
            order = [preference]
        return next((name for name in order if shutil.which(name)), None)

    # ------------------------------------------------------------------ nftables
    def _ensure_nft_table(self) -> Tuple[bool, str]:
        if self.table_ready:
            return True, ""
        exists, _ = system.run_command(["nft", "list", "table", "inet", NFT_TABLE])
        if exists:
            self.table_ready = True
            return True, ""
        ok, detail = system.run_command(["nft", "-f", "-"], stdin=NFT_RULESET)
        self.table_ready = ok
        return ok, detail

    def _nft_block(self, address: IPAddress, timeout_sec: int) -> Tuple[bool, str]:
        set_name = "blocked6" if address.version == 6 else "blocked4"
        element = f"{{ {address} timeout {max(1, timeout_sec)}s }}"
        ok, detail = False, ""
        for _ in range(2):
            ready, problem = self._ensure_nft_table()
            if not ready:
                return False, f"could not create nft table: {problem}"
            ok, detail = system.run_command(
                ["nft", "add", "element", "inet", NFT_TABLE, set_name, element]
            )
            if ok or "No such file" not in detail:
                break
            self.table_ready = False  # a firewall reload removed the table, so rebuild it
        return ok, detail

    def _nft_present(self) -> Set[str]:
        found: Set[str] = set()
        for set_name in ("blocked4", "blocked6"):
            ok, output = system.run_command(["nft", "list", "set", "inet", NFT_TABLE, set_name])
            if ok:
                found.update(
                    str(address)
                    for address in map(parse_ip, ADDRESS_TOKEN.findall(output))
                    if address
                )
        return found

    # ------------------------------------------------------------------ iptables
    @staticmethod
    def _iptables(address: IPAddress) -> Optional[str]:
        tool = "ip6tables" if address.version == 6 else "iptables"
        return tool if shutil.which(tool) else None

    def _iptables_block(self, address: IPAddress) -> Tuple[bool, str]:
        tool = self._iptables(address)
        if tool is None:
            return False, "ip6tables not installed"
        rule = ["INPUT", "-s", str(address), "-j", "DROP"]
        if system.run_command([tool, "-C", *rule])[0]:
            return True, "rule already present"
        return system.run_command([tool, "-I", *rule])

    @staticmethod
    def _iptables_present() -> Set[str]:
        found: Set[str] = set()
        for tool in ("iptables", "ip6tables"):
            if not shutil.which(tool):
                continue
            ok, output = system.run_command([tool, "-S", "INPUT"])
            if ok:
                found.update(
                    str(address)
                    for address in map(parse_ip, IPTABLES_RULE.findall(output))
                    if address
                )
        return found

    # ------------------------------------------------------------- Windows Firewall
    @staticmethod
    def _windows_rule(address: IPAddress) -> str:
        return f"name={WINDOWS_RULE_PREFIX} {address}"

    def _windows_exists(self, address: IPAddress) -> bool:
        argv = ["netsh", "advfirewall", "firewall", "show", "rule", self._windows_rule(address)]
        return system.run_command(argv)[0]

    def _windows_block(self, address: IPAddress) -> Tuple[bool, str]:
        if self._windows_exists(address):
            return True, "rule already present"
        return system.run_command(
            ["netsh", "advfirewall", "firewall", "add", "rule", self._windows_rule(address),
             "dir=in", "action=block", f"remoteip={address}"]
        )

    def _windows_unblock(self, address: IPAddress) -> Tuple[bool, str]:
        ok, detail = system.run_command(
            ["netsh", "advfirewall", "firewall", "delete", "rule", self._windows_rule(address)]
        )
        return (True, detail) if ok or not self._windows_exists(address) else (False, detail)

    # ------------------------------------------------------------------- interface
    def block(self, address: IPAddress, timeout_sec: int) -> Tuple[bool, str]:
        if self.backend == "nft":
            return self._nft_block(address, timeout_sec)
        if self.backend == "iptables":
            return self._iptables_block(address)
        if self.backend == "netsh":
            return self._windows_block(address)
        return False, "no supported firewall backend on this host"

    def unblock(self, address: IPAddress) -> Tuple[bool, str]:
        if self.backend == "nft":
            set_name = "blocked6" if address.version == 6 else "blocked4"
            ok, detail = system.run_command(
                ["nft", "delete", "element", "inet", NFT_TABLE, set_name, f"{{ {address} }}"]
            )
            # nft removes timed-out elements on its own, so a miss is not a failure.
            return (True, detail) if "No such file" in detail else (ok, detail)
        if self.backend == "iptables":
            tool = self._iptables(address)
            if tool is None:
                return False, "ip6tables not installed"
            return system.run_command([tool, "-D", "INPUT", "-s", str(address), "-j", "DROP"])
        if self.backend == "netsh":
            return self._windows_unblock(address)
        return False, "no supported firewall backend on this host"

    def present(self) -> Optional[Set[str]]:
        """Addresses the kernel is blocking right now, or None if that cannot be listed."""
        if self.backend == "nft":
            return self._nft_present()
        if self.backend == "iptables":
            return self._iptables_present()
        return None
