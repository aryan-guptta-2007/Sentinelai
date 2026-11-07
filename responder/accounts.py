"""Lock and unlock local accounts.

Locking only the password is not enough for a compromised account: SSH keys keep
working. On Linux the account is also expired, which refuses every login method. What
the account looked like first is returned, so unlocking can put it back exactly.
"""

from __future__ import annotations

import os
import shutil
from typing import Any, Dict, Tuple

from responder import system


class Accounts:
    def lock(self, name: str) -> Tuple[bool, str, Dict[str, Any]]:
        return self._lock_windows(name) if os.name == "nt" else self._lock_linux(name)

    def unlock(self, name: str, prior: Dict[str, Any]) -> Tuple[bool, str]:
        return self._unlock_windows(name) if os.name == "nt" else self._unlock_linux(name, prior)

    # --------------------------------------------------------------------- Linux
    @staticmethod
    def _shadow_state(name: str) -> Tuple[bool, str, Dict[str, Any]]:
        ok, output = system.run_command(["getent", "shadow", name])
        fields = output.split(":")
        if not ok or len(fields) < 8:
            return False, "no such account", {}
        return True, "", {"password_locked": fields[1].startswith("!"), "expire": fields[7]}

    def _lock_linux(self, name: str) -> Tuple[bool, str, Dict[str, Any]]:
        if not shutil.which("usermod"):
            return False, "usermod not available on this host", {}
        found, detail, prior = self._shadow_state(name)
        if not found:
            return False, detail, {}
        ok, detail = system.run_command(["usermod", "-L", "-e", "1", name])
        return ok, detail, prior

    @staticmethod
    def _unlock_linux(name: str, prior: Dict[str, Any]) -> Tuple[bool, str]:
        if not shutil.which("usermod"):
            return False, "usermod not available on this host"
        argv = ["usermod", "-e", str(prior.get("expire") or "")]
        if not prior.get("password_locked"):
            argv.append("-U")
        return system.run_command([*argv, name])

    # ------------------------------------------------------------------- Windows
    @staticmethod
    def _lock_windows(name: str) -> Tuple[bool, str, Dict[str, Any]]:
        ok, detail = system.run_command(["net", "user", name, "/active:no"])
        return ok, detail, {}

    @staticmethod
    def _unlock_windows(name: str) -> Tuple[bool, str]:
        return system.run_command(["net", "user", name, "/active:yes"])
