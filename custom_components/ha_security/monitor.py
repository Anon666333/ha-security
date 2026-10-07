"""Polling lifecycle and metadata change logging for future tracking."""

import asyncio
import json
import logging
from typing import Any

from .auth_monitor import async_snapshot

_LOGGER = logging.getLogger(__name__)


class AuthMonitor:
    """Keep only the latest successful detached snapshot in memory."""

    def __init__(self, auth: Any) -> None:
        self.auth = auth
        self.snapshot: dict[str, list[dict[str, Any]]] | None = None
        self._lock = asyncio.Lock()

    async def async_refresh(self, _now: Any = None) -> bool:
        """Refresh safely; failed polls retain the last successful snapshot."""
        async with self._lock:
            try:
                current = await async_snapshot(self.auth)
            except Exception:
                # Exception text/reprs from auth internals may contain secrets.
                _LOGGER.error("Auth metadata scan failed; will retry at next interval")
                return False
            previous = self.snapshot or {"users": [], "tokens": []}
            if self.snapshot is None or current != self.snapshot:
                _LOGGER.info(
                    "Auth inventory: %s users, %s refresh tokens",
                    len(current["users"]), len(current["tokens"]),
                )
                for kind, key in (("users", "user_id"), ("tokens", "token_id")):
                    old = {row[key]: row for row in previous[kind]}
                    new = {row[key]: row for row in current[kind]}
                    for identifier, row in new.items():
                        if old.get(identifier) != row:
                            _LOGGER.debug(
                                "Auth %s metadata: %s", kind,
                                json.dumps(row, sort_keys=True),
                            )
                    for identifier in old.keys() - new.keys():
                        _LOGGER.debug(
                            "Auth %s record removed: %s", kind,
                            json.dumps(identifier),
                        )
            self.snapshot = current
            return True
