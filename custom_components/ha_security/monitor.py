"""Polling lifecycle and metadata change logging for future tracking."""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any

from .auth_monitor import async_snapshot
from .security import SecurityHistory

_LOGGER = logging.getLogger(__name__)


class AuthMonitor:
    """Keep only the latest successful detached snapshot in memory."""

    def __init__(self, auth: Any, audit=None, recent_minutes=15, expose_network=False) -> None:
        self.auth = auth
        self.snapshot: dict[str, list[dict[str, Any]]] | None = None
        self._lock = asyncio.Lock()
        self.last_scan_success = False
        self.last_successful_scan = None
        self.listeners = []
        self.audit = audit
        self.history = audit.history if audit else SecurityHistory()
        self.recent_minutes = recent_minutes
        self.expose_network = expose_network
        self.stopped = False

    def subscribe(self, listener):
        """Register a platform update callback and return its cleanup."""
        self.listeners.append(listener)
        return lambda: self.listeners.remove(listener)

    async def _notify(self):
        for listener in tuple(self.listeners):
            try:
                await listener()
            except Exception as err:
                _LOGGER.error("Security entity update failed (%s)", type(err).__name__)

    async def async_close(self):
        self.stopped = True
        async with self._lock:
            if self.audit:
                await self.audit.flush()

    async def async_refresh(self, _now: Any = None) -> bool:
        """Refresh safely; failed polls retain the last successful snapshot."""
        async with self._lock:
            if self.stopped:
                return False
            try:
                current = await async_snapshot(self.auth)
            except Exception as err:
                # Exception text/reprs from auth internals may contain secrets.
                _LOGGER.error(
                    "Auth metadata scan failed (%s); will retry at next interval",
                    type(err).__name__,
                )
                self.last_scan_success = False
                await self._notify()
                return False
            previous = self.snapshot or {"users": [], "tokens": []}
            _LOGGER.debug(
                "Auth scan completed: %s users, %s refresh tokens",
                len(current["users"]), len(current["tokens"]),
            )
            # Debug logging is commonly enabled after the initial scan.
            # Emit the full safe inventory each debug scan, even if unchanged.
            if _LOGGER.isEnabledFor(logging.DEBUG):
                for kind in ("users", "tokens"):
                    for row in current[kind]:
                        _LOGGER.debug(
                            "Auth %s metadata: %s", kind,
                            json.dumps(row, sort_keys=True),
                        )
            if self.snapshot is None or current != self.snapshot:
                _LOGGER.info(
                    "Auth inventory: %s users, %s refresh tokens",
                    len(current["users"]), len(current["tokens"]),
                )
                for kind, key in (("users", "user_id"), ("tokens", "token_id")):
                    old = {row[key]: row for row in previous[kind]}
                    new = {row[key]: row for row in current[kind]}
                    for identifier in old.keys() - new.keys():
                        _LOGGER.debug(
                            "Auth %s record removed: %s", kind,
                            json.dumps(identifier),
                        )
            self.snapshot = current
            self.history.observe(current)
            if self.audit:
                self.audit.changed()
            self.last_scan_success = True
            self.last_successful_scan = datetime.now(timezone.utc).isoformat()
            await self._notify()
            return True

    async def async_service_event(self, event):
        async with self._lock:
            if self.stopped:
                return
            if self.history.service_call(event.data, event.context):
                if self.audit:
                    self.audit.changed()
                await self._notify()

    def user_summary(self, user_id):
        tokens = [
            row for row in (self.snapshot or {}).get("tokens", [])
            if row["user_id"] == user_id
        ]
        return self.history.summary(user_id, tokens, self.recent_minutes)
