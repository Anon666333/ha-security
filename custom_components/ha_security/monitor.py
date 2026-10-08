"""Polling lifecycle and metadata change logging for future tracking."""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any

from .auth_monitor import async_snapshot
from .security import SecurityHistory
from .sessions import SessionTracker

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
        self.enricher = None
        self.sessions = SessionTracker(self.history, self.session_changed)
        self.session_cleanup = None
        self.login_cleanup = None
        self.login_status = "disabled"
        self.login_reason = None
        self.login_started_at = None
        self._session_timer = None

    def session_changed(self):
        if self.stopped:
            return
        if self.audit:
            self.audit.changed()
        if self._session_timer is None:
            def publish():
                self._session_timer = None
                if not self.stopped:
                    asyncio.create_task(self._notify())
            self._session_timer = asyncio.get_running_loop().call_later(1, publish)

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
        if self.session_cleanup:
            self.session_cleanup()
            self.session_cleanup = None
        if self.login_cleanup:
            self.login_cleanup()
            self.login_cleanup = None
        if self._session_timer:
            self._session_timer.cancel()
            self._session_timer = None
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
            self.sessions.refresh_credential_ips(current["tokens"])
            if self.enricher:
                try:
                    await self.enricher(self.history, [
                        row["last_used_ip"] for row in current["tokens"] if row.get("last_used_ip")
                    ] + [row["source_ip"] for row in self.history.records[-100:]
                         if row["kind"] in ("login_success", "login_failure") and row.get("source_ip")]
                      + [row[key] for row in self.history.sessions[-100:]
                         for key in ("source_ip", "credential_last_used_ip") if row.get(key)])
                except Exception as err:
                    _LOGGER.debug("IP context lookup failed (%s)", type(err).__name__)
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
