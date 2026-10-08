"""Bounded observed WebSocket sessions and isolated optional HA adapter."""

from functools import wraps
import inspect
import logging
import uuid

from .security import safe_client, safe_ip, utcnow

_LOGGER = logging.getLogger(__name__)


class SessionTracker:
    """Track connections, not human logins or physical devices."""

    def __init__(self, history, changed=lambda: None):
        self.history = history
        self.changed = changed
        self.live = {}
        self.status = "disabled"
        self.started_at = None
        # Persisted open connections belong to a previous monitoring run.
        for row in self.history.sessions:
            if row["state"] == "connected":
                row.update(state="interrupted", ended_at=utcnow().isoformat(),
                           closed_at=None, end_reason="monitoring_interrupted")

    def start(self):
        self.status = "observing"
        self.started_at = utcnow().isoformat()
        for row in self.history.sessions:
            if row["state"] == "connected":
                row.update(state="interrupted", ended_at=self.started_at,
                           closed_at=None, end_reason="monitoring_interrupted")
        self.history.prune()

    def observe(self, connection, newly_connected=False):
        key = id(connection)
        now = utcnow().isoformat()
        if key not in self.live:
            user = connection.user
            tid = getattr(connection, "refresh_token_id", None)
            token = getattr(user, "refresh_tokens", {}).get(tid)
            row = {
                "session_id": uuid.uuid4().hex, "user_id": user.id,
                "user_name": (getattr(user, "name", None) or user.id)[:128],
                "token_id": tid, "source_ip": safe_ip(getattr(connection, "remote", None)),
                "client_id": safe_client(getattr(token, "client_id", None)),
                "client_name": (getattr(token, "client_name", None) or "")[:128] or None,
                "connected_at": now if newly_connected else None,
                "first_observed_at": now, "last_seen_at": None,
                "closed_at": None, "ended_at": None, "state": "connected",
                "start_known": newly_connected, "end_reason": None,
                "transport": "websocket",
            }
            self.live[key] = row
            self.history.sessions.append(row)
        row = self.live[key]
        if not newly_connected:
            row["last_seen_at"] = now
        self.history.prune()
        self.changed()

    def close(self, connection):
        row = self.live.pop(id(connection), None)
        if row:
            now = utcnow().isoformat()
            row.update(state="closed", closed_at=now, ended_at=now, end_reason="connection_closed")
            self.changed()

    def stop(self):
        now = utcnow().isoformat()
        for row in self.live.values():
            row.update(state="interrupted", ended_at=now, closed_at=None,
                       end_reason="monitoring_stopped")
        self.live.clear()
        self.status = "disabled"

    def view(self, user_id, network=False):
        rows = [dict(row) for row in reversed(self.history.sessions) if row["user_id"] == user_id]
        for row in rows:
            row["label"] = self.history.token_labels.get(row["token_id"]) or row["client_name"] or row["client_id"] or "Unknown client"
            if network:
                row["ip_context"] = self.history.ip_context.get(row["source_ip"], {})
            else:
                for key in ("source_ip", "client_id", "client_name", "token_id", "label"):
                    row.pop(key, None)
        active = [row for row in rows if row["state"] == "connected"]
        ended = [row for row in rows if row["state"] != "connected"]
        return {
            "active_connection_count": len(active), "tracking_status": self.status,
            "tracking_started_at": self.started_at,
            "coverage": "Connections observed since tracking started; reconnect existing clients for coverage. HTTP/cloud requests are outside this count",
            "active_connections": active[:100], "session_history": ended[:100],
            "active_connections_total": len(active), "session_history_total": len(ended),
            "sessions_truncated": len(active) > 100 or len(ended) > 100,
        }


def install_adapter(hass, tracker, connection_class=None, auth_class=None):
    """Observe selected synchronous lifecycle methods without reading payloads.

    Original methods always run unchanged. Failures in observation never enter
    HA authentication/command processing. Remove only wrappers we still own.
    """
    try:
        if connection_class is None:
            from homeassistant.components.websocket_api.connection import ActiveConnection
            from homeassistant.components.websocket_api.auth import AuthPhase
            connection_class = ActiveConnection
            auth_class = AuthPhase
        if not {"hass", "user"}.issubset(inspect.signature(connection_class.__init__).parameters):
            raise ValueError("Unsupported connection constructor")
        originals = {name: getattr(connection_class, name) for name in
                     ("__init__", "async_handle", "async_handle_close")}
        if any(inspect.iscoroutinefunction(fn) for fn in originals.values()):
            raise ValueError("Unsupported asynchronous lifecycle")
        auth_originals = {}
        if auth_class:
            for name in ("async_handle", "async_handle_supervisor_unix_socket"):
                original = getattr(auth_class, name, None)
                if original is not None:
                    if not inspect.iscoroutinefunction(original):
                        raise ValueError("Unsupported auth lifecycle")
                    auth_originals[name] = original
            if "async_handle" not in auth_originals:
                raise ValueError("Unsupported auth lifecycle")
    except Exception:
        tracker.status = "unsupported"
        return lambda: None

    def safe_observe(connection, action):
        try:
            if connection.hass is hass and tracker.status == "observing":
                action()
        except Exception as err:
            tracker.status = "error"
            _LOGGER.warning("Session observation stopped (%s)", type(err).__name__)

    @wraps(originals["__init__"])
    def init(connection, *args, **kwargs):
        originals["__init__"](connection, *args, **kwargs)
        if not auth_class:
            safe_observe(connection, lambda: tracker.observe(connection, True))

    @wraps(originals["async_handle"])
    def handle(connection, *args, **kwargs):
        safe_observe(connection, lambda: tracker.observe(connection))
        return originals["async_handle"](connection, *args, **kwargs)

    @wraps(originals["async_handle_close"])
    def close(connection, *args, **kwargs):
        try:
            return originals["async_handle_close"](connection, *args, **kwargs)
        finally:
            safe_observe(connection, lambda: tracker.close(connection))

    wrappers = {"__init__": init, "async_handle": handle, "async_handle_close": close}
    tracker.start()
    for name, wrapper in wrappers.items():
        setattr(connection_class, name, wrapper)
    auth_wrappers = {}
    for name, original in auth_originals.items():
        def make_auth_wrapper(original):
            @wraps(original)
            async def authenticated(*args, **kwargs):
                connection = await original(*args, **kwargs)
                safe_observe(connection, lambda: tracker.observe(connection, True))
                return connection
            return authenticated
        auth_wrappers[name] = make_auth_wrapper(original)
        setattr(auth_class, name, auth_wrappers[name])

    def uninstall():
        for name, wrapper in wrappers.items():
            if getattr(connection_class, name) is wrapper:
                setattr(connection_class, name, originals[name])
        for name, wrapper in auth_wrappers.items():
            if getattr(auth_class, name) is wrapper:
                setattr(auth_class, name, auth_originals[name])
        tracker.stop()
    return uninstall
