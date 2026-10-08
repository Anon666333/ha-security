"""HA storage and admin-only search/inventory actions."""

import voluptuous as vol
import json
from copy import deepcopy

from homeassistant.core import SupportsResponse
from homeassistant.helpers.service import async_register_admin_service
from homeassistant.helpers.storage import Store

from .const import DOMAIN
from .security import SecurityHistory, token_metadata, safe_ip, utcnow
from .risk import session_assessment


class AuditStore:
    def __init__(self, hass, retention_days):
        self.store = Store(hass, 1, f"{DOMAIN}.audit")
        self.history = SecurityHistory(retention_days)
        self._save_pending = False

    async def load(self):
        self.history = SecurityHistory(self.history.retention_days, await self.store.async_load())

    def changed(self):
        if not self._save_pending:
            self._save_pending = True
            self.store.async_delay_save(self._save_data, 5)

    def _save_data(self):
        self._save_pending = False
        return deepcopy(self.history.serialize())

    async def flush(self):
        await self.store.async_save(self._save_data())


def register_actions(hass, monitor):
    """Register admin-only responses; raw service data never enters history."""
    async def query(call):
        result = monitor.history.query(**dict(call.data))
        monitor.audit.changed()
        return result

    async def inventory(call):
        return {
            "last_scan_success": monitor.last_scan_success,
            "last_successful_scan": monitor.last_successful_scan,
            "users": (monitor.snapshot or {}).get("users", []),
            "tokens": [token_metadata(row) for row in (monitor.snapshot or {}).get("tokens", [])],
        }

    async def scan(call):
        return {"success": await monitor.async_refresh()}

    async def label(call):
        async with monitor._lock:
            monitor.history.set_token_label(call.data["token_id"], call.data["label"])
            monitor.audit.changed()
            await monitor._notify()
        return {"success": True}

    async def recognize(call):
        uid = call.data["user_id"]
        if uid not in {r["user_id"] for r in (monitor.snapshot or {}).get("users", [])}:
            raise vol.Invalid("Unknown user")
        tid, ip = call.data.get("token_id"), call.data.get("ip")
        ip = safe_ip(ip)
        if not tid and not ip:
            raise vol.Invalid("Provide a credential record ID or valid IP")
        if tid and not any(r["token_id"] == tid and r["user_id"] == uid for r in (monitor.snapshot or {}).get("tokens", [])):
            raise vol.Invalid("Credential does not belong to this user")
        async with monitor._lock:
            if uid not in monitor.history.recognized and len(monitor.history.recognized) >= 1000:
                raise vol.Invalid("Recognition user limit reached")
            baseline = monitor.history.recognized.setdefault(uid, {"tokens": {}, "ips": {}})
            for key, value in (("tokens", tid), ("ips", ip)):
                if value:
                    if call.data.get("recognized", True):
                        baseline[key][value] = utcnow().isoformat()
                    else:
                        baseline[key].pop(value, None)
                    while len(baseline[key]) > 1000:
                        del baseline[key][next(iter(baseline[key]))]
            monitor.history.add("recognition_changed", uid, token_id=tid, source_ip=ip,
                                recognized=call.data.get("recognized", True))
            monitor.audit.changed()
            await monitor._notify()
        return {"success": True}

    async def sessions(call):
        monitor.history.prune()
        values = []
        for row in reversed(monitor.history.sessions):
            if call.data.get("user_id") and row["user_id"] != call.data["user_id"]:
                continue
            if call.data.get("state") and row["state"] != call.data["state"]:
                continue
            detail = dict(row)
            if "security_level" not in detail:
                detail.update(session_assessment(monitor.history, row))
            detail["label"] = monitor.history.token_labels.get(row["token_id"]) or row["client_name"] or row["client_id"]
            detail["ip_context"] = monitor.history.ip_context.get(row["source_ip"], {})
            detail["credential_ip_context"] = monitor.history.ip_context.get(row.get("credential_last_used_ip"), {})
            if call.data.get("text") and call.data["text"].casefold() not in json.dumps(detail).casefold():
                continue
            values.append(detail)
        offset = call.data.get("offset", 0)
        monitor.audit.changed()
        return {"total": len(values), "sessions": values[offset:offset + call.data.get("limit", 100)],
                "tracking_status": monitor.sessions.status}

    schema = vol.Schema({
        vol.Optional("text", default=""): str,
        vol.Optional("user_id"): str,
        vol.Optional("kind"): str,
        vol.Optional("limit", default=100): vol.All(int, vol.Range(min=1, max=500)),
        vol.Optional("offset", default=0): vol.All(int, vol.Range(min=0)),
    })
    for name, handler, config in (
        ("query_audit", query, schema),
        ("get_inventory", inventory, vol.Schema({})),
        ("scan_now", scan, vol.Schema({})),
        ("query_sessions", sessions, vol.Schema({
            vol.Optional("text", default=""): str,
            vol.Optional("user_id"): str,
            vol.Optional("state"): vol.In(("connected", "closed", "interrupted")),
            vol.Optional("limit", default=100): vol.All(int, vol.Range(min=1, max=500)),
            vol.Optional("offset", default=0): vol.All(int, vol.Range(min=0)),
        })),
        ("recognize_source", recognize, vol.Schema({
            vol.Required("user_id"): str, vol.Optional("token_id"): str,
            vol.Optional("ip"): str, vol.Optional("recognized", default=True): bool,
        })),
        ("set_token_label", label, vol.Schema({
            vol.Required("token_id"): str,
            vol.Required("label"): vol.All(str, vol.Length(max=128)),
        })),
    ):
        async_register_admin_service(
            hass, DOMAIN, name, handler, schema=config,
            supports_response=SupportsResponse.ONLY,
        )


def remove_actions(hass):
    for name in ("query_audit", "get_inventory", "scan_now", "set_token_label", "query_sessions", "recognize_source"):
        hass.services.async_remove(DOMAIN, name)
