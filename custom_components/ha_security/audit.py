"""HA storage and admin-only search/inventory actions."""

import voluptuous as vol
import json
from copy import deepcopy
from pathlib import Path

from homeassistant.core import SupportsResponse
from homeassistant.helpers.service import async_register_admin_service, async_get_all_descriptions, async_set_service_schema
from homeassistant.helpers.storage import Store

from .const import DOMAIN
from .security import SecurityHistory, token_metadata, safe_ip, utcnow, parse_time
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
    integration_version = json.loads((Path(__file__).parent / "manifest.json").read_text())["version"]

    def scope_info(data):
        tid, uid = data.get("token_id"), data.get("user_id")
        result = {"activity_api_version": 2, "integration_version": integration_version}
        if tid:
            records = [r for r in monitor.history.records
                       if (r.get("token_id") or (r.get("metadata") or {}).get("token_id")) == tid
                       and (not uid or r.get("user_id") == uid)]
            sessions = [r for r in monitor.history.sessions if r.get("token_id") == tid
                        and (not uid or r.get("user_id") == uid)]
            current = any(r.get("token_id") == tid and (not uid or r.get("user_id") == uid)
                          for r in (monitor.snapshot or {}).get("tokens", []))
            result["credential_scope"] = {
                "token_id": tid, "user_id": uid, "in_current_inventory": current,
                "retained_observations": len(records), "retained_connections": len(sessions),
                "retained_actions": sum(r.get("kind") == "websocket_action" for r in records),
                "known": current or bool(records or sessions),
            }
        return result

    async def query(call):
        result = monitor.history.query(**dict(call.data))
        result.update(scope_info(call.data))
        result.update(websocket_action_status=monitor.sessions.action_status, websocket_action_reason=monitor.sessions.action_reason)
        monitor.audit.changed()
        return result

    async def inventory(call):
        return {
            "last_scan_success": monitor.last_scan_success,
            "last_successful_scan": monitor.last_successful_scan,
            "users": monitor.history.with_user_names((monitor.snapshot or {}).get("users", [])),
            "tokens": monitor.history.with_user_names([token_metadata(row) for row in (monitor.snapshot or {}).get("tokens", [])]),
        }

    async def scan(call):
        return {"success": await monitor.async_refresh()}

    async def label(call):
        async with monitor._lock:
            monitor.history.set_token_label(call.data["token_id"], call.data["label"])
            monitor.audit.changed()
            await monitor._notify()
        owner = next((row for row in (monitor.snapshot or {}).get("tokens", []) if row["token_id"] == call.data["token_id"]), None)
        if owner is None:
            owner = (monitor.history.previous or {}).get(call.data["token_id"])
        if owner is None:
            owner = next((row for row in reversed(monitor.history.sessions)
                          if row.get("token_id") == call.data["token_id"]), None)
        if owner is None:
            event = next((row for row in reversed(monitor.history.records)
                          if row.get("metadata", {}).get("token_id") == call.data["token_id"]), {})
            owner = event.get("metadata")
        return {"success": True, **monitor.history.with_user_names({
            "user_id": owner.get("user_id") if owner else None,
            "user_name": owner.get("user_name") if owner else None,
        })}

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
        return {"success": True, "user_id": uid, "user_name": monitor.history.user_names.get(uid)}

    async def sessions(call):
        monitor.history.prune()
        values = []
        for row in reversed(monitor.history.sessions):
            if call.data.get("user_id") and row["user_id"] != call.data["user_id"]:
                continue
            if call.data.get("state") and row["state"] != call.data["state"]:
                continue
            if call.data.get("token_id") and row.get("token_id") != call.data["token_id"]:
                continue
            stamp = parse_time(row.get("first_observed_at"))
            if call.data.get("since") and (stamp is None or stamp < parse_time(call.data["since"])):
                continue
            if call.data.get("until") and (stamp is None or stamp > parse_time(call.data["until"])):
                continue
            detail = monitor.history.with_user_names(row)
            if "security_level" not in detail:
                detail.update(session_assessment(monitor.history, row))
            detail["label"] = monitor.history.token_labels.get(row["token_id"]) or row["client_name"] or row["client_id"]
            detail["ip_context"] = monitor.history.ip_context.get(row["source_ip"], {})
            detail["credential_ip_context"] = monitor.history.ip_context.get(row.get("credential_last_used_ip"), {})
            if call.data.get("text") and call.data["text"].casefold() not in json.dumps(detail, ensure_ascii=False).casefold():
                continue
            values.append(detail)
        offset = call.data.get("offset", 0)
        monitor.audit.changed()
        return {"total": len(values), "sessions": values[offset:offset + call.data.get("limit", 100)],
                "tracking_status": monitor.sessions.status, **scope_info(call.data), **monitor.history.query_info(len(values), offset, call.data.get("limit", 100))}

    def timestamp(value):
        if not isinstance(value, str) or parse_time(value) is None:
            raise vol.Invalid("Use an ISO timestamp with timezone")
        return value

    schema = vol.Schema({
        vol.Optional("text", default=""): str,
        vol.Optional("token_id"): str,
        vol.Optional("since"): timestamp,
        vol.Optional("until"): timestamp,
        vol.Optional("user_id"): str,
        vol.Optional("kind"): str,
        vol.Optional("category"): vol.In(("inventory",)),
        vol.Optional("limit", default=100): vol.All(int, vol.Range(min=1, max=500)),
        vol.Optional("offset", default=0): vol.All(int, vol.Range(min=0)),
    })
    for name, handler, config in (
        ("query_audit", query, schema),
        ("get_inventory", inventory, vol.Schema({})),
        ("scan_now", scan, vol.Schema({})),
        ("query_sessions", sessions, vol.Schema({
            vol.Optional("text", default=""): str,
            vol.Optional("token_id"): str,
            vol.Optional("since"): timestamp,
            vol.Optional("until"): timestamp,
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


def user_options(monitor, include_history=True):
    users = {row["user_id"]: row.get("user_name") or row.get("name")
             for row in (monitor.snapshot or {}).get("users", [])}
    if include_history:
        users = {**monitor.history.user_names, **users}
    names = list(users.values())
    return [{"value": uid, "label": (name or "Unnamed user")
             + (f" · {uid[-8:]}" if not name or names.count(name) > 1 else "")
             + (" (historical)" if uid not in {r["user_id"] for r in (monitor.snapshot or {}).get("users", [])} else "")}
            for uid, name in sorted(users.items(), key=lambda item: ((item[1] or "").casefold(), item[0]))]


async def refresh_action_descriptions(hass, monitor):
    """Use HA's service-description API; never edit services.yaml at runtime."""
    descriptions = await async_get_all_descriptions(hass)
    for service in ("query_audit", "query_sessions", "recognize_source"):
        description = deepcopy(descriptions.get(DOMAIN, {}).get(service, {}))
        fields = description.get("fields", {})
        if "user_id" not in fields:
            continue
        options = user_options(monitor, service != "recognize_source")
        if service != "recognize_source":
            options.insert(0, {"value": "", "label": "All users"})
        selector = {"select": {"options": options, "mode": "dropdown", "custom_value": True}}
        if fields["user_id"].get("selector") == selector:
            continue
        fields["user_id"].update(name="User", selector=selector)
        async_set_service_schema(hass, DOMAIN, service, description)
        hass.bus.async_fire("service_registered", {"domain": DOMAIN, "service": service})
