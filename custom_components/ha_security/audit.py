"""HA storage and admin-only search/inventory actions."""

import voluptuous as vol
from copy import deepcopy

from homeassistant.core import SupportsResponse
from homeassistant.helpers.service import async_register_admin_service
from homeassistant.helpers.storage import Store

from .const import DOMAIN
from .security import SecurityHistory, token_metadata


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
    ):
        async_register_admin_service(
            hass, DOMAIN, name, handler, schema=config,
            supports_response=SupportsResponse.ONLY,
        )


def remove_actions(hass):
    for name in ("query_audit", "get_inventory", "scan_now"):
        hass.services.async_remove(DOMAIN, name)
