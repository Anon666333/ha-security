"""One read-only refresh-token-count sensor per discovered HA user."""

from homeassistant.components.sensor import SensorEntity
from homeassistant.helpers import entity_registry as er

from .const import DOMAIN


async def async_setup_entry(hass, entry, async_add_entities):
    """Discover users on successful snapshots and reconcile removed users."""
    monitor = hass.data[DOMAIN]
    entities = {}
    registry = er.async_get(hass)

    async def reconcile():
        if monitor.last_scan_success:
            users = {row["user_id"]: row for row in monitor.snapshot["users"]}
            expected = {f"{DOMAIN}_{uid}_refresh_tokens" for uid in users}
            for record in er.async_entries_for_config_entry(registry, entry.entry_id):
                if (
                    record.domain == "sensor"
                    and record.platform == DOMAIN
                    and record.unique_id.startswith(f"{DOMAIN}_")
                    and record.unique_id.endswith("_refresh_tokens")
                    and record.unique_id not in expected
                    and record.entity_id not in {
                        entity.entity_id for entity in entities.values()
                    }
                ):
                    registry.async_remove(record.entity_id)
            for user_id in entities.keys() - users.keys():
                entity = entities.pop(user_id)
                await entity.async_remove()
                if entity.entity_id and registry.async_get(entity.entity_id):
                    registry.async_remove(entity.entity_id)
            additions = []
            for user_id in users:
                if user_id not in entities:
                    entity = UserTokenSensor(monitor, user_id)
                    entities[user_id] = entity
                    additions.append(entity)
            if additions:
                async_add_entities(additions)
        for entity in entities.values():
            if entity.hass is not None:
                entity.async_write_ha_state()

    entry.async_on_unload(monitor.subscribe(reconcile))
    await reconcile()


class UserTokenSensor(SensorEntity):
    """Expose counts and status, never token metadata or IPs."""

    _attr_should_poll = False
    _attr_icon = "mdi:account-key"
    _attr_native_unit_of_measurement = "tokens"

    def __init__(self, monitor, user_id):
        self.monitor = monitor
        self.user_id = user_id
        self._attr_unique_id = f"{DOMAIN}_{user_id}_refresh_tokens"

    @property
    def _user(self):
        snapshot = self.monitor.snapshot or {"users": []}
        return next((u for u in snapshot["users"] if u["user_id"] == self.user_id), None)

    @property
    def name(self):
        user = self._user
        label = (user and user["name"]) or self.user_id
        return f"HA Security {label} Refresh tokens"

    @property
    def available(self):
        return self.monitor.last_scan_success and self._user is not None

    @property
    def native_value(self):
        if not self.available:
            return None
        return sum(
            token["user_id"] == self.user_id
            for token in self.monitor.snapshot["tokens"]
        )

    @property
    def extra_state_attributes(self):
        user = self._user
        if user is None:
            return {}
        return {
            "is_active": user["is_active"],
            "is_owner": user["is_owner"],
            "system_generated": user["system_generated"],
            "last_successful_scan": self.monitor.last_successful_scan,
        }
