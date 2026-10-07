"""Read-only per-user security observation entities."""

from homeassistant.components.sensor import SensorEntity, SensorDeviceClass
from homeassistant.helpers import entity_registry as er

from .const import DOMAIN

METRICS = ("refresh_tokens", "last_token_use", "last_service_call",
           "recently_observed", "known_ip_count", "new_observation_count")


async def async_setup_entry(hass, entry, async_add_entities):
    """Discover users on successful snapshots and reconcile removed users."""
    monitor = hass.data[DOMAIN]
    entities = {}
    registry = er.async_get(hass)

    async def reconcile():
        if monitor.last_scan_success:
            users = {row["user_id"]: row for row in monitor.snapshot["users"]}
            expected = {f"{DOMAIN}_{uid}_{metric}" for uid in users for metric in METRICS}
            for record in er.async_entries_for_config_entry(registry, entry.entry_id):
                if (
                    record.domain == "sensor"
                    and record.platform == DOMAIN
                    and record.unique_id.startswith(f"{DOMAIN}_")
                    and any(record.unique_id.endswith("_" + metric) for metric in METRICS)
                    and record.unique_id not in expected
                    and record.entity_id not in {
                        entity.entity_id for entity in entities.values()
                    }
                ):
                    registry.async_remove(record.entity_id)
            for key in list(entities):
                if key[0] in users:
                    continue
                entity = entities.pop(key)
                await entity.async_remove()
                if entity.entity_id and registry.async_get(entity.entity_id):
                    registry.async_remove(entity.entity_id)
            additions = []
            for user_id in users:
                for metric in METRICS:
                    key = (user_id, metric)
                    if key not in entities:
                        entity = UserTokenSensor(monitor, user_id, metric)
                        entities[key] = entity
                        additions.append(entity)
            if additions:
                async_add_entities(additions)
        for entity in entities.values():
            if entity.hass is not None:
                entity.async_write_ha_state()

    entry.async_on_unload(monitor.subscribe(reconcile))
    await reconcile()


class UserTokenSensor(SensorEntity):
    """Expose observations and optional network metadata, never secrets."""

    _attr_should_poll = False
    _attr_icon = "mdi:account-key"

    def __init__(self, monitor, user_id, metric="refresh_tokens"):
        self.monitor = monitor
        self.user_id = user_id
        self.metric = metric
        self._attr_unique_id = f"{DOMAIN}_{user_id}_{metric}"
        if metric in ("last_token_use", "last_service_call"):
            self._attr_device_class = SensorDeviceClass.TIMESTAMP
        if metric == "refresh_tokens":
            self._attr_native_unit_of_measurement = "tokens"

    @property
    def _user(self):
        snapshot = self.monitor.snapshot or {"users": []}
        return next((u for u in snapshot["users"] if u["user_id"] == self.user_id), None)

    @property
    def name(self):
        user = self._user
        label = (user and user["name"]) or self.user_id
        return f"HA Security {label} {self.metric.replace('_', ' ').capitalize()}"

    @property
    def available(self):
        return self.monitor.last_scan_success and self._user is not None

    @property
    def native_value(self):
        if not self.available:
            return None
        if self.metric != "refresh_tokens":
            value = self.monitor.user_summary(self.user_id)[self.metric]
            if self.metric == "recently_observed":
                return "recently_observed" if value else "not_recently_observed"
            return value
        return sum(
            token["user_id"] == self.user_id
            for token in self.monitor.snapshot["tokens"]
        )

    @property
    def extra_state_attributes(self):
        user = self._user
        if user is None:
            return {}
        attributes = {
            "is_active": user["is_active"],
            "is_owner": user["is_owner"],
            "system_generated": user["system_generated"],
            "last_successful_scan": self.monitor.last_successful_scan,
            "ha_security_metric": self.metric,
            "recent_window_minutes": self.monitor.recent_minutes,
        }
        if self.metric == "refresh_tokens":
            summary = self.monitor.user_summary(self.user_id)
            attributes.update({
                "recently_observed": summary["recently_observed"],
                "last_token_use": summary["last_token_use"].isoformat() if summary["last_token_use"] else None,
                "last_service_call": summary["last_service_call"].isoformat() if summary["last_service_call"] else None,
                "new_observation_count": summary["new_observation_count"],
                "known_ip_count": summary["known_ip_count"],
            })
            if self.monitor.expose_network:
                attributes.update({
                    "latest_ip": summary["latest_ip"],
                    "latest_client": summary["latest_client"],
                })
        return attributes
