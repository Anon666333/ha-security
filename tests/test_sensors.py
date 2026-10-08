"""Sensor behavior and discovery tests with a stub HA entity platform."""

import importlib
from datetime import datetime, timezone
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from test_auth_monitor import user, token
from ha_security_unit.monitor import AuthMonitor


class Entity:
    hass = None
    entity_id = None

    async def async_remove(self):
        self.removed = True

    def async_write_ha_state(self):
        self.writes = getattr(self, "writes", 0) + 1


class SensorTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        modules = {}
        for name in (
            "homeassistant", "homeassistant.components",
            "homeassistant.components.sensor", "homeassistant.helpers",
            "homeassistant.helpers.entity_registry",
            "homeassistant.helpers.device_registry",
        ):
            modules[name] = ModuleType(name)
        modules["homeassistant.components.sensor"].SensorEntity = Entity
        modules["homeassistant.components.sensor"].SensorDeviceClass = SimpleNamespace(TIMESTAMP="timestamp")
        self.registry = SimpleNamespace(
            async_get=Mock(return_value=None), async_remove=Mock(),
        )
        er = modules["homeassistant.helpers.entity_registry"]
        er.async_get = lambda hass: self.registry
        er.async_entries_for_config_entry = lambda registry, entry_id: []
        self.devices = SimpleNamespace(async_get_or_create=Mock(), async_update_device=Mock(), async_remove_device=Mock())
        self.device_entries = []
        dr = modules["homeassistant.helpers.device_registry"]
        dr.async_get = lambda hass: self.devices
        dr.async_entries_for_config_entry = lambda registry, entry_id: self.device_entries
        dr.DeviceInfo = dict
        dr.DeviceEntryType = SimpleNamespace(SERVICE="service")
        with patch.dict(sys.modules, modules):
            self.module = importlib.import_module("ha_security_unit.sensor")
        self.account = user({"record": token()})
        self.auth = SimpleNamespace(async_get_users=AsyncMock(return_value=[self.account]))
        self.monitor = AuthMonitor(self.auth)

    async def test_counts_attributes_identity_and_failure_recovery(self):
        await self.monitor.async_refresh()
        entity = self.module.UserTokenSensor(self.monitor, self.account.id)
        identity = entity._attr_unique_id
        self.assertEqual(entity.native_value, 1)
        self.assertTrue(entity.available)
        self.assertNotIn("latest_ip", entity.extra_state_attributes)
        self.assertNotIn("latest_client", entity.extra_state_attributes)
        self.assertIn("recently_observed", entity.extra_state_attributes)
        self.account.name = "Renamed"
        self.account.refresh_tokens.clear()
        await self.monitor.async_refresh()
        self.assertEqual(entity._attr_unique_id, identity)
        self.assertIn("Renamed", entity.name)
        self.assertEqual(entity.native_value, 0)
        self.auth.async_get_users.side_effect = RuntimeError("secret")
        with self.assertLogs("ha_security_unit.monitor", level="ERROR"):
            await self.monitor.async_refresh()
        self.assertFalse(entity.available)
        self.assertIsNone(entity.native_value)
        self.auth.async_get_users.side_effect = None
        await self.monitor.async_refresh()
        self.assertTrue(entity.available)

    async def test_discovery_deletion_and_subscription_cleanup(self):
        await self.monitor.async_refresh()
        entities = []
        cleanups = []
        entry = SimpleNamespace(entry_id="test", async_on_unload=cleanups.append)
        hass = SimpleNamespace(data={"ha_security": self.monitor})
        def add(new):
            for entity in new:
                entity.hass = hass
                entity.entity_id = "sensor." + getattr(entity, "user_id", "overview") + "_" + getattr(entity, "metric", "overview")
                entities.append(entity)
        await self.module.async_setup_entry(hass, entry, add)
        self.assertEqual(len(entities), 10)
        identifiers = entities[1].device_info["identifiers"]
        self.assertTrue(all(entity.device_info["identifiers"] == identifiers for entity in entities[1:]))
        self.device_entries = [SimpleNamespace(id="first-device", identifiers=identifiers)]
        self.account.name = "Renamed account"
        await self.monitor.async_refresh()
        self.assertEqual(self.devices.async_get_or_create.call_args.kwargs["name"], "Renamed account")
        extra = user()
        extra.id = "second"
        self.auth.async_get_users.return_value = [self.account, extra]
        await self.monitor.async_refresh()
        self.assertEqual(len(entities), 19)
        self.assertEqual(entities[10].native_value, 0)
        self.auth.async_get_users.return_value = [extra]
        await self.monitor.async_refresh()
        self.assertTrue(entities[1].removed)
        self.devices.async_remove_device.assert_called_once_with("first-device")
        cleanups[0]()
        self.assertEqual(self.monitor.listeners, [])

    async def test_network_opt_in_and_timestamp_sensor(self):
        self.account.refresh_tokens["record"].last_used_at = datetime.now(timezone.utc)
        self.account.refresh_tokens["record"].last_used_ip = "192.0.2.1"
        await self.monitor.async_refresh()
        self.monitor.expose_network = True
        entity = self.module.UserTokenSensor(self.monitor, self.account.id)
        self.assertEqual(entity.extra_state_attributes["latest_ip"], "192.0.2.1")
        recent = self.module.UserTokenSensor(self.monitor, self.account.id, "recently_observed")
        self.assertEqual(recent.native_value, "recently_observed")
        stamp = self.module.UserTokenSensor(self.monitor, self.account.id, "last_token_use")
        self.assertIsNotNone(stamp.native_value.tzinfo)
        activity = self.module.UserTokenSensor(self.monitor, self.account.id, "recently_used_tokens")
        self.assertEqual(activity.native_value, 1)
        self.assertEqual(activity.extra_state_attributes["tokens"][0]["last_used_ip"], "192.0.2.1")
        self.monitor.expose_network = False
        self.assertNotIn("tokens", activity.extra_state_attributes)
