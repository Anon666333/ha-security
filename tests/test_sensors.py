"""Sensor behavior and discovery tests with a stub HA entity platform."""

import importlib
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
        ):
            modules[name] = ModuleType(name)
        modules["homeassistant.components.sensor"].SensorEntity = Entity
        self.registry = SimpleNamespace(
            async_get=Mock(return_value=None), async_remove=Mock(),
        )
        er = modules["homeassistant.helpers.entity_registry"]
        er.async_get = lambda hass: self.registry
        er.async_entries_for_config_entry = lambda registry, entry_id: []
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
        self.assertEqual(set(entity.extra_state_attributes), {
            "is_active", "is_owner", "system_generated", "last_successful_scan",
        })
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
                entity.entity_id = "sensor." + entity.user_id
                entities.append(entity)
        await self.module.async_setup_entry(hass, entry, add)
        self.assertEqual(len(entities), 1)
        extra = user()
        extra.id = "second"
        self.auth.async_get_users.return_value = [self.account, extra]
        await self.monitor.async_refresh()
        self.assertEqual(len(entities), 2)
        self.assertEqual(entities[1].native_value, 0)
        self.auth.async_get_users.return_value = [extra]
        await self.monitor.async_refresh()
        self.assertTrue(entities[0].removed)
        cleanups[0]()
        self.assertEqual(self.monitor.listeners, [])
