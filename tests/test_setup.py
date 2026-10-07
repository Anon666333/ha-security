"""Entry-point tests using real schemas and a stubbed HA scheduler/bus."""

import importlib.util
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

import voluptuous as vol


def positive_int(value):
    value = int(value)
    if value < 0:
        raise vol.Invalid("must be positive")
    return value


def load_entrypoint(track):
    modules = {}
    for name in (
        "homeassistant", "homeassistant.const", "homeassistant.core",
        "homeassistant.helpers", "homeassistant.helpers.config_validation",
        "homeassistant.helpers.event", "homeassistant.helpers.typing",
    ):
        modules[name] = ModuleType(name)
    modules["homeassistant.const"].EVENT_HOMEASSISTANT_STOP = "stop"
    modules["homeassistant.core"].HomeAssistant = object
    modules["homeassistant.core"].callback = lambda fn: fn
    modules["homeassistant.helpers.config_validation"].positive_int = positive_int
    modules["homeassistant.helpers.event"].async_track_time_interval = track
    modules["homeassistant.helpers.typing"].ConfigType = dict
    path = Path(__file__).resolve().parents[1] / "custom_components/ha_security"
    spec = importlib.util.spec_from_file_location(
        "ha_security_setup_unit", path / "__init__.py",
        submodule_search_locations=[str(path)],
    )
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, modules):
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    return module


class SetupTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.cancel = Mock()
        self.track = Mock(return_value=self.cancel)
        self.module = load_entrypoint(self.track)
        self.hass = SimpleNamespace(
            auth=SimpleNamespace(async_get_users=AsyncMock(return_value=[])),
            data={}, bus=SimpleNamespace(async_listen_once=Mock()),
        )

    def test_schema_defaults_bounds_and_extra_keys(self):
        schema = self.module.CONFIG_SCHEMA
        self.assertEqual(schema({"ha_security": {}})["ha_security"]["scan_interval"], 300)
        self.assertEqual(schema({"ha_security": {"scan_interval": 30}})["ha_security"]["scan_interval"], 30)
        self.assertIn("logger", schema({"ha_security": {}, "logger": {}}))
        for invalid in (0, -1, 29, "abc"):
            with self.assertRaises(vol.Invalid):
                schema({"ha_security": {"scan_interval": invalid}})
        with self.assertRaises(vol.Invalid):
            schema({"ha_security": {"unknown": True}})

    async def test_startup_duplicate_guard_and_stop(self):
        config = self.module.CONFIG_SCHEMA({"ha_security": {}})
        self.assertTrue(await self.module.async_setup(self.hass, config))
        monitor = self.hass.data["ha_security"]
        self.assertEqual(monitor.snapshot, {"users": [], "tokens": []})
        self.assertEqual(self.track.call_args.args[2].total_seconds(), 300)
        self.assertTrue(await self.module.async_setup(self.hass, config))
        self.track.assert_called_once()
        event, stop = self.hass.bus.async_listen_once.call_args.args
        self.assertEqual(event, "stop")
        stop(None)
        self.cancel.assert_called_once()
        self.assertNotIn("ha_security", self.hass.data)

    async def test_failed_startup_still_schedules_retry(self):
        self.hass.auth.async_get_users.side_effect = RuntimeError("SECRET")
        with self.assertLogs("ha_security_setup_unit.monitor", level="ERROR"):
            self.assertTrue(await self.module.async_setup(
                self.hass, self.module.CONFIG_SCHEMA({"ha_security": {}}),
            ))
        monitor = self.hass.data["ha_security"]
        self.assertIsNone(monitor.snapshot)
        self.hass.auth.async_get_users.side_effect = None
        await self.track.call_args.args[1](None)
        self.assertEqual(monitor.snapshot, {"users": [], "tokens": []})
