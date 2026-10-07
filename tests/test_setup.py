"""Entry-point tests using real schemas and a stubbed HA scheduler/bus."""

import importlib.util
import importlib
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
        "homeassistant.config_entries",
        "homeassistant.helpers", "homeassistant.helpers.config_validation",
        "homeassistant.helpers.event", "homeassistant.helpers.typing",
    ):
        modules[name] = ModuleType(name)
    modules["homeassistant.const"].EVENT_HOMEASSISTANT_STOP = "stop"
    modules["homeassistant.config_entries"].ConfigEntry = object
    modules["homeassistant.config_entries"].ConfigFlow = Flow
    modules["homeassistant.config_entries"].OptionsFlow = Flow
    modules["homeassistant"].config_entries = modules["homeassistant.config_entries"]
    modules["homeassistant.core"].HomeAssistant = object
    modules["homeassistant.core"].callback = lambda fn: fn
    modules["homeassistant.helpers.config_validation"].positive_int = positive_int
    modules["homeassistant.helpers.config_validation"].config_entry_only_config_schema = lambda domain: vol.Schema({})
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
        module.flow_module = importlib.import_module(spec.name + ".config_flow")
    return module


class Flow:
    """Stub only HA flow routing; production schemas remain real."""

    def __init_subclass__(cls, **kwargs):
        pass

    async def async_set_unique_id(self, value):
        self.unique_id = value

    def _abort_if_unique_id_configured(self):
        if getattr(self, "configured", False):
            raise RuntimeError("already_configured")

    def async_show_form(self, **kwargs):
        return {"type": "form", **kwargs}

    def async_create_entry(self, **kwargs):
        return {"type": "create_entry", **kwargs}


class SetupTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.cancel = Mock()
        self.track = Mock(return_value=self.cancel)
        self.module = load_entrypoint(self.track)
        self.hass = SimpleNamespace(
            auth=SimpleNamespace(async_get_users=AsyncMock(return_value=[])),
            data={}, bus=SimpleNamespace(async_listen_once=Mock(return_value=Mock())),
            config_entries=SimpleNamespace(async_reload=AsyncMock()),
        )
        self.callbacks = []
        self.entry = SimpleNamespace(
            data={"scan_interval": 300}, options={}, entry_id="security",
            async_on_unload=self.callbacks.append,
            add_update_listener=Mock(return_value=Mock()),
        )

    def test_interval_schema_defaults_bounds(self):
        schema = self.module.flow_module.interval_schema(300)
        self.assertEqual(schema({})["scan_interval"], 300)
        self.assertEqual(schema({"scan_interval": 30})["scan_interval"], 30)
        for invalid in (0, -1, 29, "abc", 30.5):
            with self.assertRaises(vol.Invalid):
                schema({"scan_interval": invalid})
        with self.assertRaises(vol.Invalid):
            schema({"unknown": True})

    async def test_startup_duplicate_guard_and_stop(self):
        self.assertTrue(await self.module.async_setup(self.hass, {}))
        self.assertEqual(self.hass.data, {})
        self.assertTrue(await self.module.async_setup_entry(self.hass, self.entry))
        monitor = self.hass.data["ha_security"]
        self.assertEqual(monitor.snapshot, {"users": [], "tokens": []})
        self.assertEqual(self.track.call_args.args[2].total_seconds(), 300)
        self.assertTrue(await self.module.async_setup_entry(self.hass, self.entry))
        self.track.assert_called_once()
        event, stop = self.hass.bus.async_listen_once.call_args.args
        self.assertEqual(event, "stop")
        stop(None)
        self.cancel.assert_called_once()
        self.assertNotIn("ha_security", self.hass.data)

    async def test_failed_startup_still_schedules_retry(self):
        self.hass.auth.async_get_users.side_effect = RuntimeError("SECRET")
        with self.assertLogs("ha_security_setup_unit.monitor", level="ERROR"):
            self.assertTrue(await self.module.async_setup_entry(
                self.hass, self.entry,
            ))
        monitor = self.hass.data["ha_security"]
        self.assertIsNone(monitor.snapshot)
        self.hass.auth.async_get_users.side_effect = None
        await self.track.call_args.args[1](None)
        self.assertEqual(monitor.snapshot, {"users": [], "tokens": []})

    async def test_unload_and_options_reload(self):
        self.entry.options = {"scan_interval": 60}
        await self.module.async_setup_entry(self.hass, self.entry)
        self.assertEqual(self.track.call_args.args[2].total_seconds(), 60)
        await self.module.async_options_updated(self.hass, self.entry)
        self.hass.config_entries.async_reload.assert_awaited_once_with("security")
        self.assertTrue(await self.module.async_unload_entry(self.hass, self.entry))
        # HA runs these callbacks after async_unload_entry succeeds.
        for cleanup in self.callbacks:
            cleanup()
        self.cancel.assert_called_once()
        self.assertNotIn("ha_security", self.hass.data)

    async def test_ui_setup_invalid_input_and_duplicate(self):
        flow = self.module.flow_module.SecurityConfigFlow()
        self.assertEqual((await flow.async_step_user())["type"], "form")
        result = await flow.async_step_user({"scan_interval": 10})
        self.assertEqual(result["errors"], {"scan_interval": "invalid_interval"})
        result = await flow.async_step_user({"scan_interval": 120})
        self.assertEqual(result["data"], {"scan_interval": 120})
        self.assertEqual(result["type"], "create_entry")
        self.assertEqual(flow.unique_id, "ha_security")
        flow.configured = True
        with self.assertRaisesRegex(RuntimeError, "already_configured"):
            await flow.async_step_user()

    async def test_ui_options_defaults_validation_and_save(self):
        self.entry.options = {"scan_interval": 60}
        flow = self.module.flow_module.SecurityConfigFlow.async_get_options_flow(self.entry)
        result = await flow.async_step_init()
        self.assertEqual(result["data_schema"]({})["scan_interval"], 60)
        result = await flow.async_step_init({"scan_interval": 1})
        self.assertEqual(result["errors"], {"scan_interval": "invalid_interval"})
        result = await flow.async_step_init({"scan_interval": 90})
        self.assertEqual(result["data"], {"scan_interval": 90})
