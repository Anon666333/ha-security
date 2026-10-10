"""Entry-point tests using real schemas and a stubbed HA scheduler/bus."""

import importlib.util
import importlib
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

import voluptuous as vol
import yaml
from copy import deepcopy


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
        "homeassistant.helpers.storage", "homeassistant.helpers.service",
    ):
        modules[name] = ModuleType(name)
    modules["homeassistant.const"].EVENT_HOMEASSISTANT_STOP = "stop"
    modules["homeassistant.const"].Platform = SimpleNamespace(SENSOR="sensor")
    modules["homeassistant.const"].EVENT_CALL_SERVICE = "call_service"
    modules["homeassistant.config_entries"].ConfigEntry = object
    modules["homeassistant.config_entries"].ConfigFlow = Flow
    modules["homeassistant.config_entries"].OptionsFlow = Flow
    modules["homeassistant"].config_entries = modules["homeassistant.config_entries"]
    modules["homeassistant.core"].HomeAssistant = object
    modules["homeassistant.core"].callback = lambda fn: fn
    modules["homeassistant.core"].SupportsResponse = SimpleNamespace(ONLY="only")
    modules["homeassistant.helpers.storage"].Store = FakeStore
    modules["homeassistant.helpers.service"].async_register_admin_service = Mock()
    definitions = yaml.safe_load((Path(__file__).resolve().parents[1] / "custom_components/ha_security/services.yaml").read_text(encoding="utf-8"))
    modules["homeassistant.helpers.service"].async_get_all_descriptions = AsyncMock(side_effect=lambda hass: {"ha_security": deepcopy(definitions)})
    modules["homeassistant.helpers.service"].async_set_service_schema = Mock()
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
        module.audit_module = importlib.import_module(spec.name + ".audit")
    return module


class FakeStore:
    def __init__(self, *args):
        self.async_load = AsyncMock(return_value=None)
        self.async_save = AsyncMock()
        self.async_delay_save = Mock()


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
            data={}, bus=SimpleNamespace(
                async_fire=Mock(),
                async_listen_once=Mock(return_value=Mock()),
                async_listen=Mock(return_value=Mock()),
            ),
            services=SimpleNamespace(async_remove=Mock()),
            config_entries=SimpleNamespace(
                async_reload=AsyncMock(), async_forward_entry_setups=AsyncMock(),
                async_unload_platforms=AsyncMock(return_value=True),
            ),
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
        await stop(None)
        self.cancel.assert_called_once()
        self.assertNotIn("ha_security", self.hass.data)

    async def test_login_option_installs_and_unloads_observer(self):
        install = Mock(return_value=Mock())
        self.entry.options = {"track_logins": True}
        with patch.dict(sys.modules, {"ha_security_setup_unit.login_monitor": SimpleNamespace(install_login_adapter=install)}):
            await self.module.async_setup_entry(self.hass, self.entry)
        install.assert_called_once()
        monitor = self.hass.data["ha_security"]
        await monitor.async_close()
        install.return_value.assert_called_once()

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
        self.assertEqual(result["errors"], {"base": "invalid_settings"})
        result = await flow.async_step_user({"scan_interval": 120})
        self.assertEqual(result["data"]["scan_interval"], 120)
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
        self.assertEqual(result["errors"], {"base": "invalid_settings"})
        result = await flow.async_step_init({"scan_interval": 90})
        self.assertEqual(result["data"]["scan_interval"], 90)

    def test_mvp_option_bounds(self):
        schema = self.module.flow_module.settings_schema({})
        defaults = schema({"scan_interval": 30})
        self.assertEqual(defaults["retention_days"], 30)
        self.assertEqual(defaults["recent_minutes"], 15)
        self.assertFalse(defaults["expose_network"])
        self.assertFalse(defaults["enrich_ip"])
        self.assertFalse(defaults["track_sessions"])
        for field, invalid in (("retention_days", 0), ("retention_days", 366),
                               ("recent_minutes", 0), ("recent_minutes", 1441)):
            with self.assertRaises(vol.Invalid):
                schema({"scan_interval": 30, field: invalid})

    async def test_admin_actions_registered_and_responses(self):
        register = self.module.audit_module.async_register_admin_service
        register.reset_mock()
        await self.module.async_setup_entry(self.hass, self.entry)
        registered = {item.args[2]: item for item in register.call_args_list}
        self.assertEqual(set(registered), {"query_audit", "get_inventory", "scan_now", "set_token_label", "query_sessions", "recognize_source"})
        for item in registered.values():
            self.assertEqual(item.kwargs["supports_response"], "only")
        response = await registered["scan_now"].args[3](SimpleNamespace(data={}))
        self.assertEqual(response, {"success": True})
        response = await registered["get_inventory"].args[3](SimpleNamespace(data={}))
        self.assertEqual(response["users"], [])
        response = await registered["query_audit"].args[3](SimpleNamespace(data={"kind": "baseline_initialized"}))
        self.assertEqual(response["total"], 1)
        monitor = self.hass.data["ha_security"]
        monitor.snapshot["users"] = [{"user_id": "u", "name": "Matt", "user_name": "Matt"}]
        monitor.history.user_names["u"] = "Matt"
        monitor.snapshot["tokens"] = [{"user_id": "u", "token_id": "record-a"}]
        response = await registered["recognize_source"].args[3](SimpleNamespace(data={"user_id": "u", "token_id": "record-a"}))
        self.assertEqual(response["user_name"], "Matt")
        self.assertTrue(response["success"])
        self.assertIn("record-a", monitor.history.recognized["u"]["tokens"])
        with self.assertRaises(vol.Invalid):
            await registered["recognize_source"].args[3](SimpleNamespace(data={"user_id": "u", "token_id": "other"}))
        monitor.history.previous = {"record-a": {"user_id": "u"}}
        response = await registered["set_token_label"].args[3](SimpleNamespace(data={"token_id": "record-a", "label": "Phone"}))
        self.assertEqual(response, {"success": True, "user_id": "u", "user_name": "Matt"})
        self.assertEqual(monitor.history.token_labels["record-a"], "Phone")
        monitor.history.sessions = [{"session_id": "session-a", "token_id": "record-a", "user_id": "u",
                                     "client_name": "Mobile", "client_id": "mobile", "source_ip": "192.0.2.1",
                                     "state": "closed", "ended_at": monitor.last_successful_scan}]
        response = await registered["query_sessions"].args[3](SimpleNamespace(data={"text": "phone", "state": "closed"}))
        self.assertEqual(response["total"], 1)
        self.assertEqual(response["sessions"][0]["session_id"], "session-a")
        self.assertEqual(response["sessions"][0]["user_name"], "Matt")
        response = await registered["get_inventory"].args[3](SimpleNamespace(data={}))
        self.assertEqual(response["users"][0]["user_name"], "Matt")
        self.assertEqual(response["tokens"][0]["user_name"], "Matt")
        monitor.snapshot["tokens"] = []
        monitor.history.previous = {}
        response = await registered["set_token_label"].args[3](SimpleNamespace(data={"token_id": "record-a", "label": "Historic phone"}))
        self.assertEqual(response["user_name"], "Matt")
        response = await registered["query_audit"].args[3](SimpleNamespace(data={"text": "Matt"}))
        self.assertGreater(response["total"], 0)

    async def test_service_subscription_and_shutdown_flush(self):
        await self.module.async_setup_entry(self.hass, self.entry)
        event_type, listener = self.hass.bus.async_listen.call_args.args
        self.assertEqual(event_type, "call_service")
        event = SimpleNamespace(
            data={"domain": "light", "service": "turn_on"},
            context=SimpleNamespace(user_id="u", id="context", parent_id=None),
        )
        await listener(event)
        monitor = self.hass.data["ha_security"]
        self.assertEqual(monitor.history.query(kind="service_call")["total"], 0)
        self.assertEqual(monitor.history.last_calls["u"]["domain"], "light")
        await monitor.async_close()
        monitor.audit.store.async_save.assert_awaited_once()
        await listener(event)
        self.assertEqual(monitor.history.query(kind="service_call")["total"], 0)
        self.assertEqual(monitor.history.last_calls["u"]["domain"], "light")
        self.assertFalse(await monitor.async_refresh())

    async def test_related_activity_contract_from_real_snapshot_and_connection(self):
        """Generate real action responses for the DOM contract test, no hand-built results."""
        import json
        from test_auth_monitor import user, token
        from test_sessions import Connection
        account = user()
        a, b = token(), token()
        a.id, b.id = "credential-a", "credential-b"
        account.refresh_tokens = {a.id: a, b.id: b}
        self.hass.auth.async_get_users.return_value = [account]
        await self.module.async_setup_entry(self.hass, self.entry)
        monitor = self.hass.data["ha_security"]
        from ha_security_unit import sessions as sessions_module
        uninstall = sessions_module.install_adapter(self.hass, monitor.sessions, Connection)
        registered = {item.args[2]: item for item in self.module.audit_module.async_register_admin_service.call_args_list}
        async def invoke(service, data):
            registration = registered[service]
            return await registration.args[3](SimpleNamespace(data=registration.kwargs["schema"](data)))
        try:
            connection = Connection(self.hass, account, refresh_token_id=a.id)
            other = Connection(self.hass, account, refresh_token_id=b.id)
            context = connection.context({"type": "call_service", "domain": "light", "service": "turn_on"})
            other.context({"type": "call_service", "domain": "lock", "service": "unlock"})
            await monitor.async_service_event(SimpleNamespace(data={"domain": "light", "service": "turn_on", "service_data": {"entity_id": "light.kitchen"}}, context=context))
            scope = {"user_id": account.id, "token_id": a.id}
            inventory = await invoke("query_audit", {**scope, "category": "inventory"})
            connections = await invoke("query_sessions", scope)
            actions = await invoke("query_audit", {**scope, "category": "actions"})
            self.assertGreater(inventory["total"], 0)
            self.assertTrue(all(r["kind"] != "websocket_action" for r in inventory["records"]))
            self.assertFalse({r["id"] for r in inventory["records"]} & {r["id"] for r in actions["records"]})
            self.assertEqual(connections["total"], 1)
            self.assertEqual(actions["total"], 1)
            self.assertTrue(actions["records"][0]["invocation_observed"])
            self.assertEqual(actions["records"][0]["entity_ids"], ["light.kitchen"])
            self.assertEqual(actions["credential_scope"]["retained_connections"], 1)
            self.assertTrue(actions["credential_scope"]["known"])
            unknown = await invoke("query_audit", {"user_id": account.id, "token_id": "does-not-exist"})
            self.assertFalse(unknown["credential_scope"]["known"])
            self.assertEqual(unknown["total"], 0)
            fixture = {"user_id": account.id, "token_id": a.id, "view": monitor.sessions.view(account.id, True),
                       "inventory": inventory, "connections": connections, "actions": actions}
            path = Path(__file__).resolve().parents[1] / ".test-deps/activity-contract.json"
            path.parent.mkdir(exist_ok=True)
            path.write_text(json.dumps(fixture), encoding="utf-8")
        finally:
            uninstall()
            await monitor.async_close()

    async def test_platform_setup_failure_cleans_runtime(self):
        self.hass.config_entries.async_forward_entry_setups.side_effect = RuntimeError("platform")
        with self.assertRaisesRegex(RuntimeError, "platform"):
            await self.module.async_setup_entry(self.hass, self.entry)
        self.assertNotIn("ha_security", self.hass.data)
        self.cancel.assert_called_once()
        self.assertEqual(self.hass.services.async_remove.call_count, 6)

    async def test_storage_batches_without_indefinite_deferral(self):
        await self.module.async_setup_entry(self.hass, self.entry)
        audit = self.hass.data["ha_security"].audit
        audit.changed()
        audit.changed()
        audit.store.async_delay_save.assert_called_once()
        data = audit._save_data()
        audit.changed()
        self.assertEqual(audit.store.async_delay_save.call_count, 2)
        audit.history.add("new_test_record")
        self.assertNotEqual(len(data["records"]), len(audit.history.records))

    async def test_named_user_dropdown_updates_and_historical_accounts(self):
        await self.module.async_setup_entry(self.hass, self.entry)
        monitor = self.hass.data["ha_security"]
        monitor.snapshot["users"] = [{"user_id": "account-1", "name": "Matt"},
                                      {"user_id": "account-2", "name": "Matt"}]
        monitor.history.user_names.update({"old": "Former account", "account-1": "Matt"})
        audit = self.module.audit_module
        audit.async_set_service_schema.reset_mock()
        await audit.refresh_action_descriptions(self.hass, monitor)
        schemas = {call.args[2]: call.args[3] for call in audit.async_set_service_schema.call_args_list}
        choices = schemas["query_audit"]["fields"]["user_id"]["selector"]["select"]["options"]
        self.assertEqual(choices[0], {"value": "", "label": "All users"})
        self.assertIn({"value": "old", "label": "Former account (historical)"}, choices)
        self.assertEqual(len({row["label"] for row in choices}), len(choices))
        self.assertTrue(schemas["query_audit"]["fields"]["user_id"]["selector"]["select"]["custom_value"])
        self.assertIn("limit", schemas["query_audit"]["fields"])
        self.assertEqual({row["value"] for row in schemas["recognize_source"]["fields"]["user_id"]["selector"]["select"]["options"]}, {"account-1", "account-2"})
        audit.async_get_all_descriptions.side_effect = None
        audit.async_get_all_descriptions.return_value = {"ha_security": schemas}
        audit.async_set_service_schema.reset_mock()
        await audit.refresh_action_descriptions(self.hass, monitor)
        audit.async_set_service_schema.assert_not_called()
        monitor.snapshot["users"][0]["name"] = "Updated name"
        await audit.refresh_action_descriptions(self.hass, monitor)
        self.assertEqual(audit.async_set_service_schema.call_count, 3)

    async def test_description_setup_failure_cleans_runtime(self):
        self.module.audit_module.async_get_all_descriptions.side_effect = RuntimeError("descriptions")
        with self.assertRaisesRegex(RuntimeError, "descriptions"):
            await self.module.async_setup_entry(self.hass, self.entry)
        self.assertNotIn("ha_security", self.hass.data)
        self.cancel.assert_called_once()
        self.assertEqual(self.hass.services.async_remove.call_count, 6)
