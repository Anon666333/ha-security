"""Observed connection lifecycle, restart semantics, and adapter isolation."""

from datetime import timedelta
import json
import inspect
import uuid
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from test_auth_monitor import token
from ha_security_unit.security import SecurityHistory, utcnow
from ha_security_unit.sessions import SessionTracker, install_adapter


class Connection:
    def __init__(self, hass, user, remote="192.0.2.1", refresh_token_id="record"):
        self.hass = hass
        self.user = user
        self.remote = remote
        self.refresh_token_id = refresh_token_id
        self.messages = 0
        self.closed = False

    def async_handle(self, msg):
        self.messages += 1
        return "handled"

    def context(self, msg):
        return SimpleNamespace(id=uuid.uuid4().hex, user_id=self.user.id)

    def async_handle_close(self):
        self.closed = True


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.hass = object()
        self.user = SimpleNamespace(id="u", refresh_tokens={"record": token()})
        self.history = SecurityHistory()
        self.changed = Mock()
        self.tracker = SessionTracker(self.history, self.changed)

    def test_two_credentials_same_user_exact_context_attribution(self):
        uninstall = install_adapter(self.hass, self.tracker, Connection)
        try:
            a = Connection(self.hass, self.user, refresh_token_id="token-a")
            b = Connection(self.hass, self.user, refresh_token_id="token-b")
            ca = a.context({"type": "call_service", "domain": "light", "service": "turn_on", "service_data": {"password": "SECRET"}})
            cb = b.context({"type": "call_service", "domain": "lock", "service": "unlock"})
            # Events can arrive in the reverse order, with the same user and IP.
            self.assertTrue(self.tracker.link_service_event({"domain": "lock", "service": "unlock"}, cb))
            self.assertTrue(self.tracker.link_service_event({"domain": "light", "service": "turn_on", "service_data": {"entity_id": "light.kitchen", "password": "SECRET"}}, ca))
            first = self.history.query(token_id="token-a", kind="websocket_action")["records"]
            second = self.history.query(token_id="token-b", kind="websocket_action")["records"]
            self.assertEqual(len(first), 1)
            self.assertEqual(first[0]["domain"], "light")
            self.assertEqual(first[0]["entity_ids"], ["light.kitchen"])
            self.assertEqual(first[0]["attribution_scope"], "direct_credential")
            self.assertNotEqual(first[0]["session_id"], second[0]["session_id"])
            self.assertEqual(second[0]["domain"], "lock")
            self.assertNotIn("SECRET", json.dumps(self.history.serialize()))
            unknown = SimpleNamespace(id="unknown", user_id="u", parent_id=ca.id)
            self.assertFalse(self.tracker.link_service_event({"domain": "light", "service": "turn_on"}, unknown))
            self.assertFalse(self.tracker.link_service_event({"domain": "lock", "service": "unlock"}, ca))
            self.assertFalse(self.tracker.link_service_event({"domain": "light", "service": "turn_on"}, SimpleNamespace(id=ca.id, user_id="other")))
        finally:
            uninstall()
        self.assertFalse(self.tracker.action_contexts)

    def test_action_scope_no_token_no_payload_no_internal_query_and_failure_isolation(self):
        original = Connection.context
        uninstall = install_adapter(self.hass, self.tracker, Connection)
        try:
            a = Connection(self.hass, self.user)
            a.context({"type": "render_template", "template": "SECRET"})
            a.context({"type": "call_service", "domain": "ha_security", "service": "query_audit"})
            Connection(self.hass, self.user, refresh_token_id=None).context({"type": "call_service", "domain": "light", "service": "turn_on"})
            self.assertEqual(self.history.query(kind="websocket_action")["total"], 0)
            self.tracker.observe_action = Mock(side_effect=RuntimeError("SECRET"))
            with self.assertLogs("ha_security_unit.sessions", level="WARNING") as captured:
                context = a.context({"type": "call_service", "domain": "light", "service": "turn_on"})
            self.assertEqual(context.user_id, "u")
            self.assertNotIn("SECRET", str(captured.output))
            self.assertEqual(self.tracker.action_status, "error")
            self.assertEqual(self.tracker.status, "observing")
        finally:
            uninstall()
        self.assertIs(Connection.context, original)

    def test_context_cache_is_bounded_and_expired_links_are_not_used(self):
        self.tracker.start()
        self.tracker.action_status = "observing"
        a = Connection(self.hass, self.user)
        msg = {"type": "call_service", "domain": "light", "service": "turn_on"}
        for i in range(1002):
            self.tracker.observe_action(a, msg, SimpleNamespace(id=str(i), user_id="u"))
        self.assertEqual(len(self.tracker.action_contexts), 1000)
        self.assertNotIn("0", self.tracker.action_contexts)
        cid = "1001"
        _, row = self.tracker.action_contexts[cid]
        self.tracker.action_contexts[cid] = (-1000, row)
        self.assertFalse(self.tracker.link_service_event({"domain": "light", "service": "turn_on"}, SimpleNamespace(id=cid, user_id="u")))

    def test_concurrent_connections_same_token_different_ips_and_close(self):
        uninstall = install_adapter(self.hass, self.tracker, Connection)
        try:
            a = Connection(self.hass, self.user, "192.0.2.1")
            b = Connection(self.hass, self.user, "192.0.2.2")
            self.assertEqual(a.async_handle({"password": "SECRET"}), "handled")
            view = self.tracker.view("u", True)
            self.assertEqual(view["active_connection_count"], 2)
            self.assertEqual({r["source_ip"] for r in view["active_connections"]}, {"192.0.2.1", "192.0.2.2"})
            self.assertNotIn("SECRET", json.dumps(self.history.serialize()))
            self.assertIsNotNone(view["active_connections"][1]["last_seen_at"])
            self.assertNotIn("source_ip", self.tracker.view("u")["active_connections"][0])
            a.async_handle_close()
            self.assertTrue(a.closed)
            self.assertEqual(self.tracker.view("u")["active_connection_count"], 1)
            self.assertIsNotNone(self.tracker.view("u")["session_history"][0]["closed_at"])
            other = Connection(object(), self.user)
            self.assertEqual(self.tracker.view("u")["active_connection_count"], 1)
        finally:
            uninstall()
        self.assertEqual(self.tracker.view("u")["active_connection_count"], 0)

    def test_connection_and_credential_ips_are_distinct_scoped_and_frozen(self):
        self.user.refresh_tokens["record"].last_used_ip = "8.8.8.8"
        self.tracker.start()
        connection = Connection(self.hass, self.user, "192.168.0.10")
        self.tracker.observe(connection, newly_connected=True)
        self.history.ip_context["8.8.8.8"] = {"hostname": "public.example"}
        row = self.tracker.view("u", True)["active_connections"][0]
        self.assertEqual(row["source_ip"], "192.168.0.10")
        self.assertEqual(row["credential_last_used_ip"], "8.8.8.8")
        self.assertEqual(row["credential_ip_context"]["hostname"], "public.example")
        self.assertEqual(row["ip_context"], {})
        self.tracker.refresh_credential_ips([{"token_id": "record", "user_id": "other", "last_used_ip": "1.1.1.1"}])
        self.assertEqual(self.tracker.view("u", True)["active_connections"][0]["credential_last_used_ip"], "8.8.8.8")
        record = {"token_id": "record", "user_id": "u", "last_used_ip": "1.1.1.1", "last_used_at": "2026-10-07T12:00:00+00:00"}
        self.tracker.refresh_credential_ips([record])
        row = self.tracker.view("u", True)["active_connections"][0]
        self.assertEqual(row["source_ip"], "192.168.0.10")
        self.assertEqual(row["credential_last_used_ip"], "1.1.1.1")
        hidden = self.tracker.view("u")["active_connections"][0]
        self.assertFalse(any(key.startswith("credential_ip") or key.startswith("credential_last") for key in hidden))
        self.tracker.close(connection)
        record["last_used_ip"] = "9.9.9.9"
        self.tracker.refresh_credential_ips([record])
        self.assertEqual(self.tracker.view("u", True)["session_history"][0]["credential_last_used_ip"], "1.1.1.1")

    def test_existing_connection_unknown_start_and_restart_not_online(self):
        a = Connection(self.hass, self.user)
        self.tracker.start()
        self.tracker.observe(a)
        self.assertIsNone(self.tracker.view("u", True)["active_connections"][0]["connected_at"])
        restored = SessionTracker(SecurityHistory(data=json.loads(json.dumps(self.history.serialize()))))
        restored.start()
        view = restored.view("u", True)
        self.assertEqual(view["active_connection_count"], 0)
        self.assertEqual(view["session_history"][0]["state"], "interrupted")
        self.assertIsNone(view["session_history"][0]["closed_at"])
        restored.history.prune(utcnow() + timedelta(days=31))
        self.assertEqual(restored.view("u")["session_history_total"], 0)

    def test_observer_failure_never_breaks_core_and_uninstall_restores(self):
        original = Connection.async_handle
        uninstall = install_adapter(self.hass, self.tracker, Connection)
        a = Connection(self.hass, self.user)
        self.tracker.observe = Mock(side_effect=RuntimeError("private secret"))
        with self.assertLogs("ha_security_unit.sessions", level="WARNING") as captured:
            self.assertEqual(a.async_handle({}), "handled")
        self.assertNotIn("private secret", str(captured.output))
        a.async_handle_close()
        self.assertTrue(a.closed)
        uninstall()
        self.assertIs(Connection.async_handle, original)

    def test_unsupported_adapter_fails_closed(self):
        with self.assertLogs("ha_security_unit.sessions", level="WARNING"):
            uninstall = install_adapter(self.hass, self.tracker, object)
        self.assertEqual(self.tracker.status, "unsupported")
        self.assertEqual(self.tracker.reason, "constructor_check: ValueError")
        uninstall()

    @unittest.skipUnless(sys.version_info >= (3, 14), "Deferred annotations require Python 3.14")
    def test_ha_type_checking_annotations_do_not_block_tracking(self):
        namespace = {"Connection": Connection}
        exec("def constructor(self, hass: HomeAssistant, user: User, remote=None):\n"
             "    Connection.__init__(self, hass, user, remote)\n", namespace)
        class DeferredConnection(Connection):
            __init__ = namespace["constructor"]
        # Reproduce HA's TYPE_CHECKING-only names and the previous failure.
        with self.assertRaises(NameError):
            inspect.signature(DeferredConnection.__init__)
        uninstall = install_adapter(self.hass, self.tracker, DeferredConnection)
        try:
            self.assertEqual(self.tracker.status, "observing")
            connection = DeferredConnection(self.hass, self.user, "192.0.2.1")
            connection.async_handle({})
            self.assertEqual(self.tracker.view("u")["active_connection_count"], 1)
        finally:
            uninstall()


class AuthBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def test_failed_auth_response_does_not_create_ghost_connection(self):
        hass = object()
        user = SimpleNamespace(id="u", name="User", refresh_tokens={"record": token()})
        class Auth:
            async def async_handle(self, fail=False):
                connection = Connection(hass, user)
                if fail:
                    raise RuntimeError("auth response failed")
                return connection
        tracker = SessionTracker(SecurityHistory())
        uninstall = install_adapter(hass, tracker, Connection, Auth)
        try:
            with self.assertRaises(RuntimeError):
                await Auth().async_handle(True)
            self.assertEqual(tracker.view("u")["active_connection_count"], 0)
            connection = await Auth().async_handle()
            self.assertEqual(tracker.view("u")["active_connection_count"], 1)
            connection.async_handle_close()
            self.assertEqual(tracker.view("u")["session_history_total"], 1)
        finally:
            uninstall()
