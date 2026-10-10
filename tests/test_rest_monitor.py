"""REST attribution with bound handlers, exact contexts and secret-free records."""

import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import uuid
from datetime import timedelta

from test_auth_monitor import user
from ha_security_unit.monitor import AuthMonitor
from ha_security_unit.rest_monitor import install_rest_adapter, install_rest_reads
from ha_security_unit.security import utcnow


class Request(dict):
    method = "POST"
    match_info = {"domain": "light", "service": "turn_off"}

    @property
    def headers(self):
        raise AssertionError("Must not inspect headers")

    def json(self):
        raise AssertionError("Must not inspect body")


class RestTests(unittest.IsolatedAsyncioTestCase):
    def test_http_ip_projects_into_credentials_without_rewriting_inventory(self):
        monitor = AuthMonitor(None)
        now = utcnow()
        token = {"token_id": "llt", "user_id": "u", "client_name": "n8n", "token_type": "long_lived_access_token", "last_used_at": None, "last_used_ip": None}
        monitor.history.add("rest_request", "u", now=now-timedelta(minutes=3), token_id="llt", source_ip="192.0.2.1")
        monitor.history.add("rest_action", "u", now=now-timedelta(minutes=1), token_id="llt", source_ip="192.0.2.2")
        monitor.history.add("rest_request", "other", now=now, token_id="llt", source_ip="192.0.2.3")
        view = monitor.history.token_activity("u", [token], now=now)
        row = view["tokens"][0]
        self.assertEqual(row["observed_source_ip"], "192.0.2.2")
        self.assertEqual(row["observed_ip_source"], "http_request")
        self.assertIsNone(row["last_used_ip"])
        self.assertIsNone(row["last_used_at"])
        self.assertTrue(row["recent_ip_change"])
        self.assertEqual({r["last_used_ip"] for r in view["ip_observations"]}, {"192.0.2.1", "192.0.2.2"})
        # Frequent reads from an unchanged IP must not make an old transition recent.
        old = AuthMonitor(None).history
        old.add("rest_request", "u", now=now-timedelta(days=2), token_id="llt", source_ip="192.0.2.1")
        old.add("rest_request", "u", now=now-timedelta(days=1), token_id="llt", source_ip="192.0.2.2")
        old.add("rest_request", "u", now=now, token_id="llt", source_ip="192.0.2.2")
        self.assertFalse(old.token_activity("u", [token], now=now)["tokens"][0]["recent_ip_change"])

    def test_request_bursts_do_not_rescan_retention_or_recompute_summary(self):
        monitor = AuthMonitor(None)
        monitor.snapshot = {"tokens": [{"user_id": "u", "token_id": "llt", "token_type": "long_lived_access_token"}]}
        with patch.object(monitor.history, "prune", wraps=monitor.history.prune) as prune:
            for _ in range(100):
                monitor.history.add("rest_request", "u", token_id="llt")
            prune.assert_not_called()
        with patch.object(monitor.history, "summary", wraps=monitor.history.summary) as summary:
            for _ in range(10):
                self.assertEqual(monitor.user_summary("u")["recent_llt_token_count"], 1)
            summary.assert_called_once()
            monitor.history.add("rest_request", "u", token_id="llt")
            monitor.user_summary("u")
            self.assertEqual(summary.call_count, 2)

    def test_updates_batch_a_request_burst_once(self):
        monitor = AuthMonitor(None)
        loop = Mock()
        with patch("ha_security_unit.monitor.asyncio.get_running_loop", return_value=loop):
            for _ in range(100):
                monitor.session_changed()
        loop.call_later.assert_called_once()
        self.assertEqual(loop.call_later.call_args.args[0], 10)

    def test_recent_llt_count_is_distinct_tokens_not_calls(self):
        monitor = AuthMonitor(None)
        now = utcnow()
        for kind, uid, tid, minutes in (
            ("rest_request", "u", "llt", 1),
            ("rest_action", "u", "llt", 2),
            ("websocket_action", "u", "llt", 3),
            ("rest_request", "u", "normal", 1),
            ("rest_request", "other", "llt", 1),
            ("rest_request", "u", "llt", 16),
            ("rest_request", "u", "llt", -1),
            ("token_updated", "u", "llt", 1),
        ):
            monitor.history.add(kind, uid, now=now-timedelta(minutes=minutes), token_id=tid)
        tokens = [{"token_id": "llt", "token_type": "long_lived_access_token"},
                  {"token_id": "normal", "token_type": "normal"}]
        self.assertEqual(monitor.history.summary("u", tokens, now=now)["recent_llt_token_count"], 1)
        self.assertEqual(monitor.history.summary("u", tokens, recent_minutes=1, now=now)["recent_llt_token_count"], 1)
        tokens.append({"token_id": "second", "token_type": "long_lived_access_token"})
        monitor.history.add("rest_request", "u", now=now, token_id="second")
        self.assertEqual(monitor.history.summary("u", tokens, now=now)["recent_llt_token_count"], 2)

    async def test_get_attribution_response_errors_and_cleanup(self):
        class Route:
            method = "GET"
            resource = SimpleNamespace(canonical="/api/states/{entity_id}")
            @property
            def handler(self):
                return self._handler
        response = SimpleNamespace(status=200)
        async def handler(request):
            return response
        route = Route()
        route._handler = handler
        hass = SimpleNamespace(http=SimpleNamespace(app=SimpleNamespace(router=SimpleNamespace(routes=lambda: [route]))))
        monitor = AuthMonitor(None)
        monitor.expose_network = True
        monitor.session_changed = Mock()
        cleanup = install_rest_reads(hass, monitor)
        request = Request(hass_user=user(), hass_refresh_token_id="llt", ha_authenticated=True)
        request.method = "GET"
        request.remote = "192.0.2.123"
        request.match_info = {"entity_id": "light.hallway"}
        try:
            self.assertIs(await route.handler(request), response)
            row = monitor.history.query(category="actions")["records"][0]
            self.assertEqual(row["token_id"], "llt")
            self.assertEqual(row["http_status"], 200)
            self.assertEqual(row["source_ip"], "192.0.2.123")
            self.assertEqual(row["entity_ids"], ["light.hallway"])
            self.assertEqual(row["endpoint"], "/api/states/{entity_id}")
            request["ha_authenticated"] = False
            await route.handler(request)
            self.assertEqual(len(monitor.history.records), 1)
            request["ha_authenticated"] = True
            monitor.history.add = Mock(side_effect=RuntimeError("private"))
            self.assertIs(await route.handler(request), response)
            self.assertEqual(monitor.rest_read_status, "error")
        finally:
            cleanup()
        self.assertIs(route.handler, handler)
        class NotFound(Exception):
            status = 404
        async def missing(request):
            raise NotFound("private response")
        route._handler = missing
        monitor = AuthMonitor(None)
        monitor.session_changed = Mock()
        cleanup = install_rest_reads(hass, monitor)
        try:
            with self.assertRaises(NotFound):
                await route.handler(request)
            self.assertEqual(monitor.history.records[0]["http_status"], 404)
            self.assertNotIn("private response", json.dumps(monitor.history.serialize()))
        finally:
            cleanup()

    async def test_exclusions_before_pagination_and_log_partition(self):
        monitor = AuthMonitor(None)
        for domain, service in (("light", "turn_on"), ("todo", "get_items"), ("system_log", "write")):
            monitor.history.add("rest_action", "u", token_id="llt", domain=domain, service=service)
        result = monitor.history.query(category="actions", exclude_actions=["todo.*"], limit=1)
        self.assertEqual(result["total"], 1)
        hidden = monitor.history.query(category="actions", exclude_token_ids=["llt"])
        self.assertEqual(hidden["total"], 0)
        self.assertIsNone(result["next_offset"])
        self.assertEqual(result["records"][0]["domain"], "light")
        inventory = monitor.history.query(category="inventory")
        self.assertEqual(inventory["total"], 1)
        self.assertEqual(inventory["records"][0]["domain"], "system_log")
        self.assertEqual(len(monitor.history.records), 3)
        monitor.history.add("rest_request", "u", token_id="llt", method="GET", endpoint="/api/states")
        result = monitor.history.query(category="actions", exclude_actions=["GET /api/states*", "todo.*"])
        self.assertEqual(result["total"], 1)

    async def test_bound_handler_two_tokens_exact_invocations_and_names(self):
        class Base:
            @staticmethod
            def context(request):
                return SimpleNamespace(id=uuid.uuid4().hex, user_id=request["hass_user"].id)

        class View(Base):
            def post(self, request):
                return self.context(request)

        monitor = AuthMonitor(None)
        monitor.session_changed = Mock()
        monitor.history.user_names["user-1"] = "Matt"
        monitor.history.previous = {
            "a": {"client_name": "n8n LLT", "user_id": "user-1"},
            "b": {"client_name": "Other LLT", "user_id": "user-1"},
        }
        bound_handler = View().post
        cleanup = install_rest_adapter(monitor, View)
        try:
            contexts = []
            for tid in ("a", "b"):
                request = Request(hass_user=user(), hass_refresh_token_id=tid, ha_authenticated=True)
                contexts.append(bound_handler(request))
            wrong = SimpleNamespace(id=contexts[0].id, user_id="someone-else")
            data = {"domain": "light", "service": "turn_off", "service_data": {"entity_id": "light.hallway_light", "secret": "DO-NOT-STORE"}}
            self.assertFalse(monitor.sessions.link_service_event(data, wrong))
            await monitor.async_service_event(SimpleNamespace(data=data, context=contexts[0]))
            rows = monitor.history.query(category="actions", token_id="a")["records"]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["credential_label"], "n8n LLT")
            self.assertTrue(rows[0]["invocation_observed"])
            self.assertEqual(rows[0]["entity_ids"], ["light.hallway_light"])
            self.assertEqual(rows[0]["transport"], "rest")
            activity = monitor.history.token_activity("user-1", [
                {"token_id": "a", "user_id": "user-1", "last_used_at": None},
                {"token_id": "unused", "user_id": "user-1", "last_used_at": None},
            ])
            self.assertEqual(activity["recently_used_token_count"], 1)
            self.assertEqual(activity["tokens"][0]["activity"], "recently_used")
            self.assertIsNone(activity["tokens"][0]["last_used_at"])
            self.assertIsNotNone(activity["tokens"][0]["last_observed_action_at"])
            self.assertNotIn("session_id", rows[0])
            monitor.history.set_token_label("a", "Automation")
            self.assertEqual(monitor.history.query(category="actions", token_id="a")["records"][0]["credential_label"], "Automation")
            self.assertNotIn("DO-NOT-STORE", json.dumps(monitor.history.serialize()))
            self.assertFalse(monitor.history.query(category="inventory")["records"])
            self.assertFalse(monitor.history.query(token_id="b")["records"][0]["invocation_observed"])
        finally:
            cleanup()
        self.assertNotIn("context", View.__dict__)
        count = len(monitor.history.records)
        bound_handler(Request(hass_user=user()))
        self.assertEqual(len(monitor.history.records), count)

    async def test_missing_auth_invalid_route_and_observer_failure_preserve_context(self):
        sentinel = SimpleNamespace(id="ctx", user_id="user-1")
        class View:
            context = staticmethod(lambda request: sentinel)
        original = View.__dict__["context"]
        monitor = AuthMonitor(None)
        cleanup = install_rest_adapter(monitor, View)
        try:
            for request in (Request(hass_user=user()), Request(hass_user=user(), hass_refresh_token_id="a", ha_authenticated=False)):
                self.assertIs(View.context(request), sentinel)
            self.assertFalse(monitor.history.records)
            invalid = Request(hass_user=user(), hass_refresh_token_id="a", ha_authenticated=True)
            invalid.match_info = {"domain": "light/secret", "service": "turn_off"}
            self.assertIs(View.context(invalid), sentinel)
            invalid.match_info = {"domain": "ha_security", "service": "query_audit"}
            self.assertIs(View.context(invalid), sentinel)
            self.assertFalse(monitor.history.records)
            monitor.history.add = Mock(side_effect=RuntimeError("secret error"))
            self.assertIs(View.context(Request(hass_user=user(), hass_refresh_token_id="a", ha_authenticated=True)), sentinel)
            self.assertEqual(monitor.rest_status, "error")
            self.assertNotIn("secret", monitor.rest_reason)
        finally:
            cleanup()
        self.assertIs(View.__dict__["context"], original)
