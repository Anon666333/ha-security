"""Observation/audit regression tests using real JSON round-trips."""

from datetime import timedelta
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_auth_monitor import user, token
from ha_security_unit.security import SecurityHistory, safe_client, utcnow
from ha_security_unit.auth_monitor import async_snapshot


class HistoryTests(unittest.IsolatedAsyncioTestCase):
    async def snapshot(self, record):
        return await async_snapshot(SimpleNamespace(
            async_get_users=self.fake_users(user({"record": record})),
        ))

    def fake_users(self, account):
        async def users():
            return [account]
        return users

    async def test_initial_baseline_restart_and_new_observations(self):
        record = token()
        record.last_used_ip = "192.0.2.1"
        record.last_used_at = utcnow()
        record.client_id = "https://user:SECRET@example.test/app?token=SECRET#SECRET"
        history = SecurityHistory()
        history.observe(await self.snapshot(record))
        self.assertEqual(history.query(kind="new_ip")["total"], 0)
        self.assertNotIn("SECRET", json.dumps(history.serialize()))
        history = SecurityHistory(data=json.loads(json.dumps(history.serialize())))
        history.observe(await self.snapshot(record))
        self.assertEqual(history.query(kind="token_baseline")["total"], 1)
        record.last_used_ip = "192.0.2.2"
        record.client_id = "https://other.test/app"
        history.observe(await self.snapshot(record))
        self.assertEqual(history.query(kind="new_ip")["total"], 1)
        self.assertEqual(history.query(kind="new_client")["total"], 1)
        history.observe(await self.snapshot(record))
        self.assertEqual(history.query(kind="new_ip")["total"], 1)
        history.observe({"users": [], "tokens": []})
        self.assertEqual(history.query(kind="token_removed")["total"], 1)

    async def test_new_token_after_empty_baseline(self):
        history = SecurityHistory()
        history.observe({"users": [], "tokens": []})
        history.observe(await self.snapshot(token()))
        self.assertEqual(history.query(kind="new_token")["total"], 1)

    def test_service_context_attribution_payload_exclusion_and_search(self):
        history = SecurityHistory()
        context = SimpleNamespace(user_id="user-1", id="call-id", parent_id="parent")
        data = {
            "domain": "light", "service": "turn_on",
            "service_data": {"entity_id": ["light.kitchen"], "password": "SECRET",
                             "message": "PRIVATE", "token": "SECRET"},
        }
        self.assertTrue(history.service_call(data, context))
        row = history.query(text="kitchen", user_id="user-1", kind="service_call")["records"][0]
        self.assertEqual(row["entity_ids"], ["light.kitchen"])
        self.assertEqual(row["outcome"], "not_observed")
        self.assertEqual(row["parent_id"], "parent")
        self.assertNotIn("SECRET", json.dumps(history.serialize()))
        self.assertNotIn("PRIVATE", json.dumps(history.serialize()))
        self.assertFalse(history.service_call(data, SimpleNamespace(user_id=None)))
        self.assertEqual(history.query(text="LIGHT")["total"], 1)
        self.assertEqual(history.query(user_id="other")["total"], 0)
        self.assertEqual(history.query(offset=1)["records"], [])

    def test_retention_and_row_limit(self):
        now = utcnow()
        old = now - timedelta(days=31)
        history = SecurityHistory()
        history.add("old", now=old)
        history.add("current", now=now)
        self.assertEqual(history.query()["total"], 1)
        history.known_ips = {"u": {"192.0.2.1": old.isoformat()}}
        history.prune(now)
        self.assertEqual(history.known_ips, {})
        with patch("ha_security_unit.security.AUDIT_LIMIT", 3):
            for index in range(5):
                history.add("bounded", now=now, index=index)
            self.assertEqual(len(history.records), 3)

    def test_recent_window_future_timestamps_and_service_activity(self):
        now = utcnow()
        history = SecurityHistory()
        tokens = [{"last_used_at": (now - timedelta(minutes=10)).isoformat(),
                   "last_used_ip": "192.0.2.1", "client_id": "https://example.test/"}]
        self.assertTrue(history.summary("u", tokens, 15, now)["recently_observed"])
        self.assertFalse(history.summary("u", tokens, 5, now)["recently_observed"])
        tokens[0]["last_used_at"] = (now + timedelta(hours=1)).isoformat()
        self.assertFalse(history.summary("u", tokens, 15, now)["recently_observed"])
        context = SimpleNamespace(user_id="u", id="c", parent_id=None)
        history.service_call({"domain": "light", "service": "turn_on"}, context, now)
        self.assertTrue(history.summary("u", [], 15, now)["recently_observed"])

    def test_url_sanitization(self):
        self.assertEqual(safe_client("https://u:p@host.test:8123/app?secret=x#y"),
                         "https://host.test:8123/app")

    def test_token_activity_multiple_ips_restart_removal_and_expiry(self):
        now = utcnow()
        history = SecurityHistory()
        rows = [{"token_id": "a", "user_id": "u", "last_used_at": now.isoformat(),
                 "last_used_ip": "192.0.2.1", "client_id": "mobile"},
                {"token_id": "b", "user_id": "u", "last_used_at": now.isoformat(),
                 "last_used_ip": "192.0.2.2", "client_id": "web"}]
        history.observe({"users": [], "tokens": rows}, now)
        history.set_token_label("a", "Matt's phone")
        self.assertEqual(history.token_activity("u", rows, now=now)["recently_used_token_count"], 2)
        rows[0]["last_used_ip"] = "192.0.2.3"
        history.observe({"users": [], "tokens": rows}, now)
        history = SecurityHistory(data=json.loads(json.dumps(history.serialize())))
        history.observe({"users": [], "tokens": []}, now)
        detail = history.token_activity("u", [], now=now)
        removed = next(row for row in detail["connections"] if row["token_id"] == "a")
        self.assertEqual(removed["label"], "Matt's phone")
        self.assertEqual(removed["activity"], "removed")
        self.assertTrue(removed["ip_changed"])
        self.assertFalse(removed["new_credential"])
        self.assertEqual(detail["recently_used_token_count"], 0)
        self.assertEqual({row["last_used_ip"] for row in detail["ip_observations"]},
                         {"192.0.2.1", "192.0.2.2", "192.0.2.3"})
        rows[0]["expire_at"] = now.timestamp() - 1
        rows[1]["last_used_at"] = (now + timedelta(minutes=1)).isoformat()
        self.assertEqual(history.token_activity("u", rows, now=now)["recently_used_token_count"], 0)
        history.prune(now + timedelta(days=31))
        self.assertEqual(history.token_activity("u", [], now=now)["ip_observations"], [])
        with self.assertRaises(ValueError):
            history.set_token_label("unknown", "Unknown")
        history.set_token_label("a", "")
        self.assertNotIn("a", history.token_labels)
