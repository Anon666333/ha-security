"""Unit tests with auth-shaped fakes; no Home Assistant installation required."""

import importlib.util
import json
import logging
from pathlib import Path
import sys
from datetime import datetime, timedelta, timezone
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import AsyncMock

ROOT = Path(__file__).resolve().parents[1]
# Load the adapter package without executing the HA-dependent YAML entry point.
PACKAGE = "ha_security_unit"
package = ModuleType(PACKAGE)
package.__path__ = [str(ROOT / "custom_components" / "ha_security")]
sys.modules[PACKAGE] = package
from ha_security_unit.auth_monitor import async_snapshot
from ha_security_unit.monitor import AuthMonitor


def user(tokens=None):
    return SimpleNamespace(
        id="user-1", name="Matt", is_active=True, is_owner=True,
        system_generated=False, refresh_tokens=tokens or {},
        credentials=["SECRET-CREDENTIAL"],
    )


def token():
    return SimpleNamespace(
        id="record-1", client_id="https://example.test/",
        client_name="Test client", created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        last_used_at=None, last_used_ip=None, token_type="normal",
        expire_at=1800000000.0, access_token_expiration=timedelta(minutes=30),
        token="SECRET-TOKEN", jwt_key="SECRET-KEY",
    )


class SnapshotTests(unittest.IsolatedAsyncioTestCase):
    async def test_metadata_and_secrets(self):
        record = token()
        auth = SimpleNamespace(async_get_users=AsyncMock(return_value=[
            user({"record-1": record}), SimpleNamespace(
                id="empty", name=None, is_active=False, is_owner=False,
                system_generated=True, refresh_tokens={},
            ),
        ]))
        snapshot = await async_snapshot(auth)
        self.assertEqual(len(snapshot["users"]), 2)
        row = snapshot["tokens"][0]
        self.assertEqual(row["user_id"], "user-1")
        self.assertEqual(row["access_token_expiration_seconds"], 1800)
        self.assertEqual(row["created_at"], "2026-01-01T00:00:00+00:00")
        self.assertEqual(row["expire_at"], 1800000000.0)
        self.assertIsNone(row["last_used_at"])
        self.assertNotIn("SECRET", json.dumps(snapshot))
        record.last_used_ip = "192.0.2.1"
        self.assertIsNone(row["last_used_ip"])  # detached from live objects

    async def test_optional_fields_absent(self):
        auth = SimpleNamespace(async_get_users=AsyncMock(return_value=[
            user({"minimal": SimpleNamespace(id="minimal")}),
        ]))
        snapshot = await async_snapshot(auth)
        self.assertIsNone(snapshot["tokens"][0]["expire_at"])
        self.assertIsNone(snapshot["tokens"][0]["client_name"])

    async def test_change_logging_removal_and_retry(self):
        record = token()
        account = user({"record-1": record})
        auth = SimpleNamespace(async_get_users=AsyncMock(return_value=[account]))
        monitor = AuthMonitor(auth)
        logger = "ha_security_unit.monitor"
        with self.assertLogs(logger, level=logging.DEBUG) as captured:
            self.assertTrue(await monitor.async_refresh())
        self.assertNotIn("SECRET", "\n".join(captured.output))
        with self.assertNoLogs(logger, level=logging.DEBUG):
            await monitor.async_refresh()
        record.last_used_ip = "192.0.2.1"
        with self.assertLogs(logger, level=logging.DEBUG) as captured:
            await monitor.async_refresh()
        self.assertIn("192.0.2.1", "\n".join(captured.output))
        previous = monitor.snapshot
        auth.async_get_users.side_effect = RuntimeError("SECRET-ERROR")
        with self.assertLogs(logger, level=logging.ERROR) as captured:
            self.assertFalse(await monitor.async_refresh())
        self.assertIs(monitor.snapshot, previous)
        self.assertNotIn("SECRET-ERROR", "\n".join(captured.output))
        auth.async_get_users.side_effect = None
        account.refresh_tokens.clear()
        with self.assertLogs(logger, level=logging.DEBUG) as captured:
            self.assertTrue(await monitor.async_refresh())
        self.assertIn("record removed", "\n".join(captured.output))
        self.assertEqual(monitor.snapshot["tokens"], [])

    async def test_empty_inventory(self):
        monitor = AuthMonitor(SimpleNamespace(
            async_get_users=AsyncMock(return_value=[]),
        ))
        self.assertTrue(await monitor.async_refresh())
        self.assertEqual(monitor.snapshot, {"users": [], "tokens": []})


class ManifestTests(unittest.TestCase):
    def test_manifest_matches_package(self):
        manifest = json.loads(
            (ROOT / "custom_components/ha_security/manifest.json").read_text()
        )
        self.assertEqual(manifest["domain"], "ha_security")
        self.assertEqual(manifest["version"], "0.1.0")
        self.assertEqual(manifest["requirements"], [])


if __name__ == "__main__":
    unittest.main()
