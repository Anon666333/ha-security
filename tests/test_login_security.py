"""Login observer boundary and conservative assessment regression tests."""
import asyncio
from datetime import timedelta
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from test_auth_monitor import token
from ha_security_unit.security import SecurityHistory, utcnow
from ha_security_unit.risk import record_login, summary, session_assessment
from ha_security_unit.login_monitor import install_login_adapter


class RiskTests(unittest.TestCase):
    def setUp(self):
        self.history = SecurityHistory()
        self.now = utcnow()

    def failures(self, count, ip="8.8.8.8"):
        for i in range(count):
            record_login(self.history, "failure", ip, now=self.now - timedelta(seconds=count-i))

    def success(self, ip="8.8.8.8", tid="new", uid="u"):
        record_login(self.history, "success", ip, uid, tid, now=self.now)
        return self.history.records[-1]

    def test_cellular_change_and_two_typos_are_not_high_risk(self):
        self.failures(2)
        self.history.previous = {"known": {"user_id": "u"}}
        result = self.success(tid="known")
        self.assertEqual(result["security_level"], "normal")
        self.assertEqual(result["correlated_failure_count"], 2)
        self.assertEqual(summary(self.history, "u", now=self.now)["correlated_failed_attempts_24h"], 2)
        self.assertIsNone(self.history.records[0]["user_id"])

    def test_stacked_evidence_and_window_reset(self):
        self.failures(12)
        result = self.success()
        self.assertEqual(result["security_level"], "likely_issue")
        self.assertEqual(summary(self.history, "u", now=self.now)["security_status"], "likely_issue")
        self.now += timedelta(seconds=1)
        result = self.success(tid="next")
        self.assertEqual(result["correlated_failure_count"], 0)
        self.assertEqual(summary(self.history, "other", now=self.now)["successful_logins_24h"], 0)
        self.assertEqual(summary(self.history, now=self.now)["failed_login_attempts_24h"], 12)
        self.assertEqual(summary(self.history, now=self.now+timedelta(days=2))["successful_logins_24h"], 0)

    def test_private_missing_and_other_ip_do_not_escalate(self):
        self.failures(12)
        self.assertEqual(self.success(ip="192.168.1.5")["security_level"], "normal")
        self.assertEqual(self.success(ip=None)["correlated_failure_count"], 0)
        self.history = SecurityHistory()
        self.failures(5)
        self.assertEqual(self.success()["security_level"], "review")

    def test_session_assessment_remains_after_login_event_is_pruned(self):
        from ha_security_unit.sessions import SessionTracker
        self.success()
        tracker = SessionTracker(self.history)
        tracker.start()
        connection = SimpleNamespace(user=SimpleNamespace(id="u", name="User", refresh_tokens={"new": token()}),
                                     remote="8.8.8.8", refresh_token_id="new")
        tracker.observe(connection, newly_connected=True)
        tracker.close(connection)
        self.history.records = []
        row = tracker.view("u", True)["session_history"][0]
        self.assertEqual(row["security_level"], "review")
        self.assertTrue(row["login_event_id"])

    def test_unattributed_burst_expires_without_accusing_a_user(self):
        self.failures(6)
        self.assertEqual(summary(self.history, now=self.now)["security_status"], "review")
        self.assertEqual(summary(self.history, "u", now=self.now)["security_status"], "normal")
        self.assertEqual(summary(self.history, now=self.now+timedelta(minutes=11))["security_status"], "normal")

    def test_recognition_redaction_retention_and_session_matching(self):
        row = self.success()
        self.assertEqual(row["security_level"], "review")
        session = {"user_id": "u", "token_id": "new", "source_ip": "8.8.8.8", "first_observed_at": self.now.isoformat()}
        self.assertEqual(session_assessment(self.history, session)["security_level"], "review")
        session["source_ip"] = "192.168.1.5"
        self.assertEqual(session_assessment(self.history, session)["security_level"], "unknown")
        hidden = summary(self.history, "u", now=self.now)["login_events"][0]
        self.assertNotIn("source_ip", hidden)
        self.assertNotIn("token_id", hidden)
        self.history.recognized["u"] = {"tokens": {"new": self.now.isoformat()}, "ips": {}}
        restored = SecurityHistory(data=json.loads(json.dumps(self.history.serialize())))
        self.assertEqual(summary(restored, "u", now=self.now)["security_status"], "normal")
        self.now += timedelta(seconds=20)
        self.failures(12)
        self.success(tid="new")
        self.assertEqual(summary(self.history, "u", now=self.now)["security_status"], "review")
        self.assertEqual(summary(self.history, "u", status="disabled", now=self.now)["security_status"], "unknown")


class FakeAuth:
    def async_create_access_token(self, refresh_token, remote_ip=None):
        return "SECRET-ACCESS"


class FakeFlow:
    async def _async_flow_result_to_response(self, request, client_id, result):
        return SimpleNamespace(status=200)


class FakeTokenView:
    async def _async_handle_auth_code(self, hass, data, request):
        await asyncio.sleep(0)
        if data.get("raise"):
            raise RuntimeError("Core error")
        if data.get("fail"):
            return SimpleNamespace(status=403)
        hass.auth.async_create_access_token(data["record"], request.remote)
        return SimpleNamespace(status=200)

    async def _async_handle_refresh_token(self, hass, data, request):
        hass.auth.async_create_access_token(data["record"], request.remote)
        return SimpleNamespace(status=200)


class AdapterTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.hass = SimpleNamespace(auth=FakeAuth())
        self.monitor = SimpleNamespace(history=SecurityHistory(), stopped=False, login_status="disabled",
                                      login_reason=None, session_changed=Mock())
        self.request = SimpleNamespace(app={"hass": self.hass}, remote="8.8.8.8")
        self.record = token()
        self.record.user = SimpleNamespace(id="u")
        self.uninstall = install_login_adapter(self.hass, self.monitor, FakeFlow, FakeTokenView, FakeAuth, "hass")

    async def asyncTearDown(self):
        self.uninstall()

    async def test_explicit_failures_only_code_success_and_refresh_excluded(self):
        for error in ("invalid_auth", "invalid_code", "cannot_connect", None):
            result = {"type": "form", "errors": {"base": error}, "data": {"password": "SECRET-PASSWORD"}}
            response = await FakeFlow()._async_flow_result_to_response(self.request, "client", result)
            self.assertEqual(response.status, 200)
        await FakeTokenView()._async_handle_auth_code(self.hass, {"fail": True}, self.request)
        await FakeTokenView()._async_handle_refresh_token(self.hass, {"record": self.record}, self.request)
        await FakeTokenView()._async_handle_auth_code(self.hass, {"record": self.record, "code": "SECRET-CODE"}, self.request)
        rows = self.monitor.history.records
        self.assertEqual([r["kind"] for r in rows], ["login_failure", "login_failure", "login_success"])
        self.assertEqual(rows[-1]["correlated_failure_count"], 2)
        self.assertNotIn("SECRET", json.dumps(self.monitor.history.serialize()))

    async def test_core_exception_resets_capture_and_is_preserved(self):
        with self.assertRaisesRegex(RuntimeError, "Core error"):
            await FakeTokenView()._async_handle_auth_code(self.hass, {"raise": True}, self.request)
        await FakeTokenView()._async_handle_refresh_token(self.hass, {"record": self.record}, self.request)
        self.assertEqual(self.monitor.history.records, [])

    async def test_parallel_grants_preserve_identity_and_other_instance_excluded(self):
        other = token(); other.id = "other"; other.user = SimpleNamespace(id="v")
        await asyncio.gather(FakeTokenView()._async_handle_auth_code(self.hass, {"record": self.record}, self.request),
                             FakeTokenView()._async_handle_auth_code(self.hass, {"record": other}, self.request))
        self.assertEqual({(r["user_id"], r["token_id"]) for r in self.monitor.history.records}, {("u", "record-1"), ("v", "other")})
        other_hass = SimpleNamespace(auth=FakeAuth())
        await FakeTokenView()._async_handle_auth_code(other_hass, {"record": other}, self.request)
        self.assertEqual(len(self.monitor.history.records), 2)

    async def test_observer_failure_cannot_break_login_or_leak_exception(self):
        with patch("ha_security_unit.login_monitor.record_login", side_effect=RuntimeError("SECRET")):
            with self.assertLogs("ha_security_unit.login_monitor", level="WARNING") as captured:
                response = await FakeTokenView()._async_handle_auth_code(self.hass, {"record": self.record}, self.request)
        self.assertEqual(response.status, 200)
        self.assertEqual(self.monitor.login_status, "error")
        self.assertNotIn("SECRET", str(captured.output))

    async def test_unsupported_and_uninstall_restore(self):
        self.uninstall()
        original = FakeAuth.async_create_access_token
        with self.assertLogs("ha_security_unit.login_monitor", level="WARNING"):
            cleanup = install_login_adapter(self.hass, self.monitor, object, FakeTokenView, FakeAuth, "hass")
        self.assertEqual(self.monitor.login_status, "unsupported")
        self.assertIs(FakeAuth.async_create_access_token, original)
        cleanup()
