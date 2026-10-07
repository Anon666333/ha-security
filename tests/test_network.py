"""Provider allowlist, local-address exclusion, caching and request budgets."""

from datetime import timedelta
import asyncio
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from test_auth_monitor import token  # Initializes the isolated package.
from ha_security_unit.network import context_fields, enrich, ip_scope, lookup_public_ip
from ha_security_unit.security import SecurityHistory, utcnow


class NetworkTests(unittest.IsolatedAsyncioTestCase):
    async def test_https_transport_chunking_and_dns_failure_isolation(self):
        async def chunks(size):
            yield b'{"success":true,"ip":"8.8.8.8",'
            yield b'"country":"US","connection":{"asn":15169,"org":"Google"}}'
        response = SimpleNamespace(raise_for_status=Mock(), content=SimpleNamespace(iter_chunked=chunks))
        request = AsyncMock()
        request.__aenter__.return_value = response
        session = SimpleNamespace(get=Mock(return_value=request))
        module = ModuleType("homeassistant.helpers.aiohttp_client")
        module.async_get_clientsession = lambda hass: session
        with patch.dict(sys.modules, {module.__name__: module}), patch.object(
            asyncio.get_running_loop(), "getnameinfo", AsyncMock(side_effect=OSError("no PTR")),
        ):
            result = await lookup_public_ip(None, "8.8.8.8")
        self.assertEqual(result["lookup_status"], "available")
        self.assertEqual(result["organisation"], "Google")
        self.assertNotIn("hostname", result)
        session.get.assert_called_once_with("https://ipwho.is/8.8.8.8", allow_redirects=False)
        response.raise_for_status.side_effect = RuntimeError("provider unavailable")
        with patch.dict(sys.modules, {module.__name__: module}), patch.object(
            asyncio.get_running_loop(), "getnameinfo", AsyncMock(return_value=("dns.google", "0")),
        ):
            result = await lookup_public_ip(None, "8.8.8.8")
        self.assertEqual(result["lookup_status"], "unavailable")
        self.assertEqual(result["hostname"], "dns.google")

    async def test_opt_in_worker_skips_non_public_and_caches_failure(self):
        history = SecurityHistory()
        lookup = AsyncMock(return_value={"lookup_status": "unavailable"})
        await enrich(None, history, ["192.168.1.20", "127.0.0.1", "8.8.8.8"], lookup)
        lookup.assert_awaited_once_with(None, "8.8.8.8")
        await enrich(None, history, ["8.8.8.8"], lookup)
        self.assertEqual(lookup.await_count, 1)
        history.ip_context["8.8.8.8"]["looked_up_at"] = (utcnow() - timedelta(hours=2)).isoformat()
        await enrich(None, history, ["8.8.8.8"], lookup)
        self.assertEqual(lookup.await_count, 2)

    async def test_budget_and_success_cache_survive_restart(self):
        history = SecurityHistory()
        lookup = AsyncMock(return_value={"lookup_status": "available", "country": "US"})
        ips = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "8.8.4.4"]
        await enrich(None, history, ips, lookup)
        self.assertEqual(lookup.await_count, 3)
        history = SecurityHistory(data=history.serialize())
        await enrich(None, history, ips, lookup)
        self.assertEqual(lookup.await_count, 4)

    def test_response_identity_allowlist_and_address_classification(self):
        result = context_fields({"success": True, "ip": "8.8.8.8", "country": "US",
                                 "connection": {"asn": 15169, "org": "Google", "secret": "PRIVATE"},
                                 "secret": "PRIVATE"}, "8.8.8.8")
        self.assertEqual(result["asn"], "AS15169")
        self.assertNotIn("PRIVATE", str(result))
        with self.assertRaises(ValueError):
            context_fields({"success": True, "ip": "1.1.1.1"}, "8.8.8.8")
        self.assertEqual(ip_scope("8.8.8.8"), "public")
        self.assertEqual(ip_scope("192.168.1.20"), "private_or_reserved")
        self.assertEqual(ip_scope("::1"), "loopback")
        self.assertEqual(ip_scope("169.254.1.2"), "link_local")
        self.assertEqual(ip_scope("invalid"), "unknown")
        self.assertEqual(ip_scope("224.0.0.1"), "multicast")
