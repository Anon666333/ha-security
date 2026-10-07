"""Optional, bounded public-IP context lookups. Never send user/token data."""

import asyncio
import ipaddress
import json
import socket
from datetime import timedelta

from .security import parse_time, utcnow


def ip_scope(value):
    try:
        address = ipaddress.ip_address(value)
    except (ValueError, TypeError):
        return "unknown"
    if address.is_multicast:
        return "multicast"
    if address.is_global:
        return "public"
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link_local"
    if address.is_private:
        return "private_or_reserved"
    return "non_public"


def context_fields(data, ip):
    """Allowlist provider fields and validate that the response is for this IP."""
    if not isinstance(data, dict) or data.get("success") is not True or data.get("ip") != ip:
        raise ValueError("Lookup unavailable")
    connection = data.get("connection")
    connection = connection if isinstance(connection, dict) else {}
    result = {}
    for key in ("country", "country_code", "region", "city"):
        if isinstance(data.get(key), str):
            result[key] = data[key][:128]
    if isinstance(connection.get("org"), str):
        result["organisation"] = connection["org"][:128]
    if isinstance(connection.get("asn"), int):
        result["asn"] = f"AS{connection['asn']}"
    return result


async def lookup_public_ip(hass, ip):
    """HTTPS provider lookup plus reverse DNS, with independent failures."""
    from homeassistant.helpers.aiohttp_client import async_get_clientsession
    result = {"provider": "ipwho.is", "lookup_status": "unavailable"}
    try:
        async with asyncio.timeout(5):
            async with async_get_clientsession(hass).get(
                f"https://ipwho.is/{ip}", allow_redirects=False,
            ) as response:
                response.raise_for_status()
                raw = bytearray()
                async for chunk in response.content.iter_chunked(4096):
                    raw.extend(chunk)
                    if len(raw) > 32768:
                        raise ValueError("Oversized response")
                result.update(context_fields(json.loads(raw), ip))
                result["lookup_status"] = "available"
    except Exception:
        pass
    try:
        host, _ = await asyncio.wait_for(
            asyncio.get_running_loop().getnameinfo((ip, 0), socket.NI_NAMEREQD), 3,
        )
        result["hostname"] = host[:253]
    except Exception:
        pass
    return result


async def enrich(hass, history, ips, lookup=lookup_public_ip):
    """At most three uncached public-IP lookups per scan; back off on failure."""
    now = utcnow()
    count = 0
    for ip in sorted(set(ips)):
        if ip_scope(ip) != "public":
            continue
        cached = history.ip_context.get(ip, {})
        stamp = parse_time(cached.get("looked_up_at"))
        ttl = timedelta(days=7) if cached.get("lookup_status") == "available" else timedelta(hours=1)
        if stamp and timedelta(0) <= now - stamp < ttl:
            continue
        if count >= 3:
            break
        count += 1
        result = await lookup(hass, ip)
        history.ip_context[ip] = {**result, "looked_up_at": now.isoformat()}
    while len(history.ip_context) > 1000:
        del history.ip_context[next(iter(history.ip_context))]
