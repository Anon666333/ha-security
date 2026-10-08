"""HA Security v0.1: read-only authentication inventory."""

from datetime import timedelta
from pathlib import Path

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EVENT_HOMEASSISTANT_STOP, EVENT_CALL_SERVICE, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.typing import ConfigType

from .const import CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL, DOMAIN
from .const import CONF_ENRICH_IP
from .const import CONF_TRACK_SESSIONS, CONF_TRACK_LOGINS
from .monitor import AuthMonitor
from .audit import AuditStore, register_actions, remove_actions
from .const import (
    CONF_RETENTION_DAYS, CONF_RECENT_MINUTES, CONF_EXPOSE_NETWORK,
    DEFAULT_RETENTION_DAYS, DEFAULT_RECENT_MINUTES,
)

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Allow Home Assistant to load the UI-configured integration."""
    if getattr(hass, "http", None) and not hass.data.get(f"{DOMAIN}_static"):
        from homeassistant.components.http import StaticPathConfig
        await hass.http.async_register_static_paths([
            StaticPathConfig("/ha_security/ha-security-card.js",
                             str(Path(__file__).parent / "www" / "ha-security-card.js"), False),
        ])
        hass.data[f"{DOMAIN}_static"] = True
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Start monitoring for the single UI configuration entry."""
    if DOMAIN in hass.data:
        return True
    settings = {**entry.data, **entry.options}
    audit = AuditStore(hass, settings.get(CONF_RETENTION_DAYS, DEFAULT_RETENTION_DAYS))
    await audit.load()
    monitor = AuthMonitor(
        hass.auth, audit,
        settings.get(CONF_RECENT_MINUTES, DEFAULT_RECENT_MINUTES),
        settings.get(CONF_EXPOSE_NETWORK, False),
    )
    if settings.get(CONF_ENRICH_IP, False):
        from .network import enrich
        async def enrich_ips(history, ips):
            await enrich(hass, history, ips)
        monitor.enricher = enrich_ips
    # A failed initial read does not prevent future retry attempts.
    await monitor.async_refresh()
    unsubscribe = async_track_time_interval(
        hass, monitor.async_refresh,
        timedelta(seconds=entry.options.get(
            CONF_SCAN_INTERVAL, entry.data.get(
                CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL,
            ),
        )),
    )

    async def stop(_event):
        unsubscribe()
        await monitor.async_close()
        hass.data.pop(DOMAIN, None)

    entry.async_on_unload(unsubscribe)
    entry.async_on_unload(
        hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, stop)
    )
    entry.async_on_unload(entry.add_update_listener(async_options_updated))
    hass.data[DOMAIN] = monitor
    if settings.get(CONF_TRACK_SESSIONS, False):
        from .sessions import install_adapter
        monitor.session_cleanup = install_adapter(hass, monitor.sessions)
        audit.changed()
    if settings.get(CONF_TRACK_LOGINS, False):
        from .login_monitor import install_login_adapter
        monitor.login_cleanup = install_login_adapter(hass, monitor)
    entry.async_on_unload(hass.bus.async_listen(EVENT_CALL_SERVICE, monitor.async_service_event))
    register_actions(hass, monitor)
    try:
        await hass.config_entries.async_forward_entry_setups(entry, [Platform.SENSOR])
    except Exception:
        unsubscribe()
        await monitor.async_close()
        remove_actions(hass)
        hass.data.pop(DOMAIN, None)
        raise
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Remove the snapshot; HA invokes registered unload callbacks."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, [Platform.SENSOR])
    if unloaded:
        monitor = hass.data.get(DOMAIN)
        if monitor:
            await monitor.async_close()
        remove_actions(hass)
        hass.data.pop(DOMAIN, None)
    return unloaded


async def async_options_updated(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Apply UI options by reloading, cancelling the previous poller first."""
    await hass.config_entries.async_reload(entry.entry_id)
