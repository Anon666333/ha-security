"""HA Security v0.1: read-only authentication inventory."""

from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EVENT_HOMEASSISTANT_STOP, Platform
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.typing import ConfigType

from .const import CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL, DOMAIN
from .monitor import AuthMonitor

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Allow Home Assistant to load the UI-configured integration."""
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Start monitoring for the single UI configuration entry."""
    if DOMAIN in hass.data:
        return True
    monitor = AuthMonitor(hass.auth)
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

    @callback
    def stop(_event):
        unsubscribe()
        hass.data.pop(DOMAIN, None)

    entry.async_on_unload(unsubscribe)
    entry.async_on_unload(
        hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, stop)
    )
    entry.async_on_unload(entry.add_update_listener(async_options_updated))
    hass.data[DOMAIN] = monitor
    await hass.config_entries.async_forward_entry_setups(entry, [Platform.SENSOR])
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Remove the snapshot; HA invokes registered unload callbacks."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, [Platform.SENSOR])
    if unloaded:
        hass.data.pop(DOMAIN, None)
    return unloaded


async def async_options_updated(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Apply UI options by reloading, cancelling the previous poller first."""
    await hass.config_entries.async_reload(entry.entry_id)
