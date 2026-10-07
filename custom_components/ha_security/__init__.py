"""HA Security v0.1: read-only authentication inventory."""

from datetime import timedelta

import voluptuous as vol

from homeassistant.const import EVENT_HOMEASSISTANT_STOP
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.typing import ConfigType

from .const import CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL, DOMAIN
from .monitor import AuthMonitor

CONFIG_SCHEMA = vol.Schema(
    {
        DOMAIN: vol.Schema({
            vol.Optional(CONF_SCAN_INTERVAL, default=DEFAULT_SCAN_INTERVAL):
                vol.All(cv.positive_int, vol.Range(min=30)),
        }),
    },
    extra=vol.ALLOW_EXTRA,
)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Load from YAML and cancel polling when Home Assistant stops."""
    if DOMAIN in hass.data:
        return True
    monitor = AuthMonitor(hass.auth)
    # A failed initial read does not prevent future retry attempts.
    await monitor.async_refresh()
    unsubscribe = async_track_time_interval(
        hass, monitor.async_refresh,
        timedelta(seconds=config[DOMAIN][CONF_SCAN_INTERVAL]),
    )

    @callback
    def stop(_event):
        unsubscribe()
        hass.data.pop(DOMAIN, None)

    hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, stop)
    hass.data[DOMAIN] = monitor
    return True
