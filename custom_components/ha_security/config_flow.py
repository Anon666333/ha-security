"""UI setup and options for HA Security."""

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import callback

from .const import CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL, DOMAIN
from .const import (
    CONF_RETENTION_DAYS, CONF_RECENT_MINUTES, CONF_EXPOSE_NETWORK,
    DEFAULT_RETENTION_DAYS, DEFAULT_RECENT_MINUTES,
)


def interval_schema(default):
    """Require a whole number of seconds with a safe minimum."""
    return vol.Schema({
        vol.Required(CONF_SCAN_INTERVAL, default=default):
            vol.All(int, vol.Range(min=30)),
    })


def settings_schema(settings):
    return vol.Schema({
        vol.Required(CONF_SCAN_INTERVAL, default=settings.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)):
            vol.All(int, vol.Range(min=30)),
        vol.Optional(CONF_RETENTION_DAYS, default=settings.get(CONF_RETENTION_DAYS, DEFAULT_RETENTION_DAYS)):
            vol.All(int, vol.Range(min=1, max=365)),
        vol.Optional(CONF_RECENT_MINUTES, default=settings.get(CONF_RECENT_MINUTES, DEFAULT_RECENT_MINUTES)):
            vol.All(int, vol.Range(min=1, max=1440)),
        vol.Optional(CONF_EXPOSE_NETWORK, default=settings.get(CONF_EXPOSE_NETWORK, False)): bool,
    })


class SecurityConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Configure one monitor for this Home Assistant instance."""

    VERSION = 1

    async def async_step_user(self, user_input=None):
        await self.async_set_unique_id(DOMAIN)
        self._abort_if_unique_id_configured()
        errors = {}
        if user_input is not None:
            try:
                data = settings_schema({})(user_input)
            except vol.Invalid:
                errors["base"] = "invalid_settings"
            else:
                return self.async_create_entry(title="HA Security", data=data)
        return self.async_show_form(
            step_id="user",
            data_schema=settings_schema({}),
            errors=errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return SecurityOptionsFlow(config_entry)


class SecurityOptionsFlow(config_entries.OptionsFlow):
    """Change the polling interval from the integration's options."""

    def __init__(self, entry):
        self._entry = entry

    async def async_step_init(self, user_input=None):
        errors = {}
        if user_input is not None:
            try:
                data = settings_schema({**self._entry.data, **self._entry.options})(user_input)
            except vol.Invalid:
                errors["base"] = "invalid_settings"
            else:
                return self.async_create_entry(title="", data=data)
        return self.async_show_form(
            step_id="init",
            data_schema=settings_schema({**self._entry.data, **self._entry.options}),
            errors=errors,
        )
