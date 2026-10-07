"""UI setup and options for HA Security."""

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import callback

from .const import CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL, DOMAIN


def interval_schema(default):
    """Require a whole number of seconds with a safe minimum."""
    return vol.Schema({
        vol.Required(CONF_SCAN_INTERVAL, default=default):
            vol.All(int, vol.Range(min=30)),
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
                data = interval_schema(DEFAULT_SCAN_INTERVAL)(user_input)
            except vol.Invalid:
                errors["scan_interval"] = "invalid_interval"
            else:
                return self.async_create_entry(title="HA Security", data=data)
        return self.async_show_form(
            step_id="user",
            data_schema=interval_schema(DEFAULT_SCAN_INTERVAL),
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
        default = self._entry.options.get(
            CONF_SCAN_INTERVAL,
            self._entry.data.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
        )
        errors = {}
        if user_input is not None:
            try:
                data = interval_schema(default)(user_input)
            except vol.Invalid:
                errors["scan_interval"] = "invalid_interval"
            else:
                return self.async_create_entry(title="", data=data)
        return self.async_show_form(
            step_id="init", data_schema=interval_schema(default), errors=errors,
        )
