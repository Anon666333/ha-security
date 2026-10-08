"""Optional, isolated observation of HA login flow failures and code grants."""
from contextvars import ContextVar
from functools import wraps
import inspect
import logging

from .security import safe_ip, safe_client, utcnow
from .risk import record_login

_LOGGER = logging.getLogger(__name__)


def install_login_adapter(hass, monitor, flow_class=None, token_class=None, auth_class=None, hass_key=None):
    """Never read request bodies, response bodies, passwords, codes or token values."""
    stage = "imports"
    try:
        if flow_class is None:
            from homeassistant.components.auth.login_flow import LoginFlowBaseView
            from homeassistant.components.auth import TokenView
            from homeassistant.auth import AuthManager
            from homeassistant.components.http import KEY_HASS
            flow_class, token_class, auth_class, hass_key = LoginFlowBaseView, TokenView, AuthManager, KEY_HASS
        stage = "method_check"
        targets = ((flow_class, "_async_flow_result_to_response", {"request", "client_id", "result"}, True),
                   (token_class, "_async_handle_auth_code", {"hass", "request", "data"}, True),
                   (auth_class, "async_create_access_token", {"refresh_token", "remote_ip"}, False))
        originals = []
        for cls, name, expected, asynchronous in targets:
            fn = getattr(cls, name)
            code = getattr(inspect.unwrap(fn), "__code__", None)
            names = set(code.co_varnames[:code.co_argcount + code.co_kwonlyargcount]) if code else set()
            if not expected <= names or inspect.iscoroutinefunction(fn) != asynchronous:
                raise ValueError("Unsupported auth boundary")
            originals.append(fn)
    except Exception as err:
        monitor.login_status = "unsupported"
        monitor.login_reason = f"{stage}: {type(err).__name__}"
        _LOGGER.warning("Login observation unavailable at %s (%s)", stage, type(err).__name__)
        return lambda: None

    capture = ContextVar("ha_security_code_grant", default=None)
    monitor.login_status = "observing"
    monitor.login_started_at = utcnow().isoformat()

    def observe(**metadata):
        if monitor.stopped or monitor.login_status != "observing":
            return
        try:
            record_login(monitor.history, **metadata)
            monitor.session_changed()
        except Exception as err:
            monitor.login_status = "error"
            monitor.login_reason = f"observation: {type(err).__name__}"
            _LOGGER.warning("Login observation failed (%s)", type(err).__name__)

    @wraps(originals[0])
    async def flow(view, request, client_id, result):
        # Only HA's explicit bad password/MFA result codes are login failures.
        try:
            failure = (result.get("errors") or {}).get("base") if result.get("type") == "form" else None
        except Exception:
            failure = None
        response = await originals[0](view, request, client_id, result)
        if request.app.get(hass_key) is hass and failure in ("invalid_auth", "invalid_code"):
            observe(outcome="failure", source_ip=safe_ip(request.remote), failure_reason=failure)
        return response

    @wraps(originals[2])
    def access(auth, refresh_token, remote_ip=None, *args, **kwargs):
        value = originals[2](auth, refresh_token, remote_ip, *args, **kwargs)
        state = capture.get()
        if auth is hass.auth and state is not None:
            try:
                state.update(user_id=refresh_token.user.id, token_id=refresh_token.id,
                             client_id=safe_client(refresh_token.client_id), source_ip=safe_ip(remote_ip))
            except Exception as err:
                monitor.login_status = "error"
                monitor.login_reason = f"metadata: {type(err).__name__}"
        return value

    @wraps(originals[1])
    async def code_grant(view, request_hass, data, request):
        if request_hass is not hass:
            return await originals[1](view, request_hass, data, request)
        state = {}
        handle = capture.set(state)
        try:
            response = await originals[1](view, request_hass, data, request)
        finally:
            capture.reset(handle)
        if response.status == 200 and state.get("user_id"):
            observe(outcome="success", **state)
        return response

    replacements = (flow, code_grant, access)
    for (cls, name, _, _), replacement in zip(targets, replacements):
        setattr(cls, name, replacement)

    def uninstall():
        for (cls, name, _, _), original, replacement in zip(targets, originals, replacements):
            if getattr(cls, name) is replacement:
                setattr(cls, name, original)
        monitor.login_status = "disabled"
    return uninstall
