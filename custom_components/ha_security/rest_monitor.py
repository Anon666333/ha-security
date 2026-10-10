"""Credential attribution at the core REST service context boundary.

Uses authenticated request metadata only, never authorization headers or bodies.
This deliberately covers core service POSTs, not general HTTP traffic.
"""

from functools import wraps
import re
from time import monotonic

from .security import safe_ip


READ_ROUTES = {
    "/api/": "API status", "/api": "API status", "/api/states": "Entity states",
    "/api/states/{entity_id}": "Entity state", "/api/config": "HA configuration",
    "/api/services": "Available services", "/api/events": "Event listeners",
    "/api/components": "Loaded components",
}


def install_rest_reads(hass, monitor):
    """Wrap bounded core GET routes, including on reload after router freeze.

    aiohttp has no public runtime handler replacement API. Guard the private slot
    and restore only our own wrappers. Never change middleware or authentication.
    """
    installed = []
    monitor.rest_read_status = "unsupported"
    try:
        for route in hass.http.app.router.routes():
            canonical = getattr(route.resource, "canonical", None)
            if route.method != "GET" or canonical not in READ_ROUTES:
                continue
            original = route.handler
            if getattr(route, "_handler", None) is not original:
                continue

            def wrap(handler, endpoint):
                @wraps(handler)
                async def observed(request):
                    status = None
                    try:
                        response = await handler(request)
                        status = response.status
                        return response
                    except Exception as err:
                        status = getattr(err, "status", None)
                        raise
                    finally:
                        try:
                            tid = request.get("hass_refresh_token_id")
                            uid = getattr(request.get("hass_user"), "id", None)
                            if (not monitor.stopped and request.method == "GET"
                                    and request.get("ha_authenticated", False)
                                    and isinstance(tid, str) and tid and uid
                                    and isinstance(status, int)):
                                entity = request.match_info.get("entity_id")
                                entities = [entity] if isinstance(entity, str) and re.fullmatch(r"[a-z0-9_]+\.[a-z0-9_]+", entity) else []
                                monitor.history.add("rest_request", uid, token_id=tid,
                                                    transport="rest", method="GET",
                                                    source_ip=safe_ip(getattr(request, "remote", None)) if monitor.expose_network else None,
                                                    endpoint=endpoint, request_label=READ_ROUTES[endpoint],
                                                    http_status=status, entity_ids=entities,
                                                    outcome="http_response_observed")
                                monitor.session_changed()
                        except Exception:
                            monitor.rest_read_status = "error"
                return observed

            replacement = wrap(original, canonical)
            route._handler = replacement
            installed.append((route, original, replacement))
        monitor.rest_read_status = "observing" if installed else "unsupported"
    except Exception:
        monitor.rest_read_status = "unsupported"

    def cleanup():
        for route, original, replacement in installed:
            if route.handler is replacement:
                route._handler = original
        monitor.rest_read_status = "disabled"
    return cleanup


def install_rest_adapter(monitor, view_class=None):
    """Observe existing bound view handlers too; restore on integration unload."""
    monitor.rest_status = "unsupported"
    monitor.rest_reason = "Core REST service context adapter unavailable."
    try:
        if view_class is None:
            from homeassistant.components.api import APIDomainServicesView
            view_class = APIDomainServicesView
        original = view_class.context
        if not callable(original):
            return lambda: None
        owned = view_class.__dict__.get("context")

        @wraps(original)
        def context(request):
            result = original(request)
            try:
                user = request.get("hass_user")
                tid = request.get("hass_refresh_token_id")
                domain = request.match_info.get("domain")
                service = request.match_info.get("service")
                uid = getattr(user, "id", None)
                cid = getattr(result, "id", None)
                if (monitor.stopped or request.method != "POST"
                        or not request.get("ha_authenticated", False)
                        or not isinstance(tid, str) or not tid
                        or not isinstance(cid, str) or not cid
                        or not uid or getattr(result, "user_id", None) != uid
                        or domain == "ha_security"
                        or not all(isinstance(v, str) and re.fullmatch(r"[a-z0-9_]{1,64}", v)
                                   for v in (domain, service))):
                    return result
                tracker = monitor.sessions
                tracker.prune_action_contexts()
                monitor.history.add("rest_action", uid, token_id=tid,
                                    context_id=cid, domain=domain, service=service,
                                    transport="rest", command="call_service",
                                    source_ip=safe_ip(getattr(request, "remote", None)) if monitor.expose_network else None,
                                    invocation_observed=False, outcome="not_observed")
                tracker.action_contexts[cid] = (monotonic(), monitor.history.records[-1])
                while len(tracker.action_contexts) > 1000:
                    del tracker.action_contexts[next(iter(tracker.action_contexts))]
                monitor.session_changed()
            except Exception:
                # Observer failures must not change HA's request behavior or leak data.
                monitor.rest_status = "error"
                monitor.rest_reason = "REST action observation failed; request processing continues."
            return result

        view_class.context = staticmethod(context)
        monitor.rest_status = "observing"
        monitor.rest_reason = None

        def cleanup():
            if view_class.context is context:
                if owned is None:
                    delattr(view_class, "context")
                else:
                    view_class.context = owned
            monitor.rest_status = "disabled"
        return cleanup
    except Exception:
        return lambda: None
