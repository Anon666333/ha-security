# HA Security

A standalone Home Assistant custom integration proof-of-concept for read-only authentication visibility.

## v0.1.0

This is a local custom integration, not a Supervisor add-on. It needs no Home
Assistant approval, Core fork, HACS installation, or external service.

It enumerates all users (including inactive/system users and users with no
tokens) via `hass.auth.async_get_users()` and reads each user's
`refresh_tokens` mapping. Snapshots contain user ID/name/status and token record
ID, user association, client ID/name, creation time, last-used time/IP, token
type, refresh-token `expire_at` when available, and access-token lifetime in
seconds. Optional missing fields are null.

The monitor scans at startup and every 300 seconds by default. INFO logs show
inventory counts on change; DEBUG logs show added/changed metadata and removed
record IDs. Unchanged scans stay quiet. Failed scans retain the latest successful
snapshot and retry at the next interval. Polling is cancelled at HA shutdown.

No credentials are created, changed, or revoked. No browser fingerprinting,
auth-store file reads, monkey patches, sensors, UI, or activity/session
classification are included. Only explicitly selected metadata enters snapshots;
raw token values, JWT keys, credential objects, and auth-object representations
are never logged or retained by this integration.

## Install on a test instance

1. Copy the whole `custom_components/ha_security` folder into
   `/config/custom_components/ha_security` on your Home Assistant instance.
2. Add this to `configuration.yaml` (merge with any existing logger section):

```yaml
ha_security:
  scan_interval: 300  # seconds; minimum 30, default 300

logger:
  logs:
    custom_components.ha_security: debug
```

3. Check your configuration and restart Home Assistant.
4. Inspect Settings → System → Logs or `home-assistant.log` for the auth
   inventory and metadata records.

Metadata includes personal information (names, client URLs, IPs, timestamps).
Enable DEBUG only while investigating and protect any collected logs. Disabling
DEBUG stops detailed logging; HA log files already written follow your existing
log retention. Snapshots are in memory only, accessible internally through
`hass.data["ha_security"].snapshot`; no service or public endpoint exposes them.

To remove it, delete the YAML configuration and restart, then remove the folder.
YAML reload/config-entry unloading is not supported in v0.1.

## What the metadata means

- A refresh-token record represents a credential grant, not an online session.
  Multiple tabs may share one token; a token may remain after a client goes offline.
- Last-used fields reflect HA's recorded token usage, not every user action or
  heartbeat. IPs may reflect proxy configuration, VPNs, or shared networks.
- Client ID/name are supplied metadata and do not establish device identity.
- `expire_at` is an optional Unix timestamp for refresh-token expiry.
  `access_token_expiration_seconds` is the lifetime of issued access tokens,
  not an absolute session expiry. No expiry is inferred when data is absent.
- Polling can miss records created and removed between scans.

The auth manager and model fields are HA internals, not a guaranteed stable
custom-integration API. The adapter isolates this dependency for future changes.
The implementation was checked against current upstream source:
[auth manager](https://github.com/home-assistant/core/blob/dev/homeassistant/auth/__init__.py)
and [auth models](https://github.com/home-assistant/core/blob/dev/homeassistant/auth/models.py).

## Development and validation

`auth_monitor.py` is the read-only adapter; `monitor.py` handles snapshots and
change logging; `__init__.py` owns YAML configuration and polling lifecycle.
Future session/activity logic can consume detached snapshots without reading
credential secrets.

```shell
python -m pip install voluptuous==0.16.0
python -m unittest discover -s tests -v
python -m compileall -q custom_components
```

Unit tests use auth-shaped fakes, real Voluptuous schemas, and a stubbed HA
scheduler/bus to check configuration, retry, and shutdown cleanup. They do not prove integration loading on a real
HA instance. No live HA instance has been validated for this release. Before
relying on it, verify startup on your version, a user with no tokens, normal and
long-lived token metadata, updated last-used fields after client authentication,
record removal after manual revocation, and shutdown/restart without duplicate
polling. Do not share raw auth storage or tokens as test evidence.
