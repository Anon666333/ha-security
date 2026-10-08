# HA Security

A standalone Home Assistant custom integration proof-of-concept for read-only authentication visibility.

## v0.1.6 session dashboard

v0.1.7 fixes the session adapter's constructor check for Python 3.14 deferred
annotations, used by HA 2026.9.4. It checks parameter names without evaluating
HA's type-only imports. Unsupported/error tracking also exposes a safe
`tracking_reason` in entities and the dashboard, plus a warning in Core logs.
After updating, restart Core, reload the browser resource with `?v=0.1.7`,
and reconnect clients after enabling session tracking. If tracking is still
unsupported, report the diagnostic shown on the dashboard.

### Install the interactive dashboard

After updating and restarting HA, open **Settings → Dashboards → Resources**
(enable Advanced mode in your profile if Resources is hidden). Add a resource:

- URL: `/ha_security/ha-security-card.js?v=0.1.7`
- Type: **JavaScript module**

Replace the separate dashboard's raw configuration with
[dashboards/security.yaml](dashboards/security.yaml), then refresh the browser.
The card is bundled with the integration; no extra HACS frontend repository
or external scripts are needed. When a future release changes the card, update
the resource's version query and refresh. If HA reports "Custom element doesn't
exist: ha-security-card", check the module resource and restart/refresh.

The entity-powered card provides summary totals, selectable user cards,
Live / History / Credentials tabs, client/IP/hostname/organisation search,
status filters, expandable metadata and IP timelines, entity more-info links,
and admin credential renaming. It follows HA theme colours and adapts to mobile
widths. It does not fetch external data in the browser. Filtering covers the
bounded entity lists; **Search sessions** provides pagination over older rows.

### Observe actual WebSocket connections

In integration options enable **Observe WebSocket sessions (experimental)**.
Reconnect your existing browser/app clients after enabling or reloading it.
This records distinct authenticated WebSocket connections, including concurrent
connections sharing a credential. Per-user **Active websocket connections**
and **Session history count** sensors expose current connections and ended
session rows. An **HA Security Overview** entity supplies dashboard totals.
IP/client detail exposure and public IP enrichment remain separate options.

Tracking uses a narrowly scoped adapter observing HA's internal `AuthPhase`
successful return, `ActiveConnection` incoming-command handler and close handler.
Constructor compatibility is checked; production connection creation is recorded
only after the authentication handler returns successfully. HA's global dispatcher
signals expose totals without a user or connection object. The adapter does
not inspect command contents, change authentication, or fingerprint browsers.
Original lifecycle methods always run. Observation failures stop session
tracking without blocking HA's authentication or command handlers. Unsupported
method signatures report `unsupported`; the active-count sensor is unavailable
when tracking is disabled, unsupported or in error rather than reporting zero.
Internal APIs can change between HA releases, so real-instance validation is
required. Unloading restores the wrappers it still owns.

Coverage begins when enabled. Existing connections may have cached their old
handlers and cannot be reliably enumerated; reconnect them for coverage.
Connection establishment is **not a proven password login**. `last_seen_at`
records an incoming WebSocket command, which can include app heartbeat or
subscription traffic, not necessarily a human action. Outgoing updates alone
do not advance it. A connected socket is not proof that a person is present.
HTTP requests, token refreshes and cloud-service activity remain credential
observations, not counted live sessions. Physical device identity is not proven;
the original client metadata and optional nickname supply the device label.

Connection rows store observed start, first observation, last incoming command,
source IP, client metadata, token record ID and close time. Unknown start times
remain unknown. Shutdown/reload/crash boundaries mark old observations
**interrupted**, with an observation-end time and unknown disconnect time;
persisted connections are never restored as online. Closed/interrupted session
history uses the configured audit retention and a separate 10,000-session cap;
live connection rows are retained until tracking sees closure/stops. Entity
lists expose up to 100 current and 100 historical rows per user. IP enrichment
also considers recent session IPs at the next inventory scan, including recently
closed connections; details may arrive after the initial session row.

Manual validation: enable tracking, reconnect two tabs using the same account,
verify distinct observed connections/IP metadata, send a harmless command,
close one tab, inspect its historical row, reload the integration and confirm
remaining observations become interrupted before reconnecting. Check the
card's search, status/user filters, details, rename action and mobile layout.
The adapter and card have local tests and a synthetic browser preview; this
release has not been validated against a live HA instance.

The MVP combines authentication inventory, new IP/client/token observations,
user-context service-call auditing, per-user entities, a native Lovelace dashboard
template, and searchable local history.

### Per-user security entities

Each user gets nine sensors: active WebSocket count, historical session count,
refresh-token count, recently used token count, last recorded token use, last
attributed service call, recently observed status, known IP count, and new
IP/client/token observation count in retained history. Existing refresh-token
sensor unique IDs are preserved.

Configure the recent observation window (default 15 minutes) and audit retention
(default 30 days, range 1–365) through the integration's Configure dialog.
Recent status combines token-use timestamps and captured service invocations;
it updates on scans and service events. It can lag expiry by up to one scan
interval. A service event carrying a user context may come from an automation
or script inheriting that context, rather than a direct click.

### Search and inspect without logs or restarts

Under Developer tools → Actions, choose:

- **HA Security: Get authentication inventory** for safe user/token metadata.
- **HA Security: Search audit history** for text, user ID, event kind, result
  limit (maximum 500), and pagination offset. Results are newest first.
- **HA Security: Scan authentication now** to trigger an immediate scan.
- **HA Security: Name credential** to set a nickname using its token record ID.
  An empty label clears it. Labels are local preferences, not auth changes.
- **HA Security: Search sessions** for retained WebSocket session rows with text,
  user/state filters and pagination (up to 500 rows per response).

These actions return response data. Request/display the action response; in an
automation use a `response_variable`. They use HA's admin-service guard
(administrator users or trusted internal automation contexts).

Example search action:

```yaml
action: ha_security.query_audit
data:
  text: light
  kind: service_call
  limit: 100
response_variable: security_audit
```

The service audit stores timestamp, attributed user ID, domain/service,
explicit entity targets, and context/parent IDs. It records invocations, not
confirmed success, authorization outcome, or human intent. Calls without a
user context are skipped. No full service payloads, messages, passwords,
access/refresh token values, or signing keys are stored.

### First-observed IPs and clients

The first successful scan establishes a baseline; existing grants/IPs/clients
are not flagged as new. Subsequent new records produce `new_token`, `new_ip`,
and `new_client` events. Token metadata changes and removals are also audited.
Baselines survive restarts. Client IDs and IPs are observations, not physical
device identities or geolocation; shared browser clients, proxies, and VPNs
limit attribution. An IP/client absent beyond the retention window may be
reported as newly observed when it returns. Polling can miss transient grants.

### Local audit storage

History uses HA's storage helper in `/config/.storage/ha_security.audit`.
Retention runs on scans, events, queries, and saves. At most 10,000 audit rows
are retained even if younger than the configured retention period. Current
token baseline metadata and known-observation maps are separate from those
rows; they support change detection across restarts. Writes are delayed by
5 seconds to batch changes and flushed on orderly unload/shutdown, so abrupt
power loss can lose the latest batch. This is a local operational audit, not a
tamper-proof security log. It is included in normal HA configuration backups.
Removing the integration stops auditing but leaves this file for recovery.
For permanent deletion, remove the integration, then delete that specific file.

Client URLs have user information, query strings, and fragments stripped.
Names, client labels, IPs, and timestamps remain personal metadata.
**Expose IP/client details and retained observations on entities** is off by default. Enabling it makes
those attributes available to users with entity access and to Recorder/history;
an admin-only dashboard does not change entity access permissions.

### Lovelace Security dashboard

Use [dashboards/security.yaml](dashboards/security.yaml). Create a new dashboard
in Settings → Dashboards, choose administrator-only access, take control if
needed, and paste the file into its raw configuration editor. The template uses
the bundled HA Security card and automatically discovers HA Security sensors;
no fixed entity names or separate frontend downloads are required.

The dashboard shows session and credential details with search and filters.
Full audit pagination lives in the admin Actions interface. The dashboard is provided separately and is
never automatically installed or overwritten.

### Validation checklist

After updating via HACS and restarting Core, verify the nine sensors per user,
run Scan authentication now and Get authentication inventory, make a harmless
user-attributed service call, then search for that event. Check options reload,
history preservation across restart, and non-admin denial of audit actions.
Only the earlier inventory/logging version has been validated on the user's
live HA instance; MVP storage, sensors, service auditing, and dashboard still
require validation on the real target.

Each discovered user gets a refresh-token-count sensor, including system and
inactive users and users with zero tokens. The HA user ID provides a stable
unique identity across renames. New users are added on the next successful scan;
deleted users' entities and registry entries are removed. Failed scans mark
existing sensors unavailable, retain the previous snapshot, and recover on
the next successful scan.

Sensor attributes include active/owner/system status and last successful scan.
Token secrets remain excluded from entities. Token counts
represent stored credential grants, not online sessions. Home Assistant may
record count/status/timestamp history according to your Recorder settings.

This is a local custom integration, not a Supervisor add-on. It needs no Home
Assistant approval, Core fork, HACS installation, or external service.

It enumerates all users (including inactive/system users and users with no
tokens) via `hass.auth.async_get_users()` and reads each user's
`refresh_tokens` mapping. Snapshots contain user ID/name/status and token record
ID, user association, client ID/name, creation time, last-used time/IP, token
type, refresh-token `expire_at` when available, and access-token lifetime in
seconds. Optional missing fields are null.

The monitor scans at startup and every 300 seconds by default. INFO logs show
inventory counts on change; DEBUG logs show completion counts and the full safe
metadata inventory on every successful scan, plus removed record IDs on changes.
This lets you enable debug logging after setup and still see the current inventory.
Failed scans retain the latest successful
snapshot and retry at the next interval. Polling is cancelled at HA shutdown.

No credentials are created, changed, or revoked. No browser fingerprinting or
auth-store file reads are used. Opt-in session tracking wraps internal HA
methods as described above; it observes connections, not human presence.
Only explicitly selected metadata enters snapshots;
raw token values, JWT keys, credential objects, and auth-object representations
are never logged or retained by this integration.

## Install with HACS

The repository must be public. The installable integration and `hacs.json`
must be on the default branch or in a published release before using these
steps; an open development PR alone is not an installable HACS version.

1. Open HACS → menu → **Custom repositories**.
2. Add `https://github.com/Anon666333/ha-security` with type **Integration**.
3. Find **HA Security** in HACS and download it.
4. Restart Home Assistant.
5. Open Settings → Devices & services → Add Integration → **HA Security**.
6. Choose a polling interval and submit. No YAML is required.

HACS manages file downloads and updates; Home Assistant manages the integration's
setup and options. Restart Home Assistant after installing an update.
Without releases, HACS downloads the default branch. Published versioned releases
provide explicit versions to install and update to. No default-catalog approval
is needed to use a custom repository.

## Manual installation on a test instance

1. Copy the whole `custom_components/ha_security` folder into
   `/config/custom_components/ha_security` on your Home Assistant instance.
2. Restart Home Assistant so it discovers the custom integration.
3. Open Settings → Devices & services → Add Integration → **HA Security**.
4. Choose a polling interval (seconds; minimum 30, default 300) and submit.
   Only one HA Security instance can be configured.
5. Use the integration's **Configure** options to change the interval later.
   Changes reload the monitor automatically.
6. For detailed metadata, use **Enable debug logging** from the integration's
   menu. Disable it after your investigation; Home Assistant offers the debug
   log for download.
7. Inspect Settings → System → Logs or `home-assistant.log` for the auth
   inventory and metadata records.

When debugging, wait one polling interval or reload the configured integration
after enabling debug logging. Look for `Auth scan completed`. Each successful
scan includes this marker even with zero users/tokens or unchanged metadata.
The condensed System Logs view may show only warnings/errors; use the full Core
log or the downloaded integration debug log for DEBUG entries.
Downloading through HACS installs the files but does not start monitoring: you
must also add HA Security under Devices & services.

Metadata includes personal information (names, client URLs, IPs, timestamps).
Enable DEBUG only while investigating and protect any collected logs. Disabling
DEBUG stops detailed logging; HA log files already written follow your existing
log retention. The live snapshot is accessible internally through
`hass.data["ha_security"].snapshot`; safe metadata is also available through the
admin inventory action and the persisted local audit baseline.

No YAML is required for setup or logging. If you tested the earlier YAML draft,
remove its `ha_security:` block before restarting and adding the integration.
To remove it, delete the entry from Devices & services; polling and listeners
are cleaned up. You can then remove the custom integration folder.

## What the metadata means

### Per-user credential activity and IP history (v0.1.4)

Each discovered user appears as a **User account** service device under
HA Security in Devices & services, with all nine security sensors grouped
under it. Devices use the stable authentication user ID, so account renames
update the device name without replacing entities. Existing entities retain
their unique IDs and attach to the user device when loaded after updating.
Removed users are detached from the integration after a successful scan;
failed scans retain the existing device grouping. Names customised in HA
remain under HA's registry controls.

Each user has a **Recently used tokens** sensor. Its state counts currently
present, non-expired credential grants whose recorded last use is within the
configured recent observation window. It does not count open browser tabs,
WebSocket connections, or confirmed concurrent sessions.

Enable **Expose IP/client details and retained observations on entities** in
the integration options to see `tokens` and `ip_observations` attributes.
Each token row contains its record ID, client ID/name, creation/last-use time,
latest IP, type/expiry, and recent-use flag. Each retained observation links
the IP/client to the same token record ID, including observations for grants
that have since been removed. Record IDs are identifiers, not token secrets.

The separate dashboard YAML includes these details. Entity lists show at most
100 rows each, with total/truncation attributes; use Search audit history for
other retained rows. History survives integration reloads and HA restarts in
the local audit store, subject to configured retention (30 days by default,
up to 365) and the shared 10,000-event cap. This is not an unlimited archive.
Recorder retention is separate from the integration's audit retention.

Only IPs visible at polling time can be retained. A token shared by multiple
clients exposes only its latest recorded IP on each scan, so simultaneous
connections and rapid IP changes between scans cannot be reconstructed.
### Readable connections and optional IP context (v0.1.5)

The `connections` attribute and separate dashboard now combine current and
retained removed credentials. Each row has a friendly label, original client
metadata, source IP/address scope, activity state, first retained observation,
and change markers. Removed/expired credentials remain distinct from recently
used credentials. New-credential, new-IP and IP-changed markers describe events
in retained history; they are not transient alerts or confirmed threats.
First retained observation can advance as history expires. The dashboard shows
relative times alongside exact timestamps, separating creation, token use and
observation. Nicknames follow token record IDs across IP changes and restarts;
they do not prove the physical identity of a device. Up to 1,000 nicknames are
stored until cleared, independently of audit retention.

In integration options, **Look up public IP context (optional)** enables
HTTPS requests to [ipwho.is](https://ipwhois.io/documentation) and reverse-DNS
lookups through the host's DNS resolver. Only public source IPs are sent, with
no usernames, token identifiers or credentials. No lookup occurs by default,
and non-public IPs are classified locally. Network detail exposure is a separate
option: enable both to display enrichment in entities/dashboard.

Available enrichment includes hostname, country, region, city, ASN and
organisation. It describes the IP/network, not a person's verified location;
cloud services/proxies may account for the apparent location. Provider fields
may be absent. Each result shows lookup status and time. Provider/DNS failures
do not prevent authentication monitoring. At most three uncached public IPs
are processed per scan, so a large initial inventory fills in over several
scans. HTTPS has a five-second timeout; reverse DNS has a three-second timeout.
Successful provider results are cached for seven days; failures retry after an
hour. The local cache is capped at 1,000 IPs and pruned by audit retention.
Disabling enrichment stops new lookups but leaves retained cached context.
Lookup candidates include current token IPs and recent observed session IPs.

Update the separately supplied dashboard YAML to see the connection table,
context and grouped IP history. Entity detail lists remain capped at 100 rows;
the audit action supplies further retained metadata, not unlimited archives.

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
change logging; `config_flow.py` owns UI setup/options; `__init__.py` owns
config-entry setup, reload, and unload lifecycle.
Future session/activity logic can consume detached snapshots without reading
credential secrets.

```shell
python -m pip install voluptuous==0.16.0 PyYAML Jinja2
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
