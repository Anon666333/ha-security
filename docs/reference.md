# Detailed reference

Configuration, data semantics, troubleshooting and maintainer notes.

# HA Security

![HA Security icon](../custom_components/ha_security/brand/icon.png)

A standalone Home Assistant custom integration proof-of-concept for read-only authentication visibility.

## v0.1.10 branding and releases

Adds bundled integration icons and automatic, tested GitHub releases for HACS.
See [Branding and versioned updates](#branding-and-versioned-updates) for the
release workflow and [CHANGELOG.md](../CHANGELOG.md) for update notes.

## v0.1.9 login activity and security assessment

After installing and restarting Core, enable **Observe login outcomes** in the
integration's UI options, then update the dashboard module URL to
`/ha_security/ha-security-card.js?v=0.1.15`. No dashboard YAML changes are required.
This is independent of the WebSocket option. Observation starts when enabled;
old login outcomes cannot be reconstructed from token timestamps.

Each user device gains **Last successful login**, **Successful logins 24h**,
**Correlated failed attempts 24h**, and **Security status**. Global entities expose
successful and failed counts plus security status. Disabled/unsupported observation
makes those entities unavailable, with diagnostics in the overview/dashboard.

The new **Login activity** tab supports account, outcome and severity filters,
search, expandable address/hostname/location details, timestamps and assessment
reasons. Session badges use a matching observed login (same user, credential ID,
source IP and connection start within 10 minutes); unmatched sessions are **Not
assessed**. The badge records assessment at connection observation, not a later
claim about current safety. Current user status aggregates the past 24 hours.

Observed successes mean successful **authorization-code exchanges**, including
passwordless providers. Ordinary token refreshes, API requests and WebSocket token
authentication are excluded. Failures mean HA login flows returning explicit
`invalid_auth` or `invalid_code` (password/MFA). Malformed requests, invalid access
tokens, reverse-proxy authentication and abandoned flows are outside this coverage.
Failed users are **unknown**: no attempted usernames or credentials are collected.
Same-IP failures preceding a success are correlated, not attributed to that user;
shared NAT/proxies can include different people. Per-user counts are labelled accordingly.

Initial conservative rules:

| Assessment | Evidence |
| --- | --- |
| Normal | No rule triggered within observed coverage; unfamiliar cellular IP alone and one/two typos do not escalate |
| Review | At least 5 failures from one IP within 10 minutes; or a success using both a new credential and unfamiliar public IP |
| Likely an issue | Success after at least 10 same-IP failures within 10 minutes, with both a new credential and unfamiliar public IP |

A preceding successful login ends that IP's failure sequence. IP geolocation,
VPN/cellular changes and connection count alone do not escalate. These are
explainable heuristics, not confirmation of compromise; no credentials are revoked
and no notifications are sent automatically.

Use **Recognize credential** in login details to explicitly establish familiarity.
The admin-only **HA Security: Recognize credential or source** action also supports
an exact IP and `recognized: false` to forget a recognition. Recognition persists
locally, bounded to 1,000 users and 1,000 entries per category/user. It suppresses
novelty-only current warnings; repeated-failure warnings and historical assessments
remain. Existing IP/token observations provide familiarity without declaring them
trusted. Addresses remain behind **Expose IP/client details**; optional public-IP
enrichment uses the existing opt-in setting and never geolocates private addresses.

Login outcomes and reasons are searchable with **Search audit** (`login_success`
and `login_failure`) and use the shared retention/10,000-event cap. Counts are
retained observations, not complete all-time totals. The observer uses guarded
internal HA methods checked against Core 2026.9.4; observation failures preserve
HA's original responses and expose safe diagnostics. Unload/reload restores hooks.
No request/response bodies, passwords, MFA codes, authorization codes or token
values are inspected or persisted.

## v0.1.8 connection and credential addresses

Session details now keep the **connection source IP** separate from the same
credential's **last recorded IP**, with independent hostname and location details.
LAN access normally shows a private source IP. A public credential IP can reflect
another connection or cloud/proxy use; it is not inferred as the LAN session's
public address. Both appear when available, with credential-use and observation
timestamps. Other credentials remain in the Credentials tab rather than being
assigned to a session just because they belong to the same user.

Live rows refresh credential metadata on each inventory scan. Closed history keeps
the last observed metadata; existing historical rows may lack these fields.
Network details and public IP enrichment still require their existing UI options.
Public geolocation cannot locate a private address, and no public address is guessed.

### Session compatibility

v0.1.7 fixes the session adapter's constructor check for Python 3.14 deferred
annotations, used by HA 2026.9.4. It checks parameter names without evaluating
HA's type-only imports. Unsupported/error tracking also exposes a safe
`tracking_reason` in entities and the dashboard, plus a warning in Core logs.
After updating, restart Core, reload the browser resource with `?v=0.1.15`,
and reconnect clients after enabling session tracking. If tracking is still
unsupported, report the diagnostic shown on the dashboard.

### Install the interactive dashboard

After updating and restarting HA, open **Settings → Dashboards → Resources**
(enable Advanced mode in your profile if Resources is hidden). Add a resource:

- URL: `/ha_security/ha-security-card.js?v=0.1.15`
- Type: **JavaScript module**

Replace the separate dashboard's raw configuration with
[dashboards/security.yaml](../dashboards/security.yaml), then refresh the browser.
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

Each user gets thirteen sensors: active WebSocket count, historical session count,
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

Use [dashboards/security.yaml](../dashboards/security.yaml). Create a new dashboard
in Settings → Dashboards, choose administrator-only access, take control if
needed, and paste the file into its raw configuration editor. The template uses
the bundled HA Security card and automatically discovers HA Security sensors;
no fixed entity names or separate frontend downloads are required.

The dashboard shows session and credential details with search and filters.
Full audit pagination lives in the admin Actions interface. The dashboard is provided separately and is
never automatically installed or overwritten.

### Validation checklist

After updating via HACS and restarting Core, verify the thirteen sensors per user,
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
Published versioned releases provide explicit versions to install and update to.
The development branch is hidden from the HACS version picker. No default-catalog approval
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
HA Security in Devices & services, with all thirteen security sensors grouped
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


## Branding and versioned updates

The integration bundles an original shield-and-home icon in
`custom_components/ha_security/brand/`, with transparent 256px and 512px assets
and dark-mode equivalents. The editable SVG is included. Home Assistant 2026.3+
loads these local assets without a separate brands submission:
[Home Assistant branding documentation](https://developers.home-assistant.io/blog/2026/02/24/brands-proxy-api/).

HACS has an [open local-branding frontend issue](https://github.com/hacs/integration/issues/5402)
which can leave a placeholder even when HA displays the icon correctly. This repo
ships the supported assets; no undocumented `icon` setting is added to `hacs.json`.

Releases follow stable semantic versions: the manifest contains `0.1.10`, and
its matching GitHub tag/release is `v0.1.10`. HACS uses **published GitHub releases**
for named versions; creating a tag alone is insufficient:
[HACS version documentation](https://hacs.xyz/docs/publish/start/#versions).
No version belongs in `hacs.json`.

For each future release:

1. Start a feature/fix branch and bump `manifest.json`: patch for fixes and small
   additions, minor for a larger feature milestone or incompatible changes while
   pre-1.0, and major for incompatible changes once 1.0 is reached.
2. Add the matching version's notes to `CHANGELOG.md`, including any update steps.
   Update the README and dashboard module resource query to the same version.
3. Open a PR. CI checks the release metadata, Python 3.13/3.14 behavior and frontend.
4. Merge when ready. Only a tested push to `main` publishes the matching tag and
   GitHub release automatically. The workflow needs repository Actions enabled
   and permission to create releases. If publication fails, correct the cause and
   rerun the workflow; an existing tag at the same tested commit can be reused.
5. Verify the release's **Publish tested release** job succeeded. HACS will pick up
   the published version on its next refresh. Install the update, restart Core,
   update the dashboard resource query and refresh the browser.

Published tags are never moved, and published releases are never overwritten.
Repeated runs with an already published manifest version create no update. Keep
version bumps separate from unreleased intermediate commits: once GitHub releases
exist, changes on `main` alone are not a new HACS version. The workflow uses
GitHub's source archive; no custom release ZIP or runtime dependency is required.
Run `python scripts/release.py` locally to validate release metadata without
publishing anything.

## Next iteration: retained related activity

The Activity tab and **View related activity** buttons use existing administrator-only
Search audit and Search sessions actions. Activity starts with retained observations,
not Recorder entity history. Results include readable descriptions, current credential
nicknames, raw structured results and pages of 50 records. Failed requests display an
error; non-administrators do not gain access through the dashboard.

Related activity separates direct credential observations (recorded credential ID),
connections authenticated with that credential (recorded WebSocket credential ID),
and service invocations attributed to its user (specific credential and connection
unknown). A selected connection does not make every event for its credential an event
on that connection. Service invocations do not prove successful execution. Date filters
use local input times converted to timezone-aware timestamps; session filters use the
first observation time. Filters are inclusive. Audit coverage timestamps describe the
retained audit store, rather than complete monitoring uptime or session coverage.
Retention and the shared 10,000-event audit cap can remove older observations.

Credential types are checked against Home Assistant Core 2026.9.4 auth/models.py:
`normal`, `system`, and `long_lived_access_token`. Unknown values remain visible as
unknown types. Credential expiration uses `expire_at` where available; issued access-token
lifetime is separate and is not presented as refresh-token expiration. Last recorded
token use is HA inventory metadata and does not observe every HTTP/REST request.
Credential entity details still require the existing network-details opt-in; admin
search actions retain their existing access boundary.

Live baseline verification on October 8, 2026: the user confirmed the installed
manifest is v0.1.13 and the supplied Core-log filter returned no Recorder or slow-update
warnings. This verifies the retained log window, not every prior/future runtime interval.
The next iteration has local automated validation only until it is installed and tested.

Activity reading behavior: background entity updates and the card timer do not rebuild
the Activity tab. Use **Refresh activity** for newer records. Event rows and their
technical details retain expansion across deliberate renders. Event titles and
readable field summaries also work with older backend responses lacking descriptions;
service calls are never inferred to be WebSocket connections. Technical JSON remains
available under **Technical details (structured result)**.

## Credential-attributed WebSocket service commands

The experimental WebSocket session option also observes **call_service** commands
at `ActiveConnection.context(msg)`, checked against Core 2026.9.4. This boundary
provides the authenticated credential record ID, session and original HA context.
The original context and HA processing are preserved. Observer failures stop action
observation and expose a diagnostic without changing the original context response.
This is not complete WebSocket auditing: other command types, binary traffic and
general HTTP/REST requests are excluded from the WebSocket observer. Core REST service POSTs have a separate observer described below. HA Security's own service calls are omitted to avoid logging
the investigation itself. No service payloads, templates, credentials, request bodies
or response bodies are stored. Allowed service-event entity targets are retained;
device/area targets are not expanded.

A credential action means a service command reached context creation. It can still
fail validation/permission checks or execution later. An exact context/user/domain/
service match marks **Service invocation observed**, still without asserting success.
Links use a bounded 1,000-context, five-minute in-memory cache. Missing, expired,
user-mismatched and parent-only contexts remain unattributed. Observation starts
when enabled; older actions cannot be reconstructed. The shared audit retention/cap
applies. Disabling or unloading clears transient links.

**User activity · HA history** uses HA's `logbook/get_events` API in the dashboard,
filtering returned `context_user_id` values for the selected user. It does not create
another persisted user timeline. Queries use a window of up to 24 hours, defaulting
to the last day, with 50-row display pagination; native history availability follows
Recorder/Activity retention, filters and the current caller's access. Missing user
context is not guessed. Existing user-only audit rows remain historical records,
while new unmatched service calls update only the existing last-call summary.
**Related HA activity** on a credential action queries HA history by the saved
original context ID. Related history is contextual evidence, not confirmation of
successful physical execution. Both views remain inside the security dashboard.

Validation is local with HA-shaped fakes, including same-user credentials and
out-of-order service events, unattributed/mismatched/expired contexts, observer failure
isolation and inline native history filtering. A deployed Core 2026.9.4 two-credential
smoke test remains required before claiming live compatibility.

## Live dashboard reading

HA entity changes update the existing DOM by stable record/control identity rather
than replacing the whole card. Counts, badges and timestamps remain live while native
controls and expanded details stay mounted. Focused selects/inputs are left untouched.
The 30-second timer updates relative timestamps and reloads Activity's first page;
fixed end dates and later result pages do not poll. Explicit refresh is still available.

While a list has expanded details, existing records keep their order and new records
append. An inspected live connection that closes remains visible with its recorded
closed status. If it leaves observation without an ended record, it is labelled as
no longer observed, preserving only its last details. Other inspected rows that leave
the displayed window are retained while open. Closing them allows their removal on
the next update. Expanded rows are remembered separately per tab; scroll anchoring
compensates for layout changes above the first expanded record.

DOM identity regression tests cover changing counts, focused select preservation,
arrival order, connection closure and nested expansion. Native mobile dropdown and
scroll behavior still require a deployed browser smoke test.

## v0.1.14 installation/testing boundary

Install the whole `custom_components/ha_security` directory together and restart Core
once; then load the card resource with `?v=0.1.15`. Related activity reports dashboard
and backend versions plus credential-match counts. An older backend lacking activity
API version 2 is explicitly identified. Opening related activity resets inherited date
filters; a record without a captured credential ID cannot broaden the query to all
credentials. Inventory observations are first appearances/metadata changes/removals,
not service action history.

The Python-to-DOM contract test generates responses from an actual metadata snapshot,
connection tracker and registered admin service handlers, then clicks the live row's
related button and mode controls. It verifies the baseline observation, authenticated
connection and service command for one credential, excluding a second credential of
the same user. Tests use HA-shaped fakes, so installed first-iteration compatibility
and the real mobile browser still require a post-install smoke test. Historical
user-only calls will never acquire a credential ID retroactively.

## v0.1.15 activity categories

**Credential actions** queries only `websocket_action`. **Inventory observations**
uses `category: inventory`, whose allowlist is baseline initialization, credential
baseline/new/updated/removed, new IP and new client. The category filter applies
before totals and pagination; it excludes commands, login events, service calls
and recognition events. **User activity · HA history** reads native HA history and
filters only the user, never a credential or connection. It may contain effects of
credential commands but is broader supporting context, not another command list.
Switching sections clears the previous section's results until the new query returns.
Install the matching integration and card together; the new inventory filter requires
the v0.1.15 backend. No older user history is reattributed to a credential.


## Credential-attributed REST service calls (0.1.16)

Core `POST /api/services/{domain}/{service}` requests are observed automatically while
HA Security is loaded, independently of the WebSocket session option. This includes
LLTs used by n8n. The adapter reads only HA-authenticated request metadata and links
the service context ID, user ID, domain and service to the invocation event. It does
not infer attribution from a user, IP or timestamp. The Activity action view queries
`category: actions` to combine `rest_action` and `websocket_action` records.

Records show the user, credential name (dashboard nickname overrides HA client name),
REST transport, service and explicit entity targets when the invocation is observed.
No artificial connection session is created. Headers, bearer tokens, request bodies
and response bodies are never retained. HTTP response status and physical execution
outcomes are not observed. Commands that fail before invocation can show a recorded
context with invocation unconfirmed. General API reads and other REST endpoints are
not covered, and historical requests cannot be reconstructed.

This uses an experimental internal Core service-view context adapter (checked against
Core 2026.9.4 source). Activity reports REST observation status and an explicit reason
if unavailable. Unload restores the adapter; observer failures leave request processing
unchanged. Live verification: install the matching backend and card, restart HA, refresh
the browser resource `?v=0.1.16`, repeat an n8n light service call, and open the named LLT's
related Credential actions. Verify the target and REST transport, then repeat using a
different credential belonging to the same account to check separation. Local unit/DOM
tests do not replace this installed-HA verification.


## REST reads and action exclusions (0.1.18)

Supported authenticated GET routes: `/api/`, `/api/states`, `/api/states/{entity_id}`,
`/api/config`, `/api/services`, `/api/events`, `/api/components`. The API dependency
ensures routes exist before observation starts. The guarded adapter replaces the
existing aiohttp route handler slot and restores its own wrappers on unload. It
records HA user/credential IDs, method, allowlisted endpoint template, HTTP status,
and a validated entity ID. No headers, query strings, raw URLs or response bodies
are retained. HTTP errors retain their original behavior. Other GET endpoints,
including history/logbook and third-party endpoints, are outside this coverage.
Activity displays REST GET observation status separately from service observation.

`system_log.write` commands appear under Inventory & diagnostics; this shows an
observed log-write invocation, not log message contents or every log-file write.
Credential actions contains other service commands and supported REST reads. It
does not claim a service submission proves physical execution. HA state changes
remain available in related native history with its own attribution boundaries.

Hide actions accepts comma-separated wildcard patterns such as `todo.get_items`,
`todo.*`, or `GET /api/states*`. Patterns apply on the backend before pagination;
records are retained. Choices persist in browser local storage (shared by security
cards in that browser/origin), not HA settings. The service parameter is
`exclude_actions: ["todo.*"]`, limited to 50 patterns of up to 128 characters.
Credentials sort by latest observed use, with never-observed credentials last;
open rows keep their position during background updates to preserve inspection.


## Credential exclusions and HTTP source IP (0.1.19)

Activity includes a Credentials dropdown with checked-by-default credential choices.
It lists current inventory (regular refresh records and LLTs), uses dashboard nickname
before HA client name, and scopes choices to the selected user. All users shows the
whole current inventory with user names. Uncheck HASS.Agent to hide its activity;
Show all credentials resets exclusions. Choices persist per browser/origin and apply
to retained actions, inventory/diagnostics and connections before pagination. They do
not stop collection. HA user/context history has no reliable credential ID and cannot
apply those exclusions. Admin query services accept `exclude_token_ids`.

New REST GET and service command records include `source_ip` from HA's resolved
`request.remote` when Expose IP/client details is enabled. HA handles trusted proxy
validation; we never parse forwarding headers independently. The UI labels it HTTP
source IP (HA resolved). It may be a NAT, caller host or proxy address and is not a
physical device identity. Existing records cannot have missing IPs reconstructed.


## Recent LLT activity on user cards (0.1.21)

User cards show WebSocket connections and a separate recent LLT activity count.
The latter counts directly attributed REST reads, REST service commands and
WebSocket service commands using long-lived credentials in the configured recent
window (default 15 minutes). Inventory changes, generic user events, future and
older timestamps are excluded. This is an observed action/request count, not a
connection count or number of distinct credentials, and is independent of view
exclusions. Unsupported endpoints are outside coverage; retention limits apply.
The credential menu and card permit visible overflow so the popup is not clipped.


## Activity performance and distinct LLTs (0.1.22)

User cards now show DISTINCT long-lived token records with recent observed use,
not the number of calls. Repeated requests using one LLT count once. The count
uses the configured recent window, includes supported reads and service commands,
and is independent of view exclusions. Prior releases' call count is superseded.

Live entity notifications are batched to 10 seconds, local history saves to 20
seconds (normal unload flushes immediately), and user summaries reused within
10-second buckets until new evidence arrives. History additions enforce the audit
cap immediately but perform full retention scans at most once per minute; queries,
explicit-time operations and serialization prune immediately. Dashboard reads do
not schedule storage writes; service description choices refresh only when users
change. These reduce request-driven event-loop and disk work without dropping
requests. Up to 20 seconds of unsaved recent data may be lost on an abrupt crash.
The credential menu is wider, right-aligned and clamped to viewport bounds.


## HTTP source addresses in Credentials (0.1.23)

Credentials projects same-user, same-token REST source-IP records into its latest
observed address and IP timeline. IP evidence is labelled HTTP request (HA resolved)
or HA inventory, with recorded use time. Original inventory last_used_ip/last_used_at
remain separate. Consecutive HTTP requests from the same address collapse into one
IP-history run rather than flooding the credential timeline. A transition in the
configured recent window highlights Recent IP change; repeated calls from an
unchanged IP do not move an old transition into the recent window. This is an
observation marker, not an assertion of compromise or physical device identity.
Addresses must already have been captured with Expose IP/client details enabled.
Optional enrichment includes recent HTTP addresses at the next inventory scan.
