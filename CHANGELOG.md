# Changelog

Published releases use `vMAJOR.MINOR.PATCH` tags matching the integration manifest.

## [0.1.15]

- Separate Inventory observations from Credential actions with a backend inventory-event allowlist, applied before pagination and totals. Inventory excludes WebSocket commands, login events and user service calls.
- Explain each activity view's source and attribution scope, especially broader HA user history across credentials.
- Clear results from a different section while its replacement query loads, preventing stale action rows from appearing under Inventory observations.
- Verify non-overlap using real action responses in the Python-to-DOM contract tests.

## [0.1.14]

- Diagnose credential matching explicitly (known credential, retained observations/connections/actions); report mismatched backend activity APIs and specific empty-result causes rather than implying no activity.
- Reset unrelated date filters when opening related activity, apply the main user filter consistently, and prevent missing credential IDs from broadening into unrelated records.
- Validate live-row IDs through real inventory, session tracking and registered action responses into the DOM, including same-user credential isolation.

- Restore live updates using DOM reconciliation by record/control ID. Keep focused controls and expanded details mounted; append new records while inspecting a list and retain an inspected connection when it closes. Refresh Activity first-page results every 30 seconds; fixed date ranges and later pages remain stable.

- Link observed WebSocket service commands directly to the authenticated credential, session and original HA context. Confirm service invocation only by exact context/user/action match; never infer links from users, timing or parent contexts.
- Surface existing HA Activity history inline for user-level investigation and related action contexts. Stop adding new user-only service calls to the integration audit timeline.
- Start related activity with Credential actions; display the known user prominently and state that command submission/invocation does not establish execution success.

- Fix legacy audit responses appearing as "Connection undefined"; generate service, credential and connection descriptions from recorded fields even without backend descriptions.
- Show readable event details before optional technical JSON, with user-only service attribution and unknown execution outcomes stated plainly.
- Keep Activity stable during background HA updates; add manual refresh and preserve expanded events and technical details across renders.

- Replace entity-history links with retained related activity, separating direct credential observations, credential-authenticated WebSocket connections, and user-attributed service calls with unknown credentials.
- Add an admin-only Activity tab with date/user filters, 50-row pagination, readable event descriptions, credential nicknames, structured results and retention/coverage information.
- Label regular refresh-token, system-token and long-lived access-token records using verified HA token-type values. Display recorded credential expiration separately from issued access-token lifetime.
- Extend audit/session search actions with credential and timezone-aware date filters; return summaries, pagination and coverage alongside existing structured records.

## [0.1.13]

- Reduced sensor update work by expanding only the displayed session window, indexing credential audit evidence once, and skipping detail generation for credential counts.

- Excluded bulky session, credential, IP-observation and login-event lists from Recorder snapshots to prevent oversized-attribute warnings and repeated database writes.
- Kept dashboard details and locally retained audit/session history available; sensor states and summary attributes continue recording.

Restart Core after updating. No dashboard YAML changes are required.

## [0.1.12]

- Added user display names alongside IDs in audit history, token inventory, session results and login events.
- Added live user dropdowns to Search audit history, Search sessions and Recognize credential or source. Raw IDs remain supported for automations.
- Preserved recorded names through account renames/deletions and added name-aware audit search.
- Added login and recognition event types to the audit filter.

Restart Core and refresh the Actions page after updating. Dashboard resource: `/ha_security/ha-security-card.js?v=0.1.12`.

## [0.1.11]

- Shortened the README around features, installation and the dashboard. Moved detailed configuration and troubleshooting to a separate reference.
- Added a dashboard screenshot using sample accounts and addresses.
- Fixed search losing focus during live updates; cursor/selection remain in place and composition input is preserved.
- Fixed user-entity reconciliation removing the integration-wide login sensors, which could leave dashboard login totals blank.

After updating, restart Home Assistant, update the JavaScript module resource to `/ha_security/ha-security-card.js?v=0.1.11`, and refresh the browser. Dashboard YAML is unchanged.

## [0.1.10]

- Added an original shield-and-home icon, with transparent standard/high-resolution and dark-mode assets bundled with the integration.
- Added automatic versioned GitHub releases after both Python test jobs and frontend checks pass on `main`.
- Added release metadata checks, matching dashboard resource versions and changelog notes. Repeated runs preserve existing releases and never move published tags.
- HACS now offers published versions rather than the development branch.

After updating, restart Home Assistant. For the security dashboard, update the JavaScript module resource to `/ha_security/ha-security-card.js?v=0.1.10` and refresh the browser. Existing dashboard YAML remains compatible.

Home Assistant 2026.3+ uses the bundled icon. HACS versions affected by upstream issue #5402 may still show their placeholder; the integration assets cannot fix that frontend issue.

## [0.1.9]

- Added optional login-outcome observation, per-user login entities and same-IP failure correlation.
- Added explainable security flags, a Login activity dashboard tab and explicit credential/source recognition.
- Included separate connection-source and credential-last-use IP context from v0.1.8.

Earlier versions were distributed from the default branch without published releases.
