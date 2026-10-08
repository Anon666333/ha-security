# Changelog

Published releases use `vMAJOR.MINOR.PATCH` tags matching the integration manifest.

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
