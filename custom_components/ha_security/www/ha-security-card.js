/* Entity-powered HA Security card. No external requests or dependencies. */
const CARD_VERSION = "0.1.23";
const esc = (value) => String(value ?? "Unknown").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const exact = value => value && !Number.isNaN(Date.parse(value)) ? new Date(value).toLocaleString(undefined, {timeZoneName: "short"}) : "Not observed";
const credentialType = value => ({normal:"Regular refresh-token record",system:"System token record",long_lived_access_token:"Long-lived access-token record"}[value] || `Unknown token type (${value || "unavailable"})`);
const expiry = value => value == null ? "Not available" : exact(typeof value === "number" ? new Date(value * 1000).toISOString() : value);
const ago = value => {
  if (!value || Number.isNaN(Date.parse(value))) return "Not observed";
  const seconds = Math.max(0, Math.floor((Date.now() - Date.parse(value)) / 1000));
  return seconds < 60 ? "Just now" : seconds < 3600 ? `${Math.floor(seconds / 60)} min ago` : seconds < 86400 ? `${Math.floor(seconds / 3600)} hr ago` : `${Math.floor(seconds / 86400)} days ago`;
};
const friendly = value => ({normal:"Normal",review:"Review",likely_issue:"Likely an issue",unknown:"Not assessed"}[value] || String(value || "unknown").replaceAll("_", " "));

// Reconcile by record/control identity. Keep native controls and details mounted.
const domKey = node => node.nodeType === 1 ? ["data-id","data-key","data-user","data-tab","data-mode"].map(key => node.hasAttribute(key) ? `${node.tagName}:${key}:${node.getAttribute(key)}` : "").find(Boolean) || (["INPUT","SELECT"].includes(node.tagName) ? `${node.tagName}:${[...node.attributes].filter(a=>a.name.startsWith("data-")).map(a=>a.name+"="+a.value).join(":")}` : null) : null;
const patchDOM = (current, next, active) => {
  if (current.nodeType !== next.nodeType || current.nodeName !== next.nodeName) {
    current.replaceWith(next.cloneNode(true)); return;
  }
  if (current.nodeType !== 1) { if (current.nodeValue !== next.nodeValue) current.nodeValue = next.nodeValue; return; }
  // A focused select's option list must not change while its native popup is open.
  if (current === active && ["INPUT","SELECT","TEXTAREA"].includes(current.tagName)) return;
  for (const attr of [...current.attributes]) {
    if (attr.name === "open" && current.tagName === "DETAILS") continue;
    if (!next.hasAttribute(attr.name)) current.removeAttribute(attr.name);
  }
  for (const attr of [...next.attributes]) {
    if (attr.name === "open" && current.tagName === "DETAILS") continue;
    if (current.getAttribute(attr.name) !== attr.value) current.setAttribute(attr.name,attr.value);
  }
  const old = [...current.childNodes];
  const used = new Set();
  const keepOrder = current.classList.contains("list") && !!current.querySelector("details[open]");
  let cursor = current.firstChild;
  for (const desired of [...next.childNodes]) {
    const key = domKey(desired);
    let match = key ? old.find(n=>!used.has(n) && domKey(n) === key) : old.find(n=>!used.has(n) && !domKey(n) && n.nodeType === desired.nodeType && n.nodeName === desired.nodeName);
    if (match) { used.add(match); patchDOM(match,desired,active); }
    else { match = desired.cloneNode(true); }
    if (keepOrder) { if (!match.parentNode) current.appendChild(match); }
    else { if (match !== cursor) current.insertBefore(match,cursor); cursor = match.nextSibling; }
  }
  for (const node of old) if (!used.has(node)) node.remove();
};

class HASecurityCard extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({mode: "open"});
    this.tab = "live";
    this.user = "all";
    this.query = "";
    this.filter = "all";
    this.openRows = new Map();
    this.hiddenCredentials = new Set();
    try { this.hiddenCredentials = new Set(JSON.parse(localStorage.getItem("ha-security-hidden-credentials") || "[]")); } catch {}
    this.credentialOptions = [];
    this.excludedActions = "";
    try { this.excludedActions = localStorage.getItem("ha-security-excluded-actions") ?? this.excludedActions; } catch {}
  }
  setConfig(config) {
    const changed = JSON.stringify(config) !== JSON.stringify(this.config);
    this.config = config;
    if (changed) this.render();
  }
  set hass(hass) {
    this._hass = hass;
    const states = Object.values(hass.states).filter(s => s.attributes.ha_security_metric);
    const signature = states.map(s => `${s.entity_id}:${s.last_updated}`).join("|");
    if (signature !== this.signature) {
      this.signature = signature;
      this.render(true);
    }
  }
  connectedCallback() {
    this.menuPositionHandler ||= () => this.positionCredentialMenu();
    window.addEventListener?.('resize',this.menuPositionHandler);
    window.addEventListener?.('scroll',this.menuPositionHandler,true);
    clearInterval(this.timer);
    this.timer = setInterval(() => {
      if (this.tab === "activity" && !this.activityLoading && !this.until && !(this.activityOffset > 0)) this.loadActivity(0, true);
      else this.render(true);
    }, 30000);
  }
  disconnectedCallback() {
    clearInterval(this.timer);
    window.removeEventListener?.('resize',this.menuPositionHandler);
    window.removeEventListener?.('scroll',this.menuPositionHandler,true);
  }
  getCardSize() { return 10; }
  getGridOptions() { return {columns: 12, rows: "auto"}; }
  entities(metric) { return Object.values(this._hass?.states || {}).filter(s => s.attributes.ha_security_metric === metric); }
  field(label, value) { return `<div><dt>${esc(label)}</dt><dd>${esc(value || "Unknown")}</dd></div>`; }
  moreInfo(entity) { this.dispatchEvent(new CustomEvent("hass-more-info", {detail: {entityId: entity}, bubbles: true, composed: true})); }
  openRelated(data) {
    this.related = {token_id:data.related || null,user_id:data.owner || null,session_id:data.session || null};
    // Date filters from an unrelated investigation must not silently hide this one.
    this.since = ""; this.until = ""; this.nativeContext = null;
    this.activityResult = null; this.tab = "activity"; this.activityMode = "actions";
    return this.loadActivity(0);
  }
  activityEmpty(result) {
    if (result.source === "ha_activity") return "No HA Activity entries match this user and time range. Recorder retention and filters apply; this is not evidence of no activity.";
    if (this.related && !this.related.token_id) return "The selected record has no captured credential ID. Credential-specific results cannot be retrieved. User history is separate and does not identify its token.";
    if (result.activity_api_version !== 2) return "This backend does not report the current activity API. Install the matching integration and dashboard together before interpreting empty credential results.";
    const scope = result.credential_scope;
    if (scope && !scope.known) return "The selected credential ID is not present in the current inventory or retained observations/connections for this user. This is an unmatched credential, not a confirmed absence of activity.";
    if (this.since || this.until) return "No matching records in this date range. Clear the date filters to inspect all retained records.";
    if (this.activityOffset > 0) return "No records remain on this page. Return to the first page.";
    if (this.activityMode === "actions") return (result.websocket_action_status === "observing" || result.rest_action_status === "observing") ? "No matching REST requests or WebSocket service commands have been captured for this selection yet. Only commands observed after enabling this version are available; older user history cannot supply their token." : "Credential action collection is not observing. Enable WebSocket session tracking and check the diagnostic above. An empty result does not mean this credential was unused.";
    if (this.activityMode === "connections") return "No retained connections match this credential. If you opened this from a live connection, check the credential matching information below; missing records are not evidence that it never connected.";
    return "No retained credential inventory changes match this selection. This section contains first observations, metadata changes and removals—not an action history.";
  }
  async loadActivity(offset = 0, background = false) {
    const previousResult = this.activityResult;
    const request = this.activityRequest = (this.activityRequest || 0) + 1;
    this.activityOffset = offset;
    this.activityLoading = true;
    this.activityError = null;
    const data = {offset, limit: 50};
    const uid = this.related?.user_id || this.activityUser || (this.user !== "all" ? this.user : null);
    if (uid) data.user_id = uid;
    if (this.related?.token_id && this.activityMode !== 'user') data.token_id = this.related.token_id;
    if (this.activityMode === 'actions') { data.category = 'actions'; data.exclude_actions = (this.excludedActions || '').split(',').map(v=>v.trim()).filter(Boolean); }
    if (!["user","context"].includes(this.activityMode)) data.exclude_token_ids = [...this.hiddenCredentials];
    if (this.activityMode === 'direct') data.category = 'inventory';
    if (this.since) data.since = new Date(this.since).toISOString();
    if (this.until) data.until = new Date(this.until).toISOString();
    const scopeKey = JSON.stringify([this.activityMode,data,this.nativeContext?.id]);
    if (scopeKey !== this.resultScope) this.activityResult = null;
    this.resultScope = scopeKey;
    if (!background) this.render();
    try {
      if (this.related && !this.related.token_id && !["user","context"].includes(this.activityMode)) {
        this.activityResult = {records:[],total:0,activity_api_version:2};
        this.activityLoading = false; this.render(background); return;
      }
      let result;
      if (this.activityMode === 'user' || this.activityMode === 'context') {
        const actionTime = this.activityMode === 'context' ? this.nativeContext?.timestamp : null;
        const end = data.until || (offset > 0 && this.nativeWindowEnd ? this.nativeWindowEnd : new Date(actionTime ? Math.min(Date.now(),Date.parse(actionTime)+300000) : Date.now()).toISOString());
        const start = data.since || new Date(actionTime ? Date.parse(actionTime)-60000 : Date.parse(end)-86400000).toISOString();
        this.nativeWindowEnd = end;
        if (Date.parse(end) < Date.parse(start) || Date.parse(end)-Date.parse(start) > 86400000) throw new Error('Choose a HA Activity range of up to 24 hours');
        const query = {type:'logbook/get_events',start_time:start,end_time:end};
        if (this.activityMode === 'context' && this.nativeContext?.id) query.context_id = this.nativeContext.id;
        const events = await this._hass.callWS(query);
        const filtered = events.filter(row => this.activityMode === 'context' || !data.user_id || row.context_user_id === data.user_id);
        const rows = filtered.map((row,index)=>({...row,id:`native-${JSON.stringify([row.when,row.entity_id,row.domain,row.state,row.message,row.context_user_id])}`,kind:'ha_activity',user_id:row.context_user_id,user_name:this.entities('refresh_tokens').find(e=>e.attributes.user_id === row.context_user_id)?.attributes.user_name || 'Unknown user',timestamp:typeof row.when === 'number' ? new Date(row.when*1000).toISOString() : row.when})).reverse();
        result = {records:rows.slice(offset,offset+50),total:rows.length,next_offset:offset+50 < rows.length ? offset+50 : null,summary:`Showing ${Math.min(50,Math.max(0,rows.length-offset))} of ${rows.length} HA Activity entries`,source:'ha_activity',coverage:{limitations:this.activityMode === 'context' ? 'HA Activity queried by the recorded action context ID. Related history is contextual evidence, not proof that a device executed the command.' : 'From HA Activity/Recorder. User attribution comes from HA context; specific credential unknown. Recorder filters and retention apply.',start_time:start,end_time:end}};
      } else result = await this._hass.callWS({type:'call_service',domain:'ha_security',service:this.activityMode === 'connections' ? 'query_sessions' : 'query_audit',service_data:data,return_response:true});
      if (request !== this.activityRequest) return;
      this.activityResult = result.response || result;
      if (this.activityResult.credential_options) this.credentialOptions = this.activityResult.credential_options;
      if (background) {
        const field = this.activityResult.records ? "records" : "sessions";
        const updated = this.activityResult[field] || [];
        const open = new Set([...this.shadowRoot.querySelectorAll("details[open]")].map(el=>el.dataset.id));
        for (const row of previousResult?.[field] || []) {
          const id = row.id || row.session_id;
          if (!this.hiddenCredentials.has(row.token_id || row.metadata?.token_id) && open.has(`activity-${id}`) && !updated.some(r=>(r.id || r.session_id) === id)) updated.push({...row,retained_while_open:true});
        }
      }
    } catch (error) { if (request !== this.activityRequest) return; this.activityError = error.message || String(error); }
    this.activityLoading = false;
    this.render(background);
  }
  activityRow(row, opened) {
    const key = `activity-${row.id || row.session_id}`;
    const metadata = row.metadata || {};
    const tid = row.token_id || metadata.token_id;
    const websocketAction = ["websocket_action", "rest_action"].includes(row.kind);
    const restRead = row.kind === "rest_request";
    const native = row.kind === "ha_activity";
    const serviceCall = row.kind === "service_call";
    const session = !row.kind && !!row.session_id;
    const names = {baseline_initialized:"Initial inventory recorded",token_baseline:"Existing credential first observed",new_token:"New credential observed",token_updated:"Credential metadata updated",token_removed:"Credential removal observed",new_ip:"New credential address observed",new_client:"New client observed",login_success:"Successful login",login_failure:"Failed login attempt",recognition_changed:"Recognition updated"};
    const serviceNames = {query_audit:"Audit history searched",query_sessions:"Connection history searched",get_inventory:"Credential inventory viewed",scan_now:"Credential inventory refreshed",set_token_label:"Credential nickname changed",recognize_source:"Credential or address recognition changed"};
    const action = `${row.domain || "unknown"}.${row.service || "unknown"}`;
    const title = restRead ? `${row.user_name || "Unknown user"} read ${row.request_label || row.endpoint} (HTTP ${row.http_status})` : native ? `${row.user_name || "Unknown user"}: ${row.name || row.entity_id || "Activity"} ${row.message || (row.state !== undefined ? `changed to ${row.state}` : "event recorded")}` : websocketAction ? `${row.user_name || "Unknown user"} submitted ${action}` : serviceCall ? (row.domain === "ha_security" ? serviceNames[row.service] || `HA Security action: ${friendly(row.service)}` : `Service called: ${action}`) : session ? `WebSocket connection ${friendly(row.state || "state unavailable")}` : row.description || names[row.kind] || `Recorded event: ${friendly(row.kind)}`;
    const label = row.credential_label || row.label || metadata.client_name || metadata.client_id;
    const attribution = restRead ? "Directly linked to the authenticated REST credential. HTTP status describes the response; response contents are not retained." : native ? "History supplied by Home Assistant Activity. User attribution follows HA context; the specific credential is unknown." : websocketAction ? "Directly linked to the authenticated credential when HA created this service command context. Execution outcome is not recorded." : serviceCall ? "Home Assistant attributed this service invocation to the user. The specific credential and connection are unknown. Execution outcome was not recorded." : session ? "This WebSocket connection authenticated with the recorded credential. User service calls are not attributed to this connection." : tid ? "This observation is directly linked to the recorded credential ID. It does not identify every request made with that credential." : "This observation does not identify a specific credential or connection.";
    const fields = [this.field("Recorded at",exact(row.timestamp || row.first_observed_at)),this.field("User",row.user_name || "Unknown user")];
    if (row.source_ip) fields.push(this.field("HTTP source IP (HA resolved)",row.source_ip));
    if (restRead) {
      fields.push(this.field("Credential",label || "Unnamed credential"),this.field("Transport","REST (HTTP)"),this.field("Request",`${row.method} ${row.endpoint}`),this.field("HTTP status",row.http_status),this.field("Target entities",row.entity_ids?.join(", ") || "Not applicable"));
    } else if (native) {
      fields.push(this.field("Entity",row.entity_id || "Not specified"),this.field("Activity",row.message || row.state || "Event recorded"),this.field("Source","Home Assistant Activity / Recorder"),this.field("Specific credential","Unknown"));
    } else if (websocketAction) {
      fields.push(this.field("Action",action),this.field("Credential",label || "Unnamed credential"),this.field("Credential record ID",tid),this.field("Transport",row.transport === "rest" ? "REST (HTTP)" : "WebSocket"),...(row.session_id ? [this.field("Connection ID",row.session_id)] : []),this.field("Invocation",row.invocation_observed ? "Service invocation observed" : "Command context observed; invocation not confirmed"),this.field("Target entities",row.entity_ids?.length ? row.entity_ids.join(", ") : "No explicit entity targets recorded"),this.field("Execution outcome","Not recorded"));
    } else if (serviceCall) {
      fields.push(this.field("Action",action),this.field("Target entities",row.entity_ids?.length ? row.entity_ids.join(", ") : "No entity targets recorded"),this.field("Specific credential","Unknown"),this.field("Execution outcome","Not recorded"));
    } else {
      if (tid) fields.push(this.field("Credential",label || "Unnamed credential"),this.field("Credential record ID",tid));
      if (session) fields.push(this.field("Connection ID",row.session_id),this.field("State",friendly(row.state)),this.field("Connected at",exact(row.connected_at)),this.field("Last incoming command",exact(row.last_seen_at)),this.field("Observation ended",exact(row.ended_at || row.closed_at)));
      if (metadata.last_used_at) fields.push(this.field("Last recorded token use",exact(metadata.last_used_at)));
      if (metadata.last_used_ip || row.source_ip) fields.push(this.field("Recorded address",row.source_ip || metadata.last_used_ip));
      if (row.value) fields.push(this.field("Observed value",row.value));
      if (row.security_reasons?.length) fields.push(this.field("Assessment reasons",row.security_reasons.join("; ")));
      if (row.recognized !== undefined) fields.push(this.field("Recognition",row.recognized ? "Recognized" : "Recognition removed"));
    }
    return `<details data-id="${esc(key)}" ${opened.has(key) ? "open" : ""}><summary><div><b>${esc(title)}</b><small>${esc([row.user_name || "Unknown user",label,exact(row.timestamp || row.first_observed_at)].filter(Boolean).join(" · "))}</small></div></summary><div class="detail"><p>${esc(attribution)}</p>${row.retained_while_open ? "<p>This record left the current result page. Its last loaded details remain while open.</p>" : ""}<dl>${fields.join("")}</dl><details data-id="${esc(key)}-raw" ${opened.has(`${key}-raw`) ? "open" : ""}><summary>Technical details (structured result)</summary><pre>${esc(JSON.stringify(row,null,2))}</pre></details>${websocketAction && row.context_id ? `<button data-native-context="${esc(row.context_id)}" data-action-time="${esc(row.timestamp)}">Related HA activity</button>` : ""}${tid ? `<button data-related="${esc(tid)}" data-owner="${esc(row.user_id || "")}" data-session="${esc(row.session_id || "")}">View related activity</button>` : ""}</div></details>`;
  }
  positionCredentialMenu() {
    const dropdown = this.shadowRoot.querySelector('[data-id="credential-filter"]');
    if (!dropdown?.open) return;
    const summary = dropdown.querySelector('summary');
    const menu = dropdown.querySelector('[role="group"]');
    const rect = summary?.getBoundingClientRect?.();
    if (!rect || !menu || !window.innerWidth) return;
    const width = Math.min(560, window.innerWidth - 32);
    const left = Math.max(16, Math.min(rect.right - width, window.innerWidth - width - 16));
    const below = window.innerHeight - rect.bottom - 24;
    const above = rect.top - 24;
    const upwards = below < 240 && above > below;
    Object.assign(menu.style,{position:'fixed',right:'auto',left:`${left}px`,width:`${width}px`,
      top:upwards ? 'auto' : `${rect.bottom+8}px`, bottom:upwards ? `${window.innerHeight-rect.top+8}px` : 'auto',
      maxHeight:`${Math.max(80,upwards ? above : below)}px`,overflowY:'auto'});
  }
  credentialFilter() {
    const uid = this.related?.user_id || this.activityUser || (this.user !== "all" ? this.user : null);
    const options = this.credentialOptions.filter(row=>!uid || row.user_id === uid);
    const hidden = options.filter(row=>this.hiddenCredentials.has(row.token_id)).length;
    return `<details class="credential-filter" data-id="credential-filter" style="position:relative;display:inline-block;overflow:visible"><summary>Credentials · ${hidden} hidden</summary><div role="group" aria-label="Visible credentials" style="position:absolute;z-index:5;right:0;box-sizing:border-box;width:min(560px,calc(100vw - 48px));max-width:calc(100vw - 48px);background:var(--ha-card-background,var(--card-background-color));border:1px solid var(--divider-color);border-radius:12px;padding:12px;box-shadow:0 4px 16px #0006"><p>Checked credentials are shown. Uncheck a noisy credential to hide its retained activity.</p><button data-show-credentials>Show all credentials</button><div style="max-height:min(400px,60vh);overflow:auto">${options.map(row=>`<label style="display:block;padding:8px" data-key="credential-choice-${esc(row.token_id)}"><input type="checkbox" data-credential-choice="${esc(row.token_id)}" ${this.hiddenCredentials.has(row.token_id) ? "" : "checked"}> ${esc(row.label)} · ${esc(credentialType(row.token_type))}${uid ? "" : ` · ${esc(row.user_name)}`}</label>`).join("") || "No credential inventory loaded for this user."}</div></div></details>`;
  }
  activityPanel(opened) {
    const result = this.activityResult;
    const allRows = result?.records || result?.sessions || [];
    const rows = ["user","context"].includes(this.activityMode) ? allRows : allRows.filter(row=>!this.hiddenCredentials.has(row.token_id || row.metadata?.token_id));
    const next = result?.next_offset ?? ((this.activityOffset || 0) + rows.length < result?.total ? (this.activityOffset || 0) + 50 : null);
    return `<h2>${this.related ? "Related activity" : "Retained activity"}</h2><p>Dashboard ${CARD_VERSION} · Backend ${esc(result?.integration_version || (result?.source === "ha_activity" ? "HA native history" : "not reported"))}</p>${this.related?.token_id ? `<p>Selected credential record: ${esc(this.related.token_id)}</p>` : ""}${result?.credential_scope ? `<p>Credential match: ${result.credential_scope.known ? "Found" : "Not found"} · ${esc(result.credential_scope.retained_observations)} retained observations · ${esc(result.credential_scope.retained_connections)} connections · ${esc(result.credential_scope.retained_actions)} captured actions/requests (before filters)</p>` : ""}${this.related?.session_id ? `<p>Selected connection: ${esc(this.related.session_id)}. Credential observations may include other connections.</p>` : ""}
      <p class="note">${esc(this.activityMode === "direct" ? "Credential metadata/IP changes, first observations, removal, and observed diagnostic log writes. Device service commands and login events are excluded." : this.activityMode === "user" ? "Broader user history from Home Assistant: includes activity from all of this user's credentials and connections. It does not identify the specific token." : this.activityMode === "connections" ? "Observed WebSocket connection lifecycles authenticated with this credential; not a list of actions." : this.activityMode === "context" ? "Home Assistant history related to the recorded command context; not a separate list of credential commands." : "Service commands and supported REST reads directly attributed to the credential. Diagnostic log writes are grouped with inventory observations. Submission and invocation do not prove device execution.")}</p>
      <div class="actions">${[["actions","Credential actions"],["direct","Inventory & diagnostics"],["connections",this.related?.token_id ? "Authenticated connections" : "WebSocket connections"],["user","User activity · HA history"]].map(([id,label])=>`<button data-mode="${id}" class="${(this.activityMode || "direct") === id ? "active" : ""}">${label}</button>`).join("")}<button data-refresh-activity>Refresh activity</button></div>
      ${this.activityMode === "actions" ? `<p>Coverage: core REST service POSTs and, when session tracking is enabled, WebSocket service calls. Core GETs for status, states, config, services, events and components are also covered. Other endpoints and execution outcomes are not covered.</p>${result ? `<p>REST GET observation: ${esc(result.rest_read_status || "not reported")}. REST service observation: ${esc(result.rest_action_status || "not reported by this backend")}. ${esc(result.rest_action_reason || "")}</p>` : ""}${result && result.websocket_action_status !== "observing" ? `<p class="note">Action observation: ${esc(result.websocket_action_status || "not reported by this backend")}. ${esc(result.websocket_action_reason || "Enable WebSocket tracking and use the matching backend version.")}</p>` : ""}` : ""}${this.activityLoading ? "<p>Loading activity…</p>" : ""}<p>New activity updates every 30 seconds on the first page. Open records stay in place. Historical date ranges and later pages stay fixed.</p>
      ${this.activityMode === "actions" ? `<label>Hide actions (comma-separated, * matches any text)<input data-exclude-actions value="${esc(this.excludedActions || "")}" placeholder="system_log.write, todo.get_items, GET /api/states*"></label><p>View filter only; records remain retained. Clear this field to show all non-diagnostic actions.</p>` : ""}
      <div class="controls activity-filters" style="align-items:end"><div class="date-filters" style="display:flex;flex-wrap:wrap;gap:12px"><label>From (local time)<input type="datetime-local" data-date="since" value="${esc(this.since || "")}"></label><label>Through (local time)<input type="datetime-local" data-date="until" value="${esc(this.until || "")}"></label></div><div class="identity-filters" style="display:flex;align-items:end;gap:12px;flex-wrap:wrap"><select data-activity-user aria-label="Activity user" ${this.related ? "disabled" : ""}><option value="">All users</option>${this.entities("refresh_tokens").map(a=>`<option value="${esc(a.attributes.user_id)}" ${a.attributes.user_id === (this.related?.user_id || this.activityUser) ? "selected" : ""}>${esc(a.attributes.user_name)}</option>`).join("")}</select>${!["user","context"].includes(this.activityMode) ? this.credentialFilter() : ""}</div></div>
      ${["user","context"].includes(this.activityMode) ? "<p>Credential exclusions do not apply to HA user history, where the specific credential is unknown.</p>" : ""}
      ${this.activityError ? `<p role="alert">Could not load activity: ${esc(this.activityError)}. Administrator access required. Check that dashboard and backend versions match.</p>` : !result ? "<p>Loading retained activity…</p>" : `<p>${esc(result.summary || `Showing ${rows.length} of ${result.total ?? rows.length} matching retained observations`)}</p><p>${esc(result.coverage?.limitations || "Retained observations only. Service calls identify a user, not a credential or connection. Token timestamps do not cover every REST request.")}</p>${result.source === "ha_activity" ? `<p>History window: ${esc(exact(result.coverage.start_time))} to ${esc(exact(result.coverage.end_time))}</p>` : result.coverage ? `<p>Retention: ${esc(result.coverage.retention_days)} days · Audit cap: ${esc(result.coverage.audit_limit)} · Oldest retained audit observation: ${esc(exact(result.coverage.oldest_retained_at))}</p>` : "<p>Detailed retention coverage is unavailable from this backend response.</p>"}<div class="list">${rows.map(row=>this.activityRow(row,opened)).join("") || `<p class="note">${esc(this.activityEmpty(result))}</p>`}</div><div class="actions">${this.activityOffset > 0 ? `<button data-page="${Math.max(0,this.activityOffset-50)}">Previous</button>` : ""}${next != null ? `<button data-page="${next}">Next</button>` : ""}</div>`}`;
  }
  render(background = false) {
    if (!this._hass || this.composing) return;
    const activeSearch = this.shadowRoot.activeElement;
    const searchSelection = activeSearch?.matches?.("[data-search]") ? {
      start: activeSearch.selectionStart, end: activeSearch.selectionEnd,
      direction: activeSearch.selectionDirection,
    } : null;
    if (this.renderedTab) {
      this.openRows.set(this.renderedTab, new Set([...this.shadowRoot.querySelectorAll("details[open]")].map(el => el.dataset.id)));
    }
    const opened = this.openRows.get(this.tab) || new Set();
    const accounts = this.entities("refresh_tokens");
    const overview = this.entities("overview")[0];
    const stats = overview?.attributes || {};
    const observing = stats.tracking_status === "observing";
    const riskEntities = this.entities("security_status");
    const loginOverview = this.entities("global_successful_logins_24h")[0];
    const loginStats = loginOverview?.attributes || {};
    const sessionEntities = this.entities("active_websocket_connections");
    const credentialEntities = this.entities("recently_used_tokens");
    let rows = [];
    const sources = this.tab === "logins" ? (this.user === "all" ? [loginOverview].filter(Boolean) : riskEntities.filter(e => e.attributes.user_id === this.user)) : this.tab === "credentials" ? credentialEntities : sessionEntities;
    for (const entity of sources) {
      const attributes = entity.attributes;
      const values = this.tab === "logins" ? attributes.login_events || [] : this.tab === "credentials" ? attributes.connections || [] : this.tab === "history" ? attributes.session_history || [] : attributes.active_connections || [];
      rows.push(...values.map(row => ({...row, user_id: row.user_id || attributes.user_id, user_name: accounts.find(a => a.attributes.user_id === (row.user_id || attributes.user_id))?.attributes.user_name || "Unknown user", entity_id: entity.entity_id})));
    }
    if (this.tab === "activity") rows = [];
    rows = rows.filter(row => (this.user === "all" || row.user_id === this.user) &&
      (!this.query || JSON.stringify(row).toLowerCase().includes(this.query.toLowerCase())) &&
      (this.filter === "all" || (this.filter === "changes" ? row.new_ip || row.new_credential || row.ip_changed : row.state === this.filter || row.activity === this.filter || row.security_level === this.filter || row.kind === this.filter)));
    const activityTime = row => this.tab === "credentials" ? row.last_observed_use_at || row.last_used_at || "" : row.timestamp || row.first_observed_at || row.created_at || "";
    rows.sort((a,b) => String(activityTime(b)).localeCompare(String(activityTime(a))));
    if (background && this.renderedTab === this.tab && this.tab !== "activity") {
      for (const previous of this.displayedRows || []) {
        const id = previous.session_id || previous.token_id || previous.id;
        if (!opened.has(id) || rows.some(r=>(r.session_id || r.token_id || r.id) === id)) continue;
        const ended = this.tab === "live" ? sessionEntities.flatMap(e=>e.attributes.session_history || []).find(r=>r.session_id === previous.session_id) : null;
        rows.push({...previous,...ended,...(this.tab === "live" ? {state:ended?.state || "no_longer_observed"} : {}),retained_while_open:true});
      }
    }
    this.displayedRows = rows;
    const count = value => value === null || value === undefined ? "—" : esc(value);
    const markup = `<style>
      :host{display:block}ha-card{overflow:visible;background:var(--ha-card-background,var(--card-background-color));border-radius:20px}
      .shell{padding:24px;color:var(--primary-text-color);font-family:var(--paper-font-body1_-_font-family,system-ui)}
      header{display:flex;justify-content:space-between;gap:12px;align-items:center}h1{font-size:25px;margin:0 0 6px;letter-spacing:-.5px}h2{font-size:16px;margin:24px 0 12px}p{margin:4px 0;font-size:13px;line-height:1.5;color:var(--secondary-text-color)}
      .badge{font-size:12px;padding:7px 10px;border-radius:20px;background:var(--secondary-background-color);white-space:nowrap}.review{color:var(--warning-color,#b26a00)}.likely_issue{color:var(--error-color,#db4437)}.normal,.good{color:var(--success-color,#388e3c)}
      .stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:22px 0}.stat{padding:16px;border-radius:14px;background:var(--secondary-background-color)}.stat strong{display:block;font-size:28px;margin-bottom:5px}.stat span{font-size:12px;color:var(--secondary-text-color)}
      .users{display:flex;gap:10px;overflow-x:auto;padding:2px 0 10px}.account{min-width:150px;text-align:left;border:1px solid var(--divider-color);border-radius:12px;padding:12px}.account b{display:block;margin-bottom:10px}.account>.badge{display:inline-block;margin-bottom:10px}.websocket-count{display:block;margin-top:4px}.account small{display:block;color:var(--secondary-text-color);margin-top:5px}
      button,input,select{font:inherit;color:var(--primary-text-color);background:var(--card-background-color);border:1px solid var(--divider-color);border-radius:10px;padding:10px;cursor:pointer}button:hover{border-color:var(--primary-color)}button.active{border-color:var(--primary-color);background:var(--secondary-background-color);color:var(--primary-color)}
      .tabs{display:flex;gap:8px;margin:18px 0 12px}.tabs button{flex:1;font-weight:600}.controls{display:grid;grid-template-columns:2fr 1fr 1fr;gap:8px;margin-bottom:14px}input{min-width:0;cursor:text}select{min-width:0}
      pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px} .list{display:grid;gap:10px}details{border:1px solid var(--divider-color);border-radius:12px;overflow:hidden}summary{cursor:pointer;list-style:none;padding:15px;display:grid;grid-template-columns:1fr auto;gap:12px;align-items:center}summary::-webkit-details-marker{display:none}summary b{font-size:15px}summary small{display:block;color:var(--secondary-text-color);margin-top:5px}summary .right{text-align:right;font-size:12px}summary:hover{background:var(--secondary-background-color)}
      .credential-filter>summary{padding:10px;white-space:nowrap}.credential-filter>summary::after{content:"▾"}.credential-filter[open]>summary::after{content:"▴"}.activity-filters{grid-template-columns:minmax(0,1fr) auto}.llt-usage{display:block;margin-top:8px;padding:6px 8px;border-radius:8px;background:var(--secondary-background-color);font-size:12px}.llt-usage strong{color:var(--primary-color)}.llt-window{font-size:11px;color:var(--secondary-text-color)}
      .detail{border-top:1px solid var(--divider-color);padding:16px}.detail dl{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:0 0 16px}dt{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--secondary-text-color);margin-bottom:5px}dd{margin:0;font-size:13px;overflow-wrap:anywhere}.markers{font-size:11px;color:var(--warning-color,#b26a00);margin-top:6px}.empty{padding:26px;text-align:center;border:1px dashed var(--divider-color);border-radius:12px}.foot{margin-top:18px;font-size:12px}.timeline{border-left:2px solid var(--divider-color);padding-left:12px;margin:12px 0}.timeline p{margin:12px 0}.actions{display:flex;gap:8px;flex-wrap:wrap}.note{padding:12px;background:var(--secondary-background-color);border-radius:10px;margin:12px 0}
      @media(max-width:600px){.shell{padding:16px}.stats{grid-template-columns:repeat(2,1fr)}header{align-items:flex-start;flex-direction:column}.controls{grid-template-columns:1fr 1fr}.controls input{grid-column:1/-1}.activity-filters{grid-template-columns:1fr}.detail dl{grid-template-columns:1fr}.tabs button{padding:10px 6px;font-size:12px}}
    </style><ha-card><div class="shell">
      <div class="actions"><button data-refresh-dashboard>Refresh dashboard</button><p>Live updates · your open details stay in place</p></div><header><div><h1>${esc(this.config?.title || "Security centre")}</h1><p>Connections, account activity and retained history</p></div><span class="badge ${observing ? "good" : ""}">${observing ? "● Observing WebSockets" : esc(friendly(stats.tracking_status || "No integration data"))}</span></header>
      <div class="stats"><div class="stat"><strong>${count(stats.connected_websockets)}</strong><span>Observed open connections</span></div><div class="stat"><strong>${count(stats.recently_observed_users)}</strong><span>Recently observed users</span></div><div class="stat"><strong>${count(stats.retained_sessions)}</strong><span>Retained ended sessions</span></div><div class="stat"><strong>${count(stats.new_observations)}</strong><span>Changes in retained audit</span></div></div>
      ${stats.tracking_reason ? `<p class="note">Tracking diagnostic: ${esc(stats.tracking_reason)}</p>` : ""}
      ${!observing ? '<p class="note">Enable <b>Observe WebSocket sessions</b> in HA Security options. Disabled or unsupported tracking is not a zero-session result.</p>' : '<p>Coverage starts when tracking is enabled. Reconnect existing clients for coverage. HTTP and cloud requests are outside this connection count.</p>'}
      <h2>Login security</h2><p class="note">${stats.login_tracking_status === "observing" ? `Observed in the past 24 hours: <b>${count(loginStats.successful_logins_24h)}</b> successes · <b>${count(loginStats.failed_login_attempts_24h)}</b> failed password/MFA attempts · <span class="badge ${esc(loginStats.security_status)}">${esc(friendly(loginStats.security_status))}</span><br>Failures usually have no confirmed user. Same-IP correlation can include other people on a shared connection. Observation started ${esc(exact(stats.login_tracking_started_at))}; token refreshes are excluded.<br>${esc((loginStats.security_reasons || []).join("; "))}` : `Enable <b>Observe login outcomes</b> in HA Security options. Login assessment is unavailable while observation is ${esc(stats.login_tracking_status || "disabled")}. ${esc(stats.login_tracking_reason || "")}`}</p>
      <h2>Users <small>· select to filter</small></h2><div class="users"><button class="account ${this.user === "all" ? "active" : ""}" data-user="all"><b>All users</b><small>${accounts.length} discovered accounts</small></button>${accounts.map(account => {
        const a = account.attributes;
        const risk = riskEntities.find(s => s.attributes.user_id === a.user_id);
        const sessions = sessionEntities.find(s => s.attributes.user_id === a.user_id);
        return `<button class="account ${this.user === a.user_id ? "active" : ""}" data-user="${esc(a.user_id)}"><b>${esc(a.user_name)}</b><span class="badge ${esc(risk?.state || "unknown")}">${esc(friendly(risk?.state === "unavailable" ? "unknown" : risk?.state))}</span><span class="websocket-count">${sessions?.state === "unavailable" || !observing ? "—" : esc(sessions?.state ?? "—")} WebSocket connections</span><span class="llt-usage" title="Distinct long-lived credentials with directly observed REST reads or REST/WebSocket service commands in this window. Retained observations only; not open connections."><strong>${a.recent_llt_token_count == null ? "—" : esc(a.recent_llt_token_count)}</strong> recent LLT tokens <span class="llt-window">· last ${esc(a.recent_window_minutes ?? 15)} min</span></span><small>${a.recently_observed ? "Recently observed" : "No recent activity"}${a.system_generated ? " · System" : ""}${a.is_active === false ? " · Disabled account" : ""}</small></button>`;
      }).join("")}</div>
      <div class="tabs" role="tablist">${[["live","Live connections"],["history","Session history"],["credentials","Credentials"],["logins","Login activity"],["activity","Activity"]].map(([id,label]) => `<button role="tab" aria-selected="${this.tab === id}" class="${this.tab === id ? "active" : ""}" data-tab="${id}">${label}</button>`).join("")}</div>
      <div class="controls"><input data-search aria-label="Search sessions" placeholder="Search client, IP, hostname, organisation…" value="${esc(this.query)}"><select data-select-user aria-label="Filter user"><option value="all">All users</option>${accounts.map(a => `<option value="${esc(a.attributes.user_id)}" ${this.user === a.attributes.user_id ? "selected" : ""}>${esc(a.attributes.user_name)}</option>`).join("")}</select><select data-filter aria-label="Filter status"><option value="all">All statuses</option>${(this.tab === "logins" ? ["login_success","login_failure","normal","review","likely_issue"] : this.tab === "credentials" ? ["recently_used","outside_window","removed","expired","changes"] : this.tab === "history" ? ["closed","interrupted"] : ["connected"]).map(s => `<option value="${s}" ${this.filter === s ? "selected" : ""}>${esc(friendly(s))}</option>`).join("")}</select></div>
      ${this.tab === "activity" ? this.activityPanel(opened) : ""}
      <p ${this.tab === "activity" ? "hidden" : ""}>${rows.length} displayed ${this.tab === "logins" ? "login events" : this.tab === "credentials" ? "credentials" : "connections"} · Expand a row for details</p><div class="list" ${this.tab === "activity" ? "hidden" : ""}>${rows.map(row => this.tab === "logins" ? this.loginRow(row, opened) : this.row(row, credentialEntities, opened)).join("") || `<div class="empty"><b>${this.query || this.filter !== "all" || this.user !== "all" ? "No matching results" : this.tab === "live" ? "No open connections observed" : "No retained records yet"}</b><p>${this.tab === "live" ? "Reconnect a browser/app after enabling tracking to observe its full lifecycle." : "History begins with observations made by this integration."}</p></div>`}</div>
      <p class="foot">Dashboard ${CARD_VERSION} · Last inventory scan: ${esc(ago(stats.last_successful_scan))}. Last seen means an incoming WebSocket command, not human activity. Start time means connection establishment, not necessarily a password login. IP location is approximate.</p>
      ${sources.some(s => s.attributes.sessions_truncated || s.attributes.connections_truncated || s.attributes.login_events_truncated) ? '<p class="note">Entity lists are capped at 100 rows per user. Use HA Security: Search sessions or Search audit for additional retained history.</p>' : ""}
    </div></ha-card>`;
    const doc = this.ownerDocument;
    if (this.rendered && this.renderedTab === this.tab && doc) {
      const template = doc.createElement("template"); template.innerHTML = markup;
      const anchor = this.shadowRoot.querySelector("details[open]");
      const top = anchor?.getBoundingClientRect?.().top;
      let scrollParent = anchor;
      while (scrollParent && !(scrollParent.scrollHeight > scrollParent.clientHeight)) scrollParent = scrollParent.parentElement || scrollParent.getRootNode?.().host;
      scrollParent ||= doc.scrollingElement;
      // The shadow root itself has no attributes; reconcile its stable top-level nodes.
      const old = [...this.shadowRoot.childNodes];
      [...template.content.childNodes].forEach((node,index)=>old[index] ? patchDOM(old[index],node,activeSearch) : this.shadowRoot.appendChild(node.cloneNode(true)));
      old.slice(template.content.childNodes.length).forEach(node=>node.remove());
      if (anchor?.isConnected && scrollParent && Number.isFinite(top)) scrollParent.scrollTop += anchor.getBoundingClientRect().top - top;
    } else this.shadowRoot.innerHTML = markup;
    this.rendered = true;
    this.renderedTab = this.tab;
    this.shadowRoot.querySelectorAll("[data-refresh-dashboard]").forEach(el => el.onclick = () => {
      if (this.tab === "activity") this.loadActivity(this.activityOffset || 0);
      else this.render();
    });
    this.shadowRoot.querySelectorAll("[data-tab]").forEach(el => el.onclick = () => {this.tab = el.dataset.tab; this.filter = "all"; if (this.tab === "activity") {this.related = null; this.activityMode = "actions"; this.loadActivity(0);} this.render();});
    this.shadowRoot.querySelectorAll("[data-user]").forEach(el => el.onclick = () => {this.user = el.dataset.user; if (this.tab === "activity") {this.related=null; this.activityUser=this.user === "all" ? "" : this.user; this.loadActivity(0);} else this.render();});
    this.shadowRoot.querySelector("[data-select-user]").onchange = event => {this.user = event.target.value; if (this.tab === "activity") {this.related=null; this.activityUser=this.user === "all" ? "" : this.user; this.loadActivity(0);} else this.render();};
    const userSelect = this.shadowRoot.querySelector("[data-select-user]");
    if (userSelect !== activeSearch && userSelect.value !== this.user) userSelect.value = this.user;
    this.shadowRoot.querySelector("[data-filter]").onchange = event => {this.filter = event.target.value; this.render();};
    const search = this.shadowRoot.querySelector("[data-search]");
    search.oninput = event => {this.query = event.target.value; this.render();};
    search.oncompositionstart = () => {this.composing = true;};
    search.oncompositionend = event => {this.composing = false; this.query = event.target.value; this.render();};
    if (searchSelection) {
      search.focus({preventScroll: true});
      search.setSelectionRange(searchSelection.start, searchSelection.end, searchSelection.direction);
    }
    this.shadowRoot.querySelectorAll("[data-related]").forEach(el => el.onclick = () => {this.openRelated(el.dataset);});
    this.shadowRoot.querySelectorAll("[data-native-context]").forEach(el => el.onclick = () => {this.nativeContext={id:el.dataset.nativeContext,timestamp:el.dataset.actionTime}; this.activityMode="context"; this.loadActivity(0);});
    this.shadowRoot.querySelectorAll("[data-refresh-activity]").forEach(el => el.onclick = () => this.loadActivity(this.activityOffset || 0));
    this.shadowRoot.querySelectorAll("[data-exclude-actions]").forEach(el => el.onchange = () => {this.excludedActions=el.value; try {localStorage.setItem("ha-security-excluded-actions",el.value);} catch {} this.loadActivity(0);});
    const saveHidden = () => {try {localStorage.setItem("ha-security-hidden-credentials",JSON.stringify([...this.hiddenCredentials]));} catch {} this.render(); this.loadActivity(0);};
    this.shadowRoot.querySelectorAll("[data-credential-choice]").forEach(el=>{
      el.checked = !this.hiddenCredentials.has(el.dataset.credentialChoice);
      el.onchange=()=>{if(el.checked)this.hiddenCredentials.delete(el.dataset.credentialChoice);else this.hiddenCredentials.add(el.dataset.credentialChoice);saveHidden();};
    });
    const credentialDropdown = this.shadowRoot.querySelector('[data-id="credential-filter"]');
    if (credentialDropdown) credentialDropdown.ontoggle = () => this.positionCredentialMenu();
    this.positionCredentialMenu();
    this.shadowRoot.querySelectorAll("[data-show-credentials]").forEach(el=>el.onclick=()=>{this.hiddenCredentials.clear();saveHidden();});
    this.shadowRoot.querySelectorAll("[data-mode]").forEach(el => el.onclick = () => {this.activityMode=el.dataset.mode; this.loadActivity(0);});
    this.shadowRoot.querySelectorAll("[data-page]").forEach(el => el.onclick = () => this.loadActivity(Number(el.dataset.page)));
    this.shadowRoot.querySelectorAll("[data-date]").forEach(el => el.onchange = () => {this[el.dataset.date]=el.value; this.loadActivity(0);});
    this.shadowRoot.querySelectorAll("[data-activity-user]").forEach(el => el.onchange = () => {this.activityUser=el.value; this.loadActivity(0);});
    this.shadowRoot.querySelectorAll("[data-recognize]").forEach(el => el.onclick = async () => {
      try { await this._hass.callWS({type:"call_service",domain:"ha_security",service:"recognize_source",service_data:{user_id:el.dataset.userId,token_id:el.dataset.recognize},return_response:true}); }
      catch (error) { window.alert(`Could not recognize credential: ${error.message || error}`); }
    });
    this.shadowRoot.querySelectorAll("[data-label]").forEach(el => el.onclick = async () => {
      const label = window.prompt("Credential nickname (empty clears it)", el.dataset.current || "");
      if (label === null) return;
      try { await this._hass.callWS({type:"call_service",domain:"ha_security",service:"set_token_label",service_data:{token_id:el.dataset.label,label},return_response:true}); }
      catch (error) { window.alert(`Could not save nickname: ${error.message || error}`); }
    });
  }
  loginRow(row, opened) {
    const context = row.ip_context || {};
    return `<details data-id="${esc(row.id)}" ${opened.has(row.id) ? "open" : ""}><summary><div><b>${row.kind === "login_failure" ? "Failed password / MFA attempt" : "Successful login"}</b><small>${esc(row.user_name)} · ${esc(row.source_ip || "IP hidden or unavailable")} · ${esc(exact(row.timestamp))}</small></div><span class="badge ${esc(row.security_level || "unknown")}">${esc(friendly(row.security_level || "unknown"))}</span></summary><div class="detail"><dl>${this.field("Time",exact(row.timestamp))}${this.field("Source IP",row.source_ip)}${this.field("Hostname",context.hostname)}${this.field("Approximate location",[context.city,context.region,context.country].filter(Boolean).join(", "))}${this.field("Organisation / ASN",[context.organisation,context.asn].filter(Boolean).join(" · "))}${this.field("Same-IP preceding failures",String(row.correlated_failure_count ?? "Not linked"))}${this.field("Assessment at login",(row.security_reasons || []).join("; ") || (row.kind === "login_failure" ? "Individual failure; aggregate bursts are assessed separately" : "No additional concern detected within observed coverage"))}${this.field("Attribution",row.attribution || "Successful user's identity confirmed; preceding failed users are unknown")}${this.field("Failure reason",row.failure_reason || "None")}</dl><div class="actions"><button data-related="${esc(row.token_id || "")}" data-owner="${esc(row.user_id || "")}" data-session="${esc(row.session_id || "")}">View related activity</button>${row.token_id && row.user_id ? `<button data-recognize="${esc(row.token_id)}" data-user-id="${esc(row.user_id)}">Recognize credential</button>` : ""}</div></div></details>`;
  }
  row(row, credentialEntities, opened) {
    const context = row.ip_context || {};
    const credentialContext = row.credential_ip_context || {};
    const ip = row.source_ip || row.observed_source_ip || row.last_used_ip;
    const id = row.session_id || row.token_id;
    const status = row.state || row.activity;
    const credential = this.tab === "credentials";
    const history = credentialEntities.find(e => e.attributes.user_id === row.user_id)?.attributes.ip_observations || [];
    return `<details data-id="${esc(id)}" ${opened.has(id) ? "open" : ""}><summary><div><b>${esc(row.label || "Network details hidden")}</b><small>${credential ? esc(credentialType(row.token_type)) + " · " : ""}${esc(row.user_name)} · ${esc(ip || "IP hidden or unavailable")}${context.organisation ? ` · ${esc(context.organisation)}` : ""}</small>${row.new_ip || row.new_credential || row.ip_changed ? `<div class="markers">${[row.new_credential && "New credential",row.new_ip && "New IP",row.recent_ip_change ? "Recent IP change" : row.ip_changed && "IP changed"].filter(Boolean).join(" · ")}</div>` : ""}</div><div class="right">${!credential ? `<span class="badge ${esc(row.security_level || "unknown")}">${esc(friendly(row.security_level))}</span> ` : ""}<span class="badge ${status === "connected" || status === "recently_used" ? "good" : ""}">${esc(friendly(status))}</span><small>${esc(ago(row.last_seen_at || row.last_observed_use_at || row.last_used_at || row.first_observed_at))}</small></div></summary><div class="detail"><dl>
      ${row.retained_while_open ? this.field("Kept open",row.state === "closed" ? "This connection disconnected. Details remain here while you inspect them." : "This record left the current live list. Its last observed details remain while open.") : ""}
      ${!credential ? this.field("Security assessment",(row.security_reasons || []).join("; ")) : ""}
      ${this.field("User",row.user_name)}${this.field("Client / nickname",row.label)}${this.field("Original client",row.client_name || row.client_id)}${this.field(credential ? "Latest observed source IP" : "Connection source IP",ip)}${this.field("Hostname",context.hostname)}${this.field("Organisation / ASN",[context.organisation,context.asn].filter(Boolean).join(" · "))}${this.field("Approximate IP location",[context.city,context.region,context.country].filter(Boolean).join(", "))}${this.field("IP lookup",context.looked_up_at ? `${context.lookup_status} · ${exact(context.looked_up_at)}` : "Not available / not enabled")}
      ${credential ? this.field("IP evidence",row.observed_ip_source === "http_request" ? "HTTP request (HA resolved)" : "HA inventory") + this.field("IP use observed at",exact(row.observed_ip_at)) + this.field("HA inventory IP",row.last_used_ip) : ""}
      ${!credential && row.credential_last_used_ip && row.credential_last_used_ip !== ip ? this.field("Credential last recorded IP",row.credential_last_used_ip) + this.field("Credential IP last used",exact(row.credential_last_used_at)) + this.field("Credential IP observed",exact(row.credential_ip_observed_at)) + this.field("Credential IP hostname",credentialContext.hostname) + this.field("Credential IP organisation / ASN",[credentialContext.organisation,credentialContext.asn].filter(Boolean).join(" · ")) + this.field("Credential IP approximate location",[credentialContext.city,credentialContext.region,credentialContext.country].filter(Boolean).join(", ")) + this.field("Credential IP lookup",credentialContext.looked_up_at ? `${credentialContext.lookup_status} · ${exact(credentialContext.looked_up_at)}` : "Not available / not enabled") + this.field("Address meaning","Connection source is observed on this connection. Credential IP is the same credential's latest recorded use and may belong to another connection. Private IPs have no public geolocation.") : ""}
      ${credential ? this.field("Credential created",exact(row.created_at)) + this.field("HA inventory last use",exact(row.last_used_at)) + this.field("Last observed request / command",exact(row.last_observed_action_at)) + this.field("Credential type",credentialType(row.token_type)) + this.field("Credential expires",expiry(row.expire_at)) + this.field("Issued access-token lifetime",row.access_token_expiration_seconds == null ? "Not available" : `${row.access_token_expiration_seconds} seconds`) + this.field("Use coverage","HA inventory plus supported REST reads and REST/WebSocket service commands; not every API endpoint") : this.field("Connection established",row.connected_at ? exact(row.connected_at) : "Unknown — already connected when first observed") + this.field("Last incoming command",exact(row.last_seen_at))}
      ${this.field("First observed",exact(row.first_observed_at))}${!credential ? this.field("Disconnected",row.closed_at ? exact(row.closed_at) : row.state === "connected" ? "Connection remains open" : "Unknown — monitoring interrupted") + this.field("Observation ended",exact(row.ended_at)) : ""}
      ${this.field(credential ? "Credential record ID" : "Connection ID",id)}${!credential ? this.field("Credential record ID",row.token_id) : ""}
    </dl>${credential ? `<h2>Observed IP history</h2><div class="timeline">${history.filter(r => r.token_id === row.token_id).map(r => `<p><b>${esc(r.last_used_ip)}</b><br>Observed ${esc(exact(r.observed_at))}<br>${r.ip_source === "http_request" ? "HTTP request (HA resolved)" : "HA inventory"}<br>Use recorded ${esc(exact(r.last_used_at))}</p>`).join("") || "No retained IP observations"}</div>` : ""}<div class="actions"><button data-related="${esc(row.token_id || "")}" data-owner="${esc(row.user_id || "")}" data-session="${esc(row.session_id || "")}">View related activity</button>${row.token_id ? `<button data-label="${esc(row.token_id)}" data-current="${esc(row.label || "")}">Rename credential</button>` : ""}</div></div></details>`;
  }
}
customElements.define("ha-security-card", HASecurityCard);
window.customCards = window.customCards || [];
window.customCards.push({type:"ha-security-card",name:"HA Security",description:"Entity-powered session overview, filters and details"});
