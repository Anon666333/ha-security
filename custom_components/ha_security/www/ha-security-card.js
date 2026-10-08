/* Entity-powered HA Security card. No external requests or dependencies. */
const esc = (value) => String(value ?? "Unknown").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const exact = value => value && !Number.isNaN(Date.parse(value)) ? new Date(value).toLocaleString(undefined, {timeZoneName: "short"}) : "Not observed";
const ago = value => {
  if (!value || Number.isNaN(Date.parse(value))) return "Not observed";
  const seconds = Math.max(0, Math.floor((Date.now() - Date.parse(value)) / 1000));
  return seconds < 60 ? "Just now" : seconds < 3600 ? `${Math.floor(seconds / 60)} min ago` : seconds < 86400 ? `${Math.floor(seconds / 3600)} hr ago` : `${Math.floor(seconds / 86400)} days ago`;
};
const friendly = value => String(value || "unknown").replaceAll("_", " ");

class HASecurityCard extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({mode: "open"});
    this.tab = "live";
    this.user = "all";
    this.query = "";
    this.filter = "all";
  }
  setConfig(config) { this.config = config; this.render(); }
  set hass(hass) {
    this._hass = hass;
    const states = Object.values(hass.states).filter(s => s.attributes.ha_security_metric);
    const signature = states.map(s => `${s.entity_id}:${s.last_updated}`).join("|");
    if (signature !== this.signature) { this.signature = signature; this.render(); }
  }
  connectedCallback() { this.timer = setInterval(() => this.render(), 30000); }
  disconnectedCallback() { clearInterval(this.timer); }
  getCardSize() { return 10; }
  getGridOptions() { return {columns: 12, rows: "auto"}; }
  entities(metric) { return Object.values(this._hass?.states || {}).filter(s => s.attributes.ha_security_metric === metric); }
  field(label, value) { return `<div><dt>${esc(label)}</dt><dd>${esc(value || "Unknown")}</dd></div>`; }
  moreInfo(entity) { this.dispatchEvent(new CustomEvent("hass-more-info", {detail: {entityId: entity}, bubbles: true, composed: true})); }
  render() {
    if (!this._hass) return;
    const opened = new Set([...this.shadowRoot.querySelectorAll("details[open]")].map(el => el.dataset.id));
    const accounts = this.entities("refresh_tokens");
    const overview = this.entities("overview")[0];
    const stats = overview?.attributes || {};
    const observing = stats.tracking_status === "observing";
    const sessionEntities = this.entities("active_websocket_connections");
    const credentialEntities = this.entities("recently_used_tokens");
    let rows = [];
    const sources = this.tab === "credentials" ? credentialEntities : sessionEntities;
    for (const entity of sources) {
      const attributes = entity.attributes;
      const values = this.tab === "credentials" ? attributes.connections || [] : this.tab === "history" ? attributes.session_history || [] : attributes.active_connections || [];
      rows.push(...values.map(row => ({...row, user_id: attributes.user_id, user_name: attributes.user_name, entity_id: entity.entity_id})));
    }
    rows = rows.filter(row => (this.user === "all" || row.user_id === this.user) &&
      (!this.query || JSON.stringify(row).toLowerCase().includes(this.query.toLowerCase())) &&
      (this.filter === "all" || (this.filter === "changes" ? row.new_ip || row.new_credential || row.ip_changed : row.state === this.filter || row.activity === this.filter)));
    rows.sort((a,b) => String(b.first_observed_at || b.created_at || "").localeCompare(String(a.first_observed_at || a.created_at || "")));
    const count = value => value === null || value === undefined ? "—" : esc(value);
    this.shadowRoot.innerHTML = `<style>
      :host{display:block}ha-card{overflow:hidden;background:var(--ha-card-background,var(--card-background-color));border-radius:20px}
      .shell{padding:24px;color:var(--primary-text-color);font-family:var(--paper-font-body1_-_font-family,system-ui)}
      header{display:flex;justify-content:space-between;gap:12px;align-items:center}h1{font-size:25px;margin:0 0 6px;letter-spacing:-.5px}h2{font-size:16px;margin:24px 0 12px}p{margin:4px 0;font-size:13px;line-height:1.5;color:var(--secondary-text-color)}
      .badge{font-size:12px;padding:7px 10px;border-radius:20px;background:var(--secondary-background-color);white-space:nowrap}.good{color:var(--success-color,#388e3c)}
      .stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:22px 0}.stat{padding:16px;border-radius:14px;background:var(--secondary-background-color)}.stat strong{display:block;font-size:28px;margin-bottom:5px}.stat span{font-size:12px;color:var(--secondary-text-color)}
      .users{display:flex;gap:10px;overflow-x:auto;padding:2px 0 10px}.account{min-width:150px;text-align:left;border:1px solid var(--divider-color);border-radius:12px;padding:12px}.account b{display:block;margin-bottom:5px}.account small{display:block;color:var(--secondary-text-color);margin-top:5px}
      button,input,select{font:inherit;color:var(--primary-text-color);background:var(--card-background-color);border:1px solid var(--divider-color);border-radius:10px;padding:10px;cursor:pointer}button:hover{border-color:var(--primary-color)}button.active{border-color:var(--primary-color);background:var(--secondary-background-color);color:var(--primary-color)}
      .tabs{display:flex;gap:8px;margin:18px 0 12px}.tabs button{flex:1;font-weight:600}.controls{display:grid;grid-template-columns:2fr 1fr 1fr;gap:8px;margin-bottom:14px}input{min-width:0;cursor:text}select{min-width:0}
      .list{display:grid;gap:10px}details{border:1px solid var(--divider-color);border-radius:12px;overflow:hidden}summary{cursor:pointer;list-style:none;padding:15px;display:grid;grid-template-columns:1fr auto;gap:12px;align-items:center}summary::-webkit-details-marker{display:none}summary b{font-size:15px}summary small{display:block;color:var(--secondary-text-color);margin-top:5px}summary .right{text-align:right;font-size:12px}summary:hover{background:var(--secondary-background-color)}
      .detail{border-top:1px solid var(--divider-color);padding:16px}.detail dl{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:0 0 16px}dt{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--secondary-text-color);margin-bottom:5px}dd{margin:0;font-size:13px;overflow-wrap:anywhere}.markers{font-size:11px;color:var(--warning-color,#b26a00);margin-top:6px}.empty{padding:26px;text-align:center;border:1px dashed var(--divider-color);border-radius:12px}.foot{margin-top:18px;font-size:12px}.timeline{border-left:2px solid var(--divider-color);padding-left:12px;margin:12px 0}.timeline p{margin:12px 0}.actions{display:flex;gap:8px;flex-wrap:wrap}.note{padding:12px;background:var(--secondary-background-color);border-radius:10px;margin:12px 0}
      @media(max-width:600px){.shell{padding:16px}.stats{grid-template-columns:repeat(2,1fr)}header{align-items:flex-start;flex-direction:column}.controls{grid-template-columns:1fr 1fr}.controls input{grid-column:1/-1}.detail dl{grid-template-columns:1fr}.tabs button{padding:10px 6px;font-size:12px}}
    </style><ha-card><div class="shell">
      <header><div><h1>${esc(this.config?.title || "Security centre")}</h1><p>Connections, account activity and retained history</p></div><span class="badge ${observing ? "good" : ""}">${observing ? "● Observing WebSockets" : esc(friendly(stats.tracking_status || "No integration data"))}</span></header>
      <div class="stats"><div class="stat"><strong>${count(stats.connected_websockets)}</strong><span>Observed open connections</span></div><div class="stat"><strong>${count(stats.recently_observed_users)}</strong><span>Recently observed users</span></div><div class="stat"><strong>${count(stats.retained_sessions)}</strong><span>Retained ended sessions</span></div><div class="stat"><strong>${count(stats.new_observations)}</strong><span>Changes in retained audit</span></div></div>
      ${!observing ? '<p class="note">Enable <b>Observe WebSocket sessions</b> in HA Security options. Disabled or unsupported tracking is not a zero-session result.</p>' : '<p>Coverage starts when tracking is enabled. Reconnect existing clients for coverage. HTTP and cloud requests are outside this connection count.</p>'}
      <h2>Users <small>· select to filter</small></h2><div class="users"><button class="account ${this.user === "all" ? "active" : ""}" data-user="all"><b>All users</b><small>${accounts.length} discovered accounts</small></button>${accounts.map(account => {
        const a = account.attributes;
        const sessions = sessionEntities.find(s => s.attributes.user_id === a.user_id);
        return `<button class="account ${this.user === a.user_id ? "active" : ""}" data-user="${esc(a.user_id)}"><b>${esc(a.user_name)}</b><span>${sessions?.state === "unavailable" || !observing ? "—" : esc(sessions?.state ?? "—")} connections</span><small>${a.recently_observed ? "Recently observed" : "No recent activity"}${a.system_generated ? " · System" : ""}${a.is_active === false ? " · Disabled account" : ""}</small></button>`;
      }).join("")}</div>
      <div class="tabs" role="tablist">${[["live","Live connections"],["history","Session history"],["credentials","Credentials"]].map(([id,label]) => `<button role="tab" aria-selected="${this.tab === id}" class="${this.tab === id ? "active" : ""}" data-tab="${id}">${label}</button>`).join("")}</div>
      <div class="controls"><input data-search aria-label="Search sessions" placeholder="Search client, IP, hostname, organisation…" value="${esc(this.query)}"><select data-select-user aria-label="Filter user"><option value="all">All users</option>${accounts.map(a => `<option value="${esc(a.attributes.user_id)}" ${this.user === a.attributes.user_id ? "selected" : ""}>${esc(a.attributes.user_name)}</option>`).join("")}</select><select data-filter aria-label="Filter status"><option value="all">All statuses</option>${(this.tab === "credentials" ? ["recently_used","outside_window","removed","expired","changes"] : this.tab === "history" ? ["closed","interrupted"] : ["connected"]).map(s => `<option value="${s}" ${this.filter === s ? "selected" : ""}>${esc(friendly(s))}</option>`).join("")}</select></div>
      <p>${rows.length} displayed ${this.tab === "credentials" ? "credentials" : "connections"} · Expand a row for details</p><div class="list">${rows.map(row => this.row(row, credentialEntities, opened)).join("") || `<div class="empty"><b>${this.query || this.filter !== "all" || this.user !== "all" ? "No matching results" : this.tab === "live" ? "No open connections observed" : "No retained records yet"}</b><p>${this.tab === "live" ? "Reconnect a browser/app after enabling tracking to observe its full lifecycle." : "History begins with observations made by this integration."}</p></div>`}</div>
      <p class="foot">Last inventory scan: ${esc(ago(stats.last_successful_scan))}. Last seen means an incoming WebSocket command, not human activity. Start time means connection establishment, not necessarily a password login. IP location is approximate.</p>
      ${sources.some(s => s.attributes.sessions_truncated || s.attributes.connections_truncated) ? '<p class="note">Entity lists are capped at 100 rows per user. Use HA Security: Search sessions for additional retained connection history.</p>' : ""}
    </div></ha-card>`;
    this.shadowRoot.querySelectorAll("[data-tab]").forEach(el => el.onclick = () => {this.tab = el.dataset.tab; this.filter = "all"; this.render();});
    this.shadowRoot.querySelectorAll("[data-user]").forEach(el => el.onclick = () => {this.user = el.dataset.user; this.render();});
    this.shadowRoot.querySelector("[data-select-user]").onchange = event => {this.user = event.target.value; this.render();};
    this.shadowRoot.querySelector("[data-select-user]").value = this.user;
    this.shadowRoot.querySelector("[data-filter]").onchange = event => {this.filter = event.target.value; this.render();};
    this.shadowRoot.querySelector("[data-search]").oninput = event => {const cursor = event.target.selectionStart; this.query = event.target.value; this.render(); const input = this.shadowRoot.querySelector("[data-search]"); input.focus(); input.setSelectionRange(cursor,cursor);};
    this.shadowRoot.querySelectorAll("[data-info]").forEach(el => el.onclick = () => this.moreInfo(el.dataset.info));
    this.shadowRoot.querySelectorAll("[data-label]").forEach(el => el.onclick = async () => {
      const label = window.prompt("Credential nickname (empty clears it)", el.dataset.current || "");
      if (label === null) return;
      try { await this._hass.callWS({type:"call_service",domain:"ha_security",service:"set_token_label",service_data:{token_id:el.dataset.label,label},return_response:true}); }
      catch (error) { window.alert(`Could not save nickname: ${error.message || error}`); }
    });
  }
  row(row, credentialEntities, opened) {
    const context = row.ip_context || {};
    const ip = row.source_ip || row.last_used_ip;
    const id = row.session_id || row.token_id;
    const status = row.state || row.activity;
    const credential = this.tab === "credentials";
    const history = credentialEntities.find(e => e.attributes.user_id === row.user_id)?.attributes.ip_observations || [];
    return `<details data-id="${esc(id)}" ${opened.has(id) ? "open" : ""}><summary><div><b>${esc(row.label || "Network details hidden")}</b><small>${esc(row.user_name)} · ${esc(ip || "IP hidden or unavailable")}${context.organisation ? ` · ${esc(context.organisation)}` : ""}</small>${row.new_ip || row.new_credential || row.ip_changed ? `<div class="markers">${[row.new_credential && "New credential",row.new_ip && "New IP",row.ip_changed && "IP changed"].filter(Boolean).join(" · ")}</div>` : ""}</div><div class="right"><span class="badge ${status === "connected" || status === "recently_used" ? "good" : ""}">${esc(friendly(status))}</span><small>${esc(ago(row.last_seen_at || row.last_used_at || row.first_observed_at))}</small></div></summary><div class="detail"><dl>
      ${this.field("User",row.user_name)}${this.field("Client / nickname",row.label)}${this.field("Original client",row.client_name || row.client_id)}${this.field("Source IP",ip)}${this.field("Hostname",context.hostname)}${this.field("Organisation / ASN",[context.organisation,context.asn].filter(Boolean).join(" · "))}${this.field("Approximate IP location",[context.city,context.region,context.country].filter(Boolean).join(", "))}${this.field("IP lookup",context.looked_up_at ? `${context.lookup_status} · ${exact(context.looked_up_at)}` : "Not available / not enabled")}
      ${credential ? this.field("Credential created",exact(row.created_at)) + this.field("Token last used",exact(row.last_used_at)) : this.field("Connection established",row.connected_at ? exact(row.connected_at) : "Unknown — already connected when first observed") + this.field("Last incoming command",exact(row.last_seen_at))}
      ${this.field("First observed",exact(row.first_observed_at))}${!credential ? this.field("Disconnected",row.closed_at ? exact(row.closed_at) : row.state === "connected" ? "Connection remains open" : "Unknown — monitoring interrupted") + this.field("Observation ended",exact(row.ended_at)) : ""}
      ${this.field(credential ? "Credential record ID" : "Connection ID",id)}${!credential ? this.field("Credential record ID",row.token_id) : ""}
    </dl>${credential ? `<h2>Observed IP history</h2><div class="timeline">${history.filter(r => r.token_id === row.token_id).map(r => `<p><b>${esc(r.last_used_ip)}</b><br>Observed ${esc(exact(r.observed_at))}<br>Token last used ${esc(exact(r.last_used_at))}</p>`).join("") || "No retained IP observations"}</div>` : ""}<div class="actions"><button data-info="${esc(row.entity_id)}">Entity details &amp; history</button>${row.token_id ? `<button data-label="${esc(row.token_id)}" data-current="${esc(row.label || "")}">Rename credential</button>` : ""}</div></div></details>`;
  }
}
customElements.define("ha-security-card", HASecurityCard);
window.customCards = window.customCards || [];
window.customCards.push({type:"ha-security-card",name:"HA Security",description:"Entity-powered session overview, filters and details"});
