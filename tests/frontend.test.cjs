/* Verify rendered account attribution, unknown outcomes, filters and HTML escaping. */
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
let Card;
let html = '';
let searchNode;
const root = {activeElement:null,querySelectorAll:()=>[],querySelector:selector=>selector==='[data-search]' ? searchNode : {}};
const makeSearch = () => ({value:'',selectionStart:0,selectionEnd:0,selectionDirection:'none',
  matches:selector=>selector==='[data-search]',
  focus:()=>{root.activeElement=searchNode;},
  setSelectionRange:(start,end,direction)=>{searchNode.selectionStart=start;searchNode.selectionEnd=end;searchNode.selectionDirection=direction;},
});
Object.defineProperty(root,'innerHTML',{get:()=>html,set:value=>{html=value;root.activeElement=null;searchNode=makeSearch();}});
const context = {
  HTMLElement:class {attachShadow(){this.shadowRoot=root;}},
  customElements:{define:(_name,cls)=>{Card=cls;}},window:{},
  setInterval,clearInterval,CustomEvent:class {},
};
vm.runInNewContext(fs.readFileSync('custom_components/ha_security/www/ha-security-card.js','utf8'),context);
const entity=(metric,attributes,state='0')=>({entity_id:'sensor.'+metric,attributes:{ha_security_metric:metric,...attributes},state,last_updated:'2026-10-07'});
const login={id:'success',kind:'login_success',user_id:'u',token_id:'record',source_ip:'8.8.8.8',timestamp:'2026-10-07T12:00:00Z',security_level:'likely_issue',security_reasons:['<img src=x onerror=alert(1)>'],correlated_failure_count:12};
const failure={id:'failure',kind:'login_failure',user_id:null,source_ip:'1.1.1.1',timestamp:'2026-10-07T11:59:00Z',attribution:'unknown_user'};
const states=[entity('overview',{tracking_status:'observing',login_tracking_status:'observing'}),entity('refresh_tokens',{user_id:'u',user_name:'Matt'}),entity('global_successful_logins_24h',{successful_logins_24h:1,failed_login_attempts_24h:12,security_status:'likely_issue',login_events:[login,failure]}),entity('security_status',{user_id:'u',login_events:[login]},'likely_issue')];
const card=new Card(); card.setConfig({title:'Security centre'}); card.hass={states:Object.fromEntries(states.map(e=>[e.entity_id,e]))};
card.tab='logins';card.render();
assert.ok(root.innerHTML.includes('Likely an issue'));
assert.ok(root.innerHTML.includes('Unknown user'));
assert.ok(root.innerHTML.includes('&lt;img src=x onerror=alert(1)&gt;'));
assert.ok(!root.innerHTML.includes('<img src=x'));
assert.ok(root.innerHTML.includes('data-recognize="'));
card.user='u';card.render();
assert.ok(root.innerHTML.includes('8.8.8.8'));
assert.ok(!root.innerHTML.includes('1.1.1.1'));
card.filter='normal';card.render();assert.ok(root.innerHTML.includes('No matching results'));
card.user='all';card.filter='login_failure';card.render();
assert.ok(root.innerHTML.includes('1.1.1.1'));assert.ok(!root.innerHTML.includes('8.8.8.8'));
console.log('Frontend attribution, filters and escaping checks passed');

card.tab='live';card.filter='all';card.query='';card.render();
searchNode.focus();searchNode.value='browser';searchNode.setSelectionRange(2,5,'backward');
searchNode.oninput({target:searchNode});
assert.equal(root.activeElement,searchNode);
assert.deepEqual([searchNode.selectionStart,searchNode.selectionEnd,searchNode.selectionDirection],[2,5,'backward']);
card.render(); // periodic refresh preserves focus and selection
assert.equal(root.activeElement,searchNode);
assert.deepEqual([searchNode.selectionStart,searchNode.selectionEnd],[2,5]);
card.hass={states:Object.fromEntries(states.map(e=>[e.entity_id,{...e,last_updated:'updated'}]))};
assert.equal(root.activeElement,searchNode); // HA state updates preserve focus too
searchNode.oncompositionstart(); const composingNode=searchNode;
searchNode.value='composing';searchNode.oninput({target:searchNode});card.render();
assert.equal(searchNode,composingNode);
searchNode.oncompositionend({target:searchNode});
assert.equal(card.query,'composing');assert.equal(root.activeElement,searchNode);
root.activeElement=null;card.render();assert.equal(root.activeElement,null); // no focus stealing
console.log('Search focus, selection, live refresh and composition checks passed');
const credential={token_id:'a',user_id:'u',label:'Tablet',token_type:'long_lived_access_token',expire_at:1800000000,access_token_expiration_seconds:3600};
card.tab='credentials';
const rendered=card.row(credential,[],new Set());
assert.ok(rendered.includes('Long-lived access-token record'));
assert.ok(rendered.includes('Credential expires'));
assert.ok(rendered.includes('Last recorded token use'));
assert.ok(rendered.includes('does not observe every REST request'));
assert.ok(rendered.includes('View related activity'));
assert.ok(!rendered.includes('Entity details &amp; history'));
root.activeElement=null;
// Explicit renders and tab round trips restore expansion per tab.
card.tab='live';card.render();
root.querySelectorAll=selector=>selector==='details[open]' ? [{dataset:{id:'session-open'}}] : [];
card.render();assert.ok(card.openRows.get('live').has('session-open'));
card.tab='credentials';card.render();
root.querySelectorAll=selector=>selector==='details[open]' ? [{dataset:{id:'credential-open'}}] : [];
card.tab='live';card.render();
assert.ok(card.openRows.get('credentials').has('credential-open'));
assert.ok(card.openRows.get('live').has('session-open'));
root.querySelectorAll=()=>[];
console.log('Per-tab expansion checks passed (DOM identity covered in frontend-dom.test.cjs)');
card.tab='activity';card.related={token_id:'a',user_id:'u'};
let request;
card._hass.callWS=async value=>{request=value;return {response:{total:1,records:[{id:'x',kind:'service_call',description:'Service invoked: light.turn_on',attribution_scope:'user_only_credential_unknown',user_id:'u'}],summary:'Showing 1 of 1',coverage:{limitations:'Not every REST request'},next_offset:null}};};
(async()=>{
  card._hass.callWS=async value=>{request=value;return [{when:1791498600,entity_id:'light.kitchen',state:'on',context_user_id:'u'},{when:1791498601,entity_id:'lock.front',state:'unlocked',context_user_id:'other'}];};
  card.activityMode='user';await card.loadActivity(0);
  assert.equal(request.type,'logbook/get_events');assert.equal(request.user_id,undefined);
  assert.ok(root.innerHTML.includes('light.kitchen'));assert.ok(!root.innerHTML.includes('lock.front'));
  assert.ok(root.innerHTML.includes('User activity'));assert.ok(root.innerHTML.includes('Technical details (structured result)'));
  assert.ok(root.innerHTML.includes('specific credential unknown'));
  card._hass.callWS=async value=>{request=value;return {response:{records:[],total:0}};};
  card.activityMode='actions';await card.loadActivity(0);assert.equal(request.service_data.kind,'websocket_action');assert.equal(request.service_data.token_id,'a');
  const attributed=card.activityRow({id:'command',kind:'websocket_action',user_name:'Matt',token_id:'a',session_id:'session-a',domain:'light',service:'turn_on',context_id:'ctx',invocation_observed:true},new Set());
  assert.ok(attributed.includes('Matt submitted light.turn_on'));
  assert.ok(attributed.includes('Directly linked'));
  assert.ok(attributed.includes('Related HA activity'));
  assert.ok(!attributed.includes('specific credential and connection are unknown'));
  card._hass.callWS=async value=>{request=value;return [{when:1791498600,entity_id:'light.kitchen',state:'on',context_user_id:'u'}];};
  card.activityMode='context';card.nativeContext={id:'exact-context',timestamp:'2026-10-01T12:00:00Z'};
  await card.loadActivity(0);
  assert.equal(request.type,'logbook/get_events');assert.equal(request.context_id,'exact-context');
  assert.ok(Date.parse(request.end_time)-Date.parse(request.start_time)<=86400000);
  assert.ok(root.innerHTML.includes('contextual evidence'));
  card.activityMode='user';await card.loadActivity(0);
  assert.equal(request.context_id,undefined);
  assert.ok(Date.parse(request.start_time)>Date.parse(card.nativeContext.timestamp));
  card._hass.callWS=async value=>{request=value;return {response:{records:[],total:0}};};
  card.activityMode='direct';await card.loadActivity(50);assert.equal(request.service_data.token_id,'a');assert.equal(request.service_data.offset,50);
  card.activityMode='connections';await card.loadActivity(0);assert.equal(request.service,'query_sessions');assert.equal(request.service_data.kind,undefined);
  // Old backend records must still describe service calls accurately.
  const rawCall={id:'legacy',kind:'service_call',user_id:'u',user_name:'Matt',domain:'ha_security',service:'query_audit',entity_ids:[],timestamp:'2026-10-08T22:29:03Z'};
  const openRows=new Set(['activity-legacy','activity-legacy-raw']);
  const legacy=card.activityRow(rawCall,openRows);
  assert.ok(legacy.includes('Audit history searched'));
  assert.ok(legacy.includes('specific credential and connection are unknown'));
  assert.ok(legacy.includes('No entity targets recorded'));
  assert.ok(!legacy.includes('Connection undefined'));
  assert.ok(!legacy.includes('Credential-linked WebSocket connection'));
  assert.ok(legacy.includes('data-id="activity-legacy" open'));
  assert.ok(legacy.includes('data-id="activity-legacy-raw" open'));
  assert.ok(card.activityRow({...rawCall,domain:'light',service:'turn_on',entity_ids:['light.kitchen']},new Set()).includes('light.kitchen'));
  assert.ok(card.activityRow({session_id:'ws',state:'closed',token_id:'a'},new Set()).includes('WebSocket connection closed'));
  // Unrelated HA state updates leave the inspected activity DOM intact.
  const before=root.innerHTML;
  card.hass={states:Object.fromEntries(states.map(e=>[e.entity_id,{...e,last_updated:'another-update'}]))};
  assert.equal(root.innerHTML,before);
  card.activityResult={total:1,records:[rawCall]};
  root.querySelectorAll=selector=>selector==='details[open]' ? [...openRows].map(id=>({dataset:{id}})) : [];
  card.render();
  assert.ok(root.innerHTML.includes('data-id="activity-legacy" open'));
  assert.ok(root.innerHTML.includes('data-id="activity-legacy-raw" open'));
  assert.ok(root.innerHTML.includes('<div class="list"><details data-id="activity-legacy" open'));
  root.querySelectorAll=()=>[];
  card._hass.callWS=async()=>{throw new Error('unauthorized');};await card.loadActivity(0);assert.ok(root.innerHTML.includes('Administrator access required'));
  console.log('Related activity attribution, pagination, response and permission checks passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
