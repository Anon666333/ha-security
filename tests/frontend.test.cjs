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
