// Explicit DOM/event model only. No browser rendering, devices, or live transport.
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const ui=require('../web/studio-presentation.js');
class El {
 constructor(){this.events=new Map();this.dataset={};this.attrs={};this.textContent='';this.hidden=false;this.disabled=false;this.isConnected=true;this.scrollTop=0;}
 addEventListener(k,fn){if(!this.events.has(k))this.events.set(k,new Set());this.events.get(k).add(fn);}
 removeEventListener(k,fn){this.events.get(k)?.delete(fn);}
 emit(k,extras={}){const e={type:k,preventDefault(){this.defaultPrevented=true;},...extras};for(const fn of [...(this.events.get(k)||[])])fn(e);return e;}
 dispatchEvent(e){this.emit(e.type,e);}
 setAttribute(k,v){this.attrs[k]=v;} focus(){this.focused=true;}
}
const good=()=>({ok:true,pid:42,version:'test-dev',sessions_root:'/tmp/test',kernel_plugins_total:4});
function fixture(opts={}){
 const ids=Object.fromEntries(['workbenchView','studioDataSource','studioSourceStatus','studioCheckBackend','canvas'].map(id=>[id,new El()]));
 const doc=new El(),buttons=['panelFlow','panelLatency','panelSamples'].map(id=>{const e=new El();e.dataset.studioFocus=id;return e;});doc.getElementById=id=>ids[id];doc.querySelectorAll=()=>buttons;doc.activeElement=buttons[0];
 let count=0;const frames=new Map(),calls=[],nav=[];const href=opts.href||'http://127.0.0.1:17873/?demo=1&autoload=1';const loc=new URL(href);loc.assign=x=>nav.push(x);
 const win={location:loc,confirm:()=>opts.confirm!==false,requestAnimationFrame(fn){frames.set(++count,fn);return count;},cancelAnimationFrame(id){frames.delete(id);},CustomEvent:class{constructor(type){this.type=type;}},PktPathStudio:{getState:()=>opts.state||{},api:(url,options)=>{calls.push({url,options});return opts.api?opts.api():Promise.resolve(good());}}};
 const controller=ui.mount(doc,win),flush=()=>{for(const [id,fn]of [...frames]){frames.delete(id);fn();}};
 return {ids,buttons,doc,win,controller,calls,nav,flush};
}
const settled=()=>new Promise(resolve=>setImmediate(resolve));
test('data mode exactly follows existing app query/file contract',()=>{
 assert.equal(ui.modeFromLocation(new URL('https://example.test/?demo=1')),'demo');assert.equal(ui.modeFromLocation(new URL('https://example.test/?demo=10')),'api');assert.equal(ui.modeFromLocation(new URL('file:///test/index.html')),'demo');assert.equal(ui.modeFromLocation(new URL('https://example.test/')),'api');
});
test('mode navigation is explicit, same-origin and cleans sample-only flags',()=>{
 const next=new URL(ui.nextModeHref('http://127.0.0.1:123/?demo=1&demo=0&sample=2&saved=1&x=3','api'));assert.equal(next.origin,'http://127.0.0.1:123');assert.equal(next.search,'?x=3');const demo=new URL(ui.nextModeHref(next.href,'demo'));assert.equal(demo.searchParams.get('demo'),'1');assert.equal(demo.searchParams.get('autoload'),'1');assert.throws(()=>ui.nextModeHref('file:///index.html','api'),/HTTP/);assert.throws(()=>ui.nextModeHref(next.href,'oops'),/未知/);
});
test('health recognition rejects HTML, generic ok, malformed and unsafe identity',()=>{
 assert.equal(ui.isGoHealth(good()),true);for(const x of [null,{},'<html>',{ok:true},...['pid','version','sessions_root','kernel_plugins_total'].map(k=>({...good(),[k]:null})),{...good(),pid:2**53},{...good(),kernel_plugins_total:-1}])assert.equal(ui.isGoHealth(x),false);
});
test('demo stays explicitly synthetic and performs zero health/API calls',()=>{const f=fixture();assert.equal(f.controller.mode,'demo');assert.equal(f.ids.studioSourceStatus.dataset.state,'demo');assert.match(f.ids.studioSourceStatus.textContent,/未采集/);assert.equal(f.ids.studioCheckBackend.hidden,true);assert.equal(f.calls.length,0);});
test('real Go health is read-only same-origin; online does not claim connected device',async()=>{const f=fixture({href:'http://localhost:123/'});await settled();assert.deepEqual(f.calls,[{url:'/api/health',options:{timeout:3000}}]);assert.equal(f.ids.studioSourceStatus.dataset.state,'online');assert.match(f.ids.studioSourceStatus.textContent,/不等于设备/);assert.equal(f.nav.length,0);});
test('failure or malformed HTTP200 never silently enables demo',async()=>{for(const api of [()=>Promise.reject(new Error('404')),()=>Promise.resolve({raw:'<html>'}),()=>Promise.resolve({ok:true})]){const f=fixture({href:'http://localhost:123/',api});await settled();assert.equal(f.ids.studioSourceStatus.dataset.state,'offline');assert.equal(f.ids.studioDataSource.value,'api');assert.equal(f.nav.length,0);assert.match(f.ids.studioSourceStatus.textContent,/不会自动/);}});
test('late health is fenced by request ID and destroyed instances',async()=>{
 const resolve=[];const f=fixture({href:'http://localhost:123/',api:()=>new Promise(r=>resolve.push(r))});f.ids.studioCheckBackend.emit('click');resolve[1](good());await settled();resolve[0]({});await settled();assert.equal(f.ids.studioSourceStatus.dataset.state,'online');
 f.ids.studioCheckBackend.emit('click');f.controller.destroy();const text=f.ids.studioSourceStatus.textContent;resolve[2](good());await settled();assert.equal(f.ids.studioSourceStatus.textContent,text);
});
test('capture/quit blocks navigation; explicit confirm cancellation preserves mode',async()=>{
 for(const state of [{capturing:true},{quitting:true}]){const f=fixture({href:'http://localhost:123/',state});await settled();f.ids.studioDataSource.value='demo';f.ids.studioDataSource.emit('change');assert.equal(f.nav.length,0);assert.equal(f.ids.studioDataSource.value,'api');}
 const declined=fixture({href:'http://localhost:123/',confirm:false});declined.ids.studioDataSource.value='demo';declined.ids.studioDataSource.emit('change');assert.equal(declined.nav.length,0);
 const yes=fixture({href:'http://localhost:123/'});yes.ids.studioDataSource.value='demo';yes.ids.studioDataSource.emit('change');assert.match(yes.nav[0],/demo=1/);const file=fixture({href:'file:///index.html'});file.ids.studioDataSource.value='api';file.ids.studioDataSource.emit('change');assert.equal(file.nav.length,0);assert.match(file.ids.studioSourceStatus.textContent,/HTTP/);
});
test('all three panels focus/restore in place, preserve scroll and emit redraw',()=>{
 const f=fixture();let redraw=0;f.doc.addEventListener('pktpath:layout-resized',()=>redraw++);f.ids.canvas.scrollTop=240;
 for(let i=0;i<3;i++){f.buttons[i].emit('click');f.flush();assert.equal(f.controller.getFocused(),f.buttons[i].dataset.studioFocus);assert.equal(f.ids.workbenchView.dataset.studioFocus,f.controller.getFocused());assert.equal(f.buttons[i].attrs['aria-pressed'],'true');assert.equal(f.ids.canvas.scrollTop,0);f.buttons[i].emit('click');f.flush();assert.equal(f.controller.getFocused(),null);assert.equal(f.ids.workbenchView.dataset.studioFocus,undefined);assert.equal(f.ids.canvas.scrollTop,240);}
 assert.equal(redraw,6);assert.equal(f.buttons[0].focused,true);const before=redraw;f.controller.focusPanel('__proto__');assert.equal(redraw,before);
});
test('Escape restores transient focus; idempotent mount/destroy do not own persistent geometry',()=>{
 const f=fixture();assert.equal(ui.mount(f.doc,f.win),f.controller);f.buttons[1].emit('click');assert.equal(f.doc.emit('keydown',{key:'Escape'}).defaultPrevented,true);assert.equal(f.controller.getFocused(),null);f.buttons[2].emit('click');f.controller.destroy();f.flush();assert.equal(f.ids.workbenchView.dataset.studioFocus,undefined);assert.equal(f.ids.workbenchView._pktpathPresentation,undefined);assert.equal(f.buttons[2].events.get('click').size,0);assert.equal(f.doc.events.get('keydown').size,0);
});
test('presentation assets are wired and cannot silently start capture or write config',()=>{
 const src=fs.readFileSync(path.join(__dirname,'../web/studio-presentation.js'),'utf8'),html=fs.readFileSync(path.join(__dirname,'../web/index.html'),'utf8');assert.match(html,/studio-presentation\.css/);assert.match(html,/studio-presentation\.js/);for(const id of ['panelFlow','panelLatency','panelSamples'])assert.match(html,new RegExp('data-studio-focus="'+id+'"'));assert.doesNotMatch(src,/innerHTML|setInterval|fetch\(|localStorage|\/api\/capture|\/api\/kernel/);
});
