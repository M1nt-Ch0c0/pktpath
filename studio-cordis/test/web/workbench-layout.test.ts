// Explicit DOM/event/geometry model only. No browser rendering.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { loadBrowserScript } from './_load-browser-script.ts';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const ui = loadBrowserScript('../../web/workbench-layout.js');
// Deliberately a geometry/event MODEL, not a rendering engine or browser.
class Target {
 constructor() { this.events = new Map(); }
 addEventListener(k, f) { if (!this.events.has(k)) this.events.set(k, new Set()); this.events.get(k).add(f); }
 removeEventListener(k, f) { this.events.get(k)?.delete(f); }
 emit(k, values={}) {
  const e={ type:k, currentTarget:this, button:0, isPrimary:true, pointerId:1, clientX:100, clientY:100,
   preventDefault(){this.prevented=true;}, stopPropagation(){this.stopped=true;}, ...values };
  for(const f of [...(this.events.get(k)||[])]) f(e);
  return e;
 }
 dispatchEvent(e) { this.emit(e.type,e); return true; }
 count() { return [...this.events.values()].reduce((sum,x)=>sum+x.size,0); }
}
class Classes {
 constructor() {this.values=new Set();}
 contains(k){return this.values.has(k);}
 add(k){this.values.add(k);}
 remove(k){this.values.delete(k);}
 toggle(k, force){const on=force===undefined?!this.contains(k):force;if(on)this.add(k);else this.remove(k);return on;}
}
class Element extends Target {
 constructor(id,w=800){super();this.id=id;this.width=w;this.hidden=false;this.classList=new Classes();this.attrs={};this.properties={};this.style={setProperty:(k,v)=>this.properties[k]=v,removeProperty:(k)=>delete this.properties[k]};this.captured=new Set();}
 getBoundingClientRect(){return {width:this.width,height:600};}
 setAttribute(k,v){this.attrs[k]=String(v);}
 focus(){this.focused=true;}
 setPointerCapture(k){this.captured.add(k);}
 hasPointerCapture(k){return this.captured.has(k);}
 releasePointerCapture(k){this.captured.delete(k);this.emit('lostpointercapture',{pointerId:k});}
}
function fixture(opts={}) {
 const doc=new Target(),win=new Target();const ids={};
 for(const id of ['workbenchView','chartRow','layoutStatus','panelFlow','panelLatency','panelSamples','sessionView','railSplitter','chartSplitter','flowHeightSplitter','latencyHeightSplitter','tableHeightSplitter','btnResetLayout','flowWrap','latWrap'])ids[id]=new Element(id);
 ids.workbenchView.width=opts.width??1200;ids.chartRow.width=opts.chartWidth??800;
 doc.getElementById=(id)=>ids[id]||null;doc.body=new Element('body');doc.hidden=false;
 const store=opts.store||new Map();const writes=[];
 win.localStorage={getItem:(k)=>{if(opts.readError)throw Error('read');return store.has(k)?store.get(k):null;},setItem:(k,v)=>{if(opts.writeError)throw Error('quota');store.set(k,v);writes.push(k);},removeItem:(k)=>{if(opts.writeError)throw Error('denied');store.delete(k);}};
 if(opts.getterError)Object.defineProperty(win,'localStorage',{get(){throw Error('security');}});
 const raf=new Map();let seq=0;
 win.requestAnimationFrame=(f)=>{const n=++seq;raf.set(n,f);return n;};win.cancelAnimationFrame=(n)=>raf.delete(n);
 win.CustomEvent=class{constructor(type){this.type=type;}};
 const ros=[],mos=[];
 win.ResizeObserver=class{constructor(cb){this.cb=cb;this.targets=[];ros.push(this);}observe(el){this.targets.push(el);}disconnect(){this.disconnected=true;}};
 win.MutationObserver=class{constructor(cb){this.cb=cb;mos.push(this);}observe(){}disconnect(){this.disconnected=true;}};
 let notifications=0;doc.addEventListener('pktpath:layout-resized',()=>notifications++);
 const controller=opts.autoMount===false?null:ui.mount(doc,win);
 const flush=()=>{let rounds=0;while(raf.size){if(++rounds>30)throw Error('frame loop');const jobs=[...raf.values()];raf.clear();jobs.forEach((f)=>f());}};
 flush();
 return {doc,win,ids,store,writes,controller,flush,ros,mos,raf,notifications:()=>notifications};
}
function pointer(f,id,dx,dy=0,extra={}) {
 f.ids[id].emit('pointerdown',extra);
 f.win.emit('pointermove',{clientX:100+dx,clientY:100+dy,...extra});f.flush();
 f.win.emit('pointerup',{clientX:100+dx,clientY:100+dy,...extra});f.flush();
}

test('normalization rejects malformed/versioned/future and clamps only owned finite fields',()=>{
 for(const raw of [null, [], 2, {version:99,railWidth:500}])assert.deepEqual(ui.normalize(raw),{...ui.DEFAULT});
 const got=ui.normalize({version:1,railWidth:Infinity,chartRatio:-5,flowHeight:99999,latencyHeight:'300',tableHeight:0,unknown:'x'});
 assert.deepEqual(got,{version:1,railWidth:320,chartRatio:.1,flowHeight:1200,latencyHeight:340,tableHeight:280});
 assert.equal(ui.DEFAULT.railWidth,320);
});
test('rail pointer move commits on up only and restores in a new mount',()=>{
 const f=fixture();f.ids.railSplitter.emit('pointerdown');f.win.emit('pointermove',{clientX:250});f.flush();
 assert.equal(f.controller.snapshot().railWidth,470);assert.equal(f.ids.workbenchView.properties['--wb-rail-width'],'470px');assert.equal(f.writes.length,0);
 f.win.emit('pointerup',{clientX:250});f.flush();assert.equal(f.writes.length,1);
 assert.deepEqual(f.writes,[ui.STORAGE_KEY]);
 const g=fixture({store:f.store});assert.equal(g.controller.snapshot().railWidth,470);
});
test('chart ratio clamps both panels to 280px; independent heights clamp correctly',()=>{
 const f=fixture();pointer(f,'chartSplitter',9999);
 assert.ok(Math.abs(f.controller.snapshot().chartRatio-(1-280/790))<1e-10);
 assert.equal(f.ids.chartSplitter.attrs['aria-valuenow'],'65');
 pointer(f,'flowHeightSplitter',0,200);pointer(f,'latencyHeightSplitter',0,-9999);pointer(f,'tableHeightSplitter',0,9999);
 assert.equal(f.ids.panelFlow.style.height,'540px');assert.equal(f.ids.panelLatency.style.height,'240px');assert.equal(f.ids.panelSamples.style.height,'1600px');
});
test('release without final move still uses release coordinates',()=>{
 const f=fixture();f.ids.railSplitter.emit('pointerdown');f.win.emit('pointerup',{clientX:200});f.flush();assert.equal(f.controller.snapshot().railWidth,420);
});
test('pointer cancellation, lost capture, blur, visibility and Escape restore unsaved state',()=>{
 for(const action of ['cancel','lost','blur','hidden','escape']){
  const f=fixture();f.ids.flowHeightSplitter.emit('pointerdown');f.win.emit('pointermove',{clientY:250});f.flush();assert.equal(f.controller.snapshot().flowHeight,490);
  if(action==='cancel')f.win.emit('pointercancel');
  if(action==='lost')f.ids.flowHeightSplitter.emit('lostpointercapture');
  if(action==='blur')f.win.emit('blur');
  if(action==='hidden'){f.doc.hidden=true;f.doc.emit('visibilitychange');}
  if(action==='escape')f.win.emit('keydown',{key:'Escape'});
  f.flush();assert.equal(f.controller.snapshot().flowHeight,340,action);assert.equal(f.writes.length,0,action);assert.equal(f.doc.body.classList.contains('wb-dragging'),false);
 }
});
test('non-primary/right click/mismatched pointer are ignored; touch/pen event model shares path',()=>{
 const f=fixture();f.ids.railSplitter.emit('pointerdown',{button:2});f.win.emit('pointerup',{clientX:500});assert.equal(f.controller.snapshot().railWidth,320);
 f.ids.railSplitter.emit('pointerdown',{isPrimary:false});assert.equal(f.doc.body.classList.contains('wb-dragging'),false);
 f.ids.railSplitter.emit('pointerdown');f.win.emit('pointermove',{pointerId:2,clientX:500});f.win.emit('pointerup',{pointerId:2,clientX:500});assert.equal(f.writes.length,0);
 f.win.emit('pointercancel');
 for(const pointerType of ['touch','pen'])pointer(f,'railSplitter',16,0,{pointerType});
 assert.equal(f.controller.snapshot().railWidth,352);
});
test('keyboard arrows/Shift/Home/End/Enter and double click operate without pointer drag',()=>{
 const f=fixture();f.ids.railSplitter.emit('keydown',{key:'ArrowRight'});assert.equal(f.controller.snapshot().railWidth,336);
 f.ids.railSplitter.emit('keydown',{key:'ArrowRight',shiftKey:true});assert.equal(f.controller.snapshot().railWidth,384);
 f.ids.railSplitter.emit('keydown',{key:'Home'});assert.equal(f.controller.snapshot().railWidth,240);
 f.ids.railSplitter.emit('keydown',{key:'End'});assert.equal(f.controller.snapshot().railWidth,560);
 f.ids.railSplitter.emit('keydown',{key:'Enter'});assert.equal(f.controller.snapshot().railWidth,320);
 f.ids.tableHeightSplitter.emit('keydown',{key:'ArrowDown'});assert.equal(f.controller.snapshot().tableHeight,496);
 f.ids.tableHeightSplitter.emit('dblclick');assert.equal(f.controller.snapshot().tableHeight,480);
 const before=f.writes.length;f.ids.tableHeightSplitter.emit('keydown',{key:'ArrowDown',ctrlKey:true});assert.equal(f.writes.length,before);
});
test('stacked charts/narrow rail/hidden workbench disable relevant separator actions',()=>{
 const f=fixture({width:600,chartWidth:500});assert.equal(f.ids.workbenchView.classList.contains('wb-narrow'),true);assert.equal(f.ids.chartRow.classList.contains('wb-stacked'),true);
 assert.equal(f.ids.railSplitter.attrs['aria-disabled'],'true');assert.equal(f.ids.chartSplitter.tabIndex,-1);
 pointer(f,'railSplitter',100);pointer(f,'chartSplitter',100);assert.equal(f.writes.length,0);
 pointer(f,'flowHeightSplitter',0,100);assert.equal(f.controller.snapshot().flowHeight,440);
 f.ids.workbenchView.hidden=true;f.mos[0].cb();f.flush();pointer(f,'flowHeightSplitter',0,100);assert.equal(f.controller.snapshot().flowHeight,440);
});
test('container resize clamps effective geometry but does not overwrite preferred saved layout',()=>{
 const f=fixture({store:new Map([[ui.STORAGE_KEY,JSON.stringify({...ui.DEFAULT,railWidth:550,chartRatio:.8})]])});
 f.ids.workbenchView.width=800;f.ids.chartRow.width=500;f.win.emit('resize');f.flush();
 assert.equal(f.ids.workbenchView.properties['--wb-rail-width'],'430px');assert.equal(f.controller.snapshot().railWidth,550);assert.equal(f.writes.length,0);
 f.ids.workbenchView.width=1400;f.ids.chartRow.width=1000;f.ros[0].cb([{target:f.ids.chartRow,contentRect:{width:1000,height:340}}]);f.flush();assert.equal(f.ids.workbenchView.properties['--wb-rail-width'],'550px');
});
test('body fold mutation/visible session and resize notifications use coalesced observer path',()=>{
 const f=fixture();const start=f.notifications();f.doc.body.classList.add('rail-collapsed');f.mos[0].cb();f.flush();assert.equal(f.ids.railSplitter.attrs['aria-disabled'],'true');
 f.doc.body.classList.remove('rail-collapsed');f.doc.emit('pktpath:session-rendered');f.flush();assert.equal(f.ids.railSplitter.attrs['aria-disabled'],'false');assert.ok(f.notifications()>start);
 const before=f.notifications();const entries=[{target:f.ids.latWrap,contentRect:{width:600,height:300}}];f.ros[0].cb(entries);f.flush();assert.ok(f.notifications()>before);const once=f.notifications();f.ros[0].cb(entries);f.flush();assert.equal(f.notifications(),once);
});
test('read/getter/quota failures never block sizing or falsely claim persistence',()=>{
 for(const opts of [{getterError:true},{readError:true,writeError:true},{writeError:true}]){
  const f=fixture(opts);pointer(f,'railSplitter',20);assert.equal(f.controller.snapshot().railWidth,340);assert.match(f.ids.layoutStatus.textContent,/未能保存/);f.ids.btnResetLayout.emit('click');assert.equal(f.controller.snapshot().railWidth,320);
 }
 const corrupt=fixture({store:new Map([[ui.STORAGE_KEY,'{bad']])});assert.equal(corrupt.controller.snapshot().railWidth,320);corrupt.ids.btnResetLayout.emit('click');assert.equal(corrupt.store.has(ui.STORAGE_KEY),false);
});
test('reset cancels a live drag, clears only owned key, restore defaults and ARIA',()=>{
 const f=fixture({store:new Map([['pktpath.theme','dark'],['pktpath.rail','collapsed']])});pointer(f,'railSplitter',70);f.ids.flowHeightSplitter.emit('pointerdown');f.win.emit('pointermove',{clientY:333});f.ids.btnResetLayout.emit('click');f.flush();
 assert.deepEqual(f.controller.snapshot(),{...ui.DEFAULT});assert.equal(f.store.has(ui.STORAGE_KEY),false);assert.equal(f.store.get('pktpath.theme'),'dark');assert.equal(f.store.get('pktpath.rail'),'collapsed');assert.equal(f.ids.flowHeightSplitter.attrs['aria-valuenow'],'340');
});
test('idempotent mount and destroy remove owned observers/listeners/frames, not other app listeners',()=>{
 const f=fixture();assert.equal(ui.mount(f.doc,f.win),f.controller);f.ids.railSplitter.emit('pointerdown');f.win.emit('pointermove',{clientX:200});f.controller.destroy();f.flush();
 assert.equal(f.win.count(),0);assert.equal(f.ids.railSplitter.count(),0);assert.equal(f.raf.size,0);assert.ok(f.ros.every(x=>x.disconnected));assert.ok(f.mos.every(x=>x.disconnected));assert.equal(f.ids.workbenchView._pktpathLayout,undefined);
 f.win.emit('pointerup',{clientX:500});assert.equal(f.writes.length,0);assert.ok(ui.mount(f.doc,f.win));
});
test('HTML contract: all handles/control targets and offline scripts exist, never replace business DOM',()=>{
 const html=fs.readFileSync(path.join(here,'../../web/index.html'),'utf8');
 for(const id of ['railSplitter','chartSplitter','flowHeightSplitter','latencyHeightSplitter','tableHeightSplitter']){
  assert.equal((html.match(new RegExp(`id="${id}"`,'g'))||[]).length,1);assert.match(html,new RegExp(`id="${id}"[^>]+role="separator"`));
 }
 for(const id of ['flowWrap','latWrap','sampleBody','sampleTable','tblSearch','rail','sessionView','drawer'])assert.equal((html.match(new RegExp(`id="${id}"`,'g'))||[]).length,1);
 assert.match(html,/workbench-layout\.css/);assert.match(html,/workbench-layout\.js/);
 const source=fs.readFileSync(path.join(here,'../../web/workbench-layout.js'),'utf8');assert.doesNotMatch(source,/\bfetch\s*\(|XMLHttpRequest|\/api\//);
});


test('browser script entry initializes on DOMContentLoaded in a VM event model (not a browser)',()=>{
 const f=fixture({autoMount:false});f.doc.readyState='loading';f.win.document=f.doc;
 vm.runInNewContext(fs.readFileSync(path.join(here,'../../web/workbench-layout.js'),'utf8'),{window:f.win});
 assert.ok(f.win.PktPathWorkbenchLayout);assert.equal(f.ids.workbenchView._pktpathLayout,undefined);
 f.doc.emit('DOMContentLoaded');f.flush();assert.equal(f.ids.railSplitter.attrs['aria-valuenow'],'320');
 pointer(f,'railSplitter',30);assert.equal(f.ids.workbenchView._pktpathLayout.snapshot().railWidth,350);
 const app=fs.readFileSync(path.join(here,'../../web/app.js'),'utf8');assert.match(app,/addEventListener\('pktpath:layout-resized', debounce\(renderCharts, 50\)\)/);assert.match(app,/pktpath:session-rendered/);
 f.ids.workbenchView._pktpathLayout.destroy();
});
