/* Sprint presentation only: explicit data provenance and transient panel focus.
 * No capture/install/config writes, no background polling, no cross-origin API.
 */
(function (host, factory) {
  'use strict';
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else {
    host.PktPathPresentation = api;
    const start = () => api.mount(host.document, host);
    if (host.document.readyState === 'loading') host.document.addEventListener('DOMContentLoaded', start, { once: true });
    else start();
  }
})(typeof window === 'undefined' ? null : window, function () {
  'use strict';
  const PANEL_NAMES = Object.freeze({panelFlow:'队列路径图',panelLatency:'驻留耗时图',panelSamples:'样本明细'});
  function modeFromLocation(loc) { return /[?&]demo=1\b/.test(loc.search || '') || loc.protocol === 'file:' ? 'demo' : 'api'; }
  function nextModeHref(href, mode) {
    if (mode !== 'demo' && mode !== 'api') throw new Error('未知数据模式');
    const url = new URL(href);
    if (mode === 'api' && !/^https?:$/.test(url.protocol)) throw new Error('真实模式需要从 Go HTTP 服务打开，不能使用 file://');
    url.searchParams.delete('demo'); url.searchParams.delete('autoload'); url.searchParams.delete('sample'); url.searchParams.delete('saved');
    if (mode === 'demo') { url.searchParams.set('demo','1'); url.searchParams.set('autoload','1'); }
    return url.href;
  }
  function isGoHealth(x) {
    return !!x && x.ok === true && Number.isSafeInteger(x.pid) && x.pid > 0 && typeof x.version === 'string' && typeof x.sessions_root === 'string' && Number.isSafeInteger(x.kernel_plugins_total) && x.kernel_plugins_total >= 0;
  }
  function mount(doc,win) {
    const root=doc.getElementById('workbenchView'), select=doc.getElementById('studioDataSource'), status=doc.getElementById('studioSourceStatus'), check=doc.getElementById('studioCheckBackend');
    if (!root || !select || !status || !check) return null;
    if (root._pktpathPresentation) return root._pktpathPresentation;
    const mode=modeFromLocation(win.location), buttons=Array.from(doc.querySelectorAll('[data-studio-focus]')), canvas=doc.getElementById('canvas');
    const off=[]; let dead=false, request=0, focused=null, previousFocus=null, previousScroll=0, restoreFrame=null;
    const listen=(el,name,fn)=>{el.addEventListener(name,fn);off.push(()=>el.removeEventListener(name,fn));};
    const say=(text,state)=>{status.textContent=text;status.dataset.state=state;};
    select.value=mode;
    const bridge=()=>win.PktPathStudio || {};
    async function health() {
      if (dead) return;
      if (mode === 'demo') { check.hidden=true; say('内置样例 · 未采集设备流量','demo'); return; }
      const id=++request; check.disabled=true; say('Go API · 正在检查同源服务','checking');
      try {
        const b=bridge(); if (typeof b.api !== 'function') throw new Error('原API桥未就绪');
        const result=await b.api('/api/health',{timeout:3000});
        if (dead || id !== request) return;
        if (!isGoHealth(result)) throw new Error('响应不是预期的 Go 服务健康信息');
        say('Go 服务已连接 · '+(result.version || '开发版')+' · 不等于设备已连接','online');
      } catch (_) { if (!dead && id === request) say('Go API 不可用 · 不会自动切换样例','offline'); }
      finally { if (!dead && id === request) check.disabled=false; }
    }
    listen(check,'click',health);
    listen(select,'change',()=>{
      if (select.value === mode) return;
      const target=select.value; select.value=mode;
      const b=bridge(), state=typeof b.getState === 'function' ? b.getState() : {};
      if (state.capturing || state.quitting) { say('采集或退出处理中，暂不切换数据模式',mode === 'demo'?'demo':'checking'); return; }
      try {
        const href=nextModeHref(win.location.href,target);
        if (mode === 'api' && (typeof win.confirm !== 'function' || !win.confirm('切换到示例会重新加载界面，不会停止后台任务。确认仅查看内置示例？'))) return;
        win.location.assign(href);
      } catch (e) { say(e.message,'offline'); }
    });
    function focusPanel(id) {
      if (id && !Object.prototype.hasOwnProperty.call(PANEL_NAMES,id)) return;
      if (!focused && id) { previousFocus=doc.activeElement; previousScroll=canvas?canvas.scrollTop:0; }
      focused=id;
      if (id) root.dataset.studioFocus=id; else delete root.dataset.studioFocus;
      buttons.forEach((btn)=>{const active=btn.dataset.studioFocus === id;btn.setAttribute('aria-pressed',String(active));btn.setAttribute('aria-label',(active?'还原':'最大化')+PANEL_NAMES[btn.dataset.studioFocus]);btn.textContent=active?'还原 · Esc':'最大化';});
      doc.dispatchEvent(new win.CustomEvent('pktpath:layout-resized'));
      if (restoreFrame !== null) win.cancelAnimationFrame(restoreFrame);
      restoreFrame=win.requestAnimationFrame(()=>{
        restoreFrame=null;
        if (dead) return;
        if (canvas) canvas.scrollTop=id?0:previousScroll;
        if (!id && previousFocus && previousFocus.isConnected && typeof previousFocus.focus === 'function') previousFocus.focus();
      });
    }
    buttons.forEach((btn)=>listen(btn,'click',()=>focusPanel(focused === btn.dataset.studioFocus?null:btn.dataset.studioFocus)));
    listen(doc,'keydown',(e)=>{if(e.key==='Escape' && !e.defaultPrevented && focused){e.preventDefault();focusPanel(null);}});
    health();
    const controller={mode,focusPanel,getFocused:()=>focused,destroy:()=>{
      if(dead)return;request++;focusPanel(null);dead=true;off.forEach((fn)=>fn());if(restoreFrame!==null)win.cancelAnimationFrame(restoreFrame);delete root._pktpathPresentation;
    }};
    root._pktpathPresentation=controller;
    return controller;
  }
  return {modeFromLocation,nextModeHref,isGoHealth,mount};
});
