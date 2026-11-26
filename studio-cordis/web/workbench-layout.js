/* M1: local-only workbench geometry. No backend/config/plugin/transport calls.
 * CommonJS export is solely for dependency-free Node model tests, not a bundle.
 */
(function (host, factory) {
  'use strict';
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else {
    host.PktPathWorkbenchLayout = api;
    const start = () => api.mount(host.document, host);
    if (host.document.readyState === 'loading') host.document.addEventListener('DOMContentLoaded', start, { once: true });
    else start();
  }
})(typeof window === 'undefined' ? null : window, function () {
  'use strict';
  const STORAGE_KEY = 'pktpath.workbench-layout.v1';
  const DEFAULT = Object.freeze({ version: 1, railWidth: 320, chartRatio: 0.535, flowHeight: 340, latencyHeight: 340, tableHeight: 480 });
  const clamp = (x, min, max) => Math.max(min, Math.min(max, x));
  const finite = (x, fallback) => typeof x === 'number' && Number.isFinite(x) ? x : fallback;
  function normalize(raw) {
    const x = raw && typeof raw === 'object' && !Array.isArray(raw) && raw.version === 1 ? raw : DEFAULT;
    return {
      version: 1,
      railWidth: Math.round(clamp(finite(x.railWidth, DEFAULT.railWidth), 240, 560)),
      chartRatio: clamp(finite(x.chartRatio, DEFAULT.chartRatio), 0.1, 0.9),
      flowHeight: Math.round(clamp(finite(x.flowHeight, DEFAULT.flowHeight), 240, 1200)),
      latencyHeight: Math.round(clamp(finite(x.latencyHeight, DEFAULT.latencyHeight), 240, 1200)),
      tableHeight: Math.round(clamp(finite(x.tableHeight, DEFAULT.tableHeight), 280, 1600)),
    };
  }
  function constraints(width, chartWidth, collapsed, sessionVisible) {
    const w = Math.max(0, finite(width, 0));
    const cw = Math.max(0, finite(chartWidth, 0));
    const narrow = w < 680;
    const stacked = cw < 570;
    const railMax = Math.max(240, Math.min(560, w - 370));
    const ratioMin = stacked ? 0.5 : 280 / (cw - 10);
    return { narrow, stacked, railMax, ratioMin, ratioMax: 1 - ratioMin,
      railEnabled: !narrow && !collapsed && w > 0,
      chartEnabled: !stacked && !!sessionVisible,
      heightEnabled: !!sessionVisible,
    };
  }
  function mount(doc, win) {
    const byId = (id) => doc.getElementById(id);
    const root = byId('workbenchView');
    if (!root) return null;
    if (root._pktpathLayout) return root._pktpathLayout;
    const row = byId('chartRow');
    const status = byId('layoutStatus');
    const demoBadge = byId('layoutDemoBadge');
    if (demoBadge) demoBadge.hidden = !(/[?&]demo=1\b/.test(win.location?.search || '') || win.location?.protocol === 'file:');
    const panels = { flowHeight: byId('panelFlow'), latencyHeight: byId('panelLatency'), tableHeight: byId('panelSamples') };
    if (!row || Object.values(panels).some((x) => !x)) return null;
    let state = normalize(null), storage = null, dead = false, frame = null, notifyFrame = null, drag = null;
    const unlisten = [], observers = [];
    const say = (text) => { if (status) status.textContent = text; };
    try {
      storage = win.localStorage;
      const raw = storage.getItem(STORAGE_KEY);
      if (raw !== null) {
        const parsed = JSON.parse(raw);
        state = normalize(parsed);
        say(parsed && parsed.version === 1 ? '已恢复此浏览器布局' : '旧布局格式已忽略，使用默认布局');
      }
    } catch (_) { say('浏览器布局存储不可用；本次仍可调整'); }
    function save() {
      try {
        if (!storage) throw new Error('storage unavailable');
        storage.setItem(STORAGE_KEY, JSON.stringify(state));
        say('布局已保存在此浏览器');
      } catch (_) { say('本次布局已调整，但浏览器未能保存'); }
    }
    function listen(target, name, fn, options) {
      target.addEventListener(name, fn, options);
      unlisten.push(() => target.removeEventListener(name, fn, options));
    }
    function geometry() {
      const session = byId('sessionView');
      return constraints(root.getBoundingClientRect().width, row.getBoundingClientRect().width,
        doc.body.classList.contains('rail-collapsed'), !root.hidden && !!session && !session.hidden);
    }
    function notify() {
      if (dead || notifyFrame !== null) return;
      notifyFrame = win.requestAnimationFrame(() => {
        notifyFrame = null;
        if (!dead) doc.dispatchEvent(new win.CustomEvent('pktpath:layout-resized'));
      });
    }
    const defs = [
      { id: 'railSplitter', key: 'railWidth', axis: 'x' },
      { id: 'chartSplitter', key: 'chartRatio', axis: 'x' },
      { id: 'flowHeightSplitter', key: 'flowHeight', axis: 'y' },
      { id: 'latencyHeightSplitter', key: 'latencyHeight', axis: 'y' },
      { id: 'tableHeightSplitter', key: 'tableHeight', axis: 'y' },
    ];
    function range(def, g) {
      if (def.key === 'railWidth') return { min: 240, max: g.railMax, enabled: !root.hidden && g.railEnabled };
      if (def.key === 'chartRatio') return { min: g.ratioMin, max: g.ratioMax, enabled: !root.hidden && g.chartEnabled };
      return { min: def.key === 'tableHeight' ? 280 : 240, max: def.key === 'tableHeight' ? 1600 : 1200, enabled: g.heightEnabled };
    }
    function apply() {
      if (dead) return;
      const g = geometry();
      root.classList.toggle('wb-narrow', g.narrow);
      root.style.setProperty('--wb-rail-width', `${clamp(state.railWidth, 240, g.railMax)}px`);
      row.classList.toggle('wb-stacked', g.stacked);
      const ratio = clamp(state.chartRatio, g.ratioMin, g.ratioMax);
      row.style.gridTemplateColumns = g.stacked ? 'minmax(0, 1fr)' : `minmax(0, ${ratio}fr) 10px minmax(0, ${1 - ratio}fr)`;
      Object.keys(panels).forEach((key) => { panels[key].style.height = `${state[key]}px`; });
      defs.forEach((def) => {
        const el = byId(def.id); if (!el) return;
        const r = range(def, g), ratioKey = def.key === 'chartRatio';
        const val = clamp(state[def.key], r.min, r.max), unit = ratioKey ? 100 : 1;
        el.setAttribute('aria-valuemin', String(Math.round(r.min * unit)));
        el.setAttribute('aria-valuemax', String(Math.round(r.max * unit)));
        el.setAttribute('aria-valuenow', String(Math.round(val * unit)));
        el.setAttribute('aria-valuetext', ratioKey ? `路径图占${Math.round(val * 100)}%` : `${Math.round(val)}像素`);
        el.setAttribute('aria-disabled', String(!r.enabled));
        el.tabIndex = r.enabled ? 0 : -1;
      });
      notify();
    }
    function schedule() {
      if (dead || frame !== null) return;
      frame = win.requestAnimationFrame(() => { frame = null; apply(); });
    }
    function endDrag(commit, event) {
      if (!drag || (event && event.pointerId !== undefined && event.pointerId !== drag.pointerId)) return;
      const current = drag;
      if (commit && event) move(event);
      drag = null;
      current.off.forEach((off) => off());
      if (!commit) state = current.before;
      current.el.classList.remove('wb-active');
      doc.body.classList.remove('wb-dragging');
      doc.body.style.removeProperty('--wb-drag-cursor');
      try { if (current.el.hasPointerCapture && current.el.hasPointerCapture(current.pointerId)) current.el.releasePointerCapture(current.pointerId); } catch (_) { /* detached/ended pointer */ }
      apply();
      if (commit) save();
      else say('已取消本次拖拽，布局未保存');
    }
    function move(event) {
      if (!drag || event.pointerId !== drag.pointerId) return;
      const coord = drag.def.axis === 'x' ? event.clientX : event.clientY;
      if (!Number.isFinite(coord)) return;
      const delta = coord - drag.origin;
      const divisor = drag.def.key === 'chartRatio' ? drag.divisor : 1;
      state[drag.def.key] = clamp(drag.start + delta / divisor, drag.min, drag.max);
      state = normalize(state);
      event.preventDefault();
      schedule();
    }
    defs.forEach((def) => {
      const el = byId(def.id); if (!el) return;
      listen(el, 'pointerdown', (event) => {
        const r = range(def, geometry());
        if (dead || drag || event.button !== 0 || event.isPrimary === false || !r.enabled) return;
        const origin = def.axis === 'x' ? event.clientX : event.clientY;
        if (!Number.isFinite(origin)) return;
        event.preventDefault(); el.focus({ preventScroll: true });
        const off = [];
        drag = { def, el, before: normalize(state), pointerId: event.pointerId, origin,
          start: clamp(state[def.key], r.min, r.max), min: r.min, max: r.max,
          divisor: Math.max(1, row.getBoundingClientRect().width - 10), off };
        const during = (target, name, fn) => {
          target.addEventListener(name, fn, true);
          off.push(() => target.removeEventListener(name, fn, true));
        };
        during(win, 'pointermove', move);
        during(win, 'pointerup', (e) => endDrag(true, e));
        during(win, 'pointercancel', (e) => endDrag(false, e));
        during(win, 'blur', () => endDrag(false));
        during(el, 'lostpointercapture', (e) => endDrag(false, e));
        during(win, 'keydown', (e) => { if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); endDrag(false); } });
        doc.body.classList.add('wb-dragging');
        doc.body.style.setProperty('--wb-drag-cursor', def.axis === 'x' ? 'col-resize' : 'row-resize');
        el.classList.add('wb-active');
        try { if (el.setPointerCapture) el.setPointerCapture(event.pointerId); } catch (_) { /* window handlers still drain outside handle */ }
      });
      listen(el, 'keydown', (event) => {
        if (drag || dead || event.altKey || event.ctrlKey || event.metaKey) return;
        const r = range(def, geometry()); if (!r.enabled) return;
        const less = def.axis === 'x' ? 'ArrowLeft' : 'ArrowUp';
        const more = def.axis === 'x' ? 'ArrowRight' : 'ArrowDown';
        const step = def.key === 'chartRatio' ? (event.shiftKey ? 0.08 : 0.02) : (event.shiftKey ? 48 : 16);
        let val = clamp(state[def.key], r.min, r.max);
        if (event.key === less) val -= step;
        else if (event.key === more) val += step;
        else if (event.key === 'Home') val = r.min;
        else if (event.key === 'End') val = r.max;
        else if (event.key === 'Enter') val = DEFAULT[def.key];
        else return;
        event.preventDefault();
        state[def.key] = clamp(val, r.min, r.max); state = normalize(state);
        apply(); save();
      });
      listen(el, 'dblclick', (event) => {
        const r = range(def, geometry()); if (drag || !r.enabled) return;
        event.preventDefault(); state[def.key] = DEFAULT[def.key]; apply(); save();
      });
    });
    const reset = byId('btnResetLayout');
    if (reset) listen(reset, 'click', () => {
      endDrag(false); state = normalize(null); apply();
      try {
        if (!storage) throw new Error('storage unavailable');
        storage.removeItem(STORAGE_KEY); say('已重置为默认布局');
      } catch (_) { say('已重置本次布局；浏览器存储不可用'); }
    });
    listen(win, 'resize', () => { endDrag(false); schedule(); });
    listen(doc, 'pktpath:session-rendered', schedule);
    listen(doc, 'visibilitychange', () => { if (doc.hidden) endDrag(false); });
    if (win.ResizeObserver) {
      const sizes = new Map();
      const ro = new win.ResizeObserver((entries) => {
        let changed = false;
        entries.forEach((entry) => {
          const size = `${entry.contentRect.width}:${entry.contentRect.height}`;
          if (sizes.get(entry.target) !== size) { sizes.set(entry.target, size); changed = true; }
        });
        if (changed) schedule();
      });
      [root, row, byId('flowWrap'), byId('latWrap')].filter(Boolean).forEach((el) => ro.observe(el));
      observers.push(ro);
    }
    if (win.MutationObserver) {
      const mo = new win.MutationObserver(schedule);
      mo.observe(doc.body, { attributes: true, attributeFilter: ['class'] });
      mo.observe(root, { attributes: true, attributeFilter: ['hidden'] });
      observers.push(mo);
    }
    const controller = {
      snapshot: () => normalize(state),
      destroy: () => {
        if (dead) return;
        endDrag(false); dead = true;
        unlisten.forEach((off) => off()); observers.forEach((o) => o.disconnect());
        if (frame !== null) win.cancelAnimationFrame(frame);
        if (notifyFrame !== null) win.cancelAnimationFrame(notifyFrame);
        delete root._pktpathLayout;
      },
    };
    root._pktpathLayout = controller;
    apply();
    return controller;
  }
  return { STORAGE_KEY, DEFAULT, normalize, constraints, mount };
});
