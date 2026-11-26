/* Queue-path flow viewport: fit the full graph (including bottom TX_OK) into
 * a short panel, wheel-zoom around the pointer, drag-pan, click-vs-drag, and
 * a compact zoom toolbar. CommonJS export is solely for Node model tests.
 */
(function (host, factory) {
  'use strict';
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else host.PktPathFlowViewport = api;
})(typeof window === 'undefined' ? null : window, function () {
  'use strict';

  const MIN_ZOOM = 0.25;
  const MAX_ZOOM = 4;
  const ZOOM_STEP = 1.25;
  const CLICK_PIXELS = 5;
  const FIT_PAD_X = 16;
  const FIT_PAD_TOP = 16;
  const FIT_PAD_BOTTOM = 22;

  function layoutMetrics() {
    return { nodeW: 100, nodeH: 38, col: 132, row: 56, padX: 12, padY: 22, countOffset: 11, countDescent: 4, badgeRise: 9, badgeH: 15 };
  }

  function clampZoom(z) {
    const n = typeof z === 'number' && isFinite(z) ? z : 1;
    return Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, n));
  }

  function innerSize(maxDepth, rows, metrics) {
    const m = Object.assign(layoutMetrics(), metrics || {});
    const depth = Math.max(0, maxDepth);
    const rowCount = Math.max(1, rows);
    const width = m.padX * 2 + (depth + 1) * m.col - (m.col - m.nodeW);
    const height = m.padY * 2 + rowCount * m.row - (m.row - m.nodeH);
    return { width, height, metrics: m, rows: rowCount, maxDepth: depth };
  }

  function nodeBottom(rows, metrics) {
    const m = Object.assign(layoutMetrics(), metrics || {});
    const lastY = m.padY + (Math.max(1, rows) - 1) * m.row;
    return lastY + m.nodeH + m.countOffset + m.countDescent;
  }

  function contentBox(maxDepth, rows, metrics) {
    const inner = innerSize(maxDepth, rows, metrics);
    const m = inner.metrics;
    const badgeTop = m.padY - m.badgeRise;
    const top = Math.max(FIT_PAD_TOP, badgeTop < 0 ? -badgeTop + 2 : FIT_PAD_TOP);
    const bottomNeeded = nodeBottom(inner.rows, m) - inner.height;
    const bottom = Math.max(FIT_PAD_BOTTOM, bottomNeeded + 2);
    return {
      x: -FIT_PAD_X,
      y: -top,
      width: inner.width + FIT_PAD_X * 2,
      height: inner.height + top + bottom,
      innerWidth: inner.width,
      innerHeight: inner.height,
      padTop: top,
      padBottom: bottom,
    };
  }

  function containsNodeBottom(box, rows, metrics) {
    if (!box) return false;
    return (box.y + box.height) >= nodeBottom(rows, metrics);
  }

  function fittedState(box) {
    return { box: box, zoom: 1, vx: box.x, vy: box.y, vw: box.width, vh: box.height };
  }

  function viewBoxToViewport(state, viewW, viewH) {
    const vw = Math.max(1e-6, state.vw);
    const vh = Math.max(1e-6, state.vh);
    const k = Math.min(Math.max(0, viewW) / vw, Math.max(0, viewH) / vh);
    const usedW = vw * k;
    const usedH = vh * k;
    return { k: k || 0, ox: (viewW - usedW) / 2, oy: (viewH - usedH) / 2, x: state.vx, y: state.vy };
  }

  function contentPointAt(state, pivotX, pivotY, viewW, viewH) {
    const map = viewBoxToViewport(state, viewW, viewH);
    if (!map.k) return { x: state.vx + state.vw / 2, y: state.vy + state.vh / 2 };
    return { x: map.x + (pivotX - map.ox) / map.k, y: map.y + (pivotY - map.oy) / map.k };
  }

  function zoomAt(state, factor, pivotX, pivotY, viewW, viewH) {
    const nextZoom = clampZoom(state.zoom * factor);
    const applied = nextZoom / state.zoom;
    if (applied === 1) return Object.assign({}, state);
    const midX = viewW / 2;
    const midY = viewH / 2;
    const px = pivotX == null || !isFinite(pivotX) ? midX : pivotX;
    const py = pivotY == null || !isFinite(pivotY) ? midY : pivotY;
    const pt = contentPointAt(state, px, py, viewW, viewH);
    return {
      box: state.box,
      zoom: nextZoom,
      vw: state.vw / applied,
      vh: state.vh / applied,
      vx: pt.x - (pt.x - state.vx) / applied,
      vy: pt.y - (pt.y - state.vy) / applied,
    };
  }

  function pan(state, dxPx, dyPx, viewW, viewH) {
    const map = viewBoxToViewport(state, viewW, viewH);
    const k = map.k || 1;
    return {
      box: state.box,
      zoom: state.zoom,
      vw: state.vw,
      vh: state.vh,
      vx: state.vx - dxPx / k,
      vy: state.vy - dyPx / k,
    };
  }

  function reset(state) {
    return fittedState(state.box);
  }

  function viewBoxAttr(state) {
    return `${state.vx} ${state.vy} ${state.vw} ${state.vh}`;
  }

  function isClick(dx, dy, threshold) {
    const t = threshold == null ? CLICK_PIXELS : threshold;
    return (dx * dx + dy * dy) <= t * t;
  }

  function zoomPercent(state) {
    return Math.round((state && state.zoom ? state.zoom : 1) * 100);
  }

  function applyViewBox(svg, state) {
    if (!svg || !state) return;
    if (typeof svg.setAttribute === 'function') svg.setAttribute('viewBox', viewBoxAttr(state));
    svg.setAttribute && svg.setAttribute('preserveAspectRatio', 'xMidYMid meet');
  }

  function sizeOf(el) {
    if (!el) return { width: 0, height: 0 };
    if (typeof el.getBoundingClientRect === 'function') {
      const r = el.getBoundingClientRect();
      if (r && r.width && r.height) return { width: r.width, height: r.height };
    }
    return { width: el.clientWidth || el.width || 0, height: el.clientHeight || el.height || 0 };
  }

  function mount(wrap, svg, opts) {
    const options = opts || {};
    const win = options.window || (typeof window === 'undefined' ? null : window);
    const box = options.box || contentBox(0, 1);
    let state = options.state ? Object.assign({}, options.state, { box: options.state.box || box }) : fittedState(box);
    let currentSvg = svg;
    const toolbar = options.toolbar || {};
    const unlisten = [];
    let svgOff = [];
    const listenOn = (bucket, el, name, fn, cap) => {
      if (!el || typeof el.addEventListener !== 'function') return;
      el.addEventListener(name, fn, cap);
      bucket.push(() => el.removeEventListener(name, fn, cap));
    };
    const listen = (el, name, fn, cap) => listenOn(unlisten, el, name, fn, cap);
    let drag = null;
    let dead = false;

    function viewportSize() {
      return sizeOf(wrap);
    }

    function sync() {
      applyViewBox(currentSvg, state);
      if (toolbar.pct) toolbar.pct.textContent = zoomPercent(state) + '%';
      if (typeof options.onViewChange === 'function') options.onViewChange(state);
    }

    function zoomBy(factor, ev) {
      const size = viewportSize();
      let px = size.width / 2;
      let py = size.height / 2;
      if (ev && typeof ev.clientX === 'number' && typeof wrap.getBoundingClientRect === 'function') {
        const r = wrap.getBoundingClientRect();
        px = ev.clientX - r.left;
        py = ev.clientY - r.top;
      }
      state = zoomAt(state, factor, px, py, size.width, size.height);
      sync();
    }

    function resetView() {
      state = reset(state);
      sync();
    }

    function onWheel(e) {
      if (dead) return;
      if (typeof e.preventDefault === 'function') e.preventDefault();
      const factor = (e.deltaY || 0) > 0 ? 1 / ZOOM_STEP : ZOOM_STEP;
      zoomBy(factor, e);
    }

    function onPointerDown(e) {
      if (dead) return;
      if (e.button != null && e.button !== 0) return;
      if (e.isPrimary === false) return;
      const handle = e.target && e.target.closest && e.target.closest('.wb-splitter, .flow-zoom-toolbar, button, a');
      if (handle) return;
      const startNode = e.target && e.target.closest ? e.target.closest('[data-prefix]') : null;
      drag = { id: e.pointerId, x: e.clientX, y: e.clientY, moved: false, captured: false, node: startNode };
    }

    function onPointerMove(e) {
      if (!drag || e.pointerId !== drag.id) return;
      const dx = e.clientX - drag.x;
      const dy = e.clientY - drag.y;
      if (!drag.moved && !isClick(dx, dy)) {
        drag.moved = true;
        if (currentSvg && typeof currentSvg.setPointerCapture === 'function' && drag.id != null) {
          try { currentSvg.setPointerCapture(drag.id); drag.captured = true; } catch (_) { /* ignore */ }
        }
        if (currentSvg && currentSvg.classList) currentSvg.classList.add('flow-panning');
      }
      if (!drag.moved) return;
      if (typeof e.preventDefault === 'function') e.preventDefault();
      const size = viewportSize();
      state = pan(state, dx, dy, size.width, size.height);
      drag.x = e.clientX;
      drag.y = e.clientY;
      sync();
    }

    function endDrag(e, asClick) {
      if (!drag) return;
      const started = drag;
      drag = null;
      if (currentSvg && currentSvg.classList) currentSvg.classList.remove('flow-panning');
      if (started.captured && currentSvg && typeof currentSvg.releasePointerCapture === 'function' && started.id != null) {
        try { currentSvg.releasePointerCapture(started.id); } catch (_) { /* ignore */ }
      }
      if (!asClick || started.moved || !e) return;
      const node = started.node || (e.target && e.target.closest && e.target.closest('[data-prefix]'));
      if (!node || typeof options.onSelect !== 'function') return;
      try {
        options.onSelect(JSON.parse(node.getAttribute('data-prefix')));
      } catch (_) { /* ignore */ }
    }

    function onPointerUp(e) {
      if (!drag || (e.pointerId != null && e.pointerId !== drag.id)) return;
      endDrag(e, true);
    }

    function onPointerCancel(e) {
      if (!drag || (e.pointerId != null && e.pointerId !== drag.id)) return;
      endDrag(e, false);
    }

    function onDblClick(e) {
      if (e.target && e.target.closest && e.target.closest('.flow-zoom-toolbar, button, a')) return;
      if (typeof e.preventDefault === 'function') e.preventDefault();
      resetView();
    }

    function bindSvg(nextSvg) {
      svgOff.forEach((fn) => fn());
      svgOff = [];
      currentSvg = nextSvg;
      if (!currentSvg) return;
      if (currentSvg.style) {
        currentSvg.style.width = '100%';
        currentSvg.style.height = '100%';
        currentSvg.style.display = 'block';
        currentSvg.style.touchAction = 'none';
      }
      currentSvg.setAttribute && currentSvg.setAttribute('preserveAspectRatio', 'xMidYMid meet');
      listenOn(svgOff, currentSvg, 'wheel', onWheel, { passive: false });
      listenOn(svgOff, currentSvg, 'pointerdown', onPointerDown);
      listenOn(svgOff, currentSvg, 'pointermove', onPointerMove);
      listenOn(svgOff, currentSvg, 'pointerup', onPointerUp);
      listenOn(svgOff, currentSvg, 'pointercancel', onPointerCancel);
      listenOn(svgOff, currentSvg, 'lostpointercapture', onPointerCancel);
      listenOn(svgOff, currentSvg, 'dblclick', onDblClick);
      sync();
    }

    listen(toolbar.zoomIn, 'click', (e) => { if (e && e.preventDefault) e.preventDefault(); zoomBy(ZOOM_STEP); });
    listen(toolbar.zoomOut, 'click', (e) => { if (e && e.preventDefault) e.preventDefault(); zoomBy(1 / ZOOM_STEP); });
    listen(toolbar.reset, 'click', (e) => { if (e && e.preventDefault) e.preventDefault(); resetView(); });
    if (win) listen(win, 'blur', () => endDrag({}, false));

    bindSvg(svg);

    return {
      getState: () => state,
      zoomBy,
      resetView,
      replaceSvg: (nextSvg, nextBox) => {
        const prevZoom = state.zoom;
        const prev = state;
        if (nextBox) {
          if (prevZoom === 1) state = fittedState(nextBox);
          else state = Object.assign({}, prev, { box: nextBox });
        }
        bindSvg(nextSvg);
      },
      destroy: () => {
        if (dead) return;
        dead = true;
        drag = null;
        svgOff.forEach((fn) => fn());
        svgOff = [];
        unlisten.forEach((fn) => fn());
      },
    };
  }

  return {
    MIN_ZOOM, MAX_ZOOM, ZOOM_STEP, CLICK_PIXELS, FIT_PAD_X, FIT_PAD_TOP, FIT_PAD_BOTTOM,
    layoutMetrics, innerSize, nodeBottom, contentBox, containsNodeBottom,
    clampZoom, fittedState, viewBoxToViewport, contentPointAt, zoomAt, pan, reset,
    viewBoxAttr, isClick, zoomPercent, applyViewBox, mount,
  };
});
