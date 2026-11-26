import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadBrowserScript } from './_load-browser-script.ts';

const vp = loadBrowserScript('../../web/flow-viewport.js');

test('short-panel content box keeps the last-row TX_OK count label inside the viewBox', () => {
  const rows = 4;
  const box = vp.contentBox(5, rows);
  assert.equal(vp.containsNodeBottom(box, rows), true);
  const bottom = vp.nodeBottom(rows);
  assert.ok(box.y + box.height >= bottom);
  const fitted = vp.fittedState(box);
  assert.equal(fitted.zoom, 1);
  assert.equal(vp.viewBoxAttr(fitted), `${box.x} ${box.y} ${box.width} ${box.height}`);
  // A 240x80 panel still uses meet-fit over the full box, so nothing is cropped.
  const map = vp.viewBoxToViewport(fitted, 320, 80);
  assert.ok(map.k > 0);
  assert.ok(map.k * box.height <= 80 + 1e-9);
  assert.ok(map.k * box.width <= 320 + 1e-9);
});

test('wheel-style zoom is clamped, recenters on the pointer, and reset returns to the fitted view', () => {
  const state = vp.fittedState(vp.contentBox(3, 2));
  const zoomed = vp.zoomAt(state, 2, 50, 20, 200, 100);
  assert.equal(zoomed.zoom, 2);
  const over = vp.zoomAt(zoomed, 100, 50, 20, 200, 100);
  assert.equal(over.zoom, vp.MAX_ZOOM);
  const under = vp.zoomAt(state, 0.01, 50, 20, 200, 100);
  assert.equal(under.zoom, vp.MIN_ZOOM);
  const mid = vp.contentPointAt(state, 50, 20, 200, 100);
  const after = vp.contentPointAt(zoomed, 50, 20, 200, 100);
  assert.ok(Math.abs(mid.x - after.x) < 1e-9);
  assert.ok(Math.abs(mid.y - after.y) < 1e-9);
  const back = vp.reset(zoomed);
  assert.equal(back.zoom, 1);
  assert.equal(back.vw, state.box.width);
  assert.equal(vp.zoomPercent(zoomed), 200);
});

test('pan moves the viewBox in content space and click-vs-drag uses a pixel threshold', () => {
  const state = vp.fittedState(vp.contentBox(2, 2));
  const before = state.vx;
  const map = vp.viewBoxToViewport(state, 200, 100);
  const moved = vp.pan(state, 20, 0, 200, 100);
  assert.ok(Math.abs((before - moved.vx) * map.k - 20) < 1e-9);
  assert.equal(vp.isClick(3, 3), true);
  assert.equal(vp.isClick(6, 0), false);
});

test('mount distinguishes click from drag and does not fire node filter while panning', () => {
  const listeners = new Map();
  const svg: any = {
    style: {},
    classList: { add() {}, remove() {} },
    attrs: {},
    addEventListener(name: string, fn: Function) { listeners.set(name, fn); },
    removeEventListener(name: string) { listeners.delete(name); },
    setAttribute(k: string, v: string) { this.attrs[k] = v; },
    setPointerCapture() {},
    releasePointerCapture() {},
  };
  const wrap: any = { getBoundingClientRect: () => ({ left: 0, top: 0, width: 400, height: 200 }), clientWidth: 400, clientHeight: 200 };
  let selected: any = null;
  const ctl = vp.mount(wrap, svg, { box: vp.contentBox(2, 2), onSelect: (p: any) => { selected = p; } });
  const node = { closest: (sel: string) => sel === '[data-prefix]' ? { getAttribute: () => JSON.stringify(['TX_OK']) } : null };
  listeners.get('pointerdown')({ button: 0, isPrimary: true, pointerId: 1, clientX: 10, clientY: 10, target: node });
  listeners.get('pointerup')({ pointerId: 1, clientX: 11, clientY: 11, target: node });
  assert.deepEqual(selected, ['TX_OK']);
  selected = null;
  listeners.get('pointerdown')({ button: 0, isPrimary: true, pointerId: 2, clientX: 10, clientY: 10, target: node });
  listeners.get('pointermove')({ pointerId: 2, clientX: 40, clientY: 10, preventDefault() {}, target: node });
  listeners.get('pointerup')({ pointerId: 2, clientX: 40, clientY: 10, target: node });
  assert.equal(selected, null);
  assert.ok(ctl.getState().vx !== vp.fittedState(vp.contentBox(2, 2)).vx);
  ctl.destroy();
});

test('node click still fires when pointerup target is retargeted to svg and defers pointer capture until pan', () => {
  const listeners = new Map();
  let captured = 0;
  const svg: any = {
    style: {},
    classList: { add() {}, remove() {} },
    attrs: {},
    closest: () => null,
    addEventListener(name: string, fn: Function) { listeners.set(name, fn); },
    removeEventListener(name: string) { listeners.delete(name); },
    setAttribute(k: string, v: string) { this.attrs[k] = v; },
    setPointerCapture() { captured += 1; },
    releasePointerCapture() {},
  };
  const wrap: any = { getBoundingClientRect: () => ({ left: 0, top: 0, width: 400, height: 200 }), clientWidth: 400, clientHeight: 200 };
  let selected: any = null;
  const ctl = vp.mount(wrap, svg, { box: vp.contentBox(2, 2), onSelect: (p: any) => { selected = p; } });
  const node = { closest: (sel: string) => sel === '[data-prefix]' ? { getAttribute: () => JSON.stringify(['ENTRY', 'HTB:1']) } : null };
  listeners.get('pointerdown')({ button: 0, isPrimary: true, pointerId: 7, clientX: 20, clientY: 20, target: node });
  assert.equal(captured, 0);
  listeners.get('pointerup')({ pointerId: 7, clientX: 21, clientY: 21, target: svg });
  assert.deepEqual(selected, ['ENTRY', 'HTB:1']);
  ctl.destroy();
});
