// Explicit DOM/event model only. No browser rendering, devices, or live transport.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { loadBrowserScript } from './_load-browser-script.ts';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const ui = loadBrowserScript('../../web/studio-presentation.js');

class El {
  events = new Map();
  dataset: Record<string, string> = {};
  attrs: Record<string, string> = {};
  textContent = '';
  hidden = false;
  disabled = false;
  isConnected = true;
  scrollTop = 0;
  addEventListener(k: string, fn: Function) { if (!this.events.has(k)) this.events.set(k, new Set()); this.events.get(k)!.add(fn); }
  removeEventListener(k: string, fn: Function) { this.events.get(k)?.delete(fn); }
  emit(k: string, extras: any = {}) { const e = { type: k, preventDefault() { this.defaultPrevented = true; }, ...extras }; for (const fn of [...(this.events.get(k) || [])]) fn(e); return e; }
  dispatchEvent(e: any) { this.emit(e.type, e); }
  setAttribute(k: string, v: string) { this.attrs[k] = v; }
  focus() { (this as any).focused = true; }
}

const good = () => ({ ok: true, pid: 42, version: 'cordis-wave1', sessions_root: '/tmp/test', kernel_plugins_total: 4, runtime: { engine: 'cordis-node', node_version: 'v24.22.1' } });

function fixture(opts: any = {}) {
  const ids = Object.fromEntries(['workbenchView', 'studioDataSource', 'studioSourceStatus', 'studioCheckBackend', 'canvas'].map((id) => [id, new El()]));
  const doc: any = new El();
  const buttons = ['panelFlow', 'panelLatency', 'panelSamples'].map((id) => { const e = new El(); e.dataset.studioFocus = id; return e; });
  doc.getElementById = (id: string) => ids[id];
  doc.querySelectorAll = () => buttons;
  doc.activeElement = buttons[0];
  let count = 0;
  const frames = new Map();
  const calls: any[] = [];
  const nav: string[] = [];
  const href = opts.href || 'http://127.0.0.1:17873/?demo=1&autoload=1';
  const loc: any = new URL(href);
  loc.assign = (x: string) => nav.push(x);
  const win: any = {
    location: loc,
    confirm: () => opts.confirm !== false,
    requestAnimationFrame(fn: Function) { frames.set(++count, fn); return count; },
    cancelAnimationFrame(id: number) { frames.delete(id); },
    CustomEvent: class { type: string; constructor(type: string) { this.type = type; } },
    PktPathStudio: {
      getState: () => opts.state || {},
      api: (url: string, options: any) => { calls.push({ url, options }); return opts.api ? opts.api() : Promise.resolve(good()); },
    },
  };
  const controller = ui.mount(doc, win);
  const flush = () => { for (const [id, fn] of [...frames]) { frames.delete(id); fn(); } };
  return { ids, buttons, doc, win, controller, calls, nav, flush };
}
const settled = () => new Promise((resolve) => setImmediate(resolve));

test('data mode exactly follows existing app query/file contract', () => {
  assert.equal(ui.modeFromLocation(new URL('https://example.test/?demo=1')), 'demo');
  assert.equal(ui.modeFromLocation(new URL('https://example.test/?demo=10')), 'api');
  assert.equal(ui.modeFromLocation(new URL('file:///test/index.html')), 'demo');
  assert.equal(ui.modeFromLocation(new URL('https://example.test/')), 'api');
});

test('mode navigation is explicit, same-origin and cleans sample-only flags', () => {
  const next = new URL(ui.nextModeHref('http://127.0.0.1:123/?demo=1&demo=0&sample=2&saved=1&x=3', 'api'));
  assert.equal(next.origin, 'http://127.0.0.1:123');
  assert.equal(next.search, '?x=3');
  const demo = new URL(ui.nextModeHref(next.href, 'demo'));
  assert.equal(demo.searchParams.get('demo'), '1');
  assert.equal(demo.searchParams.get('autoload'), '1');
  assert.throws(() => ui.nextModeHref('file:///index.html', 'api'), /HTTP/);
  assert.throws(() => ui.nextModeHref(next.href, 'oops'), /未知/);
});

test('health recognition requires a Cordis runtime and rejects HTML, generic ok, malformed and unsafe identity', () => {
  assert.equal(ui.isCordisHealth(good()), true);
  for (const x of [null, {}, '<html>', { ok: true }, ...['pid', 'version', 'sessions_root', 'kernel_plugins_total'].map((k) => ({ ...good(), [k]: null })), { ...good(), pid: 2 ** 53 }, { ...good(), kernel_plugins_total: -1 }, { ...good(), runtime: { engine: 'go-studio' } }, { ...good(), runtime: null }]) {
    assert.equal(ui.isCordisHealth(x), false);
  }
});

test('demo stays explicitly synthetic and performs zero health/API calls', () => {
  const f = fixture();
  assert.equal(f.controller.mode, 'demo');
  assert.equal(f.ids.studioSourceStatus.dataset.state, 'demo');
  assert.match(f.ids.studioSourceStatus.textContent, /未采集/);
  assert.equal(f.ids.studioCheckBackend.hidden, true);
  assert.equal(f.calls.length, 0);
});

test('real Cordis health is read-only same-origin and never claims a device is connected', async () => {
  const f = fixture({ href: 'http://localhost:123/' });
  await settled();
  assert.deepEqual(f.calls, [{ url: '/api/health', options: { timeout: 3000 } }]);
  assert.equal(f.ids.studioSourceStatus.dataset.state, 'online');
  assert.match(f.ids.studioSourceStatus.textContent, /本地 Cordis 服务已连接/);
  assert.doesNotMatch(f.ids.studioSourceStatus.textContent, /不等于设备|Go 服务/);
  assert.equal(f.nav.length, 0);
});

test('failure or malformed HTTP200 never silently enables demo', async () => {
  for (const api of [() => Promise.reject(new Error('404')), () => Promise.resolve({ raw: '<html>' }), () => Promise.resolve({ ok: true })]) {
    const f = fixture({ href: 'http://localhost:123/', api });
    await settled();
    assert.equal(f.ids.studioSourceStatus.dataset.state, 'offline');
    assert.equal(f.ids.studioDataSource.value, 'api');
    assert.equal(f.nav.length, 0);
    assert.match(f.ids.studioSourceStatus.textContent, /不会自动/);
  }
});

test('late health is fenced by request ID and destroyed instances', async () => {
  const resolve: Function[] = [];
  const f = fixture({ href: 'http://localhost:123/', api: () => new Promise((r) => resolve.push(r)) });
  f.ids.studioCheckBackend.emit('click');
  resolve[1](good());
  await settled();
  resolve[0]({});
  await settled();
  assert.equal(f.ids.studioSourceStatus.dataset.state, 'online');
  f.ids.studioCheckBackend.emit('click');
  f.controller.destroy();
  const text = f.ids.studioSourceStatus.textContent;
  resolve[2](good());
  await settled();
  assert.equal(f.ids.studioSourceStatus.textContent, text);
});

test('capture/quit blocks navigation; explicit confirm cancellation preserves mode', async () => {
  for (const state of [{ capturing: true }, { quitting: true }]) {
    const f = fixture({ href: 'http://localhost:123/', state });
    await settled();
    f.ids.studioDataSource.value = 'demo';
    f.ids.studioDataSource.emit('change');
    assert.equal(f.nav.length, 0);
    assert.equal(f.ids.studioDataSource.value, 'api');
  }
  const declined = fixture({ href: 'http://localhost:123/', confirm: false });
  declined.ids.studioDataSource.value = 'demo';
  declined.ids.studioDataSource.emit('change');
  assert.equal(declined.nav.length, 0);
  const yes = fixture({ href: 'http://localhost:123/' });
  yes.ids.studioDataSource.value = 'demo';
  yes.ids.studioDataSource.emit('change');
  assert.match(yes.nav[0], /demo=1/);
  const file = fixture({ href: 'file:///index.html' });
  file.ids.studioDataSource.value = 'api';
  file.ids.studioDataSource.emit('change');
  assert.equal(file.nav.length, 0);
  assert.match(file.ids.studioSourceStatus.textContent, /HTTP/);
});

test('all three panels focus/restore in place, preserve scroll and emit redraw', () => {
  const f = fixture();
  let redraw = 0;
  f.doc.addEventListener('pktpath:layout-resized', () => redraw++);
  f.ids.canvas.scrollTop = 240;
  for (let i = 0; i < 3; i++) {
    f.buttons[i].emit('click');
    f.flush();
    assert.equal(f.controller.getFocused(), f.buttons[i].dataset.studioFocus);
    assert.equal(f.ids.workbenchView.dataset.studioFocus, f.controller.getFocused());
    assert.equal(f.buttons[i].attrs['aria-pressed'], 'true');
    assert.equal(f.ids.canvas.scrollTop, 0);
    f.buttons[i].emit('click');
    f.flush();
    assert.equal(f.controller.getFocused(), null);
    assert.equal(f.ids.workbenchView.dataset.studioFocus, undefined);
    assert.equal(f.ids.canvas.scrollTop, 240);
  }
  assert.equal(redraw, 6);
  assert.equal((f.buttons[0] as any).focused, true);
  const before = redraw;
  f.controller.focusPanel('__proto__');
  assert.equal(redraw, before);
});

test('Escape restores transient focus; idempotent mount/destroy do not own persistent geometry', () => {
  const f = fixture();
  assert.equal(ui.mount(f.doc, f.win), f.controller);
  f.buttons[1].emit('click');
  assert.equal(f.doc.emit('keydown', { key: 'Escape' }).defaultPrevented, true);
  assert.equal(f.controller.getFocused(), null);
  f.buttons[2].emit('click');
  f.controller.destroy();
  f.flush();
  assert.equal(f.ids.workbenchView.dataset.studioFocus, undefined);
  assert.equal((f.ids.workbenchView as any)._pktpathPresentation, undefined);
  assert.equal(f.buttons[2].events.get('click')!.size, 0);
  assert.equal(f.doc.events.get('keydown')!.size, 0);
});

test('presentation assets are wired and cannot silently start capture or write config', () => {
  const src = fs.readFileSync(path.join(here, '../../web/studio-presentation.js'), 'utf8');
  const html = fs.readFileSync(path.join(here, '../../web/index.html'), 'utf8');
  assert.match(html, /studio-presentation\.css/);
  assert.match(html, /studio-presentation\.js/);
  for (const id of ['panelFlow', 'panelLatency', 'panelSamples']) assert.match(html, new RegExp('data-studio-focus="' + id + '"'));
  assert.doesNotMatch(src, /innerHTML|setInterval|fetch\(|localStorage|\/api\/capture|\/api\/kernel/);
  assert.doesNotMatch(html, /真实本地 Go 服务|Go 服务已连接|不等于设备已连接|pktpath-studio\.exe/);
});
