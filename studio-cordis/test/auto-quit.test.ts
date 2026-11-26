import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { CordisHost } from '../src/kernel/host.ts';
import { registerWave1Builtins } from '../src/plugins/register.ts';
import { DEFAULT_AUTO_QUIT_MS, envFlagEnabled, parseCliArgs } from '../src/main.ts';
import { startStudioApp } from '../src/server/app.ts';

function tmpHost() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pktpath-autoquit-'));
  const appDir = path.join(root, 'app');
  const host = new CordisHost({
    appDir,
    sessionsRoot: path.join(appDir, 'sessions'),
    pluginsDir: path.join(appDir, 'plugins'),
    exportsDir: path.join(appDir, 'exports'),
    collectorsDir: path.join(root, 'collectors'),
    webDir: path.join(root, 'web'),
  });
  registerWave1Builtins(host);
  return { root, host };
}

async function wait(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

async function healthOk(url: string): Promise<boolean> {
  try {
    const res = await fetch(`${url}/api/health`, { signal: AbortSignal.timeout(800) });
    if (res.status !== 200) return false;
    const body = await res.json() as { ok?: boolean };
    return body.ok === true;
  } catch {
    return false;
  }
}

async function waitUntil(fn: () => Promise<boolean>, timeoutMs: number, label: string): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let last = false;
  while (Date.now() < deadline) {
    last = await fn();
    if (last) return;
    await wait(25);
  }
  throw new Error(`timed out waiting for ${label}`);
}

interface SseHandle {
  prelude: string;
  close(): Promise<void>;
}

async function openSse(url: string): Promise<SseHandle> {
  const ac = new AbortController();
  const res = await fetch(`${url}/api/app/events`, {
    signal: ac.signal,
    headers: { Accept: 'text/event-stream' },
  });
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type') ?? '', /text\/event-stream/);
  assert.equal(res.headers.get('cache-control'), 'no-cache, no-store');
  assert.equal(res.headers.get('x-accel-buffering'), 'no');
  const reader = res.body?.getReader();
  assert.ok(reader);
  const dec = new TextDecoder();
  let prelude = '';
  const deadline = Date.now() + 2000;
  while (Date.now() < deadline && !(prelude.includes(': connected') && prelude.includes('event: ready'))) {
    const { value, done } = await reader.read();
    if (done) break;
    prelude += dec.decode(value, { stream: true });
  }
  assert.match(prelude, /: connected/);
  assert.match(prelude, /event: ready/);
  assert.match(prelude, /data: \{"ok":true\}/);
  return {
    prelude,
    async close() {
      try { ac.abort(); } catch { /* ignore */ }
      try { await reader.cancel(); } catch { /* ignore */ }
    },
  };
}

describe('P1-12 last-tab auto-quit + CLI switches', () => {
  it('parseCliArgs defaults to 25000ms and supports --no-auto-quit / --auto-quit-ms / env', () => {
    const base = parseCliArgs(['--no-open']);
    assert.equal(base.autoQuitMs, DEFAULT_AUTO_QUIT_MS);
    assert.equal(DEFAULT_AUTO_QUIT_MS, 25_000);

    const disabled = parseCliArgs(['--no-auto-quit', '--port', '1234']);
    assert.equal(disabled.autoQuitMs, 0);
    assert.equal(disabled.port, 1234);

    const eq = parseCliArgs(['--auto-quit-ms=200']);
    assert.equal(eq.autoQuitMs, 200);

    const spaced = parseCliArgs(['--auto-quit-ms', '350']);
    assert.equal(spaced.autoQuitMs, 350);

    const envDisabled = parseCliArgs([], { PKTPATH_NO_AUTO_QUIT: 'true' });
    assert.equal(envDisabled.autoQuitMs, 0);

    const envMs = parseCliArgs([], { PKTPATH_AUTO_QUIT_MS: '400' });
    assert.equal(envMs.autoQuitMs, 400);

    assert.equal(envFlagEnabled('1'), true);
    assert.equal(envFlagEnabled('TRUE'), true);
    assert.equal(envFlagEnabled('0'), false);

    assert.throws(() => parseCliArgs(['--auto-quit-ms', '-1']));
    assert.throws(() => parseCliArgs(['--auto-quit-ms', 'nope']));
  });

  it('never connected: exceeding the timeout does not auto-quit', async () => {
    const { root, host } = tmpHost();
    await host.start();
    const app = await startStudioApp({ host, listenPort: 0, autoQuitMs: 150 });
    try {
      await wait(400);
      assert.equal(await healthOk(app.url), true);
      assert.equal(app.everHadClient, false);
      assert.equal(app.activeClients(), 0);
    } finally {
      await app.close();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('one SSE client disconnects with no capture: auto-quits after the timeout', async () => {
    const { root, host } = tmpHost();
    await host.start();
    let quit = 0;
    const app = await startStudioApp({
      host,
      listenPort: 0,
      autoQuitMs: 180,
      onQuitRequested: () => { quit += 1; },
    });
    try {
      const sse = await openSse(app.url);
      const health = await fetch(`${app.url}/api/health`).then((r) => r.json()) as { active_clients: number };
      assert.equal(health.active_clients, 1);
      await sse.close();
      await waitUntil(async () => !(await healthOk(app.url)), 1500, 'auto-quit after last tab');
      assert.equal(app.server.listening, false);
      assert.ok(quit >= 1);
    } finally {
      await app.close();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('reconnect before timeout cancels auto-quit and keeps the server alive', async () => {
    const { root, host } = tmpHost();
    await host.start();
    const app = await startStudioApp({ host, listenPort: 0, autoQuitMs: 300 });
    try {
      const first = await openSse(app.url);
      await first.close();
      await wait(80);
      const second = await openSse(app.url);
      await wait(400);
      assert.equal(await healthOk(app.url), true);
      assert.equal(app.activeClients(), 1);
      await second.close();
      await waitUntil(async () => !(await healthOk(app.url)), 1500, 'quit after second disconnect');
    } finally {
      await app.close();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('two tabs: closing one does not quit; closing the last does; duplicate close is safe', async () => {
    const { root, host } = tmpHost();
    await host.start();
    const app = await startStudioApp({ host, listenPort: 0, autoQuitMs: 200 });
    try {
      const a = await openSse(app.url);
      const b = await openSse(app.url);
      const health = await fetch(`${app.url}/api/health`).then((r) => r.json()) as { active_clients: number };
      assert.equal(health.active_clients, 2);
      await a.close();
      await a.close();
      await wait(400);
      assert.equal(await healthOk(app.url), true);
      assert.equal(app.activeClients(), 1);
      await b.close();
      await waitUntil(async () => !(await healthOk(app.url)), 1500, 'quit after last of two tabs');
    } finally {
      await app.close();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('active capture blocks auto-quit; after capture ends the idle timer starts', async () => {
    const { root, host } = tmpHost();
    await host.start();
    let capturing = true;
    const app = await startStudioApp({
      host,
      listenPort: 0,
      autoQuitMs: 180,
      hasActiveCapture: () => capturing,
    });
    try {
      const sse = await openSse(app.url);
      await sse.close();
      await wait(450);
      assert.equal(await healthOk(app.url), true, 'must not quit while capture is active');
      capturing = false;
      await waitUntil(async () => !(await healthOk(app.url)), 1500, 'quit after capture ends + idle');
    } finally {
      await app.close();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('--no-auto-quit / autoQuitMs: 0 disables auto-quit', async () => {
    const { root, host } = tmpHost();
    await host.start();
    const app = await startStudioApp({ host, listenPort: 0, autoQuitMs: 0 });
    try {
      const sse = await openSse(app.url);
      await sse.close();
      await wait(400);
      assert.equal(await healthOk(app.url), true);
      assert.equal(app.everHadClient, true);
    } finally {
      await app.close();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});
