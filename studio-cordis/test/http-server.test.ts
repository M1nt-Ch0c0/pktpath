import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { CordisHost } from '../src/kernel/host.ts';
import { registerWave1Builtins } from '../src/plugins/register.ts';
import { startStudioApp } from '../src/server/app.ts';

function sendRawHttp(port: number, payload: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const sock = net.connect(port, '127.0.0.1', () => {
      sock.write(payload);
    });
    let data = '';
    sock.on('data', (c) => { data += c.toString('utf8'); });
    sock.on('end', () => resolve(data));
    sock.on('error', reject);
  });
}

describe('Wave 1 HTTP server, Host/Origin guard, runtime plugins, removed routes 404, and CLI ready/quit protocol', () => {
  it('returns 404 for cut linux-ssh routes, enforces Host/Origin loopback guard, and serves /api/plugins* CRUD', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pktpath-http-test-'));
    try {
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
      await host.start();
      const app = await startStudioApp({ host, listenPort: 0 });
      try {
        const health = await fetch(`${app.url}/api/health`).then((r) => r.json()) as Record<string, unknown>;
        assert.equal(health.ok, true);
        assert.equal('ssh_available' in health, false);

        const state = await fetch(`${app.url}/api/kernel/state`).then((r) => r.json()) as {
          ok: boolean;
          state: Record<string, unknown>;
        };
        assert.equal(state.ok, true);
        assert.equal('kernel_ext_summary' in state.state, false);

        // Cut linux-ssh routes strictly return 404 with legacy Go wording (P2-5)
        const removedRoutes: Array<[string, string]> = [
          ['GET', '/api/ssh/targets'],
          ['POST', '/api/ssh/targets'],
          ['DELETE', '/api/ssh/targets'],
          ['POST', '/api/ssh/test'],
        ];
        for (const [method, route] of removedRoutes) {
          const resp = await fetch(`${app.url}${route}`, { method });
          assert.equal(resp.status, 404, `${method} ${route} must return 404`);
          const body = await resp.json() as { ok: boolean; error: string };
          assert.equal(body.ok, false);
          assert.equal(body.error, `unknown API endpoint: ${method} ${route}`);
        }

        // P1-3: Device-side runtime JSON plugins CRUD (/api/plugins*)
        const list0 = await fetch(`${app.url}/api/plugins`).then((r) => r.json()) as {
          ok: boolean;
          plugins: unknown[];
          slots: { sock_max: number; classful_max: number; leaf_max: number; total_count: number; enabled_count: number };
        };
        assert.equal(list0.ok, true);
        assert.equal(list0.plugins.length, 0);
        assert.equal(list0.slots.sock_max, 16);
        assert.equal(list0.slots.classful_max, 32);
        assert.equal(list0.slots.leaf_max, 32);

        const samplePluginJson = JSON.stringify({
          id: 'oem_test_qdisc',
          name: 'OEM Test Qdisc',
          version: '1.0.0',
          sock_fields: [{ struct: 'sock', field: 'sk_mark', size: 4, role: 'tag', label: 'mark' }],
          qdiscs: [{ id: 'oem_leaf', kind: 'oem_leaf', mode: 'leaf', enqueue_sym: 'oem_enq', dequeue_sym: 'oem_deq' }],
        });
        const preview = await fetch(`${app.url}/api/plugins/preview`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ filename: 'oem_test.json', content: samplePluginJson }),
        }).then((r) => r.json()) as { ok: boolean; plugin: { sock_fields: number; qdiscs: number } };
        assert.equal(preview.ok, true);
        assert.equal(preview.plugin.sock_fields, 1);
        assert.equal(preview.plugin.qdiscs, 1);

        const imported = await fetch(`${app.url}/api/plugins/import`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ filename: 'oem_test.json', content: samplePluginJson }),
        }).then((r) => r.json()) as { ok: boolean; slots: { total_count: number; enabled_count: number; sock_used: number; leaf_used: number } };
        assert.equal(imported.ok, true);
        assert.equal(imported.slots.total_count, 1);
        assert.equal(imported.slots.enabled_count, 1);
        assert.equal(imported.slots.sock_used, 1);
        assert.equal(imported.slots.leaf_used, 1);

        const toggledOff = await fetch(`${app.url}/api/plugins/toggle`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ file: 'oem_test.json', enabled: false }),
        }).then((r) => r.json()) as { ok: boolean; enabled: boolean; slots: { enabled_count: number; sock_used: number } };
        assert.equal(toggledOff.ok, true);
        assert.equal(toggledOff.enabled, false);
        assert.equal(toggledOff.slots.enabled_count, 0);
        assert.equal(toggledOff.slots.sock_used, 0);

        const deleted = await fetch(`${app.url}/api/plugins/delete`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ file: 'oem_test.json' }),
        }).then((r) => r.json()) as { ok: boolean; deleted: string; slots: { total_count: number } };
        assert.equal(deleted.ok, true);
        assert.equal(deleted.deleted, 'oem_test.json');
        assert.equal(deleted.slots.total_count, 0);

        // Y-W1-04: malformed percent-encoding returns 400 (not 500)
        const badEnc = await fetch(`${app.url}/api/kernel/plugin-asset/foo/%E0%A4%A`);
        assert.equal(badEnc.status, 400);

        // Y-W1-02: malformed Host header returns 400 without crashing the server
        const port = Number(new URL(app.url).port);
        const rawBadHost = await sendRawHttp(port, 'GET /api/health HTTP/1.1\r\nHost: bad host:99999\r\nConnection: close\r\n\r\n');
        assert.match(rawBadHost, /^HTTP\/1\.1 400 /);

        // P1-5: DNS-rebinding Host / port / cross-origin Origin guard returns 403
        const evilHost = await sendRawHttp(port, `GET /api/health HTTP/1.1\r\nHost: evil.example.com:${port}\r\nConnection: close\r\n\r\n`);
        assert.match(evilHost, /^HTTP\/1\.1 403 /);
        assert.match(evilHost, /forbidden host/);

        const wrongPort = await sendRawHttp(port, `GET /api/health HTTP/1.1\r\nHost: 127.0.0.1:${port === 65535 ? 65534 : port + 1}\r\nConnection: close\r\n\r\n`);
        assert.match(wrongPort, /^HTTP\/1\.1 403 /);
        assert.match(wrongPort, /forbidden host port/);

        const evilOrigin = await sendRawHttp(
          port,
          `POST /api/plugins/delete HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nOrigin: http://evil.example.com\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}`,
        );
        assert.match(evilOrigin, /^HTTP\/1\.1 403 /);
        assert.match(evilOrigin, /forbidden origin/);

        // Server must still be alive after malformed/forbidden requests
        const healthAfter = await fetch(`${app.url}/api/health`);
        assert.equal(healthAfter.status, 200);

        if (process.platform !== 'win32') {
          const dlg = await fetch(`${app.url}/api/dialog/pick-folder`, { method: 'POST', body: '{}' });
          assert.equal(dlg.status, 501);
        }
      } finally {
        await app.close();
      }
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('spawns src/main.ts, emits PKTPATH_STUDIO_READY, responds to /api/health, and exits 0 on POST /api/app/quit', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pktpath-cli-test-'));
    const mainTs = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../src/main.ts');
    try {
      const child = spawn(
        process.execPath,
        [mainTs, '--port', '0', '--no-open', '--app-dir', path.join(root, 'app')],
        { stdio: ['ignore', 'pipe', 'pipe'] },
      );

      const readyUrl = await new Promise<string>((resolve, reject) => {
        let buf = '';
        let stderr = '';
        const timer = setTimeout(() => {
          child.kill('SIGKILL');
          reject(new Error(`timed out waiting for PKTPATH_STUDIO_READY; stderr=${stderr}`));
        }, 10_000);
        child.stderr.on('data', (d: Buffer) => { stderr += d.toString('utf8'); });
        child.stdout.on('data', (d: Buffer) => {
          buf += d.toString('utf8');
          const m = /PKTPATH_STUDIO_READY url=(http:\/\/\S+) pid=(\d+)/.exec(buf);
          if (m) {
            clearTimeout(timer);
            resolve(m[1]);
          }
        });
        child.once('exit', (code) => {
          clearTimeout(timer);
          reject(new Error(`process exited early with code ${code}; stderr=${stderr}`));
        });
      });

      const h = await fetch(`${readyUrl}/api/health`).then((r) => r.json()) as { ok: boolean; runtime: { engine: string } };
      assert.equal(h.ok, true);
      assert.equal(h.runtime.engine, 'cordis-node');

      const exitPromise = new Promise<number | null>((resolve) => {
        child.once('exit', (code) => resolve(code));
      });
      const q = await fetch(`${readyUrl}/api/app/quit`, { method: 'POST', body: '{}' }).then((r) => r.json()) as { ok: boolean };
      assert.equal(q.ok, true);
      const exitCode = await exitPromise;
      assert.equal(exitCode, 0);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});
