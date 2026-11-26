import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { CordisHost } from '../src/kernel/host.ts';
import { registerWave1Builtins } from '../src/plugins/register.ts';
import { startStudioApp } from '../src/server/app.ts';

describe('Wave 1 HTTP server, removed routes 404, and CLI ready/quit protocol', () => {
  it('returns 404 for cut linux-ssh and unmounted legacy routes, and clean health/state', async () => {
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

        const removedRoutes: Array<[string, string]> = [
          ['GET', '/api/ssh/targets'],
          ['POST', '/api/ssh/targets'],
          ['DELETE', '/api/ssh/targets'],
          ['POST', '/api/ssh/test'],
          ['GET', '/api/plugins'],
          ['POST', '/api/plugins/import'],
        ];
        for (const [method, route] of removedRoutes) {
          const resp = await fetch(`${app.url}${route}`, { method });
          assert.equal(resp.status, 404, `${method} ${route} must return 404`);
        }

        // Y-W1-04: malformed percent-encoding returns 400 (not 500)
        const badEnc = await fetch(`${app.url}/api/kernel/plugin-asset/foo/%E0%A4%A`);
        assert.equal(badEnc.status, 400);

        // Y-W1-02: malformed Host header returns 400 without crashing the server
        const net = await import('node:net');
        const port = Number(new URL(app.url).port);
        const rawResp = await new Promise<string>((resolve, reject) => {
          const sock = net.connect(port, '127.0.0.1', () => {
            sock.write('GET /api/health HTTP/1.1\r\nHost: bad host:99999\r\nConnection: close\r\n\r\n');
          });
          let data = '';
          sock.on('data', (c) => { data += c.toString('utf8'); });
          sock.on('end', () => resolve(data));
          sock.on('error', reject);
        });
        assert.match(rawResp, /^HTTP\/1\.1 400 /);
        // Server must still be alive after malformed Host
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
