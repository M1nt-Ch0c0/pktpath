import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import zlib from 'node:zlib';
import { CordisHost } from '../src/kernel/host.ts';
import type { HostPaths, SessionProvider } from '../src/kernel/types.ts';
import { registerWave1Builtins } from '../src/plugins/register.ts';

function makeTempPaths(): { root: string; paths: HostPaths } {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pktpath-cordis-host-'));
  const appDir = path.join(root, 'app');
  return {
    root,
    paths: {
      appDir,
      sessionsRoot: path.join(appDir, 'sessions'),
      pluginsDir: path.join(appDir, 'plugins'),
      exportsDir: path.join(appDir, 'exports'),
      collectorsDir: path.join(root, 'collectors'),
      webDir: path.join(root, 'web'),
    },
  };
}

// Minimal pure-Node ZIP builder (CRC32 + deflate) for tests
function crc32(buf: Buffer): number {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c ^= buf[i];
    for (let k = 0; k < 8; k++) {
      c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
    }
  }
  return (c ^ 0xffffffff) >>> 0;
}

function buildZip(files: Array<{ name: string; content: string }>): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;

  for (const f of files) {
    const nameBuf = Buffer.from(f.name, 'utf8');
    const raw = Buffer.from(f.content, 'utf8');
    const comp = zlib.deflateRawSync(raw);
    const crc = crc32(raw);

    const lfh = Buffer.alloc(30);
    lfh.writeUInt32LE(0x04034b50, 0);
    lfh.writeUInt16LE(20, 4);
    lfh.writeUInt16LE(8, 8); // deflate
    lfh.writeUInt32LE(crc, 14);
    lfh.writeUInt32LE(comp.length, 18);
    lfh.writeUInt32LE(raw.length, 22);
    lfh.writeUInt16LE(nameBuf.length, 26);

    locals.push(lfh, nameBuf, comp);

    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(20, 4);
    cd.writeUInt16LE(20, 6);
    cd.writeUInt16LE(8, 10);
    cd.writeUInt32LE(crc, 16);
    cd.writeUInt32LE(comp.length, 20);
    cd.writeUInt32LE(raw.length, 24);
    cd.writeUInt16LE(nameBuf.length, 28);
    cd.writeUInt32LE(offset, 42);

    centrals.push(cd, nameBuf);
    offset += lfh.length + nameBuf.length + comp.length;
  }

  const cdBuf = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);

  return Buffer.concat([...locals, cdBuf, eocd]);
}

describe('CordisHost unified lifecycle & external plugins', () => {
  it('installs ZIP external plugin, awaits async disposer, preserves u64 sample_id, reloads with cache-bust, and uninstalls cleanly', async () => {
    const { root, paths } = makeTempPaths();
    try {
      const host = new CordisHost(paths);
      registerWave1Builtins(host);
      await host.start();

      // Provide mock SessionProvider to verify invalidation + export
      let invalidated = 0;
      const mockSessionProvider: SessionProvider = {
        async listSessions() { return []; },
        async openSession(p) { return { id: 'sess1', path: p }; },
        async getOverview() { return { sample_count: 1 }; },
        async getSample() { return {}; },
        async getSessionForExport(id) {
          return {
            session_id: id,
            session_dir: path.join(paths.sessionsRoot, id),
            overview: { sample_count: 1 },
          };
        },
        invalidateAnalysisCache() { invalidated += 1; },
      };
      host.provideService('test', 'session.provider', mockSessionProvider);

      const markerFile = path.join(root, 'cleanup-marker.txt');
      const zipPath = path.join(root, 'sample-ext.zip');
      const zipBuf = buildZip([
        {
          name: 'manifest.json',
          content: JSON.stringify({
            id: 'community.test-auditor',
            name: 'Test Auditor',
            version: '1.0.0',
            description: 'External test plugin',
            entrypoint: { module: 'index.mjs' },
            analyzers: [{ id: 'audit-u64', name: 'Audit U64' }],
            exporters: [{ id: 'audit-json', name: 'Audit JSON', default_ext: '.json' }],
          }),
        },
        {
          name: 'index.mjs',
          content: `
import fs from 'node:fs';
export async function setup(ctx) {
  ctx.effect(() => async () => {
    await new Promise((r) => setTimeout(r, 40));
    fs.writeFileSync(${JSON.stringify(markerFile)}, 'cleaned-v1', 'utf8');
  });
}
export async function analyze(input) {
  return {
    insights: [{
      title: 'v1-finding',
      severity: 'warn',
      sample_ids: ['18446744073709551615', 42n],
    }],
    kpis: [{ label: 'Checked', value: '1', tone: 'ok' }],
    notes: ['note-v1'],
  };
}
export async function exportSession(input) {
  fs.writeFileSync(input.out_path, JSON.stringify({ exported: input.session_id }), 'utf8');
  return { ok: true, out_path: input.out_path, summary: 'exported ok' };
}
`,
        },
      ]);
      fs.writeFileSync(zipPath, zipBuf);

      const preview = host.previewExternal(zipPath);
      assert.equal(preview.id, 'community.test-auditor');

      const installed = await host.installExternal(zipPath);
      assert.equal(installed.ok, true);
      assert.equal(installed.plugin_id, 'community.test-auditor');
      assert.ok(invalidated >= 1);

      // Run analyzer & verify >2^53-1 u64 sample_id preserved as exact decimal string
      const analysis1 = await host.runAnalyzers('sess1', paths.sessionsRoot, {});
      assert.equal(analysis1.insights.length, 1);
      assert.equal(analysis1.insights[0].title, 'v1-finding');
      assert.deepEqual(analysis1.insights[0].sample_ids, ['18446744073709551615', '42']);

      // Run export with omitted out_path (should default into exportsDir)
      const expRes = await host.runExport({ exporter_id: 'audit-json', session_id: 'sess1' });
      assert.equal(expRes.ok, true);
      assert.ok(expRes.out_path.startsWith(paths.exportsDir));
      assert.ok(fs.existsSync(expRes.out_path));

      // Modify installed module on disk and reload -> must await async disposer + cache-bust
      const installedMod = path.join(paths.pluginsDir, 'community.test-auditor', 'index.mjs');
      fs.writeFileSync(
        installedMod,
        `
export async function analyze() {
  return { insights: [{ title: 'v2-reloaded', severity: 'ok' }], kpis: [], notes: [] };
}
export async function exportSession(input) {
  return { ok: true, out_path: input.out_path, summary: 'v2' };
}
`,
        'utf8',
      );
      const reloaded = await host.reload('community.test-auditor');
      assert.equal(reloaded.ok, true);
      assert.equal(fs.readFileSync(markerFile, 'utf8'), 'cleaned-v1');

      const analysis2 = await host.runAnalyzers('sess1', paths.sessionsRoot, {});
      assert.equal(analysis2.insights[0].title, 'v2-reloaded');

      // Uninstall removes directory and plugin entry
      const un = await host.uninstallExternal('community.test-auditor');
      assert.equal(un.ok, true);
      assert.equal(fs.existsSync(path.join(paths.pluginsDir, 'community.test-auditor')), false);

      await host.shutdown();
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('hard-rejects legacy entrypoint.command, builtin.* spoofing, and Zip-Slip archives', async () => {
    const { root, paths } = makeTempPaths();
    try {
      const host = new CordisHost(paths);
      await host.start();

      // 1. entrypoint.command rejected
      const cmdDir = path.join(root, 'bad-cmd');
      fs.mkdirSync(cmdDir, { recursive: true });
      fs.writeFileSync(
        path.join(cmdDir, 'manifest.json'),
        JSON.stringify({
          id: 'community.legacy-cmd',
          name: 'Legacy Cmd',
          version: '1.0.0',
          entrypoint: { command: ['python3', 'run.py'], module: 'index.mjs' },
        }),
      );
      fs.writeFileSync(path.join(cmdDir, 'index.mjs'), 'export async function analyze() { return {}; }');
      assert.throws(() => host.previewExternal(cmdDir), /entrypoint\.command is forbidden/i);

      // 2. builtin.* spoofing rejected
      const spoofDir = path.join(root, 'bad-spoof');
      fs.mkdirSync(spoofDir, { recursive: true });
      fs.writeFileSync(
        path.join(spoofDir, 'manifest.json'),
        JSON.stringify({
          id: 'builtin.fake',
          name: 'Fake Builtin',
          version: '1.0.0',
          entrypoint: { module: 'index.mjs' },
        }),
      );
      fs.writeFileSync(path.join(spoofDir, 'index.mjs'), 'export async function analyze() { return {}; }');
      assert.throws(() => host.previewExternal(spoofDir), /cannot start with "builtin\."/i);

      // 3. Zip-Slip rejected
      const slipZip = path.join(root, 'slip.zip');
      fs.writeFileSync(slipZip, buildZip([{ name: '../evil.txt', content: 'pwned' }]));
      assert.throws(() => host.previewExternal(slipZip), /path traversal rejected/i);

      await host.shutdown();
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('isolates throwing analyzers so healthy analyzers still succeed', async () => {
    const { root, paths } = makeTempPaths();
    try {
      const host = new CordisHost(paths);
      host.registerBuiltin({
        meta: {
          id: 'builtin.test.bad-analyzer',
          name: 'Bad',
          version: '1.0.0',
          description: 'throws',
          category: 'analyzer',
          builtin: true,
          capabilities: [],
        },
        schema: { fields: [] },
        apply(ctx) {
          ctx.registerExtension('analyzer', {
            id: 'bad',
            plugin_id: 'builtin.test.bad-analyzer',
            name: 'Bad',
            run() {
              throw new Error('boom');
            },
          });
        },
      });
      host.registerBuiltin({
        meta: {
          id: 'builtin.test.good-analyzer',
          name: 'Good',
          version: '1.0.0',
          description: 'works',
          category: 'analyzer',
          builtin: true,
          capabilities: [],
        },
        schema: { fields: [] },
        apply(ctx) {
          ctx.registerExtension('analyzer', {
            id: 'good',
            plugin_id: 'builtin.test.good-analyzer',
            name: 'Good',
            run() {
              return { insights: [{ title: 'healthy', severity: 'ok' }], kpis: [], notes: [] };
            },
          });
        },
      });
      await host.start();

      const out = await host.runAnalyzers('s1', paths.sessionsRoot, {});
      assert.equal(out.insights.length, 1);
      assert.equal(out.insights[0].title, 'healthy');
      assert.ok(out.notes.some((n) => n.includes('boom')));

      await host.shutdown();
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('isolates exporter exceptions/timeouts, blocks out_path inside session_dir, and blocks plugin-asset symlink escapes', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pktpath-p2-test-'));
    try {
      const appDir = path.join(root, 'app');
      const sessDir = path.join(appDir, 'sessions', 's1');
      fs.mkdirSync(sessDir, { recursive: true });
      const outsideSecret = path.join(root, 'secret.txt');
      fs.writeFileSync(outsideSecret, 'TOP_SECRET');

      const host = new CordisHost({
        appDir,
        sessionsRoot: path.join(appDir, 'sessions'),
        pluginsDir: path.join(appDir, 'plugins'),
        exportsDir: path.join(appDir, 'exports'),
        collectorsDir: path.join(root, 'collectors'),
        webDir: path.join(root, 'web'),
      });

      host.registerBuiltin({
        meta: {
          id: 'builtin.exporter.boom',
          name: 'Boom Exporter',
          version: '0.1.0',
          description: 'test throwing exporter',
          category: 'exporter',
          builtin: true,
          capabilities: ['exporter'],
        },
        schema: { fields: [] },
        apply: (ctx) => {
          ctx.provide('session.provider', {
            getSessionForExport: async (sessionId: string) => ({
              session_id: sessionId,
              session_dir: sessDir,
              overview: {},
              session: {},
            }),
          });
          ctx.registerExtension('exporter', {
            id: 'boom',
            plugin_id: 'builtin.exporter.boom',
            name: 'Boom',
            description: 'throws',
            default_ext: '.txt',
            run: async () => {
              throw new Error('simulated exporter crash');
            },
          });
        },
      });
      const extDir = path.join(appDir, 'plugins', 'demo.symlink');
      fs.mkdirSync(extDir, { recursive: true });
      fs.writeFileSync(
        path.join(extDir, 'manifest.json'),
        JSON.stringify({
          schema_version: 2,
          id: 'demo.symlink',
          name: 'Symlink Test',
          version: '0.1.0',
          description: 'test',
          category: 'analyzer',
          entrypoint: { module: 'index.mjs' },
          capabilities: ['analyzer'],
          analyzers: [{ id: 'a1', name: 'A1', description: 'a1' }],
        }),
      );
      fs.writeFileSync(path.join(extDir, 'index.mjs'), 'export async function analyze() { return { findings: [] }; }');
      fs.symlinkSync(outsideSecret, path.join(extDir, 'escape.txt'));

      await host.start();

      // 1. out_path inside session_dir must be rejected before exporter runs
      const overwriteRes = await host.runExport({ exporter_id: 'boom', session_id: 's1', out_path: path.join(sessDir, 'out.txt') });
      assert.equal(overwriteRes.ok, false);
      assert.match(String(overwriteRes.error), /session_dir/);

      // 1b. out_path traversing a symlink pointing into session_dir must also be rejected
      const symlinkToSess = path.join(appDir, 'exports', 'link-to-sess');
      fs.mkdirSync(path.join(appDir, 'exports'), { recursive: true });
      fs.symlinkSync(sessDir, symlinkToSess);
      const symlinkOverwriteRes = await host.runExport({
        exporter_id: 'boom',
        session_id: 's1',
        out_path: path.join(symlinkToSess, 'nested', 'out.txt'),
      });
      assert.equal(symlinkOverwriteRes.ok, false);
      assert.match(String(symlinkOverwriteRes.error), /session_dir/);

      // 2. Throwing exporter must be isolated and return ok:false instead of crashing host
      const crashRes = await host.runExport({ exporter_id: 'boom', session_id: 's1', out_path: path.join(appDir, 'exports', 'safe.txt') });
      assert.equal(crashRes.ok, false);
      assert.match(String(crashRes.error), /simulated exporter crash/);

      // 3. Symlink escape inside an external plugin directory must be blocked by realpathSync
      assert.equal(host.resolvePluginAsset('demo.symlink', 'escape.txt'), undefined);
      assert.ok(host.resolvePluginAsset('demo.symlink', 'manifest.json'));

      await host.shutdown();
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});
