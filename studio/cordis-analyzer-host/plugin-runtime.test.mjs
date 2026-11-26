import { spawn } from 'node:child_process';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';
import { protocol, resolvePackageModule } from './plugin-runtime.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const runtime = resolve(here, 'plugin-runtime.mjs');
const fixtureDir = resolve(here, '../pkg/kernel/testdata/fixture-module-plugin');

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

// Path escape is rejected without starting a host.
let failed = false;
try { resolvePackageModule(fixtureDir, '../plugin.mjs'); } catch { failed = true; }
assert(failed, 'expected ../ escape to fail');
failed = false;
try { resolvePackageModule(fixtureDir, '/tmp/plugin.mjs'); } catch { failed = true; }
assert(failed, 'expected absolute module to fail');
assert(resolvePackageModule(fixtureDir, 'plugin.mjs').endsWith('plugin.mjs'), 'relative module should resolve');

function request(child, pending, req) {
  return new Promise((resolvePromise, reject) => {
    pending.set(req.id, { resolve: resolvePromise, reject });
    child.stdin.write(JSON.stringify(req) + '\n');
  });
}

const dir = await mkdtemp(resolve(tmpdir(), 'pktpath-runtime-test-'));
const child = spawn(process.execPath, [runtime], { stdio: ['pipe', 'pipe', 'inherit'] });
const pending = new Map();
const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
lines.on('line', (line) => {
  const reply = JSON.parse(line);
  const waiter = pending.get(reply.id);
  if (!waiter) return;
  pending.delete(reply.id);
  if (reply.ok) waiter.resolve(reply);
  else waiter.reject(new Error(reply.error));
});

try {
  const hello = await request(child, pending, { id: '1', protocol, op: 'hello' });
  assert(hello.core === '3.18.1', `unexpected core ${hello.core}`);
  await request(child, pending, {
    id: '2', protocol, op: 'load',
    plugin_id: 'community.analyzer.fixture-module',
    package_dir: fixtureDir,
    module: 'plugin.mjs',
    analyzers: ['community.analyzer.fixture-module.analyze'],
    exporters: ['community.analyzer.fixture-module.export'],
  });
  const inputPath = resolve(dir, 'in.json');
  const outputPath = resolve(dir, 'out.json');
  await writeFile(inputPath, JSON.stringify({
    action: 'analyze',
    plugin_id: 'community.analyzer.fixture-module',
    analyzer_id: 'community.analyzer.fixture-module.analyze',
    config: {},
    session_id: 'sess-1',
    session_dir: dir,
    overview: {
      manifest: {},
      dict: {},
      stats: { quality_alerts: [{ kind: 'gap', severity: 'error', count: 1, message: 'synthetic' }] },
      samples: [{ sample_id: 42, comm: 'demo', max_sojourn_us: 1, complete: false }],
    },
  }));
  await request(child, pending, {
    id: '3', protocol, op: 'analyze',
    plugin_id: 'community.analyzer.fixture-module',
    analyzer_id: 'community.analyzer.fixture-module.analyze',
    input_path: inputPath,
    output_path: outputPath,
  });
  const analyzed = JSON.parse(await readFile(outputPath, 'utf8'));
  assert(analyzed.insights[0].severity === 'critical', 'error alert should map to critical');
  assert(analyzed.insights[0].summary === '1', 'sample count');
  assert(analyzed.notes[0] === 'fixture-analyze', 'note');

  const exportPath = resolve(dir, 'export.json');
  await writeFile(resolve(dir, 'export-in.json'), JSON.stringify({
    action: 'export',
    plugin_id: 'community.analyzer.fixture-module',
    exporter_id: 'community.analyzer.fixture-module.export',
    config: {},
    session_id: 'sess-1',
    session_dir: dir,
    overview: {},
    out_path: exportPath,
    params: {},
  }));
  await request(child, pending, {
    id: '4', protocol, op: 'export',
    plugin_id: 'community.analyzer.fixture-module',
    exporter_id: 'community.analyzer.fixture-module.export',
    input_path: resolve(dir, 'export-in.json'),
    output_path: resolve(dir, 'export-out.json'),
  });
  const exported = JSON.parse(await readFile(exportPath, 'utf8'));
  assert(exported.note === 'fixture-export', 'export file');

  const t0 = Date.now();
  await request(child, pending, { id: '5', protocol, op: 'unload', plugin_id: 'community.analyzer.fixture-module' });
  const elapsed = Date.now() - t0;
  assert(elapsed >= 70, `unload returned before cleanup finished (${elapsed}ms)`);

  await request(child, pending, { id: '6', protocol, op: 'shutdown' });
} finally {
  try { child.stdin.end(); } catch {}
  child.kill();
  await rm(dir, { recursive: true, force: true });
}

console.log('plugin-runtime.test.mjs ok');

// Regression tests for Y-CDH-01, Y-CDH-02, Y-CDH-03.
{
  const { default: strictAssert } = await import('node:assert/strict');
  const { mkdir } = await import('node:fs/promises');
  const { join } = await import('node:path');
  const { parseJSONPreserveLargeInts } = await import('./plugin-runtime.mjs');

  const parsed = parseJSONPreserveLargeInts('{"safe":42,"big":9007199254740993,"maxu64":18446744073709551615,"neg":-9007199254740993,"flt":1.5}');
  strictAssert.strictEqual(parsed.safe, 42);
  strictAssert.strictEqual(parsed.big, '9007199254740993');
  strictAssert.strictEqual(parsed.maxu64, '18446744073709551615');
  strictAssert.strictEqual(parsed.neg, '-9007199254740993');
  strictAssert.strictEqual(parsed.flt, 1.5);

  const tmp2 = await mkdtemp(join(tmpdir(), 'pktpath-rt-reg-'));
  const child2 = spawn(process.execPath, [runtime], { stdio: ['pipe', 'pipe', 'pipe'] });
  const pending2 = new Map();
  let seq2 = 0;
  createInterface({ input: child2.stdout }).on('line', line => {
    const msg = JSON.parse(line);
    const hit = pending2.get(msg.id);
    if (hit) { pending2.delete(msg.id); hit(msg); }
  });
  const call2 = (op, extra = {}) => new Promise((resolvePromise, reject) => {
    const id = `reg-${++seq2}`;
    pending2.set(id, resolvePromise);
    child2.stdin.write(JSON.stringify({ id, protocol, op, ...extra }) + '\n', err => {
      if (err) reject(err);
    });
  });

  try {
    strictAssert.strictEqual((await call2('hello')).ok, true);

    // Y-CDH-01 + Y-CDH-03: large int preserved + reload after modifying plugin.mjs at same path
    const reloadDir = join(tmp2, 'reload-pkg');
    await mkdir(reloadDir, { recursive: true });
    await writeFile(join(reloadDir, 'plugin.mjs'), `
      export async function analyze(input) {
        const sid = input.overview?.samples?.[0]?.sample_id;
        return { insights: [], kpis: [], notes: ['v1', String(sid), typeof sid] };
      }
    `);
    strictAssert.strictEqual((await call2('load', {
      plugin_id: 'reg.reload',
      package_dir: reloadDir,
      module: 'plugin.mjs',
      analyzers: ['reg.reload.a'],
      exporters: [],
    })).ok, true);
    const in1 = join(tmp2, 'in1.json');
    const out1 = join(tmp2, 'out1.json');
    await writeFile(in1, '{"action":"analyze","overview":{"samples":[{"sample_id":9007199254740993}]}}');
    strictAssert.strictEqual((await call2('analyze', {
      plugin_id: 'reg.reload',
      analyzer_id: 'reg.reload.a',
      input_path: in1,
      output_path: out1,
    })).ok, true);
    const res1 = JSON.parse(await readFile(out1, 'utf8'));
    strictAssert.deepStrictEqual(res1.notes, ['v1', '9007199254740993', 'string']);

    strictAssert.strictEqual((await call2('unload', { plugin_id: 'reg.reload' })).ok, true);
    await writeFile(join(reloadDir, 'plugin.mjs'), `
      export async function analyze() {
        return { insights: [], kpis: [], notes: ['v2'] };
      }
    `);
    strictAssert.strictEqual((await call2('load', {
      plugin_id: 'reg.reload',
      package_dir: reloadDir,
      module: 'plugin.mjs',
      analyzers: ['reg.reload.a'],
      exporters: [],
    })).ok, true);
    const out2 = join(tmp2, 'out2.json');
    strictAssert.strictEqual((await call2('analyze', {
      plugin_id: 'reg.reload',
      analyzer_id: 'reg.reload.a',
      input_path: in1,
      output_path: out2,
    })).ok, true);
    const res2 = JSON.parse(await readFile(out2, 'utf8'));
    strictAssert.deepStrictEqual(res2.notes, ['v2']);
    strictAssert.strictEqual((await call2('unload', { plugin_id: 'reg.reload' })).ok, true);

    // Y-CDH-02: failing async disposer must NOT return ok:true / unloaded:true
    const failDir = join(tmp2, 'failclean-pkg');
    await mkdir(failDir, { recursive: true });
    await writeFile(join(failDir, 'plugin.mjs'), `
      export async function setup(ctx) {
        ctx.effect(() => async () => {
          await new Promise(r => setTimeout(r, 20));
          throw new Error('cleanup_boom');
        });
      }
      export async function analyze() { return { insights: [], kpis: [], notes: [] }; }
    `);
    strictAssert.strictEqual((await call2('load', {
      plugin_id: 'reg.failclean',
      package_dir: failDir,
      module: 'plugin.mjs',
      analyzers: ['reg.failclean.a'],
      exporters: [],
    })).ok, true);
    const unl = await call2('unload', { plugin_id: 'reg.failclean' });
    strictAssert.strictEqual(unl.ok, false);
    strictAssert.match(String(unl.error || ''), /cleanup_boom/);

    strictAssert.strictEqual((await call2('shutdown')).ok, true);
    console.log('plugin-runtime.test.mjs regressions ok');
  } finally {
    child2.kill();
    await rm(tmp2, { recursive: true, force: true });
  }
}
