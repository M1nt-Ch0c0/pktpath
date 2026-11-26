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
