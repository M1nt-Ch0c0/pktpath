// In-process JS/TS plugin runtime for the new preview.
// Plugins are ESM modules (entrypoint.module). Analyze/export payloads
// travel as sidecar JSON files so control frames stay small and large
// integers are not forced through a 64KiB protocol line.
import { Context } from '@cordisjs/core';
import { createRequire } from 'node:module';
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';
import { resolve, sep } from 'node:path';
import { readFile, writeFile } from 'node:fs/promises';
import { attachCleanupWait } from './cleanup-wait.mjs';

const require = createRequire(import.meta.url);
const coreVersion = require('@cordisjs/core/package.json').version;
export const protocol = 'pktpath.cordis3.plugin-runtime/1';

const ctx = new Context();
const cleanupWait = attachCleanupWait(ctx);
for (const level of ['error', 'warning', 'info']) {
  ctx.on(`internal/${level}`, (...args) => console.error(...args));
}
console.info = (...args) => console.error(...args);
console.log = (...args) => console.error(...args);

const plugins = new Map();
let closing = false;

export function text(value, name) {
  if (typeof value !== 'string' || !value) throw new Error(`invalid ${name}`);
  return value;
}

export function resolvePackageModule(packageDir, modulePath) {
  const rel = text(modulePath, 'module');
  if (rel.includes('\0') || rel.includes('\x00')) throw new Error('invalid module path');
  const parts = rel.replace(/\\/g, '/').split('/');
  if (parts.some(p => p === '' || p === '.' || p === '..') || parts[0] === '') {
    throw new Error('module path must be a relative path inside the package directory');
  }
  const root = resolve(text(packageDir, 'package_dir'));
  const full = resolve(root, parts.join('/'));
  const prefix = root.endsWith(sep) ? root : root + sep;
  if (full !== root && !full.startsWith(prefix)) {
    throw new Error('module path escapes package directory');
  }
  return full;
}

async function loadPlugin(req) {
  const id = text(req.plugin_id, 'plugin_id');
  if (closing) throw new Error('host closing');
  if (plugins.has(id)) throw new Error('plugin already loaded');
  const analyzers = Array.isArray(req.analyzers) ? req.analyzers.map(x => text(x, 'analyzer')) : [];
  const exporters = Array.isArray(req.exporters) ? req.exporters.map(x => text(x, 'exporter')) : [];
  if (!analyzers.length && !exporters.length) throw new Error('missing analyzers/exporters');
  const url = pathToFileURL(resolvePackageModule(req.package_dir, req.module)).href;
  const mod = await import(url);
  if (analyzers.length && typeof mod.analyze !== 'function') {
    throw new Error('declared analyzers require exported analyze()');
  }
  if (exporters.length && typeof mod.exportSession !== 'function') {
    throw new Error('declared exporters require exported exportSession()');
  }
  let ready = false;
  let settle;
  const started = new Promise((resolve, reject) => { settle = { resolve, reject }; });
  const fork = ctx.plugin({
    name: `pktpath-runtime:${id}`,
    async apply(local) {
      try {
        if (typeof mod.setup === 'function') await mod.setup(local);
        ready = true;
        settle.resolve();
      } catch (error) {
        settle.reject(error);
        throw error;
      }
    },
  });
  try {
    await ctx.start();
    await started;
    if (!ready) throw new Error('plugin setup did not complete');
  } catch (error) {
    try { fork.dispose(); } catch {}
    await cleanupWait.wait();
    throw error;
  }
  plugins.set(id, { fork, mod, analyzers: new Set(analyzers), exporters: new Set(exporters) });
  return { loaded: true, plugin: id };
}

async function unloadPlugin(id) {
  const ent = plugins.get(id);
  if (!ent) return { unloaded: true, plugin: id };
  plugins.delete(id);
  if (ent.fork) ent.fork.dispose();
  await cleanupWait.wait();
  return { unloaded: true, plugin: id };
}

async function callFile(req, kind) {
  const id = text(req.plugin_id, 'plugin_id');
  const ent = plugins.get(id);
  if (!ent) throw new Error('plugin not loaded');
  const inputPath = text(req.input_path, 'input_path');
  const outputPath = text(req.output_path, 'output_path');
  const input = JSON.parse(await readFile(inputPath, 'utf8'));
  let result;
  if (kind === 'analyze') {
    const analyzer = text(req.analyzer_id, 'analyzer_id');
    if (!ent.analyzers.has(analyzer)) throw new Error('unknown analyzer');
    result = await ent.mod.analyze(input);
  } else {
    const exporter = text(req.exporter_id, 'exporter_id');
    if (!ent.exporters.has(exporter)) throw new Error('unknown exporter');
    result = await ent.mod.exportSession(input);
  }
  if (result == null || typeof result !== 'object' || Array.isArray(result)) {
    throw new Error(`${kind} must return an object`);
  }
  await writeFile(outputPath, JSON.stringify(result), 'utf8');
  return { accepted: true };
}

export async function dispatch(req) {
  if (req.protocol !== protocol) throw new Error('unsupported protocol');
  switch (req.op) {
    case 'hello':
      if (Number(process.versions.node.split('.')[0]) < 22) {
        throw new Error('candidate requires Node >=22; tested runtime is separately reported');
      }
      if (coreVersion !== '3.18.1') throw new Error('unsupported core version');
      return { core: coreVersion, node: process.version };
    case 'load':
      return await loadPlugin(req);
    case 'analyze':
      return await callFile(req, 'analyze');
    case 'export':
      return await callFile(req, 'export');
    case 'unload':
      return await unloadPlugin(text(req.plugin_id, 'plugin_id'));
    case 'shutdown': {
      closing = true;
      for (const id of [...plugins.keys()]) await unloadPlugin(id);
      await ctx.stop();
      await cleanupWait.wait();
      return { closed: true };
    }
    default:
      throw new Error('unknown operation');
  }
}

const isMain = process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (isMain) {
  let closingStdout = false;
  const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
  lines.on('line', line => {
    Promise.resolve().then(async () => {
      if (Buffer.byteLength(line) > 65536) throw new Error('control line too large');
      const req = JSON.parse(line);
      text(req.id, 'request id');
      try {
        const data = await dispatch(req);
        process.stdout.write(JSON.stringify({ id: req.id, protocol, ok: true, ...data }) + '\n', () => {
          if (closing && req.op === 'shutdown' && !closingStdout) {
            closingStdout = true;
            lines.close();
            process.stdin.destroy();
          }
        });
      } catch (error) {
        process.stdout.write(JSON.stringify({ id: req.id, protocol, ok: false, error: String(error.message || error) }) + '\n');
      }
    }).catch(error => { console.error(error); process.exitCode = 1; lines.close(); process.stdin.destroy(); });
  });
}
