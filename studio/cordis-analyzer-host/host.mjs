// F01 candidate control plane only. Analysis payload bytes never enter JS.
import { Context } from '@cordisjs/core';
import { createRequire } from 'node:module';
import { createInterface } from 'node:readline';
if (process.argv.includes('--lifecycle')) {
  await import('./lifecycle.mjs');
} else {
const require = createRequire(import.meta.url);
const coreVersion = require('@cordisjs/core/package.json').version;
const protocol = 'pktpath.cordis3.analyzer/1';
const ctx = new Context();
for (const level of ['error', 'warning', 'info']) {
  ctx.on(`internal/${level}`, (...args) => console.error(...args));
}
const registry = new Map();
ctx.set('f01Registry', registry);
let scope, activation, active = false, cleanupDone = false;
const pending = new Map();
const cleanup = [];
let closing = false;
function text(value, name) {
  if (typeof value !== 'string' || !value) throw new Error(`invalid ${name}`);
  return value;
}
async function dispatch(req) {
  if (req.protocol !== protocol) throw new Error('unsupported protocol');
  switch (req.op) {
    case 'hello':
      if (Number(process.versions.node.split('.')[0]) < 22) throw new Error('candidate requires Node >=22; tested runtime is separately reported');
      return { core: coreVersion, node: process.version };
    case 'activate': {
      if (scope || coreVersion !== '3.18.1') throw new Error('invalid activation/core version');
      activation = text(req.generation, 'generation');
      if (!Array.isArray(req.analyzers) || !req.analyzers.length) throw new Error('missing analyzers');
      const ids = req.analyzers.map(x => text(x, 'analyzer'));
      scope = ctx.plugin({
        name: 'pktpath-f01-offline-analyzers', inject: ['f01Registry'],
        apply(local) {
          local.effect(() => {
            for (const id of ids) local.get('f01Registry').set(id, activation);
            active = true;
            return () => {
              active = false;
              registry.clear(); // admission is revoked synchronously
              // Cordis3 does not await this disposer; THIS host retains its promise.
              const drain = Promise.all([...pending.values()].map(x => x.done))
                .then(() => { cleanupDone = true; });
              cleanup.push(drain);
              return drain;
            };
          });
        },
      });
      await ctx.start();
      if (!active) throw new Error('Cordis plugin did not activate');
      return { generation: activation };
    }
    case 'begin': {
      const id = text(req.task, 'task');
      if (!active || req.generation !== activation || registry.get(req.analyzer) !== activation)
        throw new Error('inactive activation');
      if (pending.has(id)) throw new Error('duplicate task');
      let resolve;
      const done = new Promise(r => { resolve = r; });
      pending.set(id, { done, resolve });
      return { accepted: true };
    }
    case 'finish': {
      const task = pending.get(req.task);
      if (!task) throw new Error('unknown task');
      pending.delete(req.task);
      task.resolve();
      return { accepted: active && req.generation === activation };
    }
    case 'deactivate':
      if (scope) scope.dispose();
      active = false;
      return { revoked: true };
    case 'drain':
      if (active) throw new Error('deactivate before drain');
      await Promise.all(cleanup);
      if (pending.size || !cleanupDone) throw new Error('drain incomplete');
      return { drained: true, cleanupDone };
    case 'shutdown':
      if (active || pending.size || !cleanupDone) throw new Error('shutdown before drain');
      await ctx.stop();
      closing = true;
      return { closed: true };
    default: throw new Error('unknown operation');
  }
}
const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
lines.on('line', line => {
  // Process concurrently so drain does not prevent an in-flight finish message.
  Promise.resolve().then(async () => {
    if (Buffer.byteLength(line) > 65536) throw new Error('control line too large');
    const req = JSON.parse(line);
    text(req.id, 'request id');
    try {
      const data = await dispatch(req);
      process.stdout.write(JSON.stringify({ id: req.id, protocol, ok: true, ...data }) + '\n', () => {
        if (closing) { lines.close(); process.stdin.destroy(); }
      });
    } catch (error) {
      process.stdout.write(JSON.stringify({ id: req.id, protocol, ok: false, error: String(error.message) }) + '\n');
    }
  }).catch(error => { console.error(error); process.exitCode = 1; lines.close(); process.stdin.destroy(); });
});

}
