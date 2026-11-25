// F02.0/1, same locked host package, one shared Context. Control/opaque tokens only.
import { Context } from '@cordisjs/core';
import { createRequire } from 'node:module';
import { createInterface } from 'node:readline';
const core = createRequire(import.meta.url)('@cordisjs/core/package.json').version;
const protocol = 'pktpath.cordis3.lifecycle/2';
const ctx = new Context();
for (const level of ['error', 'warning', 'info']) ctx.on(`internal/${level}`, (...x) => console.error(...x));
const entries = new Map(), publications = new Map(), facades = new Map();
const pending = new Map(), retired = new Map();
let sequence = 0n, attemptSequence = 0n, closing = false;
const trace = [];
const emit = data => process.stdout.write(JSON.stringify({ protocol, ...data }) + '\n');
const key = name => `f02:${name}`;
function record(phase, data) { trace.push({ phase, ...data }); while (trace.length > 256 || Buffer.byteLength(JSON.stringify(trace)) > 32768) trace.shift(); }
function callGo(op, data) {
  const id = `node/${++sequence}`;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    emit({ kind: 'request', id, op, ...data });
  });
}
// Required service OR active plugin ID; actual service wins, not Meta.Provides.
function refresh() {
  const names = new Set([...entries.values()].flatMap(x => x.requires));
  for (const name of names) {
    let selected;
    for (const value of publications.values()) {
      const service = value.services.find(s => s.name === name);
      if (service) { selected = service; break; }
    }
    if (!selected) for (const value of publications.values()) {
      if (value.plugin === name) { selected = { instance: value.generation, owner: name }; break; }
    }
    const old = facades.get(name);
    if (old?.instance === selected?.instance) continue;
    if (old) { facades.delete(name); ctx.set(key(name), undefined); }
    // set() emits synchronously: dependent effects may recursively withdraw.
    if (selected) { facades.set(name, selected); ctx.set(key(name), selected); }
  }
}
function withdraw(attempt) { if (publications.delete(attempt)) refresh(); }
function retire(id, attempt, revision) {
  withdraw(attempt);
  const done = callGo('revoke', { plugin: id, attempt, revision });
  retired.set(id, done);
  done.catch(error => record('cleanup-blocked', { plugin: id, attempt, error: error.message }));
  return done;
}
function install(plan) {
  const old = entries.get(plan.plugin);
  if (old && BigInt(plan.revision) <= BigInt(old.revision)) return; // stale Go intent cannot revert newer
  if (old?.fork) old.fork.dispose();
  const entry = { ...plan, fork: null };
  entries.set(plan.plugin, entry);
  refresh();
  if (!plan.enabled) return;
  // Unique function per logical plugin/revision; Cordis registry keys apply identity.
  const adapter = {
    name: `pktpath:${plan.plugin}:${plan.revision}`,
    inject: plan.requires.map(key),
    async apply(local) {
      const attempt = `${plan.plugin}/${plan.revision}/${++attemptSequence}`;
      let alive = true;
      local.effect(() => () => {
        alive = false;
        record('cordis-dispose', { plugin: plan.plugin, attempt });
        return retire(plan.plugin, attempt, plan.revision);
      });
      try {
        // v3 does NOT await old disposers. Our application awaits the observable
        // Go drain ACK; Go separately quarantines if actual cleanup is unfinished.
        await retired.get(plan.plugin)?.catch(() => {});
        if (!alive) return;
        const deps = Object.fromEntries(plan.requires.map(n => [n, local.get(key(n)).instance]));
        record('cordis-apply', { plugin: plan.plugin, attempt, deps });
        const data = await callGo('prepare', { plugin: plan.plugin, revision: plan.revision, attempt, deps });
        if (!alive) { await retire(plan.plugin, attempt, plan.revision).catch(() => {}); return; }
        publications.set(attempt, { ...data, plugin: plan.plugin });
        record('published', { plugin: plan.plugin, attempt, generation: data.generation });
        refresh();
      } catch (error) {
        // Cordis3 has no async epoch cancellation. Do not let an obsolete
        // rejected Apply cancel the reused runtime's current activation.
        if (!alive) { record('stale-apply-error', { plugin: plan.plugin, attempt, error: error.message }); return; }
        record('apply-failed', { plugin: plan.plugin, attempt, error: error.message });
        throw error;
      }
    },
  };
  entry.fork = ctx.plugin(adapter);
  // Do not await here: read loop must process revoke/other replies during Apply.
  void ctx.start().catch(error => record('start-failed', { error: error.message }));
}
async function dispatch(req) {
  switch (req.op) {
    case 'hello':
      if (core !== '3.18.1' || Number(process.versions.node.split('.')[0]) < 22) throw new Error('unsupported core/runtime');
      return { core, node: process.version };
    case 'plan':
      if (closing) throw new Error('host closing');
      for (const plan of req.entries) install(plan);
      return { accepted: true };
    case 'state':
      return { data: { trace, pending: pending.size, plugins: [...entries.values()].map(e => ({ plugin: e.plugin, revision: e.revision, status: e.fork?.status ?? 'disabled' })) } };
    case 'shutdown':
      closing = true;
      for (const e of entries.values()) e.fork?.dispose();
      await Promise.allSettled([...retired.values()]);
      await ctx.stop();
      return { drained: true };
    default: throw new Error('unknown operation');
  }
}
const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
lines.on('line', line => {
  Promise.resolve().then(async () => {
    if (Buffer.byteLength(line) > 65535) throw new Error('oversize frame');
    const req = JSON.parse(line);
    if (req.protocol !== protocol || typeof req.id !== 'string') throw new Error('bad protocol/id');
    if (req.kind === 'response' && req.id.startsWith('node/')) {
      const waiter = pending.get(req.id);
      if (!waiter) return; // duplicate/late reply never re-executes
      pending.delete(req.id);
      if (req.ok) waiter.resolve(req.data); else waiter.reject(new Error(req.error));
      return;
    }
    if (req.kind !== 'request' || !req.id.startsWith('go/')) throw new Error('bad namespace/kind');
    try {
      const data = await dispatch(req);
      emit({ kind: 'response', id: req.id, ok: true, ...data });
      if (closing && req.op === 'shutdown') { lines.close(); process.stdin.destroy(); }
    } catch (error) { emit({ kind: 'response', id: req.id, ok: false, error: error.message }); }
  }).catch(error => { console.error(error); process.exitCode = 1; lines.close(); process.stdin.destroy(); });
});
