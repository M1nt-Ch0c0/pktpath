#!/usr/bin/env node
// Minimal studio-cordis stand-in used by tray host unit tests.
// Honours --host / --port / --hang-ready / --no-ready / --crash-before-ready
// / --bad-health / --ready-delay-ms / --quit-hang.

import http from 'node:http';
import fs from 'node:fs';

function arg(name, fallback = '') {
  const pref = `--${name}`;
  const eq = `--${name}=`;
  for (let i = 2; i < process.argv.length; i++) {
    const a = process.argv[i];
    if (a === pref && i + 1 < process.argv.length) return process.argv[i + 1];
    if (a.startsWith(eq)) return a.slice(eq.length);
    if (a === pref) return 'true';
  }
  return fallback;
}

const host = arg('host', '127.0.0.1') || '127.0.0.1';
const port = Number.parseInt(arg('port', '0'), 10) || 0;
const readyDelay = Number.parseInt(arg('ready-delay-ms', '0'), 10) || 0;
const noReady = process.argv.includes('--no-ready') || arg('no-ready') === 'true';
const hangReady = process.argv.includes('--hang-ready') || arg('hang-ready') === 'true';
const crashBefore = process.argv.includes('--crash-before-ready') || arg('crash-before-ready') === 'true';
const badHealth = process.argv.includes('--bad-health') || arg('bad-health') === 'true';
const quitHang = process.argv.includes('--quit-hang') || arg('quit-hang') === 'true';
const quitDelay = Number.parseInt(arg('quit-delay-ms', '30'), 10);

// Behaviour flags can also be dropped in as a sidecar file so tests do not
// have to change the launcher argv contract.
const flagsFile = process.env.PKTPATH_MOCK_FLAGS;
let flags = {};
if (flagsFile) {
  try { flags = JSON.parse(fs.readFileSync(flagsFile, 'utf8')); } catch {}
}

if (flags.crashBefore || crashBefore) {
  process.stderr.write('mock studio crashing before ready\n');
  process.exit(2);
}

if (flags.hangReady || hangReady) {
  setInterval(() => {}, 1 << 30);
}

const healthOK = !(flags.badHealth || badHealth);

const server = http.createServer((req, res) => {
  const url = req.url || '/';
  if (req.method === 'GET' && url.startsWith('/api/health')) {
    const body = healthOK ? '{"ok":true}' : '{"ok":false}';
    const code = healthOK ? 200 : 503;
    res.writeHead(code, { 'content-type': 'application/json' });
    res.end(body);
    return;
  }
  if (req.method === 'POST' && url.startsWith('/api/app/quit')) {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{"ok":true}');
    if (!(flags.quitHang || quitHang)) {
      setTimeout(() => process.exit(0), Number.isFinite(flags.quitDelayMs) ? flags.quitDelayMs : quitDelay);
    }
    return;
  }
  res.writeHead(404);
  res.end();
});

server.listen(port, host, () => {
  const addr = server.address();
  const url = `http://${host}:${addr.port}`;
  const delay = Number.isFinite(flags.readyDelayMs) ? flags.readyDelayMs : readyDelay;
  const emit = () => {
    if (!(flags.noReady || noReady)) {
      process.stdout.write(`PKTPATH_STUDIO_READY url=${url} pid=${process.pid}\n`);
    }
  };
  if (delay > 0) setTimeout(emit, delay);
  else emit();
});
