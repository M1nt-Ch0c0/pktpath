import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { CordisHost } from '../src/kernel/host.ts';
import { AdbClient } from '../src/plugins/adb/adb-client.ts';
import type { BuiltinPlugin } from '../src/kernel/types.ts';
import { createAnalysisWave1Builtins } from '../src/plugins/analysis/index.ts';
import { registerWave1Builtins } from '../src/plugins/register.ts';
import { uiThemePlugin } from '../src/plugins/ui/theme.ts';
import { handleSessionRoute } from '../src/routes/session-routes.ts';
import { startStudioApp, type RunningStudioApp } from '../src/server/app.ts';

function makeTempRoot(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

async function bootTestApp(opts: {
  root: string;
  sub?: string;
  adbPath?: string;
  preWriteConfig?: { enabled: Record<string, boolean>; configs: Record<string, Record<string, unknown>> };
}): Promise<{ app: RunningStudioApp; appDir: string }> {
  const base = opts.sub ? path.join(opts.root, opts.sub) : opts.root;
  const appDir = path.join(base, 'app');
  fs.mkdirSync(appDir, { recursive: true });
  if (opts.preWriteConfig) {
    fs.writeFileSync(path.join(appDir, 'kernel-config.json'), JSON.stringify(opts.preWriteConfig), 'utf8');
  }
  const host = new CordisHost({
    appDir,
    sessionsRoot: path.join(base, 'sessions'),
    pluginsDir: path.join(base, 'plugins'),
    exportsDir: path.join(base, 'exports'),
    collectorsDir: path.join(opts.root, 'collectors'),
    webDir: path.join(base, 'web'),
    adbPath: opts.adbPath,
  });
  for (const p of createAnalysisWave1Builtins()) {
    host.registerBuiltin(p as unknown as BuiltinPlugin);
  }
  registerWave1Builtins(host);
  host.registerBuiltin(uiThemePlugin);
  await host.start();
  const app = await startStudioApp({
    host,
    listenPort: 0,
    autoQuitMs: 0,
    extraRouteHandlers: [handleSessionRoute],
  });
  return { app, appDir };
}

async function jsonFetch(url: string, init?: RequestInit): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await fetch(url, init);
  const body = (await res.json()) as Record<string, unknown>;
  return { status: res.status, body };
}

test('Wave 2 core plugin audit: required/usedBy metadata, hard toggle lock, and friendly Chinese errors', async () => {
  const root = makeTempRoot('pktpath-wave2-core-');
  const { app } = await bootTestApp({ root });

  try {
    const stateRes = await jsonFetch(`${app.url}/api/kernel/state`);
    assert.equal(stateRes.status, 200);
    const stateObj = (stateRes.body.state ?? stateRes.body) as { plugins: unknown };
    const plugins = stateObj.plugins as Array<{
      id: string;
      name: string;
      required: boolean;
      usedBy: string[];
      enabled: boolean;
      status: string;
      error?: string;
    }>;

    // Only builtin.transport.offline is required; all builtin plugins expose required (boolean) and usedBy (string[])
    const requiredPlugins = plugins.filter((p) => p.required);
    assert.deepEqual(
      requiredPlugins.map((p) => p.id),
      ['builtin.transport.offline'],
    );
    const offline = requiredPlugins[0]!;
    assert.equal(offline.name, '本地会话存储与加载');
    assert.ok(offline.usedBy.length >= 3);

    for (const p of plugins) {
      assert.equal(typeof p.required, 'boolean', `${p.id} required should be boolean`);
      assert.ok(Array.isArray(p.usedBy), `${p.id} usedBy should be string[]`);
    }

    // Attempting to disable required plugin is hard-blocked with HTTP 400 and friendly Chinese error
    const blockRes = await jsonFetch(`${app.url}/api/kernel/plugins/toggle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: 'builtin.transport.offline', enabled: false }),
    });
    assert.equal(blockRes.status, 400);
    assert.equal(blockRes.body.ok, false);
    assert.match(String(blockRes.body.error), /本地会话存储与加载.*不可关闭/);

    // Session endpoint still works
    const sessRes = await jsonFetch(`${app.url}/api/sessions`);
    assert.equal(sessRes.status, 200);

    // Disabling optional ADB plugin produces friendly Chinese error without raw internal IDs
    const offAdb = await jsonFetch(`${app.url}/api/kernel/plugins/toggle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: 'builtin.transport.android-adb', enabled: false }),
    });
    assert.equal(offAdb.status, 200);
    const devRes = await jsonFetch(`${app.url}/api/devices`);
    assert.equal(devRes.status, 400);
    assert.match(String(devRes.body.error), /Android ADB 连接.*未启用/);
    assert.doesNotMatch(String(devRes.body.error), /plugin is disabled|service is not active/);

    // Disabling collector cascades friendly Chinese error to mode plugins and capture/start
    const offCollector = await jsonFetch(`${app.url}/api/kernel/plugins/toggle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: 'builtin.collector.ebpf-tc', enabled: false }),
    });
    assert.equal(offCollector.status, 200);
    const afterCollector = (offCollector.body.state as { plugins: typeof plugins }).plugins;
    const oneshotRec = afterCollector.find((p) => p.id === 'builtin.mode.oneshot');
    assert.ok(oneshotRec);
    assert.equal(oneshotRec.status, 'error');
    assert.match(String(oneshotRec.error), /已关闭.*暂时停用/);
    assert.doesNotMatch(String(oneshotRec.error), /required service unavailable/);

    const capStartRes = await jsonFetch(`${app.url}/api/capture/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'oneshot' }),
    });
    assert.equal(capStartRes.status, 400);
    assert.match(String(capStartRes.body.error), /短时采集功能未启用/);
    assert.doesNotMatch(String(capStartRes.body.error), /plugin is disabled|service is not active/);

    // Disabling exporter returns friendly Chinese message on runExport
    const offPcap = await jsonFetch(`${app.url}/api/kernel/plugins/toggle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: 'builtin.exporter.pcapng', enabled: false }),
    });
    assert.equal(offPcap.status, 200);
    const expOut = await app.host.runExport({ exporter_id: 'pcapng', session_id: 'nonexistent' });
    assert.equal(expOut.ok, false);
    assert.match(String(expOut.error), /导出插件「.*」未启用/);
    assert.doesNotMatch(String(expOut.error), /exporter not active/);
  } finally {
    await app.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('Wave 2 persisted config self-healing: required plugin enabled=false in kernel-config.json is healed and rewritten on startup', async () => {
  const root = makeTempRoot('pktpath-wave2-heal-');
  const { app, appDir } = await bootTestApp({
    root,
    preWriteConfig: {
      enabled: {
        'builtin.transport.offline': false,
        'builtin.ui.theme': false,
      },
      configs: {},
    },
  });

  try {
    const snap = app.host.snapshot();
    const offline = snap.plugins.find((p) => p.id === 'builtin.transport.offline');
    const theme = snap.plugins.find((p) => p.id === 'builtin.ui.theme');
    assert.ok(offline && theme);
    assert.equal(offline.enabled, true);
    assert.equal(offline.status, 'active');
    assert.equal(theme.enabled, false);
    assert.equal(theme.status, 'disabled');

    // Verify healed state was persisted back to disk
    const cfgPath = path.join(appDir, 'kernel-config.json');
    const persisted = JSON.parse(fs.readFileSync(cfgPath, 'utf8')) as { enabled: Record<string, boolean> };
    assert.equal(persisted.enabled['builtin.transport.offline'], true);
    assert.equal(persisted.enabled['builtin.ui.theme'], false);
  } finally {
    await app.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('Wave 2 Yan residual fixes: su0 remoteAgentSha, inspect propagates ensureReady failure, and 409 carries capture_id + log_lines', async () => {
  const root = makeTempRoot('pktpath-wave2-yan-');
  const mockAdb = path.join(root, 'mock-adb.sh');
  const fakeSha = 'a'.repeat(64);
  const collectorPath = path.join(root, 'collectors', 'android-arm64', 'pktpath');
  fs.mkdirSync(path.dirname(collectorPath), { recursive: true });
  fs.writeFileSync(collectorPath, 'fake-elf-binary', 'utf8');

  // 1) Test remoteAgentSha with su0 mode directly on AdbClient
  fs.writeFileSync(
    mockAdb,
    `#!/usr/bin/env bash
set -euo pipefail
if [[ "\${1:-}" == "-s" ]]; then shift 2; fi
if [[ "\${1:-}" == "shell" ]]; then
  shift
  cmd="$*"
  if [[ "$cmd" == "id -u" ]]; then
    echo "2000"; exit 0
  fi
  if [[ "$cmd" == su\\ -c* ]]; then
    echo "su -c unsupported" >&2; exit 1
  fi
  if [[ "$cmd" == "su 0 id -u" ]]; then
    echo "0"; exit 0
  fi
  if [[ "$cmd" == sha256sum* ]]; then
    # non-root cannot read /data/local/tmp/pktpath
    exit 1
  fi
  if [[ "$cmd" == *"su 0"* && "$cmd" == *"sha256sum"* ]]; then
    echo "${fakeSha}  /data/local/tmp/pktpath"; exit 0
  fi
fi
exit 0
`,
    { mode: 0o755 },
  );

  const client = new AdbClient(mockAdb);
  const rootMode = await client.ensureRoot('SER_SU0');
  assert.equal(rootMode, 'su0');
  const sha = await client.remoteAgentSha('SER_SU0');
  assert.equal(sha, fakeSha);

  // 2) Test inspectDevice propagates ensureReady failure when unrooted (does not silently swallow)
  const unrootedAdb = path.join(root, 'mock-unrooted-adb.sh');
  fs.writeFileSync(
    unrootedAdb,
    `#!/usr/bin/env bash
set -euo pipefail
if [[ "\${1:-}" == "devices" ]]; then
  echo "List of devices attached"
  echo "SER_NOROOT	device model:Pixel"
  exit 0
fi
if [[ "\${1:-}" == "-s" ]]; then shift 2; fi
if [[ "\${1:-}" == "root" ]]; then
  echo "adbd cannot run as root in production builds"; exit 0
fi
if [[ "\${1:-}" == "shell" ]]; then
  shift
  cmd="$*"
  if [[ "$cmd" == "id -u" ]]; then echo "2000"; exit 0; fi
  if [[ "$cmd" == su* ]]; then echo "Permission denied" >&2; exit 1; fi
fi
exit 0
`,
    { mode: 0o755 },
  );

  const { app: appUnrooted } = await bootTestApp({ root, sub: 'unrooted', adbPath: unrootedAdb });

  try {
    const inspectRes = await jsonFetch(`${appUnrooted.url}/api/device/inspect?serial=SER_NOROOT`);
    assert.equal(inspectRes.status, 400);
    assert.equal(inspectRes.body.ok, false);
    assert.match(String(inspectRes.body.error), /root/i);
  } finally {
    await appUnrooted.close();
  }

  // 3) Test 409 CaptureConflictError carries capture_id and log_lines
  const runAdb = path.join(root, 'mock-run-adb.sh');
  fs.writeFileSync(
    runAdb,
    `#!/usr/bin/env bash
set -euo pipefail
if [[ "\${1:-}" == "devices" ]]; then
  echo "List of devices attached"
  echo "SER_RUN	device model:Pixel"
  exit 0
fi
if [[ "\${1:-}" == "-s" ]]; then shift 2; fi
if [[ "\${1:-}" == "push" ]]; then exit 0; fi
if [[ "\${1:-}" == "shell" ]]; then
  shift
  cmd="$*"
  if [[ "$cmd" == "id -u" ]]; then echo "0"; exit 0; fi
  if [[ "$cmd" == *sha256sum* ]]; then
    sha256sum "${collectorPath}" | awk '{print $1 "  /data/local/tmp/pktpath"}'
    exit 0
  fi
  if [[ "$cmd" == *" record "* || "$cmd" == *nohup* ]]; then
    echo "@@pid=42424"
    exit 0
  fi
  if [[ "$cmd" == *"@@comm="* ]]; then
    echo "[pktpath] capture running"
    echo "@@comm=pktpath"
    echo "@@stat=S"
    exit 0
  fi
  if [[ "$cmd" == *"kill -INT"* || "$cmd" == *"kill -TERM"* || "$cmd" == *"kill -KILL"* ]]; then
    exit 0
  fi
fi
exit 0
`,
    { mode: 0o755 },
  );

  const { app: appRun } = await bootTestApp({ root, sub: 'run', adbPath: runAdb });

  try {
    const start1 = await jsonFetch(`${appRun.url}/api/capture/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ serial: 'SER_RUN', mode: 'oneshot', dev: 'wlan0', duration_sec: 30 }),
    });
    assert.equal(start1.status, 200, JSON.stringify(start1.body));
    const activeId = String(start1.body.capture_id);
    assert.ok(activeId.length > 0);

    const start2 = await jsonFetch(`${appRun.url}/api/capture/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ serial: 'SER_RUN', mode: 'oneshot', dev: 'wlan0', duration_sec: 30 }),
    });
    assert.equal(start2.status, 409);
    assert.equal(start2.body.ok, false);
    assert.equal(start2.body.capture_id, activeId);
    assert.ok(Array.isArray(start2.body.log_lines));
    assert.ok((start2.body.log_lines as string[]).some((l) => l.includes('capture running')));
    assert.deepEqual(start2.body.log_tail, start2.body.log_lines);
  } finally {
    await appRun.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});
