import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { CordisHost } from '../src/kernel/host.ts';
import { AdbClient, parseIPBrAddr, resolveAdbBinary, REMOTE_PLUGINS_DIR, wrapPriv } from '../src/plugins/adb/adb-client.ts';
import { uniquePath } from '../src/plugins/adb/capture-controller.ts';
import type { EbpfCollectorService } from '../src/plugins/adb/ebpf-tc.ts';
import { registerWave1Builtins } from '../src/plugins/register.ts';
import { startStudioApp } from '../src/server/app.ts';

// Exact whitelist of flags accepted by device/main.c `cmd_record`.
const DEVICE_MAIN_C_RECORD_FLAGS = new Set([
  '--mode',
  '--dev',
  '--scope',
  '--uid',
  '--tgid',
  '--proto',
  '--src-ip',
  '--dst-ip',
  '--src-port',
  '--dst-port',
  '--mark',
  '--sample',
  '--sample-by',
  '--duration',
  '--capture-hdr',
  '--profile',
  '--allow-partial',
  '--trigger',
  '--pre-window',
  '--post-window',
  '--mem-budget',
  '--disk-budget',
  '--plugin-dir',
]);

function assertOnlyValidDeviceFlags(args: string[]): void {
  for (let i = 0; i < args.length; i += 1) {
    const tok = args[i];
    if (tok.startsWith('--')) {
      assert.ok(
        DEVICE_MAIN_C_RECORD_FLAGS.has(tok),
        `flag "${tok}" is NOT accepted by device/main.c (args=${JSON.stringify(args)})`,
      );
    }
  }
}

function createParityMockAdb(dir: string, stateDir: string): string {
  const scriptPath = path.join(dir, 'adb');
  const script = `#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const stateDir = ${JSON.stringify(stateDir)};
const logFile = path.join(stateDir, 'adb-invocations.log');
const args = process.argv.slice(2);
fs.appendFileSync(logFile, JSON.stringify(args) + '\\n');

const remoteRoot = path.join(stateDir, 'remote');
fs.mkdirSync(remoteRoot, { recursive: true });

if (args[0] === 'devices') {
  console.log('List of devices attached');
  console.log('PARITY001\\tdevice product:pixel model:Pixel_9 device:tokay');
  process.exit(0);
}

const serial = args[0] === '-s' ? args[1] : '';
const rest = args[0] === '-s' ? args.slice(2) : args;

if (rest[0] === 'push') {
  const [, local, remote] = rest;
  const dst = path.join(remoteRoot, remote.replace(/^\\/+/, ''));
  fs.mkdirSync(path.dirname(dst), { recursive: true });
  fs.copyFileSync(local, dst);
  process.exit(0);
}

if (rest[0] === 'pull') {
  const [, remote, local] = rest;
  if (remote.endsWith('/.')) {
    console.error('forbidden trailing /. on adb pull');
    process.exit(1);
  }
  const src = path.join(remoteRoot, remote.replace(/^\\/+/, ''));
  if (!fs.existsSync(src)) {
    console.error('remote object does not exist: ' + remote);
    process.exit(1);
  }
  const st = fs.statSync(src);
  if (st.isDirectory()) {
    const target = path.join(local, path.basename(src));
    fs.mkdirSync(target, { recursive: true });
    for (const f of fs.readdirSync(src)) {
      fs.copyFileSync(path.join(src, f), path.join(target, f));
    }
  } else {
    fs.mkdirSync(path.dirname(local), { recursive: true });
    fs.copyFileSync(src, local);
  }
  process.exit(0);
}

if (rest[0] === 'shell') {
  const cmd = rest.slice(1).join(' ');
  if (cmd === 'id -u') {
    console.log('0');
    process.exit(0);
  }
  if (cmd.includes('@@model=')) {
    const agentPath = path.join(remoteRoot, 'data/local/tmp/.pktpath_studio/pktpath');
    let sha = '';
    if (fs.existsSync(agentPath)) {
      sha = crypto.createHash('sha256').update(fs.readFileSync(agentPath)).digest('hex');
    }
    console.log('@@model=Pixel 9');
    console.log('@@product=tokay');
    console.log('@@android=15');
    console.log('@@kernel=6.6.30-android15');
    console.log('@@arch=aarch64');
    console.log('@@uid=0');
    console.log('@@sha=' + sha);
    process.exit(0);
  }
  if (cmd.includes('sha256sum')) {
    if (cmd.includes('mv -f')) {
      const stage = path.join(remoteRoot, 'data/local/tmp/pktpath_tmp');
      const agent = path.join(remoteRoot, 'data/local/tmp/.pktpath_studio/pktpath');
      fs.mkdirSync(path.dirname(agent), { recursive: true });
      fs.renameSync(stage, agent);
    }
    const agent = path.join(remoteRoot, 'data/local/tmp/.pktpath_studio/pktpath');
    if (fs.existsSync(agent)) {
      const sha = crypto.createHash('sha256').update(fs.readFileSync(agent)).digest('hex');
      console.log(sha + '  /data/local/tmp/.pktpath_studio/pktpath');
    }
    process.exit(0);
  }
  if (cmd.includes('rm -rf /data/local/tmp/.pktpath_studio/plugins')) {
    const pdir = path.join(remoteRoot, 'data/local/tmp/.pktpath_studio/plugins');
    fs.rmSync(pdir, { recursive: true, force: true });
    if (cmd.includes('mkdir -p')) fs.mkdirSync(pdir, { recursive: true });
    process.exit(0);
  }
  if (cmd.includes('_plug_') && cmd.includes('mv -f')) {
    const m = /mv -f '([^']+)' '([^']+)'/.exec(cmd);
    if (m) {
      const src = path.join(remoteRoot, m[1].replace(/^\\/+/, ''));
      const dst = path.join(remoteRoot, m[2].replace(/^\\/+/, ''));
      fs.mkdirSync(path.dirname(dst), { recursive: true });
      fs.renameSync(src, dst);
    }
    process.exit(0);
  }
  if (cmd.includes('ip -br addr')) {
    console.log('lo               UNKNOWN        127.0.0.1/8');
    console.log('wlan0            UP             192.168.10.88/24');
    process.exit(0);
  }
  if (cmd.includes('pktpath inspect')) {
    const hasPluginDir = cmd.includes('--plugin-dir');
    console.log(JSON.stringify({
      dev: 'wlan0',
      scope: 'tc-egress',
      plugins_loaded: hasPluginDir ? 1 : 0,
      qdiscs: [{ handle: '8001:', kind: 'fq_codel', dev: 'wlan0' }],
    }));
    process.exit(0);
  }
  if (cmd.includes('pm list packages -U')) {
    console.log('package:com.example.demo uid:10250');
    process.exit(0);
  }
  if (cmd.includes('pktpath record')) {
    const mOut = /--out\\s+[^\\/]*(\\/data\\/local\\/tmp\\/[^'"\\\\\\s;]+)/.exec(cmd);
    if (mOut) {
      const outDir = path.join(remoteRoot, mOut[1].replace(/^\\/+/, ''));
      fs.mkdirSync(outDir, { recursive: true });
      fs.writeFileSync(path.join(outDir, 'meta.json'), JSON.stringify({ dev: 'wlan0', scope: 'tc-egress' }));
      fs.writeFileSync(outDir + '.log', 'pktpath record started\\n');
      fs.writeFileSync(path.join(stateDir, 'alive.flag'), '1');
      if (fs.existsSync(path.join(stateDir, 'stubborn.mode'))) {
        fs.writeFileSync(path.join(stateDir, 'stubborn.flag'), '1');
      }
    }
    console.log('@@pid=5151');
    process.exit(0);
  }
  if (cmd.includes('@@comm=')) {
    const alive = fs.existsSync(path.join(stateDir, 'alive.flag'));
    console.log('pktpath running');
    console.log('@@comm=' + (alive ? 'pktpath' : ''));
    console.log('@@stat=' + (alive ? 'S' : ''));
    process.exit(0);
  }
  if (cmd.startsWith('kill -')) {
    const sig = cmd.split(' ')[1];
    fs.appendFileSync(path.join(stateDir, 'signals.log'), sig + '\\n');
    const stubborn = fs.existsSync(path.join(stateDir, 'stubborn.flag'));
    if (!stubborn || sig === '-KILL') {
      fs.rmSync(path.join(stateDir, 'alive.flag'), { force: true });
      fs.rmSync(path.join(stateDir, 'stubborn.flag'), { force: true });
    }
    process.exit(0);
  }
  if (cmd.includes('@@exists=')) {
    const m = /\\[ -e '([^']+)' \\]/.exec(cmd);
    const exists = m ? fs.existsSync(path.join(remoteRoot, m[1].replace(/^\\/+/, ''))) : false;
    console.log('@@exists=' + (exists ? '1' : '0'));
    process.exit(0);
  }
  if (cmd.includes('@@gone=')) {
    console.log('@@gone=1');
    process.exit(0);
  }
  process.exit(0);
}
process.exit(0);
`;
  fs.writeFileSync(scriptPath, script, { mode: 0o755 });
  return scriptPath;
}

describe('Go vs Cordis Backend Parity (P0-1..3, P1-1..4, P2-1..4)', () => {
  it('P0-1: buildRecordArgs emits ONLY valid device/main.c flags for default UI body and all-filters body', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pktpath-p01-'));
    try {
      const host = new CordisHost({
        appDir: path.join(root, 'app'),
        sessionsRoot: path.join(root, 'app', 'sessions'),
        pluginsDir: path.join(root, 'app', 'plugins'),
        exportsDir: path.join(root, 'app', 'exports'),
        collectorsDir: path.join(root, 'collectors'),
        webDir: path.join(root, 'web'),
      });
      registerWave1Builtins(host);
      await host.start();
      const collector = host.getService<EbpfCollectorService>('collector.ebpf');
      assert.ok(collector);

      // Default UI request body (previously caused exit 2 with --hdr-bytes 96)
      const defaultUiArgs = collector.buildRecordArgs({
        serial: '5cc2e4eb',
        mode: 'oneshot',
        duration_sec: 15,
        hdr_bytes: 96,
      });
      assertOnlyValidDeviceFlags(defaultUiArgs);
      assert.deepEqual(defaultUiArgs, [
        '--mode', 'oneshot',
        '--dev', 'wlan0',
        '--scope', 'tc-egress',
        '--duration', '15s',
        '--capture-hdr', '96',
      ]);
      assert.equal(defaultUiArgs.includes('--hdr-bytes'), false);

      // Full filters + Go/Cordis aliases (port -> --dst-port, profile_sendmsg -> --profile sendmsg, sample: 4 -> 1/4)
      const fullArgs = collector.buildRecordArgs({
        serial: '5cc2e4eb',
        mode: 'daemon',
        dev: 'rmnet_data0',
        scope: 'sock-tx',
        uid: 10240,
        tgid: 4321,
        proto: 'tcp',
        src_ip: '10.0.0.2/32',
        dst_ip: '1.1.1.1',
        src_port: 54321,
        port: 443,
        mark: '0x10/0xff',
        sample: 4,
        sample_by: 'flow',
        duration_sec: 60,
        capture_hdr: 200, // clamped to 128
        profile_sendmsg: true,
        allow_partial: true,
        trigger: '2000',
        pre_window_sec: 3,
        post_window_sec: 5,
        mem_budget: '64M',
        disk_budget: '256M',
        plugin_dir: REMOTE_PLUGINS_DIR,
      });
      assertOnlyValidDeviceFlags(fullArgs);
      assert.deepEqual(fullArgs, [
        '--mode', 'daemon',
        '--dev', 'rmnet_data0',
        '--scope', 'sock-tx',
        '--uid', '10240',
        '--tgid', '4321',
        '--proto', 'tcp',
        '--src-ip', '10.0.0.2/32',
        '--dst-ip', '1.1.1.1',
        '--src-port', '54321',
        '--dst-port', '443',
        '--mark', '0x10/0xff',
        '--sample', '1/4',
        '--sample-by', 'flow',
        '--duration', '60s',
        '--capture-hdr', '128',
        '--profile', 'sendmsg',
        '--allow-partial',
        '--trigger', 'sojourn_us>2000',
        '--pre-window', '3s',
        '--post-window', '5s',
        '--mem-budget', '64M',
        '--disk-budget', '256M',
        '--plugin-dir', REMOTE_PLUGINS_DIR,
      ]);
      assert.equal(fullArgs.includes('--port'), false);
      assert.equal(fullArgs.includes('--profile-sendmsg'), false);

      // Invalid scope rejected
      assert.throws(() => collector.buildRecordArgs({ scope: 'all' }), /invalid scope/);
      assert.throws(() => collector.buildRecordArgs({ scope: 'bogus' }), /invalid scope/);
      await host.shutdown(2_000);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('P0-2/3, P1-1..4, P2-2/4: full HTTP flow with enriched devices, omitted serial, runtime JSON plugin sync, and SIGKILL escalation', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pktpath-parity-http-'));
    try {
      const binDir = path.join(root, 'bin');
      const stateDir = path.join(root, 'state');
      const appDir = path.join(root, 'app');
      const collectorsDir = path.join(root, 'collectors');
      fs.mkdirSync(binDir, { recursive: true });
      fs.mkdirSync(stateDir, { recursive: true });
      fs.mkdirSync(path.join(collectorsDir, 'android-arm64'), { recursive: true });
      fs.writeFileSync(path.join(collectorsDir, 'android-arm64', 'pktpath'), '#!/bin/sh\necho mock\n');

      const mockAdb = createParityMockAdb(binDir, stateDir);
      const host = new CordisHost({
        appDir,
        sessionsRoot: path.join(appDir, 'sessions'),
        pluginsDir: path.join(appDir, 'plugins'),
        exportsDir: path.join(appDir, 'exports'),
        collectorsDir,
        webDir: path.join(root, 'web'),
        adbPath: mockAdb,
      });
      registerWave1Builtins(host);
      await host.start();
      const app = await startStudioApp({ host, listenPort: 0 });

      try {
        // P1-1: GET /api/devices returns enriched device fields & top-level metadata
        const devs = await fetch(`${app.url}/api/devices`).then((r) => r.json()) as {
          ok: boolean;
          adb_path: string;
          adb_missing: boolean;
          adb_error: string;
          available_agents: string[];
          devices: Array<{
            serial: string;
            android_ver: string;
            kernel: string;
            root_mode: string;
            agent_ready: boolean;
          }>;
        };
        assert.equal(devs.ok, true);
        assert.equal(devs.adb_path, mockAdb);
        assert.equal(devs.adb_missing, false);
        assert.equal(devs.adb_error, '');
        assert.deepEqual(devs.available_agents, ['android-arm64']);
        assert.equal(devs.devices[0].android_ver, '15');
        assert.equal(devs.devices[0].kernel, '6.6.30-android15');
        assert.equal(devs.devices[0].root_mode, 'adbd-root');
        assert.equal(devs.devices[0].agent_ready, false);

        // P1-4: POST /api/device/prepare with omitted serial (auto-selects single device)
        const prep = await fetch(`${app.url}/api/device/prepare`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({}),
        }).then((r) => r.json()) as {
          ok: boolean;
          serial: string;
          transport: string;
          android_ver: string;
          model: string;
          pushed: boolean;
          agent_pushed: boolean;
          elapsed_ms: number;
        };
        assert.equal(prep.ok, true);
        assert.equal(prep.serial, 'PARITY001');
        assert.equal(prep.transport, 'adb');
        assert.equal(prep.android_ver, '15');
        assert.equal(prep.model, 'Pixel 9');
        assert.equal(prep.pushed, true);
        assert.equal(prep.agent_pushed, true);
        assert.equal(typeof prep.elapsed_ms, 'number');

        // P1-3: Import a runtime JSON plugin and verify inspect + capture sync it with --plugin-dir
        const imp = await fetch(`${app.url}/api/plugins/import`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            filename: 'vendor_qdisc.json',
            content: JSON.stringify({
              id: 'vendor_qdisc',
              qdiscs: [{ id: 'vq', kind: 'vq', mode: 'leaf', enqueue_sym: 'vq_enq', dequeue_sym: 'vq_deq' }],
            }),
          }),
        }).then((r) => r.json()) as { ok: boolean };
        assert.equal(imp.ok, true);

        // P0-3: GET /api/device/inspect with omitted serial syncs plugin and passes --plugin-dir
        const insp = await fetch(`${app.url}/api/device/inspect`).then((r) => r.json()) as {
          ok: boolean;
          serial: string;
          dev: string;
          scope: string;
          interfaces: unknown[];
          inspect: { plugins_loaded: number };
        };
        assert.equal(insp.ok, true);
        assert.equal(insp.serial, 'PARITY001');
        assert.equal(insp.dev, 'wlan0');
        assert.equal(insp.scope, 'tc-egress');
        assert.ok(Array.isArray(insp.interfaces));
        assert.equal(insp.inspect.plugins_loaded, 1);

        // P2-2: GET /api/device/apps returns serial and apps
        const appsResp = await fetch(`${app.url}/api/device/apps`).then((r) => r.json()) as {
          ok: boolean;
          serial: string;
          apps: Array<{ pkg: string; uid: number }>;
        };
        assert.equal(appsResp.ok, true);
        assert.equal(appsResp.serial, 'PARITY001');
        assert.equal(appsResp.apps[0].pkg, 'com.example.demo');

        // P1-2 & P2-4: Capture start (omitted serial) + status aliases + stop with SIGKILL escalation
        fs.writeFileSync(path.join(stateDir, 'stubborn.mode'), '1');
        const startResp = await fetch(`${app.url}/api/capture/start`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mode: 'oneshot', hdr_bytes: 96, duration_sec: 10 }),
        }).then((r) => r.json()) as {
          ok: boolean;
          phase: string;
          status: string;
          active: boolean;
          serial: string;
          dev: string;
          scope: string;
          remote_dir: string;
          command: string;
        };
        assert.equal(startResp.ok, true);
        assert.equal(startResp.phase, 'running');
        assert.equal(startResp.status, 'running');
        assert.equal(startResp.active, true);
        assert.equal(startResp.serial, 'PARITY001');
        assert.equal(startResp.dev, 'wlan0');
        assert.equal(startResp.scope, 'tc-egress');
        assert.ok(startResp.command.includes('--capture-hdr 96'));
        assert.ok(startResp.command.includes(`--plugin-dir ${REMOTE_PLUGINS_DIR}`));

        const stResp = await fetch(`${app.url}/api/capture/status`).then((r) => r.json()) as {
          ok: boolean;
          active: boolean;
          phase: string;
          status: string;
          dev: string;
          scope: string;
          command: string;
          log_lines: string[];
          log_tail: string[];
        };
        assert.equal(stResp.ok, true);
        assert.equal(stResp.active, true);
        assert.equal(stResp.phase, 'running');
        assert.equal(stResp.status, 'running');
        assert.equal(stResp.dev, 'wlan0');
        assert.equal(stResp.scope, 'tc-egress');
        assert.deepEqual(stResp.log_lines, stResp.log_tail);

        const stopResp = await fetch(`${app.url}/api/capture/stop`, { method: 'POST', body: '{}' }).then((r) => r.json()) as {
          ok: boolean;
          phase: string;
          status: string;
          last_session_id: string;
          session_id: string;
          session_path: string;
          session_dir: string;
          remote_cleaned: boolean;
          clean_exit: boolean;
          log_lines: string[];
        };
        assert.equal(stopResp.ok, true);
        assert.equal(stopResp.phase, 'done');
        assert.equal(stopResp.status, 'done');
        assert.equal(stopResp.last_session_id, stopResp.session_id);
        assert.equal(stopResp.session_path, stopResp.session_dir);
        assert.equal(stopResp.remote_cleaned, true);
        assert.equal(stopResp.clean_exit, false); // escalated past INT to TERM -> KILL

        const sigLog = fs.readFileSync(path.join(stateDir, 'signals.log'), 'utf8').trim().split('\n');
        assert.deepEqual(sigLog, ['-INT', '-TERM', '-KILL']);
      } finally {
        await app.close();
      }
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('P0-2, P2-1, P2-3: uniquePath, resolveAdbBinary (PKTPATH_ADB / ANDROID_SDK_ROOT), and ip -o addr parsing', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pktpath-p2-'));
    const origEnv = {
      PKTPATH_ADB: process.env.PKTPATH_ADB,
      ANDROID_SDK_ROOT: process.env.ANDROID_SDK_ROOT,
      PATH: process.env.PATH,
    };
    try {
      // P0-2 uniquePath
      const base = path.join(root, 'sess_a');
      assert.equal(uniquePath(base), base);
      fs.mkdirSync(base);
      assert.equal(uniquePath(base), `${base}_2`);

      // P2-1 resolveAdbBinary via PKTPATH_ADB and ANDROID_SDK_ROOT
      const fakeAdb1 = path.join(root, 'custom-adb');
      fs.writeFileSync(fakeAdb1, 'x');
      process.env.PATH = '';
      process.env.PKTPATH_ADB = fakeAdb1;
      assert.equal(resolveAdbBinary(undefined), fakeAdb1);

      delete process.env.PKTPATH_ADB;
      const sdkDir = path.join(root, 'sdk');
      const ptDir = path.join(sdkDir, 'platform-tools');
      fs.mkdirSync(ptDir, { recursive: true });
      const binName = process.platform === 'win32' ? 'adb.exe' : 'adb';
      const fakeAdb2 = path.join(ptDir, binName);
      fs.writeFileSync(fakeAdb2, 'x');
      process.env.ANDROID_SDK_ROOT = sdkDir;
      assert.equal(resolveAdbBinary(undefined), fakeAdb2);

      // P2-3 ip -o addr parsing
      const parsed = parseIPBrAddr([
        '1: lo    inet 127.0.0.1/8 scope host lo',
        '2: wlan0    inet 192.168.1.55/24 brd 192.168.1.255 scope global wlan0',
        '2: wlan0    inet6 fe80::1/64 scope link',
      ].join('\n'));
      assert.equal(parsed.length, 2);
      assert.equal(parsed[1].name, 'wlan0');
      assert.deepEqual(parsed[1].addrs, ['192.168.1.55/24', 'fe80::1/64']);
    } finally {
      if (origEnv.PKTPATH_ADB === undefined) delete process.env.PKTPATH_ADB;
      else process.env.PKTPATH_ADB = origEnv.PKTPATH_ADB;
      if (origEnv.ANDROID_SDK_ROOT === undefined) delete process.env.ANDROID_SDK_ROOT;
      else process.env.ANDROID_SDK_ROOT = origEnv.ANDROID_SDK_ROOT;
      process.env.PATH = origEnv.PATH;
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});


describe('Yan cross-audit fixes (Y-AUDIT-01, Y-AUDIT-02, Y-AUDIT-04)', () => {
  it('Y-AUDIT-04: wrapPriv and ensureRoot split su0 mode when su -c fails and su 0 id -u succeeds', async () => {
    assert.equal(wrapPriv('su', 'id -u'), "su -c 'id -u'");
    assert.equal(wrapPriv('su0', 'id -u'), "su 0 sh -c 'id -u'");

    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pktpath-su0-'));
    try {
      const logFile = path.join(root, 'su0.log');
      const mockAdb = path.join(root, 'adb');
      fs.writeFileSync(
        mockAdb,
        [
          '#!/usr/bin/env bash',
          'set -euo pipefail',
          `LOG="${logFile}"`,
          'echo "$*" >> "$LOG"',
          'if [ "$1" = "start-server" ]; then exit 0; fi',
          'if [ "$1" = "-s" ]; then shift 2; fi',
          'case "$1" in',
          '  root)',
          '    echo "adbd cannot run as root in production builds"',
          '    exit 0',
          '    ;;',
          '  shell)',
          '    shift',
          '    CMD="$*"',
          '    if [ "$CMD" = "id -u" ]; then echo "2000"; exit 0; fi',
          '    if [[ "$CMD" == "su -c "* ]]; then echo "su: invalid option -- c" >&2; exit 1; fi',
          '    if [ "$CMD" = "su 0 id -u" ]; then echo "0"; exit 0; fi',
          '    if [[ "$CMD" == "su 0 sh -c "* ]]; then echo "SU0_OK"; exit 0; fi',
          '    exit 1',
          '    ;;',
          'esac',
          'exit 0',
        ].join('\n'),
        { mode: 0o755 },
      );

      const client = new AdbClient(mockAdb);
      const mode = await client.ensureRoot('SU0SER');
      assert.equal(mode, 'su0');
      assert.equal(client.rootMode('SU0SER'), 'su0');

      const res = await client.priv('SU0SER', 'echo hello');
      assert.equal(res.stdout.trim(), 'SU0_OK');
      const log = fs.readFileSync(logFile, 'utf8');
      assert.ok(log.includes("su 0 sh -c 'echo hello'"), `expected su 0 sh -c in log, got: ${log}`);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('Y-AUDIT-01: POST /api/capture/start calls ensureReady automatically and fails cleanly when unrooted', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pktpath-yaudit01-'));
    try {
      const mockAdb = path.join(root, 'adb');
      fs.writeFileSync(
        mockAdb,
        [
          '#!/usr/bin/env bash',
          'set -euo pipefail',
          'if [ "$1" = "start-server" ]; then exit 0; fi',
          'if [ "$1" = "devices" ]; then echo "List of devices attached"; echo "NOROOT01 device product:test model:NoRoot"; exit 0; fi',
          'if [ "$1" = "-s" ]; then shift 2; fi',
          'case "$1" in',
          '  root) echo "adbd cannot run as root in production builds"; exit 0 ;;',
          '  shell)',
          '    shift; CMD="$*"',
          '    if [ "$CMD" = "id -u" ]; then echo "2000"; exit 0; fi',
          '    if [[ "$CMD" == "su "* ]]; then exit 1; fi',
          '    exit 0',
          '    ;;',
          'esac',
          'exit 0',
        ].join('\n'),
        { mode: 0o755 },
      );

      const collectorDir = path.join(root, 'collectors', 'android-arm64');
      fs.mkdirSync(collectorDir, { recursive: true });
      fs.writeFileSync(path.join(collectorDir, 'pktpath'), 'fake-elf');

      const webDir = path.join(root, 'web');
      fs.mkdirSync(webDir, { recursive: true });
      fs.writeFileSync(path.join(webDir, 'index.html'), '<html></html>');
      const host = new CordisHost({
        appDir: path.join(root, 'app'),
        sessionsRoot: path.join(root, 'sessions'),
        pluginsDir: path.join(root, 'plugins'),
        exportsDir: path.join(root, 'exports'),
        collectorsDir: path.join(root, 'collectors'),
        webDir,
      });
      registerWave1Builtins(host);
      await host.start();
      await host.updateConfig('builtin.transport.android-adb', { adb_path: mockAdb });
      const app = await startStudioApp({ host, port: 0, hostAddr: '127.0.0.1' });
      try {
        const r = await fetch(`${app.url}/api/capture/start`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ serial: 'NOROOT01', mode: 'oneshot', dev: 'wlan0', duration_sec: 5 }),
        });
        assert.equal(r.status, 400);
        const body = await r.json() as { ok: boolean; error: string };
        assert.equal(body.ok, false);
        assert.match(body.error, /not rooted/i);
      } finally {
        await app.close();
      }
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('Y-AUDIT-02: synchronous 900ms immediate-exit error surfaces log_lines, and background monitor auto-pulls timed oneshot', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pktpath-yaudit02-'));
    try {
      const stateDir = path.join(root, 'state');
      fs.mkdirSync(stateDir, { recursive: true });
      const modeFile = path.join(stateDir, 'mode.txt');
      const pollCountFile = path.join(stateDir, 'poll.count');
      const mockAdb = path.join(root, 'adb');
      fs.writeFileSync(
        mockAdb,
        [
          '#!/usr/bin/env bash',
          'set -euo pipefail',
          `MODE_FILE="${modeFile}"`,
          `POLL_FILE="${pollCountFile}"`,
          'if [ "$1" = "start-server" ]; then exit 0; fi',
          'if [ "$1" = "devices" ]; then echo "List of devices attached"; echo "MON01 device product:test model:MonPhone"; exit 0; fi',
          'if [ "$1" = "-s" ]; then shift 2; fi',
          'case "$1" in',
          '  push) exit 0 ;;',
          '  pull)',
          '    SRC="$2"; DST="$3"',
          '    if [[ "$SRC" == *.log ]]; then echo "record done" > "$DST"; exit 0; fi',
          '    BASE=$(basename "$SRC"); mkdir -p "$DST/$BASE"',
          '    echo "{\"schema_version\":2}" > "$DST/$BASE/manifest.json"',
          '    exit 0',
          '    ;;',
          '  shell)',
          '    shift; CMD="$*"',
          '    if [ "$CMD" = "id -u" ]; then echo "0"; exit 0; fi',
          '    if [[ "$CMD" == *"sha256sum"* ]]; then echo "eb85480c61a2ceb4d48255572a9a779b2005498110dd945eeedfe226d343f1c3  /data/local/tmp/pktpath"; exit 0; fi',
          '    if [[ "$CMD" == *"@@model="* ]]; then printf "@@model=MonPhone\n@@product=test\n@@android=15\n@@kernel=6.6\n@@arch=aarch64\n"; exit 0; fi',
          '    if [[ "$CMD" == *"@@pid="* ]]; then echo "0" > "$POLL_FILE"; echo "@@pid=99123"; exit 0; fi',
          '    if [[ "$CMD" == *"pktpath"* && "$CMD" == *"record"* && "$CMD" == *"@@pid="* ]]; then',
          '      echo "0" > "$POLL_FILE"',
          '      echo "@@pid=99123"',
          '      exit 0',
          '    fi',
          '    if [[ "$CMD" == *"/proc/99123/comm"* ]]; then',
          '      M=$(cat "$MODE_FILE")',
          '      if [ "$M" = "crash" ]; then',
          '        echo "error: failed to attach tc hook on wlan0: EPERM"',
          '        echo "@@comm="',
          '        echo "@@stat="',
          '        exit 0',
          '      fi',
          '      C=$(cat "$POLL_FILE" 2>/dev/null || echo 0)',
          '      C=$((C + 1)); echo "$C" > "$POLL_FILE"',
          '      if [ "$C" -le 1 ]; then',
          '        echo "recording on wlan0..."',
          '        echo "@@comm=pktpath"',
          '        echo "@@stat=S"',
          '      else',
          '        echo "duration elapsed, wrote manifest.json"',
          '        echo "@@comm="',
          '        echo "@@stat="',
          '      fi',
          '      exit 0',
          '    fi',
          '    if [[ "$CMD" == *"@@exists=1"* ]]; then',
          '      M=$(cat "$MODE_FILE")',
          '      if [ "$M" = "crash" ] && [[ "$CMD" == *"manifest.json"* ]]; then echo "@@exists=0"; exit 0; fi',
          '      echo "@@exists=1"; exit 0',
          '    fi',
          '    exit 0',
          '    ;;',
          'esac',
          'exit 0',
        ].join('\n'),
        { mode: 0o755 },
      );

      const collectorDir = path.join(root, 'collectors', 'android-arm64');
      fs.mkdirSync(collectorDir, { recursive: true });
      fs.writeFileSync(path.join(collectorDir, 'pktpath'), 'fake-elf');

      const webDir = path.join(root, 'web');
      fs.mkdirSync(webDir, { recursive: true });
      fs.writeFileSync(path.join(webDir, 'index.html'), '<html></html>');
      const host = new CordisHost({
        appDir: path.join(root, 'app'),
        sessionsRoot: path.join(root, 'sessions'),
        pluginsDir: path.join(root, 'plugins'),
        exportsDir: path.join(root, 'exports'),
        collectorsDir: path.join(root, 'collectors'),
        webDir,
      });
      registerWave1Builtins(host);
      await host.start();
      await host.updateConfig('builtin.transport.android-adb', { adb_path: mockAdb });
      const app = await startStudioApp({ host, port: 0, hostAddr: '127.0.0.1' });
      try {
        // Case A: immediate crash (<900ms) without manifest.json -> synchronous 500 with log_lines
        fs.writeFileSync(modeFile, 'crash');
        const crashRes = await fetch(`${app.url}/api/capture/start`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ serial: 'MON01', mode: 'oneshot', dev: 'wlan0', duration_sec: 10 }),
        });
        assert.equal(crashRes.status, 500);
        const crashBody = await crashRes.json() as { ok: boolean; error: string; capture_id?: string; log_lines?: string[] };
        assert.equal(crashBody.ok, false);
        assert.match(crashBody.error, /exited immediately.*EPERM/);
        assert.ok(crashBody.capture_id && crashBody.capture_id.length > 0);
        assert.ok(Array.isArray(crashBody.log_lines) && crashBody.log_lines.some((l) => l.includes('EPERM')));

        // Case B: survives 900ms check, then self-exits -> background monitor auto-pulls without frontend /status polling
        fs.writeFileSync(modeFile, 'oneshot');
        const okRes = await fetch(`${app.url}/api/capture/start`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ serial: 'MON01', mode: 'oneshot', dev: 'wlan0', duration_sec: 1 }),
        });
        assert.equal(okRes.status, 200);

        // Wait 1.6s WITHOUT calling /api/capture/status; background monitor should have auto-pulled already!
        await new Promise((r) => setTimeout(r, 1600));
        const sessions = fs.readdirSync(path.join(root, 'sessions')).filter((n) => !n.startsWith('.'));
        assert.equal(sessions.length, 1, 'background monitor must auto-pull session without frontend /status polling');

        const st = await fetch(`${app.url}/api/capture/status`).then((r) => r.json()) as { phase: string; last_session_id: string };
        assert.equal(st.phase, 'done');
        assert.ok(st.last_session_id.length > 0);
      } finally {
        await app.close();
      }
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});
