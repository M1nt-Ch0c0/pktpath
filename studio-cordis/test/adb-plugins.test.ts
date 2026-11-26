import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { CordisHost } from '../src/kernel/host.ts';
import { registerWave1Builtins } from '../src/plugins/register.ts';
import { startStudioApp } from '../src/server/app.ts';

interface MockAdbOpts {
  missingOutDir?: boolean;
  disablePktpathInspect?: boolean;
}

function createMockAdb(
  dir: string,
  collectorSha: string,
  opts: MockAdbOpts = {},
): { adbScript: string; logFile: string } {
  const adbScript = path.join(dir, 'mock-adb.sh');
  const stateFile = path.join(dir, 'mock-state.txt');
  const logFile = path.join(dir, 'mock-signals.log');
  const missingOutDir = opts.missingOutDir ? '1' : '0';
  const disableInspect = opts.disablePktpathInspect ? '1' : '0';

  fs.writeFileSync(
    adbScript,
    `#!/usr/bin/env bash
set -euo pipefail
STATE_FILE=${JSON.stringify(stateFile)}
LOG_FILE=${JSON.stringify(logFile)}
MISSING_OUT_DIR=${JSON.stringify(missingOutDir)}
DISABLE_INSPECT=${JSON.stringify(disableInspect)}

if [ "\${1:-}" = "start-server" ]; then
  exit 0
fi

if [ "\${1:-}" = "devices" ]; then
  echo "List of devices attached"
  echo "MOCKSER001             device usb:1-1 product:cheetah model:Pixel_7_Pro device:cheetah transport_id:1"
  exit 0
fi

if [ "\${1:-}" = "-s" ]; then
  shift 2
fi

CMD="\${1:-}"
shift || true

case "$CMD" in
  push)
    echo "pushed ok"
    exit 0
    ;;
  pull)
    REMOTE="\${1:-}"
    LOCAL="\${2:-}"
    echo "PULL:$REMOTE->$LOCAL" >> "$LOG_FILE"
    # Windows adb rejects trailing '/.' with STAT error; enforce this invariant in mock.
    case "$REMOTE" in
      */.)
        echo "adb: error: failed to stat remote object '$REMOTE': No such file or directory" >&2
        exit 1
        ;;
    esac
    case "$REMOTE" in
      *.log)
        mkdir -p "$(dirname "$LOCAL")"
        echo "pktpath record ok" > "$LOCAL"
        exit 0
        ;;
    esac
    # Standard adb pull <remoteDir> <existingLocalDir> creates <existingLocalDir>/<basename(remoteDir)>/...
    BASE="$(basename "$REMOTE")"
    if [ -d "$LOCAL" ]; then
      TARGET="$LOCAL/$BASE"
    else
      TARGET="$LOCAL"
    fi
    mkdir -p "$TARGET"
    echo '{"version":1,"samples":[]}' > "$TARGET/meta.json"
    exit 0
    ;;
  shell)
    SCMD="$*"
    case "$SCMD" in
      "id -u")
        echo "0"
        ;;
      *"getprop ro.product.model"*)
        echo "@@model=Pixel 7 Pro"
        echo "@@product=cheetah"
        echo "@@android=14"
        echo "@@kernel=5.15.131-android13"
        echo "@@arch=aarch64"
        echo "@@uid=0"
        echo "@@agent="
        ;;
      *"mv -f /data/local/tmp/pktpath_tmp"*)
        echo "${collectorSha}  /data/local/tmp/.pktpath_studio/pktpath"
        ;;
      *"sha256sum /data/local/tmp/.pktpath_studio/pktpath"*)
        echo ""
        ;;
      *"ip -br addr"*)
        echo "lo               UNKNOWN        127.0.0.1/8 ::1/128"
        echo "rmnet_data0      UP             10.20.30.40/32"
        echo "wlan0            UP             192.168.1.50/24 fe80::1/64"
        ;;
      *"pktpath inspect"*)
        echo "INSPECT:$SCMD" >> "$LOG_FILE"
        if [ "$DISABLE_INSPECT" = "1" ]; then
          echo "pktpath: inspect unavailable" >&2
          exit 127
        fi
        if echo "$SCMD" | grep -q -- "--dev 'wlan0'"; then
          echo '{"dev":"wlan0","scope":"tc-egress","qdiscs":[{"kind":"mq","handle":"0:","parent":"root","dev":"wlan0"},{"kind":"fq_codel","handle":"8001:","parent":":1","dev":"wlan0"}],"classes":[{"handle":"0:1","parent":"0:"}],"adapters":[{"adapter_id":"l2_tc_egress_core","name":"TC/Qdisc & Driver Egress Core","enabled":true}]}'
        elif echo "$SCMD" | grep -q -- "--dev 'rmnet_data0'"; then
          echo '{"dev":"rmnet_data0","scope":"tc-egress","qdiscs":[{"kind":"noqueue","handle":"0:","parent":"root","dev":"rmnet_data0"}],"classes":[],"adapters":[{"adapter_id":"l2_tc_egress_core","name":"TC/Qdisc & Driver Egress Core","enabled":true}]}'
        else
          echo "unexpected inspect dev in: $SCMD" >&2
          exit 1
        fi
        ;;
      *"tc qdisc show"*)
        echo "TC:$SCMD" >> "$LOG_FILE"
        # Never allow device-wide 'tc qdisc show' without 'dev <iface>'.
        if ! echo "$SCMD" | grep -q "tc qdisc show dev "; then
          echo "FORBIDDEN_BARE_TC_QDISC_SHOW: $SCMD" >&2
          exit 1
        fi
        if echo "$SCMD" | grep -q "dev 'wlan0'"; then
          echo "qdisc mq 0: dev wlan0 root"
          echo "qdisc fq_codel 8001: dev wlan0 parent :1 limit 10240p"
        elif echo "$SCMD" | grep -q "dev 'rmnet_data0'"; then
          echo "qdisc noqueue 0: dev rmnet_data0 root"
        fi
        ;;
      *"cmd package list packages -U"*)
        echo "package:com.example.demo uid:10234"
        echo "package:android uid:1000"
        ;;
      *"pktpath record"*)
        echo "running" > "$STATE_FILE"
        echo "START:$SCMD" >> "$LOG_FILE"
        echo "@@pid=4242"
        ;;
      *"@@exists=1"*)
        if [ "$MISSING_OUT_DIR" = "1" ]; then
          echo "@@exists=0"
        else
          echo "@@exists=1"
        fi
        ;;
      *"/proc/4242/comm"*)
        if [ "$MISSING_OUT_DIR" = "1" ]; then
          echo "pktpath: error: bpf_object__load failed: Operation not permitted"
          echo "@@comm="
          echo "@@stat="
        else
          echo "capturing..."
          if [ -f "$STATE_FILE" ]; then
            echo "@@comm=pktpath"
            echo "@@stat=S"
          else
            echo "@@comm="
            echo "@@stat="
          fi
        fi
        ;;
      *"tail -n"*)
        if [ "$MISSING_OUT_DIR" = "1" ]; then
          echo "pktpath: initializing eBPF on wlan0"
          echo "pktpath: error: bpf_object__load failed: Operation not permitted"
        else
          echo "capturing..."
        fi
        ;;
      *"kill -USR1 4242"*)
        echo "SIGUSR1" >> "$LOG_FILE"
        ;;
      *"kill -INT 4242"*)
        echo "SIGINT" >> "$LOG_FILE"
        rm -f "$STATE_FILE"
        ;;
      *"kill -TERM 4242"*)
        echo "SIGTERM" >> "$LOG_FILE"
        rm -f "$STATE_FILE"
        ;;
      *"rm -rf /data/local/tmp/.pktpath_studio/run_"*)
        echo "CLEANUP" >> "$LOG_FILE"
        echo "@@gone=1"
        ;;
      *)
        echo "ok"
        ;;
    esac
    ;;
esac
`,
    { mode: 0o755 },
  );
  return { adbScript, logFile };
}

async function createTestHarness(opts: MockAdbOpts = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pktpath-adb-test-'));
  const collectorDir = path.join(root, 'collectors', 'android-arm64');
  fs.mkdirSync(collectorDir, { recursive: true });
  const collectorFile = path.join(collectorDir, 'pktpath');
  fs.writeFileSync(collectorFile, 'MOCK_ARM64_ELF_PAYLOAD');
  const collectorSha = crypto.createHash('sha256').update('MOCK_ARM64_ELF_PAYLOAD').digest('hex');

  const { adbScript: mockAdb, logFile } = createMockAdb(root, collectorSha, opts);
  const appDir = path.join(root, 'app');

  const host = new CordisHost({
    appDir,
    sessionsRoot: path.join(appDir, 'sessions'),
    pluginsDir: path.join(appDir, 'plugins'),
    exportsDir: path.join(appDir, 'exports'),
    collectorsDir: path.join(root, 'collectors'),
    webDir: path.join(root, 'web'),
    adbPath: mockAdb,
  });
  registerWave1Builtins(host);
  await host.start();
  const app = await startStudioApp({ host, listenPort: 0 });
  return { root, appDir, collectorSha, logFile, host, app };
}

describe('Wave 1+2 ADB built-in plugins (mock adb unit tests, NOT real device/BPF)', () => {
  it('covers devices -> prepare -> inspect -> apps -> oneshot & daemon start/flush/race/stop/dispose cleanup', async () => {
    const { root, appDir, collectorSha, logFile, host, app } = await createTestHarness();
    try {
      // 1. Devices
      const devRes = await fetch(`${app.url}/api/devices`).then((r) => r.json()) as {
        ok: boolean;
        adb_missing: boolean;
        devices: Array<{ serial: string; model: string; transport: string }>;
      };
      assert.equal(devRes.ok, true);
      assert.equal(devRes.adb_missing, false);
      assert.equal(devRes.devices[0].serial, 'MOCKSER001');

      // 2. Prepare
      const prepRes = await fetch(`${app.url}/api/device/prepare`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ serial: 'MOCKSER001' }),
      }).then((r) => r.json()) as { ok: boolean; root_mode: string; agent_sha256: string; pushed: boolean };
      assert.equal(prepRes.ok, true);
      assert.equal(prepRes.root_mode, 'adbd-root');
      assert.equal(prepRes.agent_sha256, collectorSha);

      // 3. Inspect with empty dev -> auto-picks wlan0 & runs pktpath inspect --json
      const inspRes = await fetch(`${app.url}/api/device/inspect?serial=MOCKSER001&dev=`).then((r) => r.json()) as {
        ok: boolean;
        dev: string;
        scope: string;
        ifaces: Array<{ name: string }>;
        interfaces: Array<{ name: string }>;
        qdiscs: Array<{ kind: string; parent: string; dev: string }>;
        inspect?: {
          dev: string;
          qdiscs: Array<{ kind: string; parent: string; dev: string }>;
          classes: Array<{ handle: string; parent: string }>;
          adapters: Array<{ adapter_id: string; enabled: boolean }>;
        };
      };
      assert.equal(inspRes.ok, true);
      assert.equal(inspRes.dev, 'wlan0');
      assert.equal(inspRes.scope, 'tc-egress');
      assert.ok(inspRes.ifaces.some((i) => i.name === 'wlan0'));
      assert.equal(inspRes.interfaces.length, inspRes.ifaces.length);
      assert.ok(inspRes.inspect, 'expected structured pktpath inspect JSON');
      assert.equal(inspRes.inspect.dev, 'wlan0');
      assert.equal(inspRes.inspect.qdiscs.length, 2);
      assert.ok(inspRes.inspect.qdiscs.every((q) => q.dev === 'wlan0'));
      assert.equal(inspRes.inspect.classes.length, 1);
      assert.equal(inspRes.inspect.adapters[0].adapter_id, 'l2_tc_egress_core');

      const appsRes = await fetch(`${app.url}/api/device/apps?serial=MOCKSER001`).then((r) => r.json()) as {
        ok: boolean;
        apps: Array<{ pkg: string; uid: number }>;
      };
      assert.equal(appsRes.ok, true);
      assert.equal(appsRes.apps[0].pkg, 'com.example.demo');

      // 4. Flush while idle -> 409
      const idleFlush = await fetch(`${app.url}/api/capture/flush`, { method: 'POST', body: '{}' });
      assert.equal(idleFlush.status, 409);

      // 5. Oneshot start -> flush must return 400 -> stop (must pull without '/.' and flatten into session_dir)
      const startOne = await fetch(`${app.url}/api/capture/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ serial: 'MOCKSER001', mode: 'oneshot', dev: 'wlan0', duration_sec: 10 }),
      }).then((r) => r.json()) as { ok: boolean; mode: string; capture_id: string };
      assert.equal(startOne.ok, true);
      assert.equal(startOne.mode, 'oneshot');

      const flushDuringOneshot = await fetch(`${app.url}/api/capture/flush`, { method: 'POST', body: '{}' });
      assert.equal(flushDuringOneshot.status, 400);

      const stopOne = await fetch(`${app.url}/api/capture/stop`, { method: 'POST', body: '{}' }).then((r) => r.json()) as {
        ok: boolean;
        status: string;
        session_dir: string;
      };
      assert.equal(stopOne.ok, true);
      assert.equal(stopOne.status, 'done');
      assert.ok(fs.existsSync(path.join(stopOne.session_dir, 'meta.json')));
      assert.ok(fs.existsSync(path.join(stopOne.session_dir, 'studio_record.log')));
      assert.equal(
        fs.existsSync(path.join(stopOne.session_dir, `run_${startOne.capture_id}`)),
        false,
        'pulled session_dir must be flattened, not nested under run_<id>',
      );
      assert.equal(
        fs.existsSync(path.join(appDir, 'sessions', `.pulling_${startOne.capture_id}`)),
        false,
        'temporary .pulling_* staging directory must be removed after move',
      );

      // 6. Daemon start -> duplicate start returns 409 -> flush sends SIGUSR1 -> status -> stop
      const [rStartA, rStartB] = await Promise.all([
        fetch(`${app.url}/api/capture/start`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            serial: 'MOCKSER001',
            mode: 'daemon',
            dev: 'wlan0',
            trigger: '50000',
            pre_window_sec: 3,
            post_window_sec: 4,
          }),
        }),
        fetch(`${app.url}/api/capture/start`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ serial: 'MOCKSER001', mode: 'daemon' }),
        }),
      ]);
      assert.deepEqual([rStartA.status, rStartB.status].sort(), [200, 409]);
      const okResp = rStartA.status === 200 ? rStartA : rStartB;
      const startDaemon = await okResp.json() as { ok: boolean; mode: string; remote_pid: number };
      assert.equal(startDaemon.ok, true);
      assert.equal(startDaemon.mode, 'daemon');
      assert.equal(startDaemon.remote_pid, 4242);

      const [flushA, flushB] = await Promise.all([
        fetch(`${app.url}/api/capture/flush`, { method: 'POST', body: '{}' }).then((r) => r.json()),
        fetch(`${app.url}/api/capture/flush`, { method: 'POST', body: '{}' }).then((r) => r.json()),
      ]) as Array<{ ok: boolean; signal: string; flush_count: number }>;
      assert.equal(flushA.ok, true);
      assert.equal(flushB.ok, true);
      assert.equal(flushA.signal, 'SIGUSR1');
      assert.equal(flushB.signal, 'SIGUSR1');
      assert.deepEqual([flushA.flush_count, flushB.flush_count].sort(), [1, 2]);

      const stDaemon = await fetch(`${app.url}/api/capture/status`).then((r) => r.json()) as {
        status: string;
        mode: string;
        flush_count: number;
      };
      assert.equal(stDaemon.status, 'running');
      assert.equal(stDaemon.mode, 'daemon');
      assert.equal(stDaemon.flush_count, 2);

      const stopDaemon = await fetch(`${app.url}/api/capture/stop`, { method: 'POST', body: '{}' }).then((r) => r.json()) as {
        ok: boolean;
        status: string;
        session_dir: string;
      };
      assert.equal(stopDaemon.ok, true);
      assert.equal(stopDaemon.status, 'done');
      assert.ok(fs.existsSync(path.join(stopDaemon.session_dir, 'meta.json')));

      // 7. Start daemon again and disable builtin.mode.daemon mid-run -> must send SIGTERM + CLEANUP
      const startDaemon2 = await fetch(`${app.url}/api/capture/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ serial: 'MOCKSER001', mode: 'daemon' }),
      });
      assert.equal(startDaemon2.status, 200);

      await host.toggle('builtin.mode.daemon', false);
      const signals = fs.readFileSync(logFile, 'utf8');
      assert.ok(signals.includes('SIGUSR1'));
      assert.ok(signals.includes('SIGTERM'));
      assert.ok(signals.includes('CLEANUP'));
      assert.equal(signals.includes('/.->'), false, 'adb pull must never pass trailing /. to remote path');

      // Flush when daemon plugin disabled -> 400
      const disabledFlush = await fetch(`${app.url}/api/capture/flush`, { method: 'POST', body: '{}' });
      assert.equal(disabledFlush.status, 400);

      // 8. Disabling collector.ebpf cascades to block oneshot start -> 400
      await host.toggle('builtin.collector.ebpf-tc', false);
      const blockedStart = await fetch(`${app.url}/api/capture/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ serial: 'MOCKSER001', mode: 'oneshot' }),
      });
      assert.equal(blockedStart.status, 400);
    } finally {
      await app.close();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('checks remote outDir before pull and surfaces collector log_tail when remote directory is missing', async () => {
    const { root, logFile, app } = await createTestHarness({ missingOutDir: true });
    try {
      const startResp = await fetch(`${app.url}/api/capture/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ serial: 'MOCKSER001', mode: 'oneshot', dev: 'wlan0', duration_sec: 10 }),
      });
      assert.equal(startResp.status, 500);
      const startRes = await startResp.json() as {
        ok: boolean;
        error?: string;
        capture_id?: string;
        log_tail?: string[];
        log_lines?: string[];
      };
      assert.equal(startRes.ok, false);
      assert.match(startRes.error ?? '', /exited immediately/i);
      assert.match(startRes.error ?? '', /bpf_object__load failed/);
      assert.ok(startRes.capture_id && startRes.capture_id.length > 0);
      assert.ok(Array.isArray(startRes.log_tail) && startRes.log_tail.some((line) => line.includes('bpf_object__load failed')));
      assert.ok(Array.isArray(startRes.log_lines) && startRes.log_lines.some((line) => line.includes('bpf_object__load failed')));

      const stBody = await fetch(`${app.url}/api/capture/status`).then((r) => r.json()) as {
        status: string;
        error?: string;
        log_tail?: string[];
      };
      assert.equal(stBody.status, 'error');
      assert.match(stBody.error ?? '', /bpf_object__load failed/);
      assert.ok(Array.isArray(stBody.log_tail) && stBody.log_tail.some((l) => l.includes('bpf_object__load failed')));

      const logContent = fs.readFileSync(logFile, 'utf8');
      assert.equal(logContent.includes('PULL:'), false, 'must not call adb pull when remote outDir is missing');
    } finally {
      await app.close();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('falls back to scoped tc qdisc show dev <defaultIface> when pktpath inspect is unavailable (never bare tc qdisc show)', async () => {
    const { root, logFile, app } = await createTestHarness({ disablePktpathInspect: true });
    try {
      const inspRes = await fetch(`${app.url}/api/device/inspect?serial=MOCKSER001`).then((r) => r.json()) as {
        ok: boolean;
        dev: string;
        scope: string;
        qdiscs: string[];
        inspect?: unknown;
      };
      assert.equal(inspRes.ok, true);
      assert.equal(inspRes.dev, 'wlan0');
      assert.equal(inspRes.scope, 'tc-egress');
      assert.equal(inspRes.inspect, undefined);
      assert.equal(inspRes.qdiscs.length, 2);
      assert.ok(inspRes.qdiscs.every((line) => line.includes('dev wlan0')));

      const logContent = fs.readFileSync(logFile, 'utf8');
      assert.ok(logContent.includes("TC:tc qdisc show dev 'wlan0'"));
      assert.equal(logContent.includes('FORBIDDEN_BARE_TC_QDISC_SHOW'), false);
    } finally {
      await app.close();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});
