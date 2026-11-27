import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import {
  parseExternalPluginDir,
  previewExternalPackage,
  validateBpfObjectFile,
} from '../src/kernel/external-loader.ts';
import { CordisHost } from '../src/kernel/host.ts';
import {
  AdbClient,
  normalizeDeviceArch,
  REMOTE_PLUGINS_DIR,
  type ExternalBpfSyncItem,
} from '../src/plugins/adb/adb-client.ts';
import {
  collectEnabledExternalBpfBundles,
} from '../src/plugins/adb/capture-controller.ts';
import {
  EBPF_PROBE_PRESETS,
  ebpfTcPlugin,
  PROBE_PRESET_GROUPS,
  VALID_PROBE_GROUPS,
  type EbpfCollectorService,
} from '../src/plugins/adb/ebpf-tc.ts';
import { registerWave1Builtins } from '../src/plugins/register.ts';

function makeElf64Bpf(eMachine = 247, eiClass = 2, eiData = 1, extraBytes = 32): Buffer {
  const buf = Buffer.alloc(64 + extraBytes, 0);
  buf[0] = 0x7f;
  buf[1] = 0x45; // E
  buf[2] = 0x4c; // L
  buf[3] = 0x46; // F
  buf[4] = eiClass; // ELFCLASS64 = 2
  buf[5] = eiData; // ELFDATA2LSB = 1
  buf[6] = 1; // EV_CURRENT
  buf.writeUInt16LE(1, 16); // ET_REL
  buf.writeUInt16LE(eMachine, 18); // EM_BPF = 247
  buf.writeUInt32LE(1, 20); // EV_CURRENT
  return buf;
}

function sha256Hex(buf: Buffer): string {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function createExternalBpfPluginDir(
  parentDir: string,
  opts: {
    id?: string;
    arches?: Array<'arm64' | 'x86_64'>;
    shaOverride?: string;
    bpfBuf?: Buffer;
    abiVersion?: number;
    objRelPath?: string;
    extraSchema?: Record<string, unknown>;
    hooks?: Array<Record<string, unknown>>;
  } = {},
): { pluginDir: string; sha: string; objPath: string } {
  const id = opts.id ?? 'pktpath.pwru-sample';
  const pluginDir = path.join(parentDir, id);
  fs.mkdirSync(path.join(pluginDir, 'bpf'), { recursive: true });
  fs.writeFileSync(path.join(pluginDir, 'index.mjs'), 'export function setup() {}\n', 'utf8');

  const bpfBuf = opts.bpfBuf ?? makeElf64Bpf();
  const sha = opts.shaOverride ?? sha256Hex(bpfBuf);
  const arches = opts.arches ?? ['arm64'];
  const objects: Record<string, { path: string; sha256: string }> = {};
  let firstObjPath = '';
  for (const arch of arches) {
    const rel = opts.objRelPath ?? `bpf/pwru_${arch}.bpf.o`;
    const abs = path.join(pluginDir, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, bpfBuf);
    if (!firstObjPath) firstObjPath = abs;
    objects[arch] = { path: rel, sha256: sha };
  }

  const manifest = {
    id,
    name: 'PWRU Sample BPF Plugin',
    version: '1.0.0',
    description: 'Test external plugin with precompiled ELF64 EM_BPF object',
    capabilities: ['collector.bpf-probes'],
    entrypoint: { module: 'index.mjs' },
    schema: opts.extraSchema ?? {
      fields: [
        { key: 'probe_ingress_rx', label: 'Ingress', type: 'boolean', default: true, group: 'probes' },
      ],
      groups: [{ id: 'probes', label: 'Probes' }],
      presets: [{ id: 'default', label: 'Default', values: { probe_ingress_rx: true } }],
    },
    kernel_probes: {
      abi_version: opts.abiVersion ?? 1,
      objects,
      hooks: opts.hooks ?? [
        {
          id: 'ext.ingress.netif_receive_skb',
          group: 'ingress_rx',
          sec: 'tp_netif_receive_skb',
          type: 'tracepoint',
          target: 'net:netif_receive_skb',
          stage: 'rx_ingress',
        },
      ],
    },
  };
  fs.writeFileSync(path.join(pluginDir, 'manifest.json'), JSON.stringify(manifest, null, 2), 'utf8');
  return { pluginDir, sha, objPath: firstObjPath };
}

function makeFakeDeviceAdbScript(rootDir: string, fakeDeviceRoot: string, arch = 'aarch64'): string {
  const scriptPath = path.join(rootDir, 'mock-adb-wave3.sh');
  const logPath = path.join(rootDir, 'adb-calls.log');
  const script = `#!/usr/bin/env bash
set -euo pipefail
LOG="${logPath}"
DEVROOT="${fakeDeviceRoot}"
echo "$*" >> "$LOG"

if [ "\${1:-}" = "start-server" ]; then
  exit 0
fi
if [ "\${1:-}" = "devices" ]; then
  echo "List of devices attached"
  echo "wave3dev1 device product:test model:Pixel_Test device:test"
  exit 0
fi
if [ "\${1:-}" = "-s" ]; then
  shift 2
fi

cmd="\${1:-}"
shift || true

case "$cmd" in
  push)
    src="$1"
    dst="$2"
    target="$DEVROOT$dst"
    mkdir -p "$(dirname "$target")"
    cp "$src" "$target"
    echo "1 file pushed."
    exit 0
    ;;
  shell)
    shcmd="$1"
    if [ "$shcmd" = "id -u" ]; then
      echo "0"
      exit 0
    fi
    if [ "$shcmd" = "uname -m" ]; then
      echo "${arch}"
      exit 0
    fi
    # Rewrite /data/local/tmp paths into fakeDeviceRoot and execute in bash
    rewritten="$(printf '%s' "$shcmd" | sed "s|/data/local/tmp|$DEVROOT/data/local/tmp|g")"
    bash -c "$rewritten"
    exit $?
    ;;
  *)
    exit 0
    ;;
esac
`;
  fs.writeFileSync(scriptPath, script, { mode: 0o755 });
  return scriptPath;
}

describe('Wave 3 Slice 2: ConfigSchema, ebpf-tc probes/presets, external BPF package, and ADB bundle sync', () => {
  it('ebpf-tc schema exposes 9 probe groups, 4 presets, readOnly core_drop, badges, and never emits --preset', async () => {
    // Schema contract assertions
    assert.equal(VALID_PROBE_GROUPS.length, 9);
    assert.ok(Array.isArray(ebpfTcPlugin.schema.presets));
    assert.equal(ebpfTcPlugin.schema.presets!.length, 4);
    assert.deepEqual(
      ebpfTcPlugin.schema.presets!.map((p) => p.id),
      ['egress', 'drop-pwru', 'full-path', 'tcp-diag'],
    );
    assert.ok(Array.isArray(ebpfTcPlugin.schema.groups));
    assert.ok(ebpfTcPlugin.schema.groups!.length >= 3);

    const fieldByKey = new Map(ebpfTcPlugin.schema.fields.map((f) => [f.key, f]));
    assert.equal(fieldByKey.get('probe_core_drop')?.readOnly, true);
    assert.equal(fieldByKey.get('probe_ingress_rx')?.badge, '高开销');
    assert.equal(fieldByKey.get('probe_drop_stack')?.badge, '高开销');
    assert.equal(fieldByKey.get('probe_tcp_probe')?.badge, '高噪·易丢样');
    assert.equal(fieldByKey.get('probe_tcp_probe')?.default, false);

    // Ensure tcp_probe is NOT enabled in any of the 4 default presets
    for (const preset of EBPF_PROBE_PRESETS) {
      assert.equal(preset.values.probe_tcp_probe, false, `preset ${preset.id} must not enable tcp_probe`);
      assert.equal(preset.values.probe_core_drop, true, `preset ${preset.id} must enable core_drop`);
    }

    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pktpath-w3-ebpf-'));
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
      const collector = host.getService<EbpfCollectorService>('collector.ebpf')!;
      assert.ok(collector);

      // Each of the 4 presets emits --probe-groups + --preset-label and NEVER --preset
      for (const [presetId, expectedGroups] of Object.entries(PROBE_PRESET_GROUPS)) {
        const norm = collector.normalizeRecordSpec({ probe_preset: presetId });
        assert.equal(norm.probePreset, presetId);
        assert.deepEqual([...norm.requestedGroups].sort(), [...expectedGroups].sort());
        assert.equal(norm.args.includes('--preset'), false, 'Studio must NEVER pass --preset');
        const idxG = norm.args.indexOf('--probe-groups');
        const idxL = norm.args.indexOf('--preset-label');
        assert.ok(idxG >= 0 && idxL >= 0);
        assert.equal(norm.args[idxL + 1], presetId);
        assert.deepEqual(norm.args[idxG + 1].split(',').sort(), [...expectedGroups].sort());
      }

      // Custom tweak automatically resolves preset label to 'custom' and enforces core_drop
      const customNorm = collector.normalizeRecordSpec({
        probe_groups: ['ingress_rx', 'tcp_probe'],
      });
      assert.equal(customNorm.probePreset, 'custom');
      assert.ok(customNorm.requestedGroups.includes('core_drop'));
      assert.ok(customNorm.requestedGroups.includes('ingress_rx'));
      assert.ok(customNorm.requestedGroups.includes('tcp_probe'));
      assert.equal(customNorm.args.includes('--preset'), false);

      // Empty probe_groups and unknown group IDs are rejected
      assert.throws(() => collector.normalizeRecordSpec({ probe_groups: [] }), /cannot be empty/);
      assert.throws(() => collector.normalizeRecordSpec({ probe_groups: ' , ' }), /cannot be empty/);
      assert.throws(() => collector.normalizeRecordSpec({ probe_groups: ['bogus_group'] }), /invalid probe group/);
      assert.throws(() => collector.normalizeRecordSpec({ probe_preset: 'nonexistent' }), /invalid probe_preset/);

      // Updating persisted plugin config changes default resolved groups & preset
      await host.updateConfig('builtin.collector.ebpf-tc', {
        probe_preset: 'drop-pwru',
        probe_core_drop: true,
        probe_egress_tc: false,
        probe_sock_app: false,
        probe_ingress_rx: true,
        probe_netfilter_nat: true,
        probe_drop_stack: true,
      });
      const updatedCollector = host.getService<EbpfCollectorService>('collector.ebpf')!;
      const afterCfg = updatedCollector.normalizeRecordSpec({});
      assert.equal(afterCfg.probePreset, 'drop-pwru');
      assert.deepEqual(
        [...afterCfg.requestedGroups].sort(),
        [...PROBE_PRESET_GROUPS['drop-pwru']].sort(),
      );

      await host.shutdown(2_000);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('external-loader validates kernel_probes ELF64 EM_BPF + SHA256 and rejects tampered/non-BPF/bad-ABI packages', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pktpath-w3-ext-'));
    try {
      // 1. Valid BPF plugin package
      const { pluginDir, sha } = createExternalBpfPluginDir(root, { arches: ['arm64', 'x86_64'] });
      const parsed = parseExternalPluginDir(pluginDir);
      assert.equal(parsed.manifest.kernel_probes?.abi_version, 1);
      assert.equal(parsed.manifest.kernel_probes?.objects.arm64?.sha256, sha);
      assert.equal(parsed.manifest.kernel_probes?.hooks.length, 1);
      // Preserves schema.presets & schema.groups
      assert.equal(parsed.manifest.schema.presets?.length, 1);
      assert.equal(parsed.manifest.schema.groups?.length, 1);

      const preview = previewExternalPackage(pluginDir);
      assert.equal(preview.has_kernel_bpf, true);
      assert.equal(preview.kernel_bpf_objects.length, 2);

      // 2. Non-BPF plugin preview reports has_kernel_bpf: false
      const plainDir = path.join(root, 'plain.plugin');
      fs.mkdirSync(plainDir, { recursive: true });
      fs.writeFileSync(path.join(plainDir, 'index.mjs'), 'export function setup() {}\n', 'utf8');
      fs.writeFileSync(
        path.join(plainDir, 'manifest.json'),
        JSON.stringify({
          id: 'plain.plugin',
          name: 'Plain Plugin',
          version: '1.0.0',
          entrypoint: { module: 'index.mjs' },
        }),
        'utf8',
      );
      const plainPreview = previewExternalPackage(plainDir);
      assert.equal(plainPreview.has_kernel_bpf, false);
      assert.deepEqual(plainPreview.kernel_bpf_objects, []);

      // 3. Forged SHA256 rejected
      const badShaDir = createExternalBpfPluginDir(root, {
        id: 'pktpath.bad-sha',
        shaOverride: '0'.repeat(64),
      }).pluginDir;
      assert.throws(() => parseExternalPluginDir(badShaDir), /sha256 mismatch/);

      // 4. Non-BPF ELF (e_machine = 62 x86_64) rejected
      const nonBpfDir = createExternalBpfPluginDir(root, {
        id: 'pktpath.non-bpf',
        bpfBuf: makeElf64Bpf(62),
      }).pluginDir;
      assert.throws(() => parseExternalPluginDir(nonBpfDir), /EM_BPF/);

      // 5. ELF32 rejected
      const elf32Dir = createExternalBpfPluginDir(root, {
        id: 'pktpath.elf32',
        bpfBuf: makeElf64Bpf(247, 1),
      }).pluginDir;
      assert.throws(() => parseExternalPluginDir(elf32Dir), /ELF64/);

      // 6. Unsupported abi_version rejected
      const badAbiDir = createExternalBpfPluginDir(root, {
        id: 'pktpath.bad-abi',
        abiVersion: 2,
      }).pluginDir;
      assert.throws(() => parseExternalPluginDir(badAbiDir), /abi_version/);

      // 7. Path traversal rejected
      const escapeDir = path.join(root, 'pktpath.escape');
      fs.mkdirSync(escapeDir, { recursive: true });
      fs.writeFileSync(path.join(escapeDir, 'index.mjs'), 'export function setup() {}\n', 'utf8');
      fs.writeFileSync(
        path.join(escapeDir, 'manifest.json'),
        JSON.stringify({
          id: 'pktpath.escape',
          name: 'Escape',
          version: '1.0.0',
          entrypoint: { module: 'index.mjs' },
          kernel_probes: {
            abi_version: 1,
            objects: { arm64: { path: '../outside.bpf.o', sha256: 'a'.repeat(64) } },
            hooks: [
              { id: 'h1', group: 'ingress_rx', sec: 'tp', type: 'tracepoint', target: 'net:netif_receive_skb' },
            ],
          },
        }),
        'utf8',
      );
      assert.throws(() => parseExternalPluginDir(escapeDir), /invalid kernel_probes\.objects\.arm64 path/);

      // 8. validateBpfObjectFile rejects non-ELF bytes directly
      const junkPath = path.join(root, 'junk.bpf.o');
      const junkBuf = Buffer.alloc(128, 0x41);
      fs.writeFileSync(junkPath, junkBuf);
      assert.throws(() => validateBpfObjectFile(junkPath, sha256Hex(junkBuf)), /not an ELF/);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('ADB detectArch, multi-plugin bundle.json sync, SHA256 reuse, missing-arch skip, and legacy .json coexistence', async () => {
    assert.equal(normalizeDeviceArch('aarch64'), 'arm64');
    assert.equal(normalizeDeviceArch('arm64'), 'arm64');
    assert.equal(normalizeDeviceArch('x86_64'), 'x86_64');
    assert.equal(normalizeDeviceArch('amd64'), 'x86_64');
    assert.equal(normalizeDeviceArch('armv7l'), undefined);

    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pktpath-w3-adb-'));
    try {
      const appDir = path.join(root, 'app');
      const pluginsDir = path.join(appDir, 'plugins');
      const fakeDeviceRoot = path.join(root, 'fake-device');
      fs.mkdirSync(pluginsDir, { recursive: true });
      fs.mkdirSync(fakeDeviceRoot, { recursive: true });

      // Install an arm64-only external BPF plugin + a legacy flat runtime .json plugin
      const { sha, objPath } = createExternalBpfPluginDir(pluginsDir, {
        id: 'pktpath.pwru-probes',
        arches: ['arm64'],
      });
      const legacyJsonPath = path.join(pluginsDir, 'legacy-nat.json');
      fs.writeFileSync(legacyJsonPath, JSON.stringify({ id: 'legacy-nat', enabled: true }), 'utf8');

      // Missing-arch graceful skip when device is x86_64
      const x86Collected = collectEnabledExternalBpfBundles(
        pluginsDir,
        appDir,
        'x86_64',
        ['core_drop', 'ingress_rx'],
      );
      assert.equal(x86Collected.bundles.length, 0);
      assert.equal(x86Collected.skipped.length, 1);
      assert.equal(x86Collected.skipped[0].plugin_id, 'pktpath.pwru-probes');
      assert.equal(x86Collected.skipped[0].status, 'unavailable_for_arch');

      // Matching arch arm64 collects bundle
      const armCollected = collectEnabledExternalBpfBundles(
        pluginsDir,
        appDir,
        'arm64',
        ['core_drop', 'ingress_rx'],
      );
      assert.equal(armCollected.skipped.length, 0);
      assert.equal(armCollected.bundles.length, 1);

      // Run AdbClient against mock ADB backed by fakeDeviceRoot
      const mockAdb = makeFakeDeviceAdbScript(root, fakeDeviceRoot, 'aarch64');
      const adb = new AdbClient(mockAdb);
      const detectedArch = await adb.detectArch('wave3dev1');
      assert.equal(detectedArch, 'arm64');

      // 1st sync: pushes legacy .json + .bpf.o + bundle.json
      const res1 = await adb.syncAllPlugins('wave3dev1', [legacyJsonPath], armCollected.bundles);
      assert.equal(res1.legacySynced, 1);
      assert.equal(res1.bpfSynced, 1);
      assert.equal(res1.bpfReused, 0);

      // Verify remote filesystem layout
      const remotePluginsRoot = path.join(fakeDeviceRoot, REMOTE_PLUGINS_DIR);
      assert.ok(fs.existsSync(path.join(remotePluginsRoot, 'legacy-nat.json')));
      const remoteBundleDir = path.join(remotePluginsRoot, 'pktpath.pwru-probes');
      const remoteObjPath = path.join(remoteBundleDir, 'pwru_arm64.bpf.o');
      const remoteBundleJsonPath = path.join(remoteBundleDir, 'bundle.json');
      assert.ok(fs.existsSync(remoteObjPath));
      assert.ok(fs.existsSync(remoteBundleJsonPath));

      const bundleJson = JSON.parse(fs.readFileSync(remoteBundleJsonPath, 'utf8'));
      assert.equal(bundleJson.abi_version, 1);
      assert.equal(bundleJson.plugin_id, 'pktpath.pwru-probes');
      assert.equal(bundleJson.arch, 'arm64');
      assert.equal(bundleJson.object, 'pwru_arm64.bpf.o');
      assert.equal(bundleJson.sha256, sha);
      assert.deepEqual(bundleJson.enabled_groups, ['ingress_rx']);
      assert.equal(bundleJson.hooks.length, 1);
      assert.equal(bundleJson.hooks[0].id, 'ext.ingress.netif_receive_skb');

      // 2nd sync with identical .bpf.o: reuses remote .bpf.o via SHA256 match!
      const res2 = await adb.syncAllPlugins('wave3dev1', [legacyJsonPath], armCollected.bundles);
      assert.equal(res2.legacySynced, 1);
      assert.equal(res2.bpfSynced, 0);
      assert.equal(res2.bpfReused, 1);

      // Disabled plugin in kernel-config.json is skipped
      fs.writeFileSync(
        path.join(appDir, 'kernel-config.json'),
        JSON.stringify({ enabled: { 'pktpath.pwru-probes': false }, configs: {} }),
        'utf8',
      );
      const disabledCollected = collectEnabledExternalBpfBundles(
        pluginsDir,
        appDir,
        'arm64',
        ['core_drop', 'ingress_rx'],
      );
      assert.equal(disabledCollected.bundles.length, 0);
      assert.equal(disabledCollected.skipped.length, 0);

      // Tampered local .bpf.o right before push is rejected before touching device
      const badBundle: ExternalBpfSyncItem = {
        ...armCollected.bundles[0],
        localObjectPath: objPath,
        sha256: 'f'.repeat(64),
      };
      await assert.rejects(
        () => adb.syncAllPlugins('wave3dev1', [], [badBundle]),
        /sha256 mismatch/,
      );
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});
