import fs from 'node:fs';
import path from 'node:path';
import type { BuiltinPlugin } from '../../kernel/types.ts';
import {
  AdbClient,
  REMOTE_AGENT,
  resolveAdbBinary,
  sha256File,
  type AppEntry,
  type DeviceEntry,
  type IfaceInfo,
  type RootMode,
} from './adb-client.ts';
import { enabledRuntimePluginPaths } from './runtime-plugins.ts';

export interface EnrichedDeviceEntry extends DeviceEntry {
  transport: 'adb';
  android_ver: string;
  arch: string;
  kernel: string;
  root_mode: RootMode | '';
  agent_ready: boolean;
}

export interface ListDevicesResult {
  devices: EnrichedDeviceEntry[];
  adb_devices: EnrichedDeviceEntry[];
  adb_enabled: boolean;
  adb_path: string;
  adb_missing: boolean;
  adb_error: string;
  available_agents: string[];
}

export interface PrepareDeviceResult {
  serial: string;
  transport: 'adb';
  root_mode: RootMode;
  kernel: string;
  arch: string;
  android_ver: string;
  model: string;
  agent_path: string;
  agent_sha256: string;
  pushed: boolean;
  agent_pushed: boolean;
  elapsed_ms: number;
}

export interface AdbTransportService {
  readonly adbPath: string | undefined;
  readonly adbMissing: boolean;
  readonly collectorPath: string | undefined;
  readonly client: AdbClient;
  listDevices(): Promise<ListDevicesResult>;
  defaultSerial(): Promise<string>;
  prepareDevice(serial: string): Promise<PrepareDeviceResult>;
  ensureReady(serial: string): Promise<void>;
  inspectDevice(serial: string, dev?: string, scope?: string, enablePlugins?: boolean): Promise<{
    serial: string;
    scope: string;
    dev: string;
    ifaces: IfaceInfo[];
    interfaces: IfaceInfo[];
    qdiscs: unknown[];
    inspect?: Record<string, unknown>;
  }>;
  listApps(serial: string): Promise<AppEntry[]>;
}

interface CachedDeviceState {
  rootMode?: RootMode;
  kernel?: string;
  androidVer?: string;
  model?: string;
  agentSha256?: string;
  preparedAt?: number;
}

function detectAvailableAgents(collectorsDir: string): string[] {
  const candidates: Array<[string, string]> = [
    ['android-arm64', path.join(collectorsDir, 'android-arm64', 'pktpath')],
    ['linux-x86_64', path.join(collectorsDir, 'linux-x86_64', 'pktpath')],
    ['linux-arm64', path.join(collectorsDir, 'linux-arm64', 'pktpath')],
  ];
  const out: string[] = [];
  for (const [key, filePath] of candidates) {
    try {
      if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
        out.push(key);
      }
    } catch {
      // ignore
    }
  }
  return out;
}

export const androidAdbPlugin: BuiltinPlugin = {
  meta: {
    id: 'builtin.transport.android-adb',
    name: 'Android ADB 连接',
    version: '1.0.0',
    description: '通过本地 adb 发现 Android 设备、检测 root、推送随包 arm64 采集器并拉取会话。',
    category: 'transport',
    icon: 'smartphone',
    builtin: true,
    capabilities: ['transport.adb', 'device.discover', 'device.prepare', 'device.inspect'],
    provides: ['transport.adb'],
    requires: [],
    tags: ['android', 'adb', 'transport'],
  },
  schema: {
    fields: [
      {
        key: 'adb_path',
        label: 'ADB 可执行文件路径（留空自动查找）',
        type: 'string',
        default: '',
      },
    ],
  },
  apply(ctx, cfg) {
    const cfgPath = typeof cfg.adb_path === 'string' && cfg.adb_path.trim() ? cfg.adb_path.trim() : undefined;
    const adbPath = resolveAdbBinary(cfgPath ?? ctx.host.paths.adbPath);
    const client = new AdbClient(adbPath);
    const collectorCandidate = path.join(ctx.host.paths.collectorsDir, 'android-arm64', 'pktpath');
    const collectorPath = fs.existsSync(collectorCandidate) ? collectorCandidate : undefined;
    const devState = new Map<string, CachedDeviceState>();

    const getWantSha = (): string => {
      if (!collectorPath) return '';
      try {
        return sha256File(collectorPath).toLowerCase();
      } catch {
        return '';
      }
    };

    const prepareDevice = async (serial: string): Promise<PrepareDeviceResult> => {
      const t0 = Date.now();
      if (!serial.trim()) throw new Error('serial is required');
      if (!adbPath) throw new Error('adb executable not found');
      if (!collectorPath) {
        throw new Error(`android-arm64 collector not found at ${collectorCandidate}`);
      }
      const rootMode = await client.ensureRoot(serial);
      if (rootMode === 'none') {
        throw new Error(
          `device ${serial} is not rooted: neither adbd root, adb root, nor su -c granted uid 0 (eBPF capture requires root)`,
        );
      }
      const props = await client.props(serial).catch(() => ({
        model: '',
        product: '',
        androidVer: '',
        kernel: '',
        arch: 'arm64',
        shellUid: '',
        agentSha256: '',
      }));
      const wantSha = sha256File(collectorPath);
      const { pushed, remoteSha } = await client.ensureAgent(serial, collectorPath, wantSha);
      devState.set(serial, {
        rootMode,
        kernel: props.kernel,
        androidVer: props.androidVer,
        model: props.model,
        agentSha256: remoteSha.toLowerCase(),
        preparedAt: Date.now(),
      });
      return {
        serial,
        transport: 'adb',
        root_mode: rootMode,
        kernel: props.kernel,
        arch: props.arch || 'arm64',
        android_ver: props.androidVer,
        model: props.model,
        agent_path: REMOTE_AGENT,
        agent_sha256: remoteSha,
        pushed,
        agent_pushed: pushed,
        elapsed_ms: Date.now() - t0,
      };
    };

    const ensureReady = async (serial: string): Promise<void> => {
      if (!collectorPath) return;
      const wantSha = getWantSha();
      const st = devState.get(serial);
      if (st?.agentSha256 && wantSha && st.agentSha256 === wantSha && client.rootMode(serial)) {
        return;
      }
      await prepareDevice(serial);
    };

    const listDevices = async (): Promise<ListDevicesResult> => {
      const availableAgents = detectAvailableAgents(ctx.host.paths.collectorsDir);
      if (!adbPath) {
        return {
          devices: [],
          adb_devices: [],
          adb_enabled: true,
          adb_path: '',
          adb_missing: true,
          adb_error: '',
          available_agents: availableAgents,
        };
      }
      let raw: DeviceEntry[] = [];
      let adbError = '';
      try {
        raw = await client.devices();
      } catch (err) {
        adbError = err instanceof Error ? err.message : String(err);
      }

      const wantSha = getWantSha();
      const devices: EnrichedDeviceEntry[] = await Promise.all(
        raw.map(async (e): Promise<EnrichedDeviceEntry> => {
          const entry: EnrichedDeviceEntry = {
            ...e,
            transport: 'adb',
            android_ver: '',
            arch: 'arm64',
            kernel: '',
            root_mode: '',
            agent_ready: false,
          };
          if (e.state !== 'device') {
            client.forgetRoot(e.serial);
            return entry;
          }
          try {
            const p = await client.props(e.serial);
            if (p.model) entry.model = p.model;
            if (p.product) entry.product = p.product;
            entry.android_ver = p.androidVer;
            entry.kernel = p.kernel;
            if (p.arch) entry.arch = p.arch;

            let mode: RootMode | '' = client.rootMode(e.serial) ?? '';
            if (!mode && p.shellUid === '0') {
              mode = 'adbd-root';
            }
            if (mode === 'adbd-root' && p.shellUid && p.shellUid !== '0') {
              client.forgetRoot(e.serial);
              mode = '';
            }
            entry.root_mode = mode;

            const cached = devState.get(e.serial);
            let gotSha = (p.agentSha256 ?? '').toLowerCase();
            if (!gotSha && cached?.agentSha256 && mode === 'su') {
              gotSha = cached.agentSha256;
            }
            entry.agent_ready = Boolean(wantSha && gotSha && gotSha === wantSha);
          } catch {
            // keep basic entry if props probe fails
          }
          return entry;
        }),
      );

      return {
        devices,
        adb_devices: devices,
        adb_enabled: true,
        adb_path: adbPath,
        adb_missing: false,
        adb_error: adbError,
        available_agents: availableAgents,
      };
    };

    const service: AdbTransportService = {
      adbPath,
      adbMissing: !adbPath,
      collectorPath,
      client,
      listDevices,
      async defaultSerial(): Promise<string> {
        if (!adbPath) return '';
        try {
          const raw = await client.devices();
          const ready = raw.filter((d) => d.state === 'device');
          return ready.length > 0 ? ready[0].serial : '';
        } catch {
          return '';
        }
      },
      prepareDevice,
      ensureReady,
      async inspectDevice(serial: string, dev?: string, scope = 'tc-egress', enablePlugins = true) {
        if (!serial.trim()) throw new Error('serial is required');
        if (!adbPath) throw new Error('adb executable not found');
        // P0-3: ensure root + deploy agent before running `pktpath inspect --json`
        if (collectorPath) {
          await ensureReady(serial).catch(() => {});
        }
        const pluginPaths = enablePlugins ? enabledRuntimePluginPaths(ctx.host.paths.pluginsDir) : undefined;
        const res = await client.inspect(serial, dev, scope, pluginPaths);
        return {
          serial,
          scope: res.scope,
          dev: res.dev,
          ifaces: res.ifaces,
          interfaces: res.ifaces,
          qdiscs: res.qdiscs,
          ...(res.inspect ? { inspect: res.inspect } : {}),
        };
      },
      async listApps(serial: string) {
        if (!serial.trim()) throw new Error('serial is required');
        if (!adbPath) throw new Error('adb executable not found');
        return client.listApps(serial);
      },
    };

    ctx.provide('transport.adb', service);
    ctx.registerExtension('transport', {
      id: 'adb',
      plugin_id: 'builtin.transport.android-adb',
      name: 'Android ADB',
      adb_missing: !adbPath,
      collector_ready: Boolean(collectorPath),
    });
  },
};
