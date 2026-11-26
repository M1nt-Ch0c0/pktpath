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

export interface AdbTransportService {
  readonly adbPath: string | undefined;
  readonly adbMissing: boolean;
  readonly collectorPath: string | undefined;
  readonly client: AdbClient;
  listDevices(): Promise<{ devices: DeviceEntry[]; adb_missing: boolean }>;
  prepareDevice(serial: string): Promise<{
    serial: string;
    root_mode: RootMode;
    kernel: string;
    arch: string;
    agent_path: string;
    agent_sha256: string;
    pushed: boolean;
  }>;
  inspectDevice(serial: string, dev?: string, scope?: string): Promise<{
    serial: string;
    scope: string;
    dev: string;
    ifaces: IfaceInfo[];
    qdiscs: string[];
  }>;
  listApps(serial: string): Promise<AppEntry[]>;
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

    const service: AdbTransportService = {
      adbPath,
      adbMissing: !adbPath,
      collectorPath,
      client,
      async listDevices() {
        if (!adbPath) {
          return { devices: [], adb_missing: true };
        }
        const devices = await client.devices();
        return { devices, adb_missing: false };
      },
      async prepareDevice(serial: string) {
        if (!serial.trim()) throw new Error('serial is required');
        if (!adbPath) throw new Error('adb executable not found');
        if (!collectorPath) {
          throw new Error(`android-arm64 collector not found at ${collectorCandidate}`);
        }
        const rootMode = await client.ensureRoot(serial);
        if (rootMode === 'none') {
          throw new Error(`device ${serial} has no root access`);
        }
        const props = await client.props(serial);
        const wantSha = sha256File(collectorPath);
        const { pushed, remoteSha } = await client.ensureAgent(serial, collectorPath, wantSha);
        return {
          serial,
          root_mode: rootMode,
          kernel: props.kernel,
          arch: props.arch || 'aarch64',
          agent_path: REMOTE_AGENT,
          agent_sha256: remoteSha,
          pushed,
        };
      },
      async inspectDevice(serial: string, dev?: string, scope = 'all') {
        if (!serial.trim()) throw new Error('serial is required');
        if (!adbPath) throw new Error('adb executable not found');
        const res = await client.inspect(serial, dev);
        return {
          serial,
          scope,
          dev: dev ?? '',
          ifaces: res.ifaces,
          qdiscs: res.qdiscs,
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
