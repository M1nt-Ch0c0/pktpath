import fs from 'node:fs';
import path from 'node:path';
import { discoverExternalPlugins } from '../../kernel/external-loader.ts';
import type { HostServices, KernelProbeArch } from '../../kernel/types.ts';
import type { SessionProvider } from '../analysis/types.ts';
import { REMOTE_PLUGINS_DIR, type ExternalBpfSyncItem, type RemoteRun } from './adb-client.ts';
import type { AdbTransportService } from './android-adb.ts';
import { VALID_PROBE_GROUPS, type CaptureScope, type CaptureSpec, type EbpfCollectorService, type ProbeGroupId, type ProbePresetLabel } from './ebpf-tc.ts';
import { enabledRuntimePluginPaths } from './runtime-plugins.ts';

export type CaptureStateKind = 'idle' | 'running' | 'pulling' | 'done' | 'error';

export interface CaptureStartResult {
  ok: true;
  capture_id: string;
  status: 'running';
  phase: 'running';
  active: true;
  mode: 'oneshot' | 'daemon';
  serial: string;
  dev: string;
  scope: CaptureScope;
  remote_pid: number;
  remote_dir: string;
  command: string;
  probe_preset?: ProbePresetLabel;
  requested_groups?: ProbeGroupId[];
  skipped_bpf_plugins?: SkippedBpfPlugin[];
}

export interface SkippedBpfPlugin {
  plugin_id: string;
  status: 'unavailable_for_arch';
  reason: string;
}

export interface CaptureStatusSnapshot {
  ok: true;
  active: boolean;
  status: CaptureStateKind;
  phase: CaptureStateKind;
  capture_id: string;
  mode: 'oneshot' | 'daemon' | '';
  serial: string;
  dev: string;
  scope: string;
  remote_pid?: number;
  remote_dir?: string;
  command?: string;
  elapsed_sec: number;
  duration_sec: number;
  flush_count?: number;
  session_id?: string;
  last_session_id: string;
  session_dir?: string;
  session_path: string;
  error: string;
  log_tail: string[];
  log_lines: string[];
}

export interface CaptureStopResult {
  ok: boolean;
  active: false;
  status: CaptureStateKind;
  phase: CaptureStateKind;
  capture_id?: string;
  session_id?: string;
  last_session_id?: string;
  session_dir?: string;
  session_path?: string;
  overview?: Record<string, unknown>;
  remote_cleaned: boolean;
  clean_exit: boolean;
  self_exited: boolean;
  error?: string;
  log_tail?: string[];
  log_lines?: string[];
}

export class CaptureConflictError extends Error {
  readonly statusCode = 409;
  readonly captureId?: string;
  readonly logLines?: string[];
  constructor(msg: string, captureId?: string, logLines?: string[]) {
    super(msg);
    this.captureId = captureId;
    this.logLines = logLines;
  }
}

export class CaptureBadRequestError extends Error {
  readonly statusCode = 400;
  constructor(msg: string) {
    super(msg);
  }
}

export class CaptureStartFailedError extends Error {
  readonly statusCode = 500;
  readonly captureId: string;
  readonly logLines: string[];

  constructor(msg: string, captureId: string, logLines: string[]) {
    super(msg);
    this.captureId = captureId;
    this.logLines = logLines;
  }
}

function makeCaptureId(mode: 'oneshot' | 'daemon'): string {
  const now = new Date();
  const pad = (n: number) => String(n).padStart(2, '0');
  const stamp = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}_${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
  const rand = Math.random().toString(36).slice(2, 6);
  return `${mode}_${stamp}_${rand}`;
}

export function sanitizeDirName(raw: string): string {
  const cleaned = raw.replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^[_.-]+|[_.-]+$/g, '');
  return cleaned || 'capture';
}

export function uniquePath(basePath: string): string {
  if (!fs.existsSync(basePath)) return basePath;
  for (let i = 2; i < 1000; i += 1) {
    const candidate = `${basePath}_${i}`;
    if (!fs.existsSync(candidate)) return candidate;
  }
  return `${basePath}_${Date.now()}`;
}

const BUILTIN_PROBE_GROUP_SET = new Set<string>(VALID_PROBE_GROUPS);

function readKernelConfigState(appDir: string): {
  enabled: Record<string, boolean>;
  configs: Record<string, Record<string, unknown>>;
} {
  const cfgPath = path.join(appDir, 'kernel-config.json');
  try {
    if (!fs.existsSync(cfgPath)) return { enabled: {}, configs: {} };
    const raw = JSON.parse(fs.readFileSync(cfgPath, 'utf8')) as Record<string, unknown>;
    const enabled = (raw && typeof raw.enabled === 'object' && raw.enabled !== null
      ? raw.enabled
      : {}) as Record<string, boolean>;
    const configs = (raw && typeof raw.configs === 'object' && raw.configs !== null
      ? raw.configs
      : {}) as Record<string, Record<string, unknown>>;
    return { enabled, configs };
  } catch {
    return { enabled: {}, configs: {} };
  }
}

export function hasEnabledExternalBpfPlugins(pluginsDir: string, appDir: string): boolean {
  const { enabled } = readKernelConfigState(appDir);
  const { loaded } = discoverExternalPlugins(pluginsDir);
  return loaded.some((ext) => Boolean(ext.manifest.kernel_probes) && enabled[ext.manifest.id] !== false);
}

export function collectEnabledExternalBpfBundles(
  pluginsDir: string,
  appDir: string,
  arch: KernelProbeArch | undefined,
  requestedGroups: readonly string[],
): {
  bundles: ExternalBpfSyncItem[];
  skipped: SkippedBpfPlugin[];
} {
  const { enabled, configs } = readKernelConfigState(appDir);
  const { loaded } = discoverExternalPlugins(pluginsDir);
  const reqSet = new Set(requestedGroups);
  const bundles: ExternalBpfSyncItem[] = [];
  const skipped: SkippedBpfPlugin[] = [];

  for (const ext of loaded) {
    const kp = ext.manifest.kernel_probes;
    if (!kp) continue;
    const pluginId = ext.manifest.id;
    if (enabled[pluginId] === false) continue;

    if (!arch || !kp.objects[arch]) {
      skipped.push({
        plugin_id: pluginId,
        status: 'unavailable_for_arch',
        reason: arch
          ? `no precompiled BPF object for arch "${arch}"`
          : 'could not detect target device arch',
      });
      continue;
    }

    const objDecl = kp.objects[arch]!;
    const pluginCfg = configs[pluginId] ?? {};
    const schemaFields = new Map(ext.manifest.schema.fields.map((f) => [f.key, f]));
    const hookGroups = [...new Set(kp.hooks.map((h) => h.group))];
    const hasPluginGroupToggles = hookGroups.some(
      (g) => schemaFields.has(`probe_${g}`) || pluginCfg[`probe_${g}`] !== undefined,
    );

    const enabledGroups: string[] = [];
    for (const g of hookGroups) {
      if (hasPluginGroupToggles) {
        const key = `probe_${g}`;
        const val = pluginCfg[key] !== undefined ? pluginCfg[key] : schemaFields.get(key)?.default;
        if (val === true || val === 'true' || val === 1) {
          enabledGroups.push(g);
        }
      } else if (BUILTIN_PROBE_GROUP_SET.has(g)) {
        if (reqSet.has(g)) enabledGroups.push(g);
      } else {
        enabledGroups.push(g);
      }
    }

    if (enabledGroups.length === 0) continue;
    const enabledGroupSet = new Set(enabledGroups);
    const activeHooks = kp.hooks.filter((h) => enabledGroupSet.has(h.group));
    if (activeHooks.length === 0) continue;

    bundles.push({
      pluginId,
      abiVersion: 1,
      arch,
      localObjectPath: path.resolve(ext.dir, objDecl.path),
      objectFileName: path.basename(objDecl.path),
      sha256: objDecl.sha256,
      enabledGroups,
      hooks: activeHooks,
    });
  }

  return { bundles, skipped };
}

/**
 * Serialized capture controller shared by `builtin.mode.oneshot` and
 * `builtin.mode.daemon`. Every mutating transition (start / flush / stop / abort)
 * runs through an async queue so concurrent HTTP calls cannot race or orphan
 * remote processes/files.
 */
export class CaptureController {
  private readonly host: HostServices;
  private lockChain: Promise<unknown> = Promise.resolve();
  private monitorTimer: ReturnType<typeof setInterval> | null = null;
  private monitorTickBusy = false;

  private state: CaptureStateKind = 'idle';
  private captureId?: string;
  private mode?: 'oneshot' | 'daemon';
  private serial?: string;
  private dev?: string;
  private scope?: CaptureScope;
  private run?: RemoteRun;
  private startedAt = 0;
  private endedAt = 0;
  private durationSec = 0;
  private flushCount = 0;
  private cleanupRemote = true;
  private sessionId?: string;
  private sessionDir?: string;
  private overview?: Record<string, unknown>;
  private remoteCleaned = false;
  private cleanExit = true;
  private selfExited = false;
  private lastError?: string;
  private logTail: string[] = [];

  constructor(host: HostServices) {
    this.host = host;
  }

  /** Read-only: true while a device capture is running or being finalized (pulled). */
  hasActiveCapture(): boolean {
    return this.state === 'running' || this.state === 'pulling';
  }

  private runExclusive<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.lockChain.then(fn, fn);
    this.lockChain = next.catch(() => {});
    return next;
  }

  private stopMonitor(): void {
    if (this.monitorTimer) {
      clearInterval(this.monitorTimer);
      this.monitorTimer = null;
    }
  }

  private startMonitor(adb: AdbTransportService, expectedId: string): void {
    this.stopMonitor();
    const timer = setInterval(() => {
      if (this.monitorTickBusy) return;
      if (this.state !== 'running' || this.captureId !== expectedId) {
        this.stopMonitor();
        return;
      }
      this.monitorTickBusy = true;
      void this.runExclusive(async () => {
        if (this.state !== 'running' || this.captureId !== expectedId || !this.serial || !this.run) {
          this.stopMonitor();
          return;
        }
        try {
          const p = await adb.client.poll(this.serial, this.run, 60);
          if (p.lines.length > 0) this.logTail = p.lines;
          if (!p.alive) {
            this.stopMonitor();
            this.selfExited = true;
            await this.finishPull(adb);
          }
        } catch {
          // Transient poll error: keep monitoring on next tick (mirrors Go capture.go monitor).
        }
      }).finally(() => {
        this.monitorTickBusy = false;
      });
    }, 1000);
    if (typeof timer.unref === 'function') {
      timer.unref();
    }
    this.monitorTimer = timer;
  }

  private async finishPull(adb: AdbTransportService): Promise<void> {
    this.stopMonitor();
    if (!this.serial || !this.run || !this.captureId) return;
    const activeRun = this.run;
    const activeSerial = this.serial;
    const activeId = this.captureId;
    const activeDev = this.dev ?? 'wlan0';
    this.state = 'pulling';
    fs.mkdirSync(this.host.paths.sessionsRoot, { recursive: true });
    const folderName = sanitizeDirName(`${activeId}_${activeSerial}_${activeDev}`);
    const localDir = uniquePath(path.join(this.host.paths.sessionsRoot, folderName));
    const tmpParent = path.join(this.host.paths.sessionsRoot, `.pulling_${activeId}`);
    let pulledOk = false;
    try {
      const remoteExists = await adb.client.remoteExists(activeSerial, activeRun.outDir);
      if (!remoteExists) {
        const latestTail = await adb.client.readLogTail(activeSerial, activeRun.logPath, 60).catch(() => []);
        if (latestTail.length > 0) this.logTail = latestTail;
        const lastMsg = this.logTail.length > 0 ? this.logTail[this.logTail.length - 1] : '';
        throw new Error(
          lastMsg
            ? `remote run directory missing (record failed?): ${lastMsg}`
            : `remote run directory missing: ${activeRun.outDir}`,
        );
      }

      await adb.client.prepareForPull(activeSerial, activeRun);
      fs.rmSync(tmpParent, { recursive: true, force: true });
      fs.mkdirSync(tmpParent, { recursive: true });
      // Never append "/." to remote path (Windows adb pull rejects/misbehaves with trailing "/.").
      await adb.client.pull(activeSerial, activeRun.outDir, tmpParent);

      const nested = path.join(tmpParent, path.posix.basename(activeRun.outDir));
      const srcDir = fs.existsSync(nested) && fs.statSync(nested).isDirectory() ? nested : tmpParent;
      fs.rmSync(localDir, { recursive: true, force: true });
      fs.renameSync(srcDir, localDir);
      fs.rmSync(tmpParent, { recursive: true, force: true });

      // Best-effort pull of studio_record.log alongside the session files.
      await adb.client.pull(activeSerial, activeRun.logPath, path.join(localDir, 'studio_record.log')).catch(() => {});

      this.sessionId = path.basename(localDir);
      this.sessionDir = localDir;
      this.overview = undefined;

      // Best-effort register & load overview via session.provider if present.
      const provider = this.host.getService<SessionProvider>('session.provider');
      if (provider) {
        try {
          const opened = await provider.openSession(localDir);
          if (opened?.id) {
            this.sessionId = opened.id;
            const ov = await provider.getOverview(opened.id);
            if (ov && typeof ov === 'object') {
              this.overview = ov;
            }
          }
        } catch {
          // Do not fail capture pull if minimal/partial session cannot be reconstructed yet.
        }
      }

      this.state = 'done';
      this.lastError = undefined;
      pulledOk = true;
    } catch (err) {
      fs.rmSync(tmpParent, { recursive: true, force: true });
      this.state = 'error';
      this.lastError = err instanceof Error ? err.message : String(err);
    } finally {
      this.endedAt = Date.now();
      if (this.cleanupRemote) {
        this.remoteCleaned = await adb.client.cleanupRun(activeSerial, activeRun).catch(() => false);
      } else {
        this.remoteCleaned = false;
      }
      if (!pulledOk && this.logTail.length === 0) {
        this.logTail = await adb.client.readLogTail(activeSerial, activeRun.logPath, 60).catch(() => []);
      }
    }
  }

  start(
    spec: CaptureSpec,
    opts: { cleanupRemote: boolean },
  ): Promise<CaptureStartResult> {
    return this.runExclusive(async () => {
      if (this.state === 'running' || this.state === 'pulling') {
        throw new CaptureConflictError(
          `capture ${this.captureId} is already active`,
          this.captureId,
          [...this.logTail],
        );
      }
      const adb = this.host.getService<AdbTransportService>('transport.adb');
      const collector = this.host.getService<EbpfCollectorService>('collector.ebpf');
      if (!adb || !collector) {
        throw new CaptureBadRequestError('请先在插件页启用「Android ADB 连接」和「eBPF TC / Socket 采集器」插件后再开始采集。');
      }
      let serial = (spec.serial ?? '').trim();
      if (!serial) {
        serial = await adb.defaultSerial();
      }
      if (!serial) {
        throw new CaptureBadRequestError('serial is required (no connected ADB device found)');
      }

      // Always ensure device root + collector version match before start (mirrors Go capture.go:237).
      await adb.ensureReady(serial);

      // First normalize/validate without plugin_dir to catch invalid args cleanly as HTTP 400.
      let normalized;
      try {
        normalized = collector.normalizeRecordSpec(spec);
      } catch (err) {
        throw new CaptureBadRequestError(err instanceof Error ? err.message : String(err));
      }

      let args = [...normalized.args];
      let skippedBpfPlugins: SkippedBpfPlugin[] = [];
      if (normalized.enablePlugins && !spec.plugin_dir) {
        const pluginPaths = enabledRuntimePluginPaths(this.host.paths.pluginsDir);
        let bpfBundles: ExternalBpfSyncItem[] = [];
        if (hasEnabledExternalBpfPlugins(this.host.paths.pluginsDir, this.host.paths.appDir)) {
          const arch = await adb.client.detectArch(serial);
          const collected = collectEnabledExternalBpfBundles(
            this.host.paths.pluginsDir,
            this.host.paths.appDir,
            arch,
            normalized.requestedGroups,
          );
          bpfBundles = collected.bundles;
          skippedBpfPlugins = collected.skipped;
        }
        if (pluginPaths.length > 0 || bpfBundles.length > 0) {
          const syncRes = await adb.client.syncAllPlugins(serial, pluginPaths, bpfBundles).catch(() => ({
            legacySynced: 0,
            bpfSynced: 0,
            bpfReused: 0,
          }));
          if (syncRes.legacySynced + syncRes.bpfSynced + syncRes.bpfReused > 0) {
            args.push('--plugin-dir', REMOTE_PLUGINS_DIR);
          }
        }
      }

      const id = makeCaptureId(normalized.mode);
      const run = await adb.client.startRecord(serial, id, args);
      this.state = 'running';
      this.captureId = id;
      this.mode = normalized.mode;
      this.serial = serial;
      this.dev = normalized.dev;
      this.scope = normalized.scope;
      this.run = run;
      this.startedAt = Date.now();
      this.endedAt = 0;
      this.durationSec = normalized.durationSec;
      this.flushCount = 0;
      this.cleanupRemote = typeof spec.cleanup_remote === 'boolean' ? spec.cleanup_remote : opts.cleanupRemote;
      this.sessionId = undefined;
      this.sessionDir = undefined;
      this.overview = undefined;
      this.remoteCleaned = false;
      this.cleanExit = true;
      this.selfExited = false;
      this.lastError = undefined;
      this.logTail = [];

      // Catch immediate failures (bad args, BPF load error) synchronously (mirrors Go capture.go:286-309).
      await new Promise((r) => setTimeout(r, 900));
      const initialPoll = await adb.client.poll(serial, run, 60).catch(() => ({ alive: true, lines: [] as string[] }));
      if (initialPoll.lines.length > 0) {
        this.logTail = initialPoll.lines;
      }
      if (!initialPoll.alive) {
        const hasManifest = await adb.client.remoteExists(serial, `${run.outDir}/manifest.json`).catch(() => false);
        if (!hasManifest) {
          const lastMsg = this.logTail.length > 0 ? this.logTail[this.logTail.length - 1] : '';
          const msg = lastMsg
            ? `pktpath record exited immediately: ${lastMsg}`
            : 'pktpath record exited immediately';
          this.state = 'error';
          this.lastError = msg;
          this.endedAt = Date.now();
          // Await remote cleanup before reporting failure so no dangling cleanup process races with callers.
          this.remoteCleaned = await adb.client.cleanupRun(serial, run).catch(() => false);
          throw new CaptureStartFailedError(msg, id, [...this.logTail]);
        }
      }

      // Background monitor polls every 1s and auto-finalizes timed oneshot runs on self-exit.
      this.startMonitor(adb, id);

      return {
        ok: true,
        capture_id: id,
        status: 'running',
        phase: 'running',
        active: true,
        mode: normalized.mode,
        serial,
        dev: normalized.dev,
        scope: normalized.scope,
        remote_pid: run.pid,
        remote_dir: run.outDir,
        command: run.command,
        probe_preset: normalized.probePreset,
        requested_groups: normalized.requestedGroups,
        ...(skippedBpfPlugins.length > 0 ? { skipped_bpf_plugins: skippedBpfPlugins } : {}),
      };
    });
  }

  flush(): Promise<{ ok: true; capture_id: string; signal: 'SIGUSR1'; remote_pid: number; flush_count: number }> {
    return this.runExclusive(async () => {
      if (this.state !== 'running' || !this.serial || !this.run || !this.captureId) {
        throw new CaptureConflictError('no active capture to flush');
      }
      if (this.mode !== 'daemon') {
        throw new CaptureBadRequestError('flush (SIGUSR1) is only supported in daemon mode');
      }
      const adb = this.host.getService<AdbTransportService>('transport.adb');
      if (!adb) throw new CaptureBadRequestError('「Android ADB 连接」插件未启用，无法向设备发送落盘指令。');
      await adb.client.signal(this.serial, this.run.pid, 'USR1');
      this.flushCount += 1;
      return {
        ok: true,
        capture_id: this.captureId,
        signal: 'SIGUSR1',
        remote_pid: this.run.pid,
        flush_count: this.flushCount,
      };
    });
  }

  status(): Promise<CaptureStatusSnapshot> {
    return this.runExclusive(async () => {
      if (this.state === 'running' && this.serial && this.run) {
        const adb = this.host.getService<AdbTransportService>('transport.adb');
        if (adb) {
          try {
            const p = await adb.client.poll(this.serial, this.run);
            if (p.lines.length > 0) this.logTail = p.lines;
            if (!p.alive) {
              this.selfExited = true;
              await this.finishPull(adb);
            }
          } catch (err) {
            this.state = 'error';
            this.endedAt = Date.now();
            this.lastError = err instanceof Error ? err.message : String(err);
          }
        }
      }
      const active = this.state === 'running' || this.state === 'pulling';
      const refTime = this.endedAt > 0 ? this.endedAt : Date.now();
      const elapsedSec = this.startedAt > 0 ? Math.round(((refTime - this.startedAt) / 1000) * 1000) / 1000 : 0;
      const logs = [...this.logTail];
      return {
        ok: true,
        active,
        status: this.state,
        phase: this.state,
        capture_id: this.captureId ?? '',
        mode: this.mode ?? '',
        serial: this.serial ?? '',
        dev: this.dev ?? '',
        scope: this.scope ?? '',
        remote_pid: this.run?.pid,
        remote_dir: this.run?.outDir,
        command: this.run?.command,
        elapsed_sec: elapsedSec,
        duration_sec: this.durationSec,
        flush_count: this.flushCount,
        session_id: this.sessionId,
        last_session_id: this.sessionId ?? '',
        session_dir: this.sessionDir,
        session_path: this.sessionDir ?? '',
        error: this.lastError ?? '',
        log_tail: logs,
        log_lines: logs,
      };
    });
  }

  stop(): Promise<CaptureStopResult> {
    return this.runExclusive(async () => {
      if (this.state === 'done') {
        const logs = this.logTail.length > 0 ? [...this.logTail] : undefined;
        return {
          ok: true,
          active: false,
          status: 'done',
          phase: 'done',
          capture_id: this.captureId,
          session_id: this.sessionId,
          last_session_id: this.sessionId,
          session_dir: this.sessionDir,
          session_path: this.sessionDir,
          overview: this.overview,
          remote_cleaned: this.remoteCleaned,
          clean_exit: this.cleanExit,
          self_exited: this.selfExited,
          log_tail: logs,
          log_lines: logs,
        };
      }
      if (this.state !== 'running' || !this.serial || !this.run) {
        return {
          ok: false,
          active: false,
          status: this.state,
          phase: this.state,
          capture_id: this.captureId,
          remote_cleaned: this.remoteCleaned,
          clean_exit: false,
          self_exited: this.selfExited,
          error: 'no active capture',
        };
      }
      const adb = this.host.getService<AdbTransportService>('transport.adb');
      if (!adb) {
        return {
          ok: false,
          active: false,
          status: 'error',
          phase: 'error',
          capture_id: this.captureId,
          remote_cleaned: false,
          clean_exit: false,
          self_exited: false,
          error: '「Android ADB 连接」插件未启用，无法停止远端采集。',
        };
      }

      const waitUntilExited = async (timeoutMs: number): Promise<boolean> => {
        const deadline = Date.now() + timeoutMs;
        while (Date.now() < deadline) {
          try {
            const p = await adb.client.poll(this.serial!, this.run!);
            if (p.lines.length > 0) this.logTail = p.lines;
            if (!p.alive) return true;
          } catch {
            return true;
          }
          await new Promise((r) => setTimeout(r, 150));
        }
        return false;
      };

      this.stopMonitor();
      // Check if it already self-exited before sending INT.
      const preCheck = await adb.client.poll(this.serial, this.run).catch(() => ({ alive: false, lines: [] }));
      if (preCheck.lines.length > 0) this.logTail = preCheck.lines;
      if (!preCheck.alive) {
        this.selfExited = true;
        this.cleanExit = true;
      } else {
        this.selfExited = false;
        this.cleanExit = true;
        await adb.client.signal(this.serial, this.run.pid, 'INT').catch(() => {});
        let exited = await waitUntilExited(3_000);
        if (!exited) {
          this.cleanExit = false;
          await adb.client.signal(this.serial, this.run.pid, 'TERM').catch(() => {});
          exited = await waitUntilExited(1_500);
        }
        if (!exited) {
          this.cleanExit = false;
          await adb.client.signal(this.serial, this.run.pid, 'KILL').catch(() => {});
          await waitUntilExited(500);
        }
      }

      await this.finishPull(adb);
      const logs = this.logTail.length > 0 ? [...this.logTail] : undefined;
      return {
        ok: this.state === 'done',
        active: false,
        status: this.state,
        phase: this.state,
        capture_id: this.captureId,
        session_id: this.sessionId,
        last_session_id: this.sessionId,
        session_dir: this.sessionDir,
        session_path: this.sessionDir,
        overview: this.overview,
        remote_cleaned: this.remoteCleaned,
        clean_exit: this.cleanExit,
        self_exited: this.selfExited,
        error: this.lastError,
        log_tail: logs,
        log_lines: logs,
      };
    });
  }

  abortForMode(targetMode: 'oneshot' | 'daemon'): Promise<void> {
    return this.runExclusive(async () => {
      if (this.mode !== targetMode || this.state !== 'running' || !this.serial || !this.run) {
        return;
      }
      this.stopMonitor();
      const adb = this.host.getService<AdbTransportService>('transport.adb');
      if (adb) {
        await adb.client.signal(this.serial, this.run.pid, 'TERM').catch(() => {});
        await adb.client.cleanupRun(this.serial, this.run).catch(() => {});
      }
      this.run = undefined;
      this.state = 'idle';
    });
  }
}

export function getOrCreateCaptureController(host: HostServices): CaptureController {
  const existing = host.getService<CaptureController>('capture.controller');
  if (existing) return existing;
  const created = new CaptureController(host);
  host.provideService('host', 'capture.controller', created);
  return created;
}
