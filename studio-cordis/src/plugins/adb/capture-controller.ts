import fs from 'node:fs';
import path from 'node:path';
import type { HostServices } from '../../kernel/types.ts';
import type { RemoteRun } from './adb-client.ts';
import type { AdbTransportService } from './android-adb.ts';
import type { CaptureSpec, EbpfCollectorService } from './ebpf-tc.ts';

export type CaptureStateKind = 'idle' | 'running' | 'pulling' | 'done' | 'error';

export interface CaptureStatusSnapshot {
  ok: true;
  status: CaptureStateKind;
  capture_id?: string;
  mode?: 'oneshot' | 'daemon';
  serial?: string;
  remote_pid?: number;
  elapsed_sec?: number;
  duration_sec?: number;
  flush_count?: number;
  session_id?: string;
  session_dir?: string;
  error?: string;
  log_tail?: string[];
}

export class CaptureConflictError extends Error {
  readonly statusCode = 409;
  constructor(msg: string) {
    super(msg);
  }
}

export class CaptureBadRequestError extends Error {
  readonly statusCode = 400;
  constructor(msg: string) {
    super(msg);
  }
}

function makeCaptureId(mode: 'oneshot' | 'daemon'): string {
  const now = new Date();
  const pad = (n: number) => String(n).padStart(2, '0');
  const stamp = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}_${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
  const rand = Math.random().toString(36).slice(2, 6);
  return `${mode}_${stamp}_${rand}`;
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

  private state: CaptureStateKind = 'idle';
  private captureId?: string;
  private mode?: 'oneshot' | 'daemon';
  private serial?: string;
  private run?: RemoteRun;
  private startedAt = 0;
  private durationSec = 0;
  private flushCount = 0;
  private cleanupRemote = true;
  private sessionId?: string;
  private sessionDir?: string;
  private lastError?: string;
  private logTail: string[] = [];

  constructor(host: HostServices) {
    this.host = host;
  }

  private runExclusive<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.lockChain.then(fn, fn);
    this.lockChain = next.catch(() => {});
    return next;
  }

  private async finishPull(adb: AdbTransportService): Promise<void> {
    if (!this.serial || !this.run || !this.captureId) return;
    const activeRun = this.run;
    const activeSerial = this.serial;
    const activeId = this.captureId;
    this.state = 'pulling';
    const localDir = path.join(this.host.paths.sessionsRoot, activeId);
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
            : `remote run directory missing (${activeRun.outDir})`,
        );
      }

      await adb.client.prepareForPull(activeSerial, activeRun);
      fs.rmSync(tmpParent, { recursive: true, force: true });
      fs.mkdirSync(tmpParent, { recursive: true });
      await adb.client.pull(activeSerial, activeRun.outDir, tmpParent);

      const pulledSubdir = path.join(tmpParent, path.posix.basename(activeRun.outDir));
      const pulledDir = fs.existsSync(pulledSubdir) && fs.statSync(pulledSubdir).isDirectory()
        ? pulledSubdir
        : tmpParent;
      fs.rmSync(localDir, { recursive: true, force: true });
      fs.renameSync(pulledDir, localDir);
      fs.rmSync(tmpParent, { recursive: true, force: true });

      await adb.client
        .pull(activeSerial, activeRun.logPath, path.join(localDir, 'studio_record.log'), 60_000)
        .catch(() => {});

      this.sessionId = activeId;
      this.sessionDir = localDir;
      pulledOk = true;
      this.state = 'done';
      this.lastError = undefined;
    } catch (err) {
      if (this.logTail.length === 0) {
        const latestTail = await adb.client.readLogTail(activeSerial, activeRun.logPath, 60).catch(() => []);
        if (latestTail.length > 0) this.logTail = latestTail;
      }
      this.state = 'error';
      this.lastError = err instanceof Error ? err.message : String(err);
      if (!pulledOk) {
        fs.rmSync(localDir, { recursive: true, force: true });
      }
    } finally {
      fs.rmSync(tmpParent, { recursive: true, force: true });
      if (this.cleanupRemote) {
        await adb.client.cleanupRun(activeSerial, activeRun).catch(() => {});
      }
      this.run = undefined;
    }
  }

  start(
    spec: CaptureSpec,
    opts: { cleanupRemote: boolean },
  ): Promise<{ ok: true; capture_id: string; status: 'running'; mode: 'oneshot' | 'daemon'; remote_pid: number }> {
    return this.runExclusive(async () => {
      if (this.state === 'running' || this.state === 'pulling') {
        throw new CaptureConflictError(`a capture is already in progress (${this.captureId ?? 'active'})`);
      }
      const adb = this.host.getService<AdbTransportService>('transport.adb');
      if (!adb) {
        throw new CaptureBadRequestError('builtin.transport.android-adb is disabled');
      }
      const collector = this.host.getService<EbpfCollectorService>('collector.ebpf');
      if (!collector) {
        throw new CaptureBadRequestError('builtin.collector.ebpf-tc is disabled');
      }
      if (!spec.serial || !spec.serial.trim()) {
        throw new CaptureBadRequestError('serial is required');
      }

      const mode: 'oneshot' | 'daemon' = spec.mode === 'daemon' ? 'daemon' : 'oneshot';
      const id = makeCaptureId(mode);
      const args = collector.buildRecordArgs({ ...spec, mode });
      const started = await adb.client.startRecord(spec.serial.trim(), id, args);

      this.state = 'running';
      this.captureId = id;
      this.mode = mode;
      this.serial = spec.serial.trim();
      this.run = started;
      this.startedAt = Date.now();
      this.durationSec = mode === 'oneshot'
        ? (typeof spec.duration_sec === 'number' && spec.duration_sec > 0
            ? Math.floor(spec.duration_sec)
            : collector.defaultDurationSec)
        : 0;
      this.flushCount = 0;
      this.cleanupRemote = opts.cleanupRemote;
      this.sessionId = undefined;
      this.sessionDir = undefined;
      this.lastError = undefined;
      this.logTail = [];

      return { ok: true, capture_id: id, status: 'running', mode, remote_pid: started.pid };
    });
  }

  flush(): Promise<{ ok: true; capture_id: string; signal: 'SIGUSR1'; remote_pid: number; flush_count: number }> {
    return this.runExclusive(async () => {
      if (this.state !== 'running' || !this.run || !this.serial || !this.captureId) {
        throw new CaptureConflictError('no active capture');
      }
      if (this.mode !== 'daemon') {
        throw new CaptureBadRequestError('flush (SIGUSR1) is only supported in daemon mode');
      }
      const adb = this.host.getService<AdbTransportService>('transport.adb');
      if (!adb) {
        throw new CaptureBadRequestError('builtin.transport.android-adb is disabled');
      }
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
            const polled = await adb.client.poll(this.serial, this.run, 40);
            this.logTail = polled.lines;
            if (!polled.alive) {
              await this.finishPull(adb);
            }
          } catch (err) {
            this.logTail = [...this.logTail, `poll warning: ${err instanceof Error ? err.message : String(err)}`];
          }
        }
      }
      return {
        ok: true,
        status: this.state,
        capture_id: this.captureId,
        mode: this.mode,
        serial: this.serial,
        remote_pid: this.run?.pid,
        elapsed_sec: this.startedAt ? Math.floor((Date.now() - this.startedAt) / 1000) : undefined,
        duration_sec: this.mode === 'oneshot' ? this.durationSec : undefined,
        flush_count: this.mode === 'daemon' ? this.flushCount : undefined,
        session_id: this.sessionId,
        session_dir: this.sessionDir,
        error: this.lastError,
        log_tail: this.logTail.length > 0 ? this.logTail : undefined,
      };
    });
  }

  stop(): Promise<{
    ok: boolean;
    status: CaptureStateKind;
    session_id?: string;
    session_dir?: string;
    error?: string;
    log_tail?: string[];
  }> {
    return this.runExclusive(async () => {
      if (this.state !== 'running' || !this.serial || !this.run) {
        return {
          ok: this.state !== 'error',
          status: this.state,
          session_id: this.sessionId,
          session_dir: this.sessionDir,
          error: this.lastError,
          log_tail: this.logTail.length > 0 ? this.logTail : undefined,
        };
      }
      const adb = this.host.getService<AdbTransportService>('transport.adb');
      if (!adb) {
        this.state = 'error';
        this.lastError = 'builtin.transport.android-adb is disabled';
        this.run = undefined;
        return { ok: false, status: this.state, error: this.lastError };
      }
      await adb.client.signal(this.serial, this.run.pid, 'INT').catch(() => {});
      const waitUntilExited = async (maxWaitMs: number): Promise<boolean> => {
        const deadline = Date.now() + maxWaitMs;
        while (Date.now() < deadline) {
          try {
            const p = await adb.client.poll(this.serial!, this.run!, 20);
            if (p.lines.length > 0) this.logTail = p.lines;
            if (!p.alive) return true;
          } catch {
            return true;
          }
          await new Promise((r) => setTimeout(r, 150));
        }
        return false;
      };
      const exited = await waitUntilExited(3_000);
      if (!exited) {
        await adb.client.signal(this.serial, this.run.pid, 'TERM').catch(() => {});
        await waitUntilExited(1_500);
      }
      await this.finishPull(adb);
      return {
        ok: this.state === 'done',
        status: this.state,
        session_id: this.sessionId,
        session_dir: this.sessionDir,
        error: this.lastError,
        log_tail: this.logTail.length > 0 ? this.logTail : undefined,
      };
    });
  }

  abortForMode(targetMode: 'oneshot' | 'daemon'): Promise<void> {
    return this.runExclusive(async () => {
      if (this.mode !== targetMode || this.state !== 'running' || !this.serial || !this.run) {
        return;
      }
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
