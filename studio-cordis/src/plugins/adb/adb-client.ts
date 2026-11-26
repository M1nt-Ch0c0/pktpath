import { execFile } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const REMOTE_DIR = '/data/local/tmp/.pktpath_studio';
export const REMOTE_AGENT = `${REMOTE_DIR}/pktpath`;
export const REMOTE_TMP = '/data/local/tmp/pktpath_tmp';

export type RootMode = '' | 'adbd-root' | 'adb-root' | 'su' | 'none';

export interface AdbResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export interface DeviceEntry {
  serial: string;
  state: string;
  model: string;
  product: string;
  device: string;
  transport: 'adb';
}

export interface DeviceProps {
  model: string;
  product: string;
  androidVer: string;
  kernel: string;
  arch: string;
  shellUid: string;
  agentSha256: string;
}

export interface IfaceInfo {
  name: string;
  state: string;
  addrs: string[];
}

export interface AppEntry {
  pkg: string;
  uid: number;
}

export interface RemoteRun {
  id: string;
  outDir: string;
  logPath: string;
  pidPath: string;
  pid: number;
  command: string;
}

function normNL(s: string): string {
  return s.replaceAll('\r\n', '\n');
}

function lastLine(s: string): string {
  const trimmed = s.trim();
  const idx = trimmed.lastIndexOf('\n');
  return idx >= 0 ? trimmed.slice(idx + 1).trim() : trimmed;
}

function firstLineIsZero(s: string): boolean {
  for (const line of normNL(s).split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    return trimmed === '0';
  }
  return false;
}

export function shQuote(s: string): string {
  return `'${s.replaceAll("'", "'\\''")}'`;
}

export function parseMarked(out: string): Record<string, string> {
  const m: Record<string, string> = {};
  for (const raw of normNL(out).split('\n')) {
    const line = raw.trim();
    if (!line.startsWith('@@')) continue;
    const eq = line.indexOf('=');
    if (eq > 2) {
      m[line.slice(2, eq)] = line.slice(eq + 1).trim();
    }
  }
  return m;
}

export function parseDevicesL(out: string): DeviceEntry[] {
  const res: DeviceEntry[] = [];
  for (const raw of normNL(out).split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('List of devices') || line.startsWith('*') || line.startsWith('adb server')) {
      continue;
    }
    const fields = line.split(/\s+/);
    if (fields.length < 2) continue;
    const entry: DeviceEntry = {
      serial: fields[0],
      state: fields[1],
      model: '',
      product: '',
      device: '',
      transport: 'adb',
    };
    let rest = fields.slice(2);
    if (fields[1] === 'no' && fields[2] === 'permissions') {
      entry.state = 'no permissions';
      rest = fields.slice(3);
    }
    for (const kv of rest) {
      const idx = kv.indexOf(':');
      if (idx <= 0) continue;
      const k = kv.slice(0, idx);
      const v = kv.slice(idx + 1);
      if (k === 'model') entry.model = v.replaceAll('_', ' ');
      else if (k === 'product') entry.product = v;
      else if (k === 'device') entry.device = v;
    }
    res.push(entry);
  }
  return res;
}

export function parseIPBrAddr(out: string): IfaceInfo[] {
  const res: IfaceInfo[] = [];
  const seen = new Map<string, number>();
  for (const raw of normNL(out).split('\n')) {
    const fields = raw.trim().split(/\s+/).filter(Boolean);
    if (fields.length < 2) continue;
    let name = fields[0];
    const at = name.indexOf('@');
    if (at > 0) name = name.slice(0, at);
    const addrs = fields.slice(2).filter((a) => a.includes('.') || a.includes(':'));
    const existingIdx = seen.get(name);
    if (existingIdx !== undefined) {
      res[existingIdx].addrs.push(...addrs);
    } else {
      seen.set(name, res.length);
      res.push({ name, state: fields[1], addrs });
    }
  }
  return res;
}

const PKG_LINE_RE = /^package:(\S+)\s+uid:(\d+)/;

export function parsePackages(out: string): AppEntry[] {
  const m = new Map<string, number>();
  for (const raw of normNL(out).split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    let pkg = '';
    let uid = -1;
    const match = PKG_LINE_RE.exec(line);
    if (match) {
      pkg = match[1];
      uid = Number.parseInt(match[2], 10);
    } else {
      const f = line.split(/\s+/);
      if (f.length >= 2 && f[0].includes('.')) {
        const parsed = Number.parseInt(f[1], 10);
        if (Number.isInteger(parsed) && parsed >= 0) {
          pkg = f[0];
          uid = parsed;
        }
      }
    }
    if (!pkg || uid < 0) continue;
    const old = m.get(pkg);
    if (old === undefined || uid < old) {
      m.set(pkg, uid);
    }
  }
  const apps: AppEntry[] = [...m.entries()].map(([pkg, uid]) => ({ pkg, uid }));
  apps.sort((a, b) => {
    const aUser = a.uid >= 10000;
    const bUser = b.uid >= 10000;
    if (aUser !== bUser) return aUser ? -1 : 1;
    return a.pkg.localeCompare(b.pkg);
  });
  return apps;
}

export function sha256File(filePath: string): string {
  const hash = crypto.createHash('sha256');
  hash.update(fs.readFileSync(filePath));
  return hash.digest('hex');
}

export function resolveAdbBinary(preferredPath?: string): string | undefined {
  if (preferredPath && fs.existsSync(preferredPath)) {
    return preferredPath;
  }
  const envPath = process.env.PATH ?? '';
  const sep = process.platform === 'win32' ? ';' : ':';
  const candidates = process.platform === 'win32' ? ['adb.exe', 'adb'] : ['adb'];
  for (const dir of envPath.split(sep)) {
    if (!dir) continue;
    for (const name of candidates) {
      const full = path.join(dir, name);
      try {
        if (fs.existsSync(full) && fs.statSync(full).isFile()) {
          return full;
        }
      } catch {
        // ignore inaccessible PATH entries
      }
    }
  }
  return undefined;
}

export function wrapPriv(mode: RootMode, command: string): string {
  if (mode === 'su') {
    return `su -c ${shQuote(command)}`;
  }
  return command;
}

export function runPaths(id: string): { outDir: string; logPath: string; pidPath: string } {
  const outDir = `${REMOTE_DIR}/run_${id}`;
  return { outDir, logPath: `${outDir}.log`, pidPath: `${outDir}.pid` };
}

export class AdbClient {
  readonly adbPath: string | undefined;
  private readonly rootCache = new Map<string, RootMode>();
  private serverStarted = false;

  constructor(adbPath?: string) {
    this.adbPath = adbPath;
  }

  get available(): boolean {
    return Boolean(this.adbPath);
  }

  private async ensureServer(): Promise<void> {
    if (this.serverStarted || !this.adbPath) return;
    this.serverStarted = true;
    await this.execRaw(['start-server'], 15_000).catch(() => {});
  }

  private execRaw(args: string[], timeoutMs: number): Promise<AdbResult> {
    if (!this.adbPath) {
      return Promise.reject(new Error('adb executable not available'));
    }
    return new Promise<AdbResult>((resolve, reject) => {
      execFile(
        this.adbPath!,
        args,
        {
          timeout: timeoutMs,
          maxBuffer: 16 * 1024 * 1024,
          windowsHide: true,
        },
        (err, stdout, stderr) => {
          const out = normNL(String(stdout ?? ''));
          const errOut = normNL(String(stderr ?? ''));
          if (!err) {
            resolve({ stdout: out, stderr: errOut, exitCode: 0 });
            return;
          }
          const code = typeof (err as { code?: unknown }).code === 'number'
            ? (err as { code: number }).code
            : 1;
          const combined = `${out.trim()}\n${errOut.trim()}`.trim();
          const wrapped = new Error(`adb ${args.slice(0, 4).join(' ')}: exit ${code}: ${lastLine(combined) || err.message}`);
          (wrapped as Error & { adbResult?: AdbResult }).adbResult = {
            stdout: out,
            stderr: errOut,
            exitCode: code,
          };
          reject(wrapped);
        },
      );
    });
  }

  async run(args: string[], timeoutMs = 20_000): Promise<AdbResult> {
    if (!this.adbPath) {
      throw new Error('adb executable not available');
    }
    await this.ensureServer();
    return this.execRaw(args, timeoutMs);
  }

  async shell(serial: string, command: string, timeoutMs = 20_000): Promise<AdbResult> {
    return this.run(['-s', serial, 'shell', command], timeoutMs);
  }

  rootMode(serial: string): RootMode {
    return this.rootCache.get(serial) ?? '';
  }

  forgetRoot(serial: string): void {
    this.rootCache.delete(serial);
  }

  async ensureRoot(serial: string): Promise<RootMode> {
    try {
      const r = await this.shell(serial, 'id -u', 10_000);
      if (firstLineIsZero(r.stdout)) {
        this.rootCache.set(serial, 'adbd-root');
        return 'adbd-root';
      }
    } catch (err) {
      const r = (err as { adbResult?: AdbResult }).adbResult;
      if (!r || !r.stdout.trim()) {
        throw new Error(`device ${serial} not reachable: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    const rr = await this.run(['-s', serial, 'root'], 15_000).catch((e: unknown) => {
      const res = (e as { adbResult?: AdbResult }).adbResult;
      return res ?? { stdout: '', stderr: String(e), exitCode: 1 };
    });
    const combined = `${rr.stdout}\n${rr.stderr}`.toLowerCase();
    if (!combined.includes('cannot run as root') && !combined.includes('not allowed')) {
      await this.run(['-s', serial, 'wait-for-device'], 15_000).catch(() => {});
      const r2 = await this.shell(serial, 'id -u', 8_000).catch(() => ({ stdout: '', stderr: '', exitCode: 1 }));
      if (firstLineIsZero(r2.stdout)) {
        this.rootCache.set(serial, 'adb-root');
        return 'adb-root';
      }
    }

    const rSu = await this.shell(serial, "su -c 'id -u'", 25_000).catch(() => ({ stdout: '', stderr: '', exitCode: 1 }));
    if (firstLineIsZero(rSu.stdout)) {
      this.rootCache.set(serial, 'su');
      return 'su';
    }

    const rSu0 = await this.shell(serial, 'su 0 id -u', 15_000).catch(() => ({ stdout: '', stderr: '', exitCode: 1 }));
    if (firstLineIsZero(rSu0.stdout)) {
      this.rootCache.set(serial, 'su');
      return 'su';
    }

    this.rootCache.set(serial, 'none');
    return 'none';
  }

  async priv(serial: string, command: string, timeoutMs = 20_000): Promise<AdbResult> {
    let mode = this.rootMode(serial);
    if (!mode) {
      mode = await this.ensureRoot(serial);
    }
    if (mode === 'none') {
      throw new Error(`device ${serial} has no root access (adbd-root / adb-root / su all unavailable)`);
    }
    return this.shell(serial, wrapPriv(mode, command), timeoutMs);
  }

  async devices(): Promise<DeviceEntry[]> {
    const r = await this.run(['devices', '-l'], 10_000);
    return parseDevicesL(r.stdout);
  }

  async props(serial: string): Promise<DeviceProps> {
    const script = [
      'echo "@@model=$(getprop ro.product.model)"',
      'echo "@@product=$(getprop ro.product.name)"',
      'echo "@@android=$(getprop ro.build.version.release)"',
      'echo "@@kernel=$(uname -r)"',
      'echo "@@arch=$(uname -m)"',
      'echo "@@uid=$(id -u)"',
      `echo "@@agent=$(sha256sum ${REMOTE_AGENT} 2>/dev/null | cut -d' ' -f1)"`,
    ].join('; ');
    const r = await this.shell(serial, script, 10_000);
    const m = parseMarked(r.stdout);
    return {
      model: m.model ?? '',
      product: m.product ?? '',
      androidVer: m.android ?? '',
      kernel: m.kernel ?? '',
      arch: m.arch ?? '',
      shellUid: m.uid ?? '',
      agentSha256: (m.agent ?? '').toLowerCase(),
    };
  }

  async remoteAgentSha(serial: string): Promise<string> {
    const r = await this.shell(serial, `sha256sum ${REMOTE_AGENT} 2>/dev/null`, 10_000).catch(() => ({
      stdout: '',
      stderr: '',
      exitCode: 1,
    }));
    const first = r.stdout.trim().split(/\s+/)[0] ?? '';
    if (first.length === 64) return first.toLowerCase();
    if (this.rootMode(serial) === 'su') {
      const rp = await this.priv(serial, `sha256sum ${REMOTE_AGENT} 2>/dev/null`, 15_000).catch(() => ({
        stdout: '',
        stderr: '',
        exitCode: 1,
      }));
      const pfirst = rp.stdout.trim().split(/\s+/)[0] ?? '';
      if (pfirst.length === 64) return pfirst.toLowerCase();
    }
    return '';
  }

  async ensureAgent(serial: string, localPath: string, wantSha: string): Promise<{ pushed: boolean; remoteSha: string }> {
    const want = wantSha.trim().toLowerCase();
    if (!localPath || !want) {
      throw new Error('bundled android-arm64 pktpath collector unavailable');
    }
    const existing = await this.remoteAgentSha(serial);
    if (existing === want) {
      return { pushed: false, remoteSha: existing };
    }
    await this.run(['-s', serial, 'push', localPath, REMOTE_TMP], 60_000);
    const installCmd = [
      'umask 022',
      `mkdir -p ${REMOTE_DIR}`,
      `chmod 755 ${REMOTE_DIR}`,
      `mv -f ${REMOTE_TMP} ${REMOTE_AGENT}`,
      `chmod 755 ${REMOTE_AGENT}`,
      `sha256sum ${REMOTE_AGENT}`,
    ].join(' && ');
    const r = await this.priv(serial, installCmd, 30_000);
    const got = (r.stdout.trim().split(/\s+/)[0] ?? '').toLowerCase();
    if (got !== want) {
      await this.shell(serial, `rm -f ${REMOTE_TMP}`, 10_000).catch(() => {});
      throw new Error(`agent sha256 mismatch after install: got "${got}" want "${want}"`);
    }
    return { pushed: true, remoteSha: got };
  }

  async inspect(serial: string, dev?: string): Promise<{ ifaces: IfaceInfo[]; qdiscs: string[] }> {
    const ifaceRes = await this.shell(serial, 'ip -br addr 2>/dev/null', 10_000);
    const ifaces = parseIPBrAddr(ifaceRes.stdout);
    const qdiscCmd = dev
      ? `tc qdisc show dev ${shQuote(dev)} 2>/dev/null`
      : 'tc qdisc show 2>/dev/null';
    const qRes = await this.priv(serial, qdiscCmd, 10_000).catch(() => ({ stdout: '', stderr: '', exitCode: 1 }));
    const qdiscs = normNL(qRes.stdout)
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean);
    return { ifaces, qdiscs };
  }

  async listApps(serial: string): Promise<AppEntry[]> {
    const r = await this.shell(serial, 'cmd package list packages -U 2>/dev/null', 15_000).catch(() => ({
      stdout: '',
      stderr: '',
      exitCode: 1,
    }));
    const apps = parsePackages(r.stdout);
    if (apps.length > 0) return apps;
    const r2 = await this.priv(serial, 'cat /data/system/packages.list 2>/dev/null', 15_000).catch(() => ({
      stdout: '',
      stderr: '',
      exitCode: 1,
    }));
    return parsePackages(r2.stdout);
  }

  async startRecord(serial: string, id: string, args: string[]): Promise<RemoteRun> {
    const { outDir, logPath, pidPath } = runPaths(id);
    const quoted = args.map((a) => shQuote(a));
    quoted.push('--out', shQuote(outDir));
    const agentCmd = `${REMOTE_AGENT} record ${quoted.join(' ')}`;
    const inner = `echo $$ > ${pidPath}; exec ${agentCmd}`;
    const script = [
      'umask 022',
      `cd ${REMOTE_DIR}`,
      `rm -rf ${outDir} ${logPath} ${pidPath}`,
      'S=; command -v setsid >/dev/null 2>&1 && S=setsid',
      `($S sh -c ${shQuote(inner)} > ${logPath} 2>&1 < /dev/null &)`,
      `i=0; while [ ! -s ${pidPath} ] && [ $i -lt 30 ]; do sleep 0.1; i=$((i+1)); done`,
      `echo "@@pid=$(cat ${pidPath} 2>/dev/null)"`,
    ].join('; ');
    const r = await this.priv(serial, script, 20_000);
    const m = parseMarked(r.stdout);
    const pid = Number.parseInt(m.pid ?? '0', 10);
    if (!Number.isInteger(pid) || pid <= 0) {
      throw new Error(`record did not report a PID: ${lastLine(r.stdout + '\n' + r.stderr)}`);
    }
    return {
      id,
      outDir,
      logPath,
      pidPath,
      pid,
      command: `pktpath record ${args.join(' ')} --out ${outDir}`,
    };
  }

  async poll(serial: string, run: RemoteRun, tail = 60): Promise<{ alive: boolean; lines: string[] }> {
    const script = `tail -n ${tail} ${run.logPath} 2>/dev/null; echo ""; echo "@@comm=$(cat /proc/${run.pid}/comm 2>/dev/null)"; echo "@@stat=$(cut -d' ' -f3 /proc/${run.pid}/stat 2>/dev/null)"`;
    const r = await this.priv(serial, script, 10_000);
    let comm = '';
    let stat = '';
    const lines: string[] = [];
    for (const raw of normNL(r.stdout).split('\n')) {
      if (raw.startsWith('@@comm=')) {
        comm = raw.slice('@@comm='.length).trim();
        continue;
      }
      if (raw.startsWith('@@stat=')) {
        stat = raw.slice('@@stat='.length).trim();
        continue;
      }
      if (raw.trim()) lines.push(raw.trimEnd());
    }
    const alive = Boolean(comm) && stat !== 'Z' && (comm.includes('pktpath') || comm === 'sh');
    return { alive, lines };
  }

  async signal(serial: string, pid: number, sig: 'INT' | 'TERM' | 'USR1' | 'KILL'): Promise<void> {
    if (pid <= 0) throw new Error(`invalid pid ${pid}`);
    await this.priv(serial, `kill -${sig} ${pid}`, 10_000);
  }

  async prepareForPull(serial: string, run: RemoteRun): Promise<void> {
    await this.priv(
      serial,
      `chmod -R a+rX ${run.outDir} 2>/dev/null; chmod a+r ${run.logPath} 2>/dev/null; true`,
      15_000,
    ).catch(() => {});
  }

  async pull(serial: string, remote: string, local: string, timeoutMs = 120_000): Promise<void> {
    fs.mkdirSync(path.dirname(local), { recursive: true });
    await this.run(['-s', serial, 'pull', remote, local], timeoutMs);
  }

  async cleanupRun(serial: string, run: RemoteRun): Promise<boolean> {
    const r = await this.priv(
      serial,
      `rm -rf ${run.outDir} ${run.logPath} ${run.pidPath}; [ -e ${run.outDir} ] && echo "@@gone=0" || echo "@@gone=1"`,
      20_000,
    ).catch(() => ({ stdout: '', stderr: '', exitCode: 1 }));
    return parseMarked(r.stdout).gone === '1';
  }
}
