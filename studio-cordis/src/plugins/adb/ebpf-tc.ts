import type { BuiltinPlugin } from '../../kernel/types.ts';

export const VALID_CAPTURE_SCOPES = ['tc-egress', 'ip-tx', 'sock-tx', 'rx-sock', 'fwd'] as const;
export type CaptureScope = (typeof VALID_CAPTURE_SCOPES)[number];

const VALID_SCOPE_SET = new Set<string>(VALID_CAPTURE_SCOPES);
const VALID_PROTO_MAP: Record<string, string> = {
  tcp: 'tcp',
  udp: 'udp',
  icmp: 'icmp',
  icmpv6: 'icmpv6',
  icmp6: 'icmpv6',
};

const RE_DEV = /^[A-Za-z0-9_.@:\-]{1,32}$/;
const RE_IP_CIDR = /^[0-9A-Fa-f:.]+(\/\d{1,3})?$/;
const RE_MARK = /^(0x[0-9A-Fa-f]+|\d+)(\/(0x[0-9A-Fa-f]+|\d+))?$/;
const RE_SAMPLE = /^(1\/)?\d{1,7}$/;
const RE_TRIGGER = /^[a-z_]+>\d+(,\s*[a-z_]+>\d+)*$/;
const RE_BUDGET = /^\d+[KkMmGg]?[Bb]?$/;

export interface CaptureSpec {
  serial?: string;
  mode?: 'oneshot' | 'daemon';
  dev?: string;
  scope?: string;
  duration_sec?: number | string;
  duration?: number | string;
  sample?: number | string;
  sample_by?: string;
  uid?: number | string;
  tgid?: number | string;
  pkg?: string;
  proto?: string;
  src_port?: number | string;
  dst_port?: number | string;
  /** Legacy Cordis UI alias; mapped to --dst-port (device/main.c has no --port). */
  port?: number | string;
  src_ip?: string;
  dst_ip?: string;
  mark?: string;
  /** Official Go / device/main.c field name. */
  capture_hdr?: number | string;
  /** Cordis UI alias for capture_hdr; mapped to --capture-hdr. */
  hdr_bytes?: number | string;
  profile_sendmsg?: boolean;
  /** Alias for profile_sendmsg. */
  sendmsg_profile?: boolean;
  allow_partial?: boolean;
  enable_plugins?: boolean;
  cleanup_remote?: boolean;
  trigger?: string;
  pre_window_sec?: number | string;
  post_window_sec?: number | string;
  mem_budget?: string;
  disk_budget?: string;
  plugin_dir?: string;
}

export interface NormalizedCaptureSpec {
  mode: 'oneshot' | 'daemon';
  dev: string;
  scope: CaptureScope;
  durationSec: number;
  enablePlugins: boolean;
  args: string[];
}

export interface EbpfCollectorService {
  readonly defaultDurationSec: number;
  readonly defaultSample: number;
  readonly defaultHdrBytes: number;
  buildRecordArgs(spec: CaptureSpec): string[];
  normalizeRecordSpec(spec: CaptureSpec): NormalizedCaptureSpec;
}

function parseOptionalInt(raw: unknown): number | undefined {
  if (typeof raw === 'number' && Number.isFinite(raw)) return Math.trunc(raw);
  if (typeof raw === 'string') {
    const s = raw.trim();
    if (!s) return undefined;
    const stripped = s.endsWith('s') || s.endsWith('S') ? s.slice(0, -1).trim() : s;
    if (!/^-?\d+$/.test(stripped)) return undefined;
    const n = Number.parseInt(stripped, 10);
    if (Number.isFinite(n)) return n;
  }
  return undefined;
}

function parseBool(raw: unknown): boolean {
  if (typeof raw === 'boolean') return raw;
  if (typeof raw === 'number') return raw !== 0;
  if (typeof raw === 'string') {
    const s = raw.trim().toLowerCase();
    return s === '1' || s === 'true' || s === 'yes' || s === 'on';
  }
  return false;
}

export const ebpfTcPlugin: BuiltinPlugin = {
  meta: {
    id: 'builtin.collector.ebpf-tc',
    name: 'eBPF TC / Socket 采集器',
    version: '1.0.0',
    description: '配置并构造原生 Android arm64 eBPF 采集参数（网卡、方向、采样率、过滤与常驻缓冲条件）。',
    category: 'collector',
    icon: 'cpu',
    builtin: true,
    capabilities: ['collector.ebpf', 'collector.tc', 'collector.socket'],
    provides: ['collector.ebpf'],
    usedBy: ['短时采集模式 (Oneshot)', '常驻录制模式 (Daemon)'],
    requires: [],
    tags: ['ebpf', 'tc', 'collector'],
  },
  schema: {
    fields: [
      {
        key: 'default_duration_sec',
        label: '默认采集时长（秒）',
        type: 'number',
        default: 15,
        min: 1,
        max: 300,
      },
      {
        key: 'default_sample',
        label: '默认采样步长（1 表示全量）',
        type: 'number',
        default: 1,
        min: 1,
        max: 1000,
      },
      {
        key: 'default_hdr_bytes',
        label: '默认包头抓取字节数',
        type: 'number',
        default: 96,
        min: 0,
        max: 128,
      },
    ],
  },
  apply(ctx, cfg) {
    const defaultDurationSec = typeof cfg.default_duration_sec === 'number' && cfg.default_duration_sec > 0
      ? Math.floor(cfg.default_duration_sec)
      : 15;
    const defaultSample = typeof cfg.default_sample === 'number' && cfg.default_sample >= 1
      ? Math.floor(cfg.default_sample)
      : 1;
    const defaultHdrBytes = typeof cfg.default_hdr_bytes === 'number' && cfg.default_hdr_bytes >= 0
      ? Math.min(128, Math.floor(cfg.default_hdr_bytes))
      : 96;

    const normalizeRecordSpec = (spec: CaptureSpec): NormalizedCaptureSpec => {
      const modeRaw = typeof spec.mode === 'string' ? spec.mode.trim().toLowerCase() : '';
      if (modeRaw && modeRaw !== 'oneshot' && modeRaw !== 'daemon') {
        throw new Error(`invalid mode "${spec.mode}" (oneshot|daemon)`);
      }
      const mode: 'oneshot' | 'daemon' = modeRaw === 'daemon' ? 'daemon' : 'oneshot';

      const dev = typeof spec.dev === 'string' && spec.dev.trim() ? spec.dev.trim() : 'wlan0';
      if (!RE_DEV.test(dev)) {
        throw new Error(`invalid dev "${dev}"`);
      }

      const scopeRaw = typeof spec.scope === 'string' && spec.scope.trim() ? spec.scope.trim() : 'tc-egress';
      if (!VALID_SCOPE_SET.has(scopeRaw)) {
        throw new Error(`invalid scope "${scopeRaw}" (${VALID_CAPTURE_SCOPES.join('|')})`);
      }
      const scope = scopeRaw as CaptureScope;

      const args: string[] = ['--mode', mode, '--dev', dev, '--scope', scope];

      const uid = parseOptionalInt(spec.uid);
      if (uid !== undefined && uid >= 0 && uid < 0xffffffff) {
        args.push('--uid', String(uid));
      }

      const tgid = parseOptionalInt(spec.tgid);
      if (tgid !== undefined && tgid > 0) {
        args.push('--tgid', String(tgid));
      }

      if (typeof spec.proto === 'string') {
        const p = spec.proto.trim().toLowerCase();
        if (p && p !== 'all' && p !== 'any' && p !== '*') {
          const norm = VALID_PROTO_MAP[p];
          if (!norm) {
            throw new Error(`invalid proto "${spec.proto}"`);
          }
          args.push('--proto', norm);
        }
      }

      for (const [key, flag] of [['src_ip', '--src-ip'], ['dst_ip', '--dst-ip']] as const) {
        const raw = spec[key];
        if (typeof raw === 'string') {
          const v = raw.trim();
          if (v && v.toLowerCase() !== 'any') {
            if (!RE_IP_CIDR.test(v)) {
              throw new Error(`invalid ${key} "${v}"`);
            }
            args.push(flag, v);
          }
        }
      }

      const srcPort = parseOptionalInt(spec.src_port);
      if (srcPort !== undefined && srcPort !== 0) {
        if (srcPort < 0 || srcPort > 65535) throw new Error(`invalid src_port ${srcPort}`);
        args.push('--src-port', String(srcPort));
      }

      const dstPort = parseOptionalInt(spec.dst_port ?? spec.port);
      if (dstPort !== undefined && dstPort !== 0) {
        if (dstPort < 0 || dstPort > 65535) throw new Error(`invalid dst_port ${dstPort}`);
        args.push('--dst-port', String(dstPort));
      }

      if (typeof spec.mark === 'string' && spec.mark.trim()) {
        const mark = spec.mark.trim();
        if (!RE_MARK.test(mark)) {
          throw new Error(`invalid mark "${mark}"`);
        }
        args.push('--mark', mark);
      }

      // Sample: supports "1/N", N, or defaultSample (>1). Always emit "1/N" format for device/main.c.
      if (spec.sample !== undefined && spec.sample !== null && String(spec.sample).trim() !== '') {
        let s = String(spec.sample).trim();
        if (!RE_SAMPLE.test(s)) {
          throw new Error(`invalid sample "${s}" (expected 1/N)`);
        }
        if (!s.startsWith('1/') && s !== '0') {
          s = `1/${s}`;
        }
        if (s !== '0' && s !== '1/1') {
          args.push('--sample', s);
        }
      } else if (defaultSample > 1) {
        args.push('--sample', `1/${defaultSample}`);
      }

      if (typeof spec.sample_by === 'string' && spec.sample_by.trim()) {
        const sb = spec.sample_by.trim().toLowerCase();
        if (sb !== 'pkt' && sb !== 'flow') {
          throw new Error(`invalid sample_by "${spec.sample_by}"`);
        }
        args.push('--sample-by', sb);
      }

      let dur = parseOptionalInt(spec.duration_sec ?? spec.duration);
      if (mode === 'oneshot') {
        if (dur === undefined || dur <= 0) {
          dur = defaultDurationSec;
        }
      }
      let finalDur = 0;
      if (dur !== undefined && dur > 0) {
        if (dur > 24 * 3600) {
          throw new Error('duration_sec too large');
        }
        args.push('--duration', `${dur}s`);
        finalDur = dur;
      }

      const rawHdr = spec.capture_hdr !== undefined ? spec.capture_hdr : spec.hdr_bytes;
      const hdrParsed = parseOptionalInt(rawHdr);
      const hdrBytes = hdrParsed !== undefined ? hdrParsed : defaultHdrBytes;
      if (hdrBytes > 0) {
        args.push('--capture-hdr', String(Math.min(128, hdrBytes)));
      }

      if (parseBool(spec.profile_sendmsg) || parseBool(spec.sendmsg_profile)) {
        args.push('--profile', 'sendmsg');
      }

      if (parseBool(spec.allow_partial)) {
        args.push('--allow-partial');
      }

      if (mode === 'daemon') {
        if (typeof spec.trigger === 'string' && spec.trigger.trim()) {
          let trig = spec.trigger.trim();
          if (/^\d+$/.test(trig) && Number.parseInt(trig, 10) > 0) {
            trig = `sojourn_us>${trig}`;
          }
          trig = trig.replace(/\s+/g, '');
          if (trig) {
            if (!RE_TRIGGER.test(trig)) {
              throw new Error(`invalid daemon trigger "${spec.trigger}"`);
            }
            args.push('--trigger', trig);
          }
        }
        const preWin = parseOptionalInt(spec.pre_window_sec);
        if (preWin !== undefined && preWin > 0) {
          args.push('--pre-window', `${preWin}s`);
        }
        const postWin = parseOptionalInt(spec.post_window_sec);
        if (postWin !== undefined && postWin > 0) {
          args.push('--post-window', `${postWin}s`);
        }
      }

      for (const [key, flag] of [['mem_budget', '--mem-budget'], ['disk_budget', '--disk-budget']] as const) {
        const raw = spec[key];
        if (typeof raw === 'string' && raw.trim()) {
          const b = raw.trim();
          if (!RE_BUDGET.test(b)) {
            throw new Error(`invalid ${key} "${b}"`);
          }
          args.push(flag, b);
        }
      }

      if (typeof spec.plugin_dir === 'string' && spec.plugin_dir.trim()) {
        args.push('--plugin-dir', spec.plugin_dir.trim());
      }

      const enablePlugins = spec.enable_plugins === undefined ? true : parseBool(spec.enable_plugins);

      return { mode, dev, scope, durationSec: finalDur, enablePlugins, args };
    };

    const service: EbpfCollectorService = {
      defaultDurationSec,
      defaultSample,
      defaultHdrBytes,
      normalizeRecordSpec,
      buildRecordArgs(spec: CaptureSpec): string[] {
        return normalizeRecordSpec(spec).args;
      },
    };

    ctx.provide('collector.ebpf', service);
    ctx.registerExtension('collector', {
      id: 'ebpf-tc',
      plugin_id: 'builtin.collector.ebpf-tc',
      name: 'eBPF TC / Socket',
      default_duration_sec: defaultDurationSec,
      default_sample: defaultSample,
      default_hdr_bytes: defaultHdrBytes,
      scopes: [...VALID_CAPTURE_SCOPES],
    });
  },
};
