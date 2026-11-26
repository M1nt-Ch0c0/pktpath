import type { BuiltinPlugin } from '../../kernel/types.ts';

export interface CaptureSpec {
  serial: string;
  mode: 'oneshot' | 'daemon';
  dev?: string;
  scope?: string;
  duration_sec?: number;
  sample?: number;
  uid?: number;
  pkg?: string;
  proto?: string;
  port?: number;
  dst_ip?: string;
  hdr_bytes?: number;
  profile_sendmsg?: boolean;
  allow_partial?: boolean;
  trigger?: string;
  pre_window_sec?: number;
  post_window_sec?: number;
  mem_budget?: string;
  disk_budget?: string;
}

export interface EbpfCollectorService {
  readonly defaultDurationSec: number;
  readonly defaultSample: number;
  readonly defaultHdrBytes: number;
  buildRecordArgs(spec: CaptureSpec): string[];
}

const VALID_TRIGGER_RE = /^[a-zA-Z0-9_]+([<>]=?|==)[0-9]+$/;
const VALID_BUDGET_RE = /^[0-9]+[kKmMgG]?[bB]?$/;

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
        max: 256,
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
      ? Math.floor(cfg.default_hdr_bytes)
      : 96;

    const service: EbpfCollectorService = {
      defaultDurationSec,
      defaultSample,
      defaultHdrBytes,
      buildRecordArgs(spec: CaptureSpec): string[] {
        const mode = spec.mode === 'daemon' ? 'daemon' : 'oneshot';
        const args: string[] = ['--mode', mode];

        if (mode === 'oneshot') {
          const duration = typeof spec.duration_sec === 'number' && spec.duration_sec > 0
            ? Math.floor(spec.duration_sec)
            : defaultDurationSec;
          args.push('--duration', String(duration));
        }

        if (spec.dev && spec.dev.trim()) {
          args.push('--dev', spec.dev.trim());
        }
        if (spec.scope && spec.scope.trim()) {
          args.push('--scope', spec.scope.trim());
        }
        const sample = typeof spec.sample === 'number' && spec.sample >= 1
          ? Math.floor(spec.sample)
          : defaultSample;
        if (sample > 1) {
          args.push('--sample', String(sample));
        }
        if (typeof spec.uid === 'number' && Number.isInteger(spec.uid) && spec.uid >= 0) {
          args.push('--uid', String(spec.uid));
        }
        if (spec.proto && spec.proto.trim()) {
          args.push('--proto', spec.proto.trim());
        }
        if (typeof spec.port === 'number' && Number.isInteger(spec.port) && spec.port > 0) {
          args.push('--port', String(spec.port));
        }
        if (spec.dst_ip && spec.dst_ip.trim()) {
          args.push('--dst-ip', spec.dst_ip.trim());
        }
        const hdrBytes = typeof spec.hdr_bytes === 'number' && spec.hdr_bytes >= 0
          ? Math.floor(spec.hdr_bytes)
          : defaultHdrBytes;
        if (hdrBytes > 0) {
          args.push('--hdr-bytes', String(hdrBytes));
        }
        if (spec.profile_sendmsg) {
          args.push('--profile-sendmsg');
        }
        if (spec.allow_partial) {
          args.push('--allow-partial');
        }

        if (mode === 'daemon') {
          if (typeof spec.trigger === 'string' && spec.trigger.trim()) {
            let trig = spec.trigger.replaceAll(' ', '');
            if (/^\d+$/.test(trig)) {
              trig = `sojourn_us>${trig}`;
            }
            if (!VALID_TRIGGER_RE.test(trig)) {
              throw new Error(`invalid daemon trigger "${spec.trigger}"`);
            }
            args.push('--trigger', trig);
          }
          if (typeof spec.pre_window_sec === 'number' && spec.pre_window_sec > 0) {
            args.push('--pre-window', `${Math.floor(spec.pre_window_sec)}s`);
          }
          if (typeof spec.post_window_sec === 'number' && spec.post_window_sec > 0) {
            args.push('--post-window', `${Math.floor(spec.post_window_sec)}s`);
          }
        }

        if (typeof spec.mem_budget === 'string' && spec.mem_budget.trim()) {
          const b = spec.mem_budget.trim();
          if (!VALID_BUDGET_RE.test(b)) throw new Error(`invalid mem_budget "${b}"`);
          args.push('--mem-budget', b);
        }
        if (typeof spec.disk_budget === 'string' && spec.disk_budget.trim()) {
          const b = spec.disk_budget.trim();
          if (!VALID_BUDGET_RE.test(b)) throw new Error(`invalid disk_budget "${b}"`);
          args.push('--disk-budget', b);
        }

        return args;
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
      scopes: ['all', 'ingress', 'egress', 'socket'],
    });
  },
};
