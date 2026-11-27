import type { BuiltinPlugin, ConfigField, ConfigGroup, ConfigPreset } from '../../kernel/types.ts';

export const VALID_CAPTURE_SCOPES = ['tc-egress', 'ip-tx', 'sock-tx', 'rx-sock', 'fwd'] as const;
export type CaptureScope = (typeof VALID_CAPTURE_SCOPES)[number];

export const VALID_PROBE_GROUPS = [
  'core_drop',
  'egress_tc',
  'sock_app',
  'ingress_rx',
  'l3_route',
  'netfilter_nat',
  'tcp_diag',
  'drop_stack',
  'tcp_probe',
] as const;
export type ProbeGroupId = (typeof VALID_PROBE_GROUPS)[number];

export const PROBE_PRESET_GROUPS = {
  egress: ['core_drop', 'egress_tc', 'sock_app'] as const,
  'drop-pwru': ['core_drop', 'drop_stack', 'ingress_rx', 'netfilter_nat'] as const,
  'full-path': ['core_drop', 'egress_tc', 'ingress_rx', 'l3_route', 'netfilter_nat', 'sock_app'] as const,
  'tcp-diag': ['core_drop', 'tcp_diag', 'egress_tc', 'sock_app'] as const,
} as const;
export type ProbePresetId = keyof typeof PROBE_PRESET_GROUPS;
export type ProbePresetLabel = ProbePresetId | 'custom';

const VALID_SCOPE_SET = new Set<string>(VALID_CAPTURE_SCOPES);
const VALID_PROBE_GROUP_SET = new Set<string>(VALID_PROBE_GROUPS);
const VALID_PRESET_LABELS = new Set<string>([...Object.keys(PROBE_PRESET_GROUPS), 'custom']);

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

function presetValues(groups: readonly ProbeGroupId[], presetId: ProbePresetId): Record<string, unknown> {
  const set = new Set<string>(groups);
  const out: Record<string, unknown> = { probe_preset: presetId };
  for (const g of VALID_PROBE_GROUPS) {
    out[`probe_${g}`] = set.has(g);
  }
  return out;
}

export const EBPF_PROBE_PRESETS: ConfigPreset[] = [
  {
    id: 'egress',
    label: '默认发包排查',
    description: '追踪发包队列、网卡驱动与进程归属，低开销日常使用。',
    badge: '推荐',
    values: presetValues(PROBE_PRESET_GROUPS.egress, 'egress'),
  },
  {
    id: 'drop-pwru',
    label: '丢包溯源（pwru）',
    description: '定位丢包内核调用栈，覆盖收包入口与防火墙/NAT 丢包点。',
    values: presetValues(PROBE_PRESET_GROUPS['drop-pwru'], 'drop-pwru'),
  },
  {
    id: 'full-path',
    label: '全路径诊断',
    description: '同时观测发包、收包、路由转发与防火墙/NAT 完整链路。',
    values: presetValues(PROBE_PRESET_GROUPS['full-path'], 'full-path'),
  },
  {
    id: 'tcp-diag',
    label: 'TCP 重传与状态',
    description: '低频采集 TCP 状态切换、重传与发包路径。',
    values: presetValues(PROBE_PRESET_GROUPS['tcp-diag'], 'tcp-diag'),
  },
];

export const EBPF_CONFIG_GROUPS: ConfigGroup[] = [
  {
    id: 'general',
    label: '基础采集参数',
    description: '默认采集时长、采样步长与包头抓取长度。',
    collapsible: false,
  },
  {
    id: 'probes_basic',
    label: '核心探针分组',
    description: '日常发包与丢包分析的基础观测点。',
    collapsible: false,
  },
  {
    id: 'probes_pwru',
    label: '扩展路径探针（pwru）',
    description: '按需开启收包、路由、防火墙/NAT、TCP 诊断与丢包调用栈。',
    collapsible: true,
    defaultCollapsed: false,
  },
  {
    id: 'probes_expert',
    label: '高开销专家探针',
    description: '高频逐包探针，仅建议在短时定向排查时开启。',
    collapsible: true,
    defaultCollapsed: true,
  },
];

const EBPF_CONFIG_FIELDS: ConfigField[] = [
  {
    key: 'default_duration_sec',
    label: '默认采集时长（秒）',
    type: 'number',
    default: 15,
    min: 1,
    max: 300,
    group: 'general',
  },
  {
    key: 'default_sample',
    label: '默认采样步长（1 表示全量）',
    type: 'number',
    default: 1,
    min: 1,
    max: 1000,
    group: 'general',
  },
  {
    key: 'default_hdr_bytes',
    label: '默认包头抓取字节数',
    type: 'number',
    default: 96,
    min: 0,
    max: 128,
    group: 'general',
  },
  {
    key: 'probe_preset',
    label: '探针预设',
    type: 'select',
    default: 'egress',
    description: '快速切换推荐探针组合；手动修改下方开关时自动切换为自定义。',
    group: 'probes_basic',
    options: [
      { value: 'egress', label: '默认发包排查' },
      { value: 'drop-pwru', label: '丢包溯源（pwru）' },
      { value: 'full-path', label: '全路径诊断' },
      { value: 'tcp-diag', label: 'TCP 重传与状态' },
      { value: 'custom', label: '自定义' },
    ],
  },
  {
    key: 'probe_core_drop',
    label: '丢包与生命周期',
    type: 'boolean',
    default: true,
    readOnly: true,
    description: '必选基座：捕获内核丢包与报文生命周期事件。',
    group: 'probes_basic',
  },
  {
    key: 'probe_egress_tc',
    label: '发包队列与驱动（TC/Qdisc）',
    type: 'boolean',
    default: true,
    description: '捕获发包队列入队、驱动发送与流量控制阶段。',
    group: 'probes_basic',
  },
  {
    key: 'probe_sock_app',
    label: '进程与 Socket 归属',
    type: 'boolean',
    default: true,
    description: '关联发送进程、应用 UID 与 Socket 路径。',
    group: 'probes_basic',
  },
  {
    key: 'probe_ingress_rx',
    label: '收包入口（Ingress）',
    type: 'boolean',
    default: false,
    badge: '高开销',
    description: '追踪网卡收包入口路径。',
    group: 'probes_pwru',
  },
  {
    key: 'probe_l3_route',
    label: '路由与隧道/转发',
    type: 'boolean',
    default: false,
    description: '追踪 IPv4/IPv6 路由接收、本地交付与转发。',
    group: 'probes_pwru',
  },
  {
    key: 'probe_netfilter_nat',
    label: '防火墙与 NAT',
    type: 'boolean',
    default: false,
    description: '追踪 Netfilter 规则拦截与连接跟踪转发。',
    group: 'probes_pwru',
  },
  {
    key: 'probe_tcp_diag',
    label: 'TCP 状态与重传',
    type: 'boolean',
    default: false,
    description: '低频记录 TCP 重传与连接状态迁移。',
    group: 'probes_pwru',
  },
  {
    key: 'probe_drop_stack',
    label: '丢包内核调用栈',
    type: 'boolean',
    default: false,
    badge: '高开销',
    description: '发生丢包时抓取内核调用栈，辅助定位丢包函数。',
    group: 'probes_pwru',
  },
  {
    key: 'probe_tcp_probe',
    label: 'TCP 逐包 ACK 探测',
    type: 'boolean',
    default: false,
    badge: '高噪·易丢样',
    description: '记录每个 TCP ACK 的窗口与 RTT，高频流量下容易产生丢样。',
    group: 'probes_expert',
  },
];

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
  probe_groups?: string[] | string;
  probe_preset?: string;
}

export interface NormalizedCaptureSpec {
  mode: 'oneshot' | 'daemon';
  dev: string;
  scope: CaptureScope;
  durationSec: number;
  enablePlugins: boolean;
  probePreset: ProbePresetLabel;
  requestedGroups: ProbeGroupId[];
  args: string[];
}

export interface EbpfCollectorService {
  readonly defaultDurationSec: number;
  readonly defaultSample: number;
  readonly defaultHdrBytes: number;
  readonly defaultProbePreset: ProbePresetLabel;
  readonly defaultProbeGroups: ProbeGroupId[];
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

function sameGroupSet(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false;
  const setA = new Set(a);
  return b.every((g) => setA.has(g));
}

export function inferProbePresetLabel(groups: readonly ProbeGroupId[]): ProbePresetLabel {
  for (const [presetId, presetGroups] of Object.entries(PROBE_PRESET_GROUPS) as Array<
    [ProbePresetId, readonly ProbeGroupId[]]
  >) {
    if (sameGroupSet(groups, presetGroups)) {
      return presetId;
    }
  }
  return 'custom';
}

export function normalizeProbeGroupsList(raw: string[] | string): ProbeGroupId[] {
  const tokens = Array.isArray(raw)
    ? raw.map((x) => String(x).trim()).filter(Boolean)
    : raw
        .split(',')
        .map((x) => x.trim())
        .filter(Boolean);
  if (tokens.length === 0) {
    throw new Error('probe_groups cannot be empty');
  }
  const seen = new Set<ProbeGroupId>();
  for (const tok of tokens) {
    if (!VALID_PROBE_GROUP_SET.has(tok)) {
      throw new Error(`invalid probe group "${tok}" (allowed: ${VALID_PROBE_GROUPS.join(', ')})`);
    }
    seen.add(tok as ProbeGroupId);
  }
  // core_drop is the mandatory base group.
  seen.add('core_drop');
  return VALID_PROBE_GROUPS.filter((g) => seen.has(g));
}

function resolveProbeGroupsFromConfig(cfg: Record<string, unknown>): {
  groups: ProbeGroupId[];
  preset: ProbePresetLabel;
} {
  const hasExplicitToggles = VALID_PROBE_GROUPS.some((g) => cfg[`probe_${g}`] !== undefined);
  let groups: ProbeGroupId[];

  if (hasExplicitToggles) {
    const enabled = new Set<ProbeGroupId>();
    for (const g of VALID_PROBE_GROUPS) {
      const val = cfg[`probe_${g}`];
      const defaultOn = g === 'core_drop' || g === 'egress_tc' || g === 'sock_app';
      const isOn = val === undefined ? defaultOn : parseBool(val);
      if (isOn) enabled.add(g);
    }
    // Always enforce core_drop mandatory base.
    enabled.add('core_drop');
    groups = VALID_PROBE_GROUPS.filter((g) => enabled.has(g));
  } else if (typeof cfg.probe_preset === 'string' && cfg.probe_preset.trim() in PROBE_PRESET_GROUPS) {
    const p = cfg.probe_preset.trim() as ProbePresetId;
    groups = [...PROBE_PRESET_GROUPS[p]];
  } else {
    groups = [...PROBE_PRESET_GROUPS.egress];
  }

  return {
    groups,
    preset: inferProbePresetLabel(groups),
  };
}

export const ebpfTcPlugin: BuiltinPlugin = {
  meta: {
    id: 'builtin.collector.ebpf-tc',
    name: 'eBPF TC / Socket 采集器',
    version: '1.1.0',
    description: '配置并构造原生 Android arm64 / Linux eBPF 采集参数、探针分组与推荐预设。',
    category: 'collector',
    icon: 'cpu',
    builtin: true,
    capabilities: ['collector.ebpf', 'collector.tc', 'collector.socket', 'collector.probe-groups'],
    provides: ['collector.ebpf'],
    usedBy: ['短时采集模式 (Oneshot)', '常驻录制模式 (Daemon)'],
    requires: [],
    tags: ['ebpf', 'tc', 'collector', 'probes'],
  },
  schema: {
    fields: EBPF_CONFIG_FIELDS,
    presets: EBPF_PROBE_PRESETS,
    groups: EBPF_CONFIG_GROUPS,
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
    const defaultProbes = resolveProbeGroupsFromConfig(cfg);

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

      // Resolve probe groups & preset label.
      // Per Wave 3 contract §2: Studio MUST only emit --probe-groups + --preset-label, NEVER --preset.
      let requestedGroups: ProbeGroupId[];
      let probePreset: ProbePresetLabel;
      if (spec.probe_groups !== undefined) {
        requestedGroups = normalizeProbeGroupsList(spec.probe_groups);
        const inferred = inferProbePresetLabel(requestedGroups);
        if (typeof spec.probe_preset === 'string' && spec.probe_preset.trim()) {
          const reqPreset = spec.probe_preset.trim();
          if (!VALID_PRESET_LABELS.has(reqPreset)) {
            throw new Error(`invalid probe_preset "${reqPreset}"`);
          }
          probePreset = reqPreset === inferred ? inferred : 'custom';
        } else {
          probePreset = inferred;
        }
      } else if (typeof spec.probe_preset === 'string' && spec.probe_preset.trim()) {
        const reqPreset = spec.probe_preset.trim();
        if (reqPreset === 'custom') {
          requestedGroups = [...defaultProbes.groups];
          probePreset = inferProbePresetLabel(requestedGroups);
        } else if (reqPreset in PROBE_PRESET_GROUPS) {
          const p = reqPreset as ProbePresetId;
          requestedGroups = [...PROBE_PRESET_GROUPS[p]];
          probePreset = p;
        } else {
          throw new Error(`invalid probe_preset "${reqPreset}"`);
        }
      } else {
        requestedGroups = [...defaultProbes.groups];
        probePreset = defaultProbes.preset;
      }

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

      args.push('--probe-groups', requestedGroups.join(','), '--preset-label', probePreset);

      const enablePlugins = spec.enable_plugins === undefined ? true : parseBool(spec.enable_plugins);

      return {
        mode,
        dev,
        scope,
        durationSec: finalDur,
        enablePlugins,
        probePreset,
        requestedGroups,
        args,
      };
    };

    const service: EbpfCollectorService = {
      defaultDurationSec,
      defaultSample,
      defaultHdrBytes,
      defaultProbePreset: defaultProbes.preset,
      defaultProbeGroups: defaultProbes.groups,
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
      default_probe_preset: defaultProbes.preset,
      default_probe_groups: defaultProbes.groups,
      probe_groups: [...VALID_PROBE_GROUPS],
      probe_presets: Object.keys(PROBE_PRESET_GROUPS),
      scopes: [...VALID_CAPTURE_SCOPES],
    });
  },
};
