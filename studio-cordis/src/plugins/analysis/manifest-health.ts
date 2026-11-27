// Wave 3 Slice 4: Manifest 4-state probe inventory, capabilities health banner,
// vmlinux BTF drop_reason_map resolution (with subsystem single-entry fallback),
// and external .bpf.o plugin hit attribution.
//
// Contract: /workspace/pktpath-community/WAVE3-CONTRACT-20261127.md

import type { Session, Site } from './reconstruct/model.ts'
import type { SessionOverview } from './reconstruct/views.ts'

export type ProbeStatus =
  | 'attached'
  | 'disabled_by_user'
  | 'unavailable_in_kernel'
  | 'attach_failed'

export type DropReasonSource = 'vmlinux_btf' | 'unavailable'

export type HealthSeverity = 'ok' | 'warn' | 'error'

export interface ProbeGroupDefinition {
  readonly id: string
  readonly label: string
  readonly readOnly?: boolean
  readonly badge?: string
}

export const WAVE3_PROBE_GROUPS: readonly ProbeGroupDefinition[] = [
  { id: 'core_drop', label: '核心丢包底座', readOnly: true, badge: '必选底座' },
  { id: 'egress_tc', label: '出向 TX / Qdisc', badge: '默认开启' },
  { id: 'sock_app', label: 'Socket / 进程归属' },
  { id: 'ingress_rx', label: '入向 RX / GRO' },
  { id: 'l3_route', label: 'L3 路由 / IP 转发' },
  { id: 'netfilter_nat', label: 'Netfilter / Conntrack' },
  { id: 'tcp_diag', label: 'TCP 重传 / 状态迁移' },
  { id: 'drop_stack', label: '丢包调用栈', badge: '高开销' },
  { id: 'tcp_probe', label: 'TCP 细粒度包事件', badge: '高频/高开销' },
] as const

export const WAVE3_PROBE_GROUP_MAP: ReadonlyMap<string, ProbeGroupDefinition> = new Map(
  WAVE3_PROBE_GROUPS.map((g) => [g.id, g]),
)

export interface ProbePresetDefinition {
  readonly id: string
  readonly label: string
  readonly enabled_groups: readonly string[]
}

export const WAVE3_PRESETS: readonly ProbePresetDefinition[] = [
  { id: 'egress', label: '出向排查（默认）', enabled_groups: ['core_drop', 'egress_tc'] },
  {
    id: 'drop-pwru',
    label: '全路径丢包（pwru 风格）',
    enabled_groups: ['core_drop', 'l3_route', 'netfilter_nat', 'drop_stack'],
  },
  {
    id: 'full-path',
    label: '双向全路径',
    enabled_groups: [
      'core_drop',
      'egress_tc',
      'sock_app',
      'ingress_rx',
      'l3_route',
      'netfilter_nat',
      'tcp_diag',
    ],
  },
  {
    id: 'tcp-diag',
    label: 'TCP 诊断',
    enabled_groups: ['core_drop', 'sock_app', 'tcp_diag', 'tcp_probe'],
  },
] as const

export const EXTERNAL_BPF_SITE_ID_MIN = 0x2000
export const EXTERNAL_BPF_SITE_ID_MAX = 0xfffe

const VALID_PROBE_STATUSES = new Set<ProbeStatus>([
  'attached',
  'disabled_by_user',
  'unavailable_in_kernel',
  'attach_failed',
])

const MAX_REASON_LEN = 2048

export interface ProbeInventoryItem {
  id: string
  group: string
  source: string
  plugin_id?: string
  bpf_sha256?: string
  target: string
  status: ProbeStatus
  reason?: string
}

export interface ManifestCapabilities {
  btf_available: boolean | null
  drop_reason_available: boolean | null
  drop_reason_source: DropReasonSource
  stack_symbolize_available: boolean | null
  notes: string[]
}

export interface NormalizedWave3Manifest {
  present: boolean
  probe_preset: string | null
  requested_groups: string[]
  effective_groups: string[]
  probe_inventory: ProbeInventoryItem[]
  capabilities: ManifestCapabilities
  drop_reason_map: Record<string, string>
}

export interface ResolvedDropReason {
  code: number
  subsystem: number
  name: string | null
  source: DropReasonSource
  verified: boolean
  subsystem_unmapped: boolean
  label: string
  note: string | null
}

export interface ProbeGroupStateSummary {
  group_id: string
  label: string
  status: ProbeStatus | 'partial' | 'unknown'
  display_status: string
  attached_count: number
  disabled_count: number
  unavailable_count: number
  failed_count: number
  hit_count: number
  reasons: string[]
}

export interface SampleLossSummary {
  missed_delta: number
  ringbuf_drops: number
  events_dropped: number
  admissions_rejected: number
  unobservable_missed_source: boolean
  has_loss: boolean
}

export interface ExternalBpfPluginAttribution {
  plugin_id: string
  bpf_sha256: string | null
  groups: string[]
  probes: ProbeInventoryItem[]
  attached_count: number
  failed_count: number
  unavailable_count: number
  disabled_count: number
  hit_count: number
  sample_count: number
  sample_ids: string[]
  status_summary: string
}

export interface HealthBanner {
  severity: HealthSeverity
  title: string
  summary: string
  zero_hit_verdict: string
  degraded_probes: ProbeInventoryItem[]
  disabled_groups: Array<{
    group_id: string
    label: string
    display_status: string
  }>
  capability_warnings: string[]
  sample_loss_warning: string | null
}

export interface DropReasonSummaryItem {
  code: number
  count: number
  resolved: ResolvedDropReason
}

export interface SessionHealthReport {
  present: boolean
  probe_preset: string | null
  requested_groups: string[]
  effective_groups: string[]
  banner: HealthBanner
  group_states: ProbeGroupStateSummary[]
  unobserved_groups: string[]
  probe_inventory: ProbeInventoryItem[]
  capabilities: ManifestCapabilities
  sample_loss: SampleLossSummary
  external_bpf_plugins: ExternalBpfPluginAttribution[]
  drop_reasons_summary: DropReasonSummaryItem[]
}

function asRecord(v: unknown): Record<string, unknown> | null {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return null
  return v as Record<string, unknown>
}

function asString(v: unknown): string {
  return typeof v === 'string' ? v.trim() : ''
}

function asOptionalBool(v: unknown): boolean | null {
  return typeof v === 'boolean' ? v : null
}

function asNonNegInt(v: unknown): number {
  if (typeof v === 'number' && Number.isFinite(v) && v >= 0) return Math.trunc(v)
  if (typeof v === 'bigint' && v >= 0n) return Number(v)
  if (typeof v === 'string' && /^\d+$/.test(v.trim())) return Number(v.trim())
  return 0
}

function asStringArray(v: unknown): string[] {
  if (!Array.isArray(v)) return []
  const out: string[] = []
  const seen = new Set<string>()
  for (const item of v) {
    const s = asString(item)
    if (s && !seen.has(s)) {
      seen.add(s)
      out.push(s)
    }
  }
  return out
}

function truncateReason(raw: string): string {
  const s = raw.trim()
  if (s.length <= MAX_REASON_LEN) return s
  const head = s.slice(0, 1200)
  const tail = s.slice(-600)
  return `${head}\n... [truncated ${s.length - 1800} chars] ...\n${tail}`
}

function groupLabel(groupId: string): string {
  return WAVE3_PROBE_GROUP_MAP.get(groupId)?.label ?? groupId
}

export function normalizeWave3Manifest(manifest: Record<string, unknown> | undefined | null): NormalizedWave3Manifest {
  const m = asRecord(manifest) ?? {}
  const hasWave3Field =
    'probe_inventory' in m ||
    'capabilities' in m ||
    'drop_reason_map' in m ||
    'probe_preset' in m ||
    'requested_groups' in m ||
    'effective_groups' in m

  const probe_preset = asString(m['probe_preset']) || null
  const requested_groups = asStringArray(m['requested_groups'])
  const effective_groups = asStringArray(m['effective_groups'])

  const probe_inventory: ProbeInventoryItem[] = []
  if (Array.isArray(m['probe_inventory'])) {
    for (const rawItem of m['probe_inventory']) {
      const rec = asRecord(rawItem)
      if (!rec) continue
      const id = asString(rec['id']) || asString(rec['target']) || `probe_${probe_inventory.length}`
      const group = asString(rec['group']) || 'unknown'
      const source = asString(rec['source']) || 'builtin'
      const target = asString(rec['target']) || id
      const rawStatus = asString(rec['status'])
      let status: ProbeStatus
      let reason = asString(rec['reason'])
      if (VALID_PROBE_STATUSES.has(rawStatus as ProbeStatus)) {
        status = rawStatus as ProbeStatus
      } else {
        status = 'attach_failed'
        reason = reason || `invalid probe status: ${rawStatus || '<empty>'}`
      }
      if ((status === 'unavailable_in_kernel' || status === 'attach_failed') && !reason) {
        reason = status === 'unavailable_in_kernel' ? 'kernel probe target unavailable' : 'probe attach failed'
      }
      const item: ProbeInventoryItem = {
        id,
        group,
        source,
        target,
        status,
      }
      const pluginId = asString(rec['plugin_id'])
      if (pluginId) item.plugin_id = pluginId
      const sha = asString(rec['bpf_sha256'])
      if (sha) item.bpf_sha256 = sha
      if (reason) item.reason = truncateReason(reason)
      probe_inventory.push(item)
    }
  }

  const capRec = asRecord(m['capabilities'])
  const rawSource = asString(capRec?.['drop_reason_source'])
  const drop_reason_source: DropReasonSource =
    rawSource === 'vmlinux_btf' ? 'vmlinux_btf' : 'unavailable'
  const capabilities: ManifestCapabilities = {
    btf_available: asOptionalBool(capRec?.['btf_available']),
    drop_reason_available: asOptionalBool(capRec?.['drop_reason_available']),
    drop_reason_source,
    stack_symbolize_available: asOptionalBool(capRec?.['stack_symbolize_available']),
    notes: asStringArray(capRec?.['notes']),
  }

  // Rule 5.1.4: drop_reason_map is valid ONLY when drop_reason_source === 'vmlinux_btf'.
  const drop_reason_map: Record<string, string> = {}
  if (drop_reason_source === 'vmlinux_btf') {
    const rawMap = asRecord(m['drop_reason_map'])
    if (rawMap) {
      for (const [k, v] of Object.entries(rawMap)) {
        const name = asString(v)
        if (/^\d+$/.test(k.trim()) && name) {
          drop_reason_map[k.trim()] = name
        }
      }
    }
  }

  return {
    present: hasWave3Field,
    probe_preset,
    requested_groups,
    effective_groups,
    probe_inventory,
    capabilities,
    drop_reason_map,
  }
}

export function parseDropReasonCode(reason: number | bigint | string | null | undefined): number | null {
  if (reason === null || reason === undefined) return null
  if (typeof reason === 'number') {
    if (!Number.isFinite(reason) || reason < 0) return null
    return reason >>> 0
  }
  if (typeof reason === 'bigint') {
    if (reason < 0n) return null
    return Number(reason & 0xffffffffn)
  }
  const s = reason.trim()
  if (!s) return null
  if (/^0x[0-9a-f]+$/i.test(s)) {
    return Number(BigInt(s) & 0xffffffffn)
  }
  if (/^\d+$/.test(s)) {
    return Number(BigInt(s) & 0xffffffffn)
  }
  return null
}

/**
 * Contract §5.1.4 & §5.1.5:
 * - When drop_reason_source === 'vmlinux_btf': exact lookup drop_reason_map[String(code)].
 *   If missing and (code >>> 16) !== 0: single-entry fallback showing raw value +
 *   "子系统枚举未在 vmlinux BTF 中" (NEVER truncate low 16 bits!).
 * - When drop_reason_source === 'unavailable': raw value + "未验证枚举".
 */
export function resolveDropReason(
  reason: number | bigint | string | null | undefined,
  manifest: NormalizedWave3Manifest,
): ResolvedDropReason | null {
  const code = parseDropReasonCode(reason)
  if (code === null) return null
  const subsystem = (code >>> 16) & 0xffff

  if (manifest.capabilities.drop_reason_source === 'vmlinux_btf') {
    const exact = manifest.drop_reason_map[String(code)]
    if (exact) {
      return {
        code,
        subsystem,
        name: exact,
        source: 'vmlinux_btf',
        verified: true,
        subsystem_unmapped: false,
        label: `${exact} (${code})`,
        note: null,
      }
    }
    if (subsystem !== 0) {
      return {
        code,
        subsystem,
        name: null,
        source: 'vmlinux_btf',
        verified: false,
        subsystem_unmapped: true,
        label: `${code}（子系统枚举未在 vmlinux BTF 中）`,
        note: '子系统枚举未在 vmlinux BTF 中',
      }
    }
    return {
      code,
      subsystem,
      name: null,
      source: 'vmlinux_btf',
      verified: false,
      subsystem_unmapped: false,
      label: `${code}（vmlinux BTF 未收录）`,
      note: 'vmlinux BTF 未收录该丢包码',
    }
  }

  return {
    code,
    subsystem,
    name: null,
    source: 'unavailable',
    verified: false,
    subsystem_unmapped: false,
    label: `${code}（未验证枚举）`,
    note: '未验证枚举',
  }
}

export function isExternalBpfSite(site: Site | undefined, siteIdx?: number): boolean {
  if (site) {
    if (site.source === 'external_bpf' || Boolean(site.plugin_id)) return true
    if (site.site_idx >= EXTERNAL_BPF_SITE_ID_MIN && site.site_idx <= EXTERNAL_BPF_SITE_ID_MAX) return true
  }
  if (siteIdx !== undefined && siteIdx >= EXTERNAL_BPF_SITE_ID_MIN && siteIdx <= EXTERNAL_BPF_SITE_ID_MAX) {
    return true
  }
  return false
}

function extractSampleLoss(manifest: Record<string, unknown>, overview?: SessionOverview): SampleLossSummary {
  const q = overview?.stats?.quality
  const missed_delta = asNonNegInt(q?.missed_delta ?? 0)
  const ringbuf_drops = asNonNegInt(manifest['ringbuf_drops'])
  const events_dropped = asNonNegInt(manifest['events_dropped'])
  const admissions = asRecord(manifest['admissions'])
  const admissions_rejected = asNonNegInt(admissions?.['rejected'])
  const unobservable_missed_source = Boolean(q?.unobservable_missed_source)
  const has_loss =
    missed_delta > 0 ||
    ringbuf_drops > 0 ||
    events_dropped > 0 ||
    admissions_rejected > 0 ||
    unobservable_missed_source
  return {
    missed_delta,
    ringbuf_drops,
    events_dropped,
    admissions_rejected,
    unobservable_missed_source,
    has_loss,
  }
}

function collectSiteAndDropStats(
  session: Session,
  normalized: NormalizedWave3Manifest,
): {
  groupHits: Map<string, number>
  externalHits: Map<string, { hitCount: number; sampleIds: Set<string>; groups: Set<string> }>
  dropReasonCounts: Map<number, number>
} {
  const groupHits = new Map<string, number>()
  const externalHits = new Map<string, { hitCount: number; sampleIds: Set<string>; groups: Set<string> }>()
  const dropReasonCounts = new Map<number, number>()

  // Build quick lookup from target/symbol/id -> ProbeInventoryItem for attribution
  const probeById = new Map<string, ProbeInventoryItem>()
  const probeByTarget = new Map<string, ProbeInventoryItem>()
  for (const p of normalized.probe_inventory) {
    probeById.set(p.id, p)
    if (p.target) probeByTarget.set(p.target, p)
  }

  for (const sample of session.samples.values()) {
    const sidStr = sample.sample_id.toString()
    for (const br of sample.branches) {
      if (br.drop_reason !== undefined) {
        const code = parseDropReasonCode(br.drop_reason)
        if (code !== null) {
          dropReasonCounts.set(code, (dropReasonCounts.get(code) ?? 0) + 1)
        }
      }
      for (const st of br.steps) {
        const site = session.resolveSite(st.site_dict_idx)
        const inv =
          (site?.name ? probeById.get(site.name) : undefined) ??
          (site?.symbol ? probeByTarget.get(site.symbol) : undefined) ??
          (site?.target ? probeByTarget.get(site.target) : undefined)
        const grp = site?.group || inv?.group
        if (grp) {
          groupHits.set(grp, (groupHits.get(grp) ?? 0) + 1)
        }
        const isExt = isExternalBpfSite(site, st.site_dict_idx) || inv?.source === 'external_bpf'
        if (isExt) {
          const pluginId = site?.plugin_id || inv?.plugin_id || `external_site_0x${st.site_dict_idx.toString(16)}`
          let bucket = externalHits.get(pluginId)
          if (!bucket) {
            bucket = { hitCount: 0, sampleIds: new Set<string>(), groups: new Set<string>() }
            externalHits.set(pluginId, bucket)
          }
          bucket.hitCount += 1
          if (bucket.sampleIds.size < 20) bucket.sampleIds.add(sidStr)
          if (grp) bucket.groups.add(grp)
        }
      }
    }
  }

  return { groupHits, externalHits, dropReasonCounts }
}

export function buildSessionHealth(session: Session, overview?: SessionOverview): SessionHealthReport {
  const normalized = normalizeWave3Manifest(session.manifest)
  const sample_loss = extractSampleLoss(session.manifest, overview)
  const { groupHits, externalHits, dropReasonCounts } = collectSiteAndDropStats(session, normalized)

  // Group inventory by group id
  const probesByGroup = new Map<string, ProbeInventoryItem[]>()
  for (const item of normalized.probe_inventory) {
    let arr = probesByGroup.get(item.group)
    if (!arr) {
      arr = []
      probesByGroup.set(item.group, arr)
    }
    arr.push(item)
  }

  const orderedGroupIds: string[] = []
  const seenGroups = new Set<string>()
  for (const g of WAVE3_PROBE_GROUPS) {
    if (
      probesByGroup.has(g.id) ||
      normalized.requested_groups.includes(g.id) ||
      normalized.effective_groups.includes(g.id)
    ) {
      orderedGroupIds.push(g.id)
      seenGroups.add(g.id)
    }
  }
  for (const gid of probesByGroup.keys()) {
    if (!seenGroups.has(gid)) {
      orderedGroupIds.push(gid)
      seenGroups.add(gid)
    }
  }

  const group_states: ProbeGroupStateSummary[] = []
  const unobserved_groups: string[] = []
  const disabled_groups: Array<{ group_id: string; label: string; display_status: string }> = []

  for (const gid of orderedGroupIds) {
    const items = probesByGroup.get(gid) ?? []
    let attached = 0
    let disabled = 0
    let unavailable = 0
    let failed = 0
    const reasons: string[] = []
    for (const it of items) {
      if (it.status === 'attached') attached++
      else if (it.status === 'disabled_by_user') disabled++
      else if (it.status === 'unavailable_in_kernel') {
        unavailable++
        if (it.reason) reasons.push(`${it.id}: ${it.reason}`)
      } else if (it.status === 'attach_failed') {
        failed++
        if (it.reason) reasons.push(`${it.id}: ${it.reason}`)
      }
    }
    const hits = groupHits.get(gid) ?? 0
    let status: ProbeGroupStateSummary['status'] = 'unknown'
    let display_status = '未知'

    if (items.length === 0) {
      if (normalized.effective_groups.includes(gid)) {
        status = 'attached'
        display_status =
          hits > 0
            ? `已观测（命中 ${hits} 次）`
            : sample_loss.has_loss
              ? '0 命中（存在丢样，不保证未发生）'
              : '已观测，窗口内 0 次触发'
      } else {
        status = 'disabled_by_user'
        display_status = '未开启（未观测）'
      }
    } else if (attached === items.length) {
      status = 'attached'
      display_status =
        hits > 0
          ? `已观测（命中 ${hits} 次）`
          : sample_loss.has_loss
            ? '0 命中（存在丢样，不保证未发生）'
            : '已观测，窗口内 0 次触发'
    } else if (disabled === items.length) {
      status = 'disabled_by_user'
      display_status = '未开启（未观测）'
    } else if (failed > 0 && attached === 0) {
      status = 'attach_failed'
      display_status = '挂载失败（未观测）'
    } else if (unavailable > 0 && attached === 0) {
      status = 'unavailable_in_kernel'
      display_status = '内核不支持（未观测）'
    } else {
      status = 'partial'
      display_status = `部分挂载（${attached}/${items.length}，存在降级）`
    }

    if (status === 'disabled_by_user') {
      disabled_groups.push({
        group_id: gid,
        label: groupLabel(gid),
        display_status: '未开启（未观测）',
      })
    }
    if (status !== 'attached') {
      unobserved_groups.push(gid)
    }

    group_states.push({
      group_id: gid,
      label: groupLabel(gid),
      status,
      display_status,
      attached_count: attached,
      disabled_count: disabled,
      unavailable_count: unavailable,
      failed_count: failed,
      hit_count: hits,
      reasons,
    })
  }

  // Degraded probes (Rule 5.1.2: attach_failed or unavailable_in_kernel)
  const degraded_probes = normalized.probe_inventory.filter(
    (p) => p.status === 'attach_failed' || p.status === 'unavailable_in_kernel',
  )
  const failedProbes = degraded_probes.filter((p) => p.status === 'attach_failed')
  const unavailableProbes = degraded_probes.filter((p) => p.status === 'unavailable_in_kernel')

  // Capability warnings (Rule 5.1.3)
  const capability_warnings: string[] = []
  if (normalized.present) {
    if (normalized.capabilities.btf_available === false) {
      capability_warnings.push('内核未提供 vmlinux BTF（CO-RE / 丢包原因枚举受限）')
    }
    if (
      normalized.capabilities.drop_reason_available === false ||
      normalized.capabilities.drop_reason_source !== 'vmlinux_btf'
    ) {
      capability_warnings.push('drop_reason 枚举不可用（未验证枚举，仅显示原始数值）')
    }
    if (normalized.capabilities.stack_symbolize_available === false) {
      capability_warnings.push('内核调用栈符号化不可用（drop_stack 仅保留原始地址或降级）')
    }
    for (const note of normalized.capabilities.notes) {
      if (!capability_warnings.includes(note)) capability_warnings.push(note)
    }
  }

  // Sample loss warning (Rule 5.1.3)
  let sample_loss_warning: string | null = null
  if (sample_loss.has_loss) {
    const parts: string[] = []
    if (sample_loss.missed_delta > 0) parts.push(`missed_delta=${sample_loss.missed_delta}`)
    if (sample_loss.ringbuf_drops > 0) parts.push(`ringbuf_drops=${sample_loss.ringbuf_drops}`)
    if (sample_loss.events_dropped > 0) parts.push(`events_dropped=${sample_loss.events_dropped}`)
    if (sample_loss.admissions_rejected > 0) parts.push(`admissions.rejected=${sample_loss.admissions_rejected}`)
    if (sample_loss.unobservable_missed_source) parts.push('存在不可观测丢样源')
    sample_loss_warning = `存在采样丢样（${parts.join('，')}），0 命中不保证事件未发生`
  }

  // Determine banner severity (strictly never silent green when degraded or lossy!)
  const coreDropState = group_states.find((g) => g.group_id === 'core_drop')
  const coreDropDegraded =
    coreDropState !== undefined &&
    (coreDropState.status === 'attach_failed' ||
      coreDropState.status === 'unavailable_in_kernel' ||
      coreDropState.status === 'partial')

  let severity: HealthSeverity = 'ok'
  if (failedProbes.length > 0 || coreDropDegraded) {
    severity = 'error'
  } else if (unavailableProbes.length > 0 || capability_warnings.length > 0 || sample_loss.has_loss) {
    severity = 'warn'
  }

  // Zero-hit verdict (Yan Red Line #3)
  let zero_hit_verdict: string
  if (coreDropDegraded) {
    zero_hit_verdict = '核心丢包底座未完整挂载（不保证未发生）'
  } else if (sample_loss.has_loss) {
    zero_hit_verdict = '0 命中（存在丢样，不保证未发生）'
  } else {
    zero_hit_verdict = '已观测，窗口内 0 次触发'
  }

  let title: string
  let summary: string
  if (severity === 'error') {
    title = `探针挂载存在失败（${failedProbes.length} 项失败）`
    const reasons = failedProbes
      .slice(0, 3)
      .map((p) => `${p.plugin_id ? `[${p.plugin_id}] ` : ''}${p.id}: ${p.reason ?? 'attach_failed'}`)
    summary = reasons.join('；') || '存在核心探针或外置插件探针挂载失败，当前观测结果不完整。'
  } else if (severity === 'warn') {
    const warnParts: string[] = []
    if (unavailableProbes.length > 0) warnParts.push(`${unavailableProbes.length} 项探针内核不支持`)
    if (capability_warnings.length > 0) warnParts.push(`${capability_warnings.length} 项内核能力降级`)
    if (sample_loss.has_loss) warnParts.push('存在采样丢样')
    title = `观测存在降级（${warnParts.join('、')}）`
    summary = [
      ...unavailableProbes.slice(0, 2).map((p) => `${p.id}: ${p.reason ?? 'unavailable_in_kernel'}`),
      ...capability_warnings.slice(0, 2),
      ...(sample_loss_warning ? [sample_loss_warning] : []),
    ].join('；')
  } else {
    const attachedCount = normalized.probe_inventory.filter((p) => p.status === 'attached').length
    const disabledNote =
      disabled_groups.length > 0
        ? `；${disabled_groups.length} 组未开启（未观测）`
        : ''
    title = normalized.present ? '探针与能力观测完整' : '会话未携带 Wave 3 探针清单（兼容旧格式）'
    summary = normalized.present
      ? `已挂载 ${attachedCount} 项探针，无降级且零丢样${disabledNote}。`
      : '旧版会话格式不含 probe_inventory/capabilities，按兼容模式展示。'
  }

  // External .bpf.o plugin attribution
  const extByPlugin = new Map<
    string,
    {
      bpf_sha256: string | null
      groups: Set<string>
      probes: ProbeInventoryItem[]
    }
  >()
  for (const p of normalized.probe_inventory) {
    if (p.source !== 'external_bpf' && !p.plugin_id) continue
    const pid = p.plugin_id || p.id
    let entry = extByPlugin.get(pid)
    if (!entry) {
      entry = { bpf_sha256: p.bpf_sha256 ?? null, groups: new Set<string>(), probes: [] }
      extByPlugin.set(pid, entry)
    }
    if (!entry.bpf_sha256 && p.bpf_sha256) entry.bpf_sha256 = p.bpf_sha256
    entry.groups.add(p.group)
    entry.probes.push(p)
  }
  for (const [pid, hit] of externalHits.entries()) {
    let entry = extByPlugin.get(pid)
    if (!entry) {
      entry = { bpf_sha256: null, groups: new Set<string>(), probes: [] }
      extByPlugin.set(pid, entry)
    }
    for (const g of hit.groups) entry.groups.add(g)
  }

  const external_bpf_plugins: ExternalBpfPluginAttribution[] = []
  for (const [plugin_id, entry] of [...extByPlugin.entries()].sort((a, b) =>
    a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0,
  )) {
    const hit = externalHits.get(plugin_id)
    const hit_count = hit?.hitCount ?? 0
    const sample_ids = hit ? [...hit.sampleIds] : []
    const attached_count = entry.probes.filter((p) => p.status === 'attached').length
    const failed_count = entry.probes.filter((p) => p.status === 'attach_failed').length
    const unavailable_count = entry.probes.filter((p) => p.status === 'unavailable_in_kernel').length
    const disabled_count = entry.probes.filter((p) => p.status === 'disabled_by_user').length

    let status_summary: string
    if (failed_count > 0) {
      status_summary = `挂载失败（${failed_count} 项失败）`
    } else if (unavailable_count > 0 && attached_count === 0) {
      status_summary = '内核不支持（未观测）'
    } else if (disabled_count > 0 && attached_count === 0) {
      status_summary = '未开启（未观测）'
    } else if (hit_count > 0) {
      status_summary = `已观测（命中 ${hit_count} 次，涉及 ${sample_ids.length} 条样本）`
    } else if (sample_loss.has_loss) {
      status_summary = '0 命中（存在丢样，不保证未发生）'
    } else {
      status_summary = '已观测，窗口内 0 次触发'
    }

    external_bpf_plugins.push({
      plugin_id,
      bpf_sha256: entry.bpf_sha256,
      groups: [...entry.groups].sort(),
      probes: entry.probes,
      attached_count,
      failed_count,
      unavailable_count,
      disabled_count,
      hit_count,
      sample_count: sample_ids.length,
      sample_ids,
      status_summary,
    })
  }

  // Drop reasons summary
  const drop_reasons_summary: DropReasonSummaryItem[] = []
  for (const [code, count] of [...dropReasonCounts.entries()].sort((a, b) => b[1] - a[1] || a[0] - b[0])) {
    const resolved = resolveDropReason(code, normalized)
    if (resolved) {
      drop_reasons_summary.push({ code, count, resolved })
    }
  }

  return {
    present: normalized.present,
    probe_preset: normalized.probe_preset,
    requested_groups: normalized.requested_groups,
    effective_groups: normalized.effective_groups,
    banner: {
      severity,
      title,
      summary,
      zero_hit_verdict,
      degraded_probes,
      disabled_groups,
      capability_warnings,
      sample_loss_warning,
    },
    group_states,
    unobserved_groups,
    probe_inventory: normalized.probe_inventory,
    capabilities: normalized.capabilities,
    sample_loss,
    external_bpf_plugins,
    drop_reasons_summary,
  }
}
