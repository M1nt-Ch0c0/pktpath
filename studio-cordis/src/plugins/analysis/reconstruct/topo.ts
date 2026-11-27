// Pure TypeScript port of studio/pkg/reconstruct/topo.go (erasableSyntaxOnly).

import { LINK_TYPE_ETHERNET } from '../wire/consts.ts'
import { asBigInt, asInt, truthy } from '../wire/wire.ts'
import type { WireEvent } from '../wire/wire.ts'

export interface Site {
  site_idx: number
  adapter_id: string
  name: string
  symbol: string
  qdisc_kind?: string
  probe_type: string
  probe_version: string
  stage: number
  has_stage: boolean
  evidence_level: number
  plugin_id?: string
  group?: string
  source?: string
  target?: string
}

export interface TopoDevice {
  ifindex: bigint
  has_ifindex: boolean
  dev_gen: bigint
  name: string
  linktype: number
  has_linktype: boolean
}

export interface TopoQdisc {
  ifindex: bigint
  has_ifindex: boolean
  dev_gen: bigint
  queue_gen: bigint
  has_queue_gen: boolean
  kind: string
  handle: bigint
  has_handle: boolean
  parent: bigint
  has_parent: boolean
}

export interface ClassInfo {
  ifindex: bigint
  has_ifindex: boolean
  dev_gen: bigint
  kind: string
  handle: number // u32
  has_handle: boolean
  parent: number // u32
  has_parent: boolean
  leaf: number // u32
  prio: number
  has_prio: boolean
  quantum: number
  rate_bps: bigint
  ceil_bps: bigint
  bytes: bigint
  packets: bigint
  drops: bigint
  overlimits: bigint
}

export interface TopoEpoch {
  epoch_id: number
  ts_ns: bigint
  netns_inum: bigint
  has_netns: boolean
  devices: TopoDevice[]
  qdiscs: TopoQdisc[]
  classes: ClassInfo[]
}

export interface Calibration {
  boottime_ns: bigint
  realtime_ns: bigint
  err_ns: bigint
}

export interface QdiscInfo {
  kind: string
  handle: bigint
  parent: bigint
  queue_gen: bigint
}

export function jstr(v: unknown): string {
  if (v === null || v === undefined) return ''
  if (typeof v === 'string') return v
  return String(v)
}

export function parseTCHandleAny(v: unknown): number | undefined {
  if (v === null || v === undefined) return undefined
  if (typeof v === 'string') {
    const st = v.trim().toLowerCase()
    if (st === '') return undefined
    if (st === 'root') return 0xffffffff
    if (st === 'ffff:fff1' || st === 'ingress' || st === 'clsact') return 0xfffffff1
    const idx = st.indexOf(':')
    if (idx >= 0) {
      const majS = st.slice(0, idx)
      const minS = st.slice(idx + 1)
      let maj = 0
      let min = 0
      if (majS !== '') {
        if (!/^[0-9a-f]{1,4}$/.test(majS)) return undefined
        maj = parseInt(majS, 16)
      }
      if (minS !== '') {
        if (!/^[0-9a-f]{1,4}$/.test(minS)) return undefined
        min = parseInt(minS, 16)
      }
      return (((maj << 16) | min) >>> 0)
    }
  }
  const n = asInt(v)
  if (n !== undefined) return n >>> 0
  return undefined
}

function asU64(v: unknown): bigint {
  const b = asBigInt(v)
  if (b !== undefined && b > 0n) return b
  return 0n
}

export function parseSites(d: Record<string, unknown>): Map<number, Site> {
  const out = new Map<number, Site>()
  const arr = d['sites']
  if (!Array.isArray(arr)) return out
  for (const a of arr) {
    if (typeof a !== 'object' || a === null || Array.isArray(a)) continue
    const m = a as Record<string, unknown>
    const idx = asInt(m['site_idx'])
    if (idx === undefined) continue
    const stageVal = m['stage'] !== undefined && m['stage'] !== null ? asInt(m['stage']) : undefined
    const s: Site = {
      site_idx: idx,
      adapter_id: jstr(m['adapter_id']),
      name: jstr(m['name']),
      symbol: jstr(m['symbol']),
      qdisc_kind: jstr(m['qdisc_kind']).trim().toLowerCase() || undefined,
      probe_type: 'probe_type' in m ? jstr(m['probe_type']) : '',
      probe_version: jstr(m['probe_version']),
      stage: stageVal ?? 0,
      has_stage: stageVal !== undefined,
      evidence_level: asInt(m['evidence_level']) ?? 0,
    }
    const pluginId = jstr(m['plugin_id'])
    if (pluginId) s.plugin_id = pluginId
    const group = jstr(m['group'])
    if (group) s.group = group
    const source = jstr(m['source'])
    if (source) s.source = source
    const target = jstr(m['target'])
    if (target) s.target = target
    out.set(idx, s)
  }
  return out
}

export function mergeManifestSites(sites: Map<number, Site>, manifest: Record<string, unknown>): void {
  const arr = manifest['sites']
  if (!Array.isArray(arr)) return
  for (const a of arr) {
    if (typeof a !== 'object' || a === null || Array.isArray(a)) continue
    const m = a as Record<string, unknown>
    const idx = asInt(m['site_idx']) ?? asInt(m['site_id']) ?? asInt(m['id'])
    if (idx === undefined) continue
    const pluginId = jstr(m['plugin_id']) || undefined
    const group = jstr(m['group']) || undefined
    const source = jstr(m['source']) || (pluginId || idx >= 0x2000 ? 'external_bpf' : undefined)
    const target = jstr(m['target']) || undefined
    const existing = sites.get(idx)
    if (existing) {
      if (pluginId && !existing.plugin_id) existing.plugin_id = pluginId
      if (group && !existing.group) existing.group = group
      if (source && !existing.source) existing.source = source
      if (target && !existing.target) existing.target = target
      continue
    }
    const stageVal = m['stage'] !== undefined && m['stage'] !== null ? asInt(m['stage']) : undefined
    const name = jstr(m['name']) || jstr(m['probe_id']) || target || `site_${idx}`
    const symbol = jstr(m['symbol']) || target || name
    sites.set(idx, {
      site_idx: idx,
      adapter_id: jstr(m['adapter_id']) || (pluginId ? `plugin:${pluginId}` : 'external_bpf'),
      name,
      symbol,
      qdisc_kind: jstr(m['qdisc_kind']).trim().toLowerCase() || undefined,
      probe_type: 'probe_type' in m ? jstr(m['probe_type']) : (source === 'external_bpf' ? 'external_bpf' : ''),
      probe_version: jstr(m['probe_version']),
      stage: stageVal ?? 0,
      has_stage: stageVal !== undefined,
      evidence_level: asInt(m['evidence_level']) ?? 0,
      ...(pluginId ? { plugin_id: pluginId } : {}),
      ...(group ? { group } : {}),
      ...(source ? { source } : {}),
      ...(target ? { target } : {}),
    })
  }
}

export function parseTopology(d: Record<string, unknown>): TopoEpoch[] {
  const out: TopoEpoch[] = []
  const arr = d['topology_epochs']
  if (!Array.isArray(arr)) return out
  for (const a of arr) {
    if (typeof a !== 'object' || a === null || Array.isArray(a)) continue
    const m = a as Record<string, unknown>
    const netnsVal = m['netns_inum'] !== undefined && m['netns_inum'] !== null ? asBigInt(m['netns_inum']) : undefined
    const ep: TopoEpoch = {
      epoch_id: asInt(m['epoch_id']) ?? 0,
      ts_ns: asBigInt(m['ts_ns']) ?? 0n,
      netns_inum: netnsVal ?? 0n,
      has_netns: netnsVal !== undefined,
      devices: [],
      qdiscs: [],
      classes: [],
    }
    if (Array.isArray(m['devices'])) {
      for (const dv of m['devices']) {
        if (typeof dv !== 'object' || dv === null || Array.isArray(dv)) continue
        const dm = dv as Record<string, unknown>
        const ifidx = dm['ifindex'] !== undefined && dm['ifindex'] !== null ? asBigInt(dm['ifindex']) : undefined
        const lt = dm['linktype'] !== undefined && dm['linktype'] !== null ? asInt(dm['linktype']) : undefined
        ep.devices.push({
          ifindex: ifidx ?? 0n,
          has_ifindex: ifidx !== undefined,
          dev_gen: asBigInt(dm['dev_gen']) ?? 0n,
          name: jstr(dm['name']),
          linktype: lt ?? 0,
          has_linktype: lt !== undefined,
        })
      }
    }
    if (Array.isArray(m['qdiscs'])) {
      for (const qv of m['qdiscs']) {
        if (typeof qv !== 'object' || qv === null || Array.isArray(qv)) continue
        const qm = qv as Record<string, unknown>
        const ifidx = qm['ifindex'] !== undefined && qm['ifindex'] !== null ? asBigInt(qm['ifindex']) : undefined
        const qgen = qm['queue_gen'] !== undefined && qm['queue_gen'] !== null ? asBigInt(qm['queue_gen']) : undefined
        const h = parseTCHandleAny(qm['handle'])
        const p = parseTCHandleAny(qm['parent'])
        ep.qdiscs.push({
          ifindex: ifidx ?? 0n,
          has_ifindex: ifidx !== undefined,
          dev_gen: asBigInt(qm['dev_gen']) ?? 0n,
          queue_gen: qgen ?? 0n,
          has_queue_gen: qgen !== undefined,
          kind: jstr(qm['kind']),
          handle: h !== undefined ? BigInt(h) : 0n,
          has_handle: h !== undefined,
          parent: p !== undefined ? BigInt(p) : 0n,
          has_parent: p !== undefined,
        })
      }
    }
    if (Array.isArray(m['classes'])) {
      for (const cv of m['classes']) {
        if (typeof cv !== 'object' || cv === null || Array.isArray(cv)) continue
        const cm = cv as Record<string, unknown>
        const ifidx = cm['ifindex'] !== undefined && cm['ifindex'] !== null ? asBigInt(cm['ifindex']) : undefined
        const h = parseTCHandleAny(cm['handle']) ?? parseTCHandleAny(cm['classid'])
        const p = parseTCHandleAny(cm['parent'])
        const lf = parseTCHandleAny(cm['leaf'])
        const prio = cm['prio'] !== undefined && cm['prio'] !== null ? asInt(cm['prio']) : undefined
        ep.classes.push({
          ifindex: ifidx ?? 0n,
          has_ifindex: ifidx !== undefined,
          dev_gen: asBigInt(cm['dev_gen']) ?? 0n,
          kind: jstr(cm['kind']),
          handle: h ?? 0,
          has_handle: h !== undefined,
          parent: p ?? 0,
          has_parent: p !== undefined,
          leaf: lf ?? 0,
          prio: prio ?? 0,
          has_prio: prio !== undefined,
          quantum: asInt(cm['quantum']) ?? 0,
          rate_bps: asU64(cm['rate_bps']),
          ceil_bps: asU64(cm['ceil_bps']),
          bytes: asU64(cm['bytes']),
          packets: asU64(cm['packets']),
          drops: asU64(cm['drops']),
          overlimits: asU64(cm['overlimits']),
        })
      }
    }
    out.push(ep)
  }
  return out
}

export function parseCalibrations(m: Record<string, unknown>): Calibration[] {
  const out: Calibration[] = []
  const arr = m['calibrations']
  if (!Array.isArray(arr)) return out
  for (const a of arr) {
    if (typeof a !== 'object' || a === null || Array.isArray(a)) continue
    const cm = a as Record<string, unknown>
    const bt = asBigInt(cm['boottime_ns']) ?? 0n
    const rt = cm['realtime_ns'] !== undefined && cm['realtime_ns'] !== null ? (asBigInt(cm['realtime_ns']) ?? bt) : bt
    const err =
      'err_ns' in cm
        ? (asBigInt(cm['err_ns']) ?? 0n)
        : (asBigInt(cm['est_err_ns']) ?? 0n)
    out.push({ boottime_ns: bt, realtime_ns: rt, err_ns: err })
  }
  return out
}

export function isParentTCClass(parent: bigint): boolean {
  const p = Number(parent & 0xffffffffn) >>> 0
  return p !== 0 && ((p & 0xffff0000) >>> 0) !== 0xffff0000
}

export function formatTCHandle(h: bigint | undefined): string {
  if (h === undefined) return '0:'
  const v = Number(h & 0xffffffffn) >>> 0
  if (v === 0xffffffff) return 'root'
  if (v === 0xfffffff1) return 'ffff:fff1'
  if (v === 0) return '0:'
  const major = (v >>> 16) & 0xffff
  const minor = v & 0xffff
  if (minor === 0) return `${major.toString(16)}:`
  return `${major.toString(16)}:${minor.toString(16)}`
}

export function formatBitrate(bps: bigint): string {
  if (bps === 0n) return ''
  const trimFloat = (v: number, unit: string): string => {
    let s = v.toFixed(2)
    s = s.replace(/0+$/, '').replace(/\.$/, '')
    return s + unit
  }
  if (bps >= 1_000_000_000n) {
    if (bps % 1_000_000_000n === 0n) return `${bps / 1_000_000_000n}G`
    return trimFloat(Number(bps) / 1e9, 'G')
  }
  if (bps >= 1_000_000n) {
    if (bps % 1_000_000n === 0n) return `${bps / 1_000_000n}M`
    return trimFloat(Number(bps) / 1e6, 'M')
  }
  if (bps >= 1_000n) {
    if (bps % 1_000n === 0n) return `${bps / 1_000n}K`
    return trimFloat(Number(bps) / 1e3, 'K')
  }
  return `${bps.toString()}bps`
}

export function formatClassRate(rateBps: bigint, ceilBps: bigint): string {
  const r = formatBitrate(rateBps)
  const c = formatBitrate(ceilBps)
  if (r !== '' && c !== '' && rateBps !== ceilBps) return `${r}→${c}`
  if (r !== '') return r
  return c
}

export function formatClassSummary(ci: ClassInfo | undefined): string {
  if (!ci) return ''
  const parts: string[] = []
  const hStr = formatTCHandle(BigInt(ci.handle))
  if (ci.kind !== '') {
    parts.push(`class ${ci.kind} ${hStr}`)
  } else {
    parts.push(`class ${hStr}`)
  }
  if (ci.has_prio && ci.kind.toLowerCase() === 'htb') {
    parts.push(`prio ${ci.prio}`)
  } else if (ci.has_prio && ci.prio !== 0) {
    parts.push(`prio ${ci.prio}`)
  }
  const rate = formatClassRate(ci.rate_bps, ci.ceil_bps)
  if (rate !== '') parts.push(`rate ${rate}`)
  return parts.join(' · ')
}

export function manifestStr(m: Record<string, unknown>, key: string, def: string): string {
  if (!(key in m)) return def
  const v = m[key]
  if (v === null || v === undefined) return 'None'
  return jstr(v)
}

export function manifestStrOr(m: Record<string, unknown>, key: string, def: string): string {
  const v = m[key]
  if (!truthy(v)) return def
  return jstr(v)
}

export function evOpt(ev: WireEvent, name: string): bigint | undefined {
  return ev.get(name)
}

export function inferQdiscKindFromSite(site: Site | undefined): string {
  if (!site) return ''
  if (site.qdisc_kind) return site.qdisc_kind
  const sym = (site.symbol + ' ' + site.name).toLowerCase()
  if (sym.includes('pfifo_fast')) return 'pfifo_fast'
  if (sym.includes('pfifo_tail') || sym.includes('pfifo_head_drop') || sym.includes('ptail')) return 'pfifo_head_drop'
  if (sym.includes('bfifo')) return 'bfifo'
  if (sym.includes('pfifo') || sym.includes('qdisc_dequeue_head') || sym.includes('fifo')) return 'pfifo'
  if (sym.includes('sfq')) return 'sfq'
  if (sym.includes('fq_codel')) return 'fq_codel'
  if (sym.includes('htb')) return 'htb'
  return ''
}

export function resolveDevInfoFromTopo(
  topo: TopoEpoch[],
  ifindex: bigint,
  devGen?: bigint,
  netns?: bigint,
): TopoDevice | undefined {
  let best: TopoDevice | undefined
  for (const ep of topo) {
    if (netns !== undefined && netns !== 0n && ep.netns_inum !== 0n && ep.netns_inum !== netns) {
      continue
    }
    for (const d of ep.devices) {
      if (!d.has_ifindex || d.ifindex !== ifindex) continue
      if (devGen !== undefined && devGen !== 0n && d.dev_gen !== 0n && d.dev_gen !== devGen) continue
      best = d
    }
  }
  if (!best) {
    for (const ep of topo) {
      for (const d of ep.devices) {
        if (d.has_ifindex && d.ifindex === ifindex) return d
      }
    }
  }
  return best
}

export function resolveDevLinktypeFromTopo(topo: TopoEpoch[], ifindex: bigint, devGen?: bigint): number {
  const d = resolveDevInfoFromTopo(topo, ifindex, devGen)
  if (d && d.has_linktype) return d.linktype
  return LINK_TYPE_ETHERNET
}
