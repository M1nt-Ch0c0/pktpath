/**
 * Wave 3 Appendix A (A.1 & A.3) — TCP Time-Sequence / cwnd & RTT series builder
 * and optional TLS plaintext sidecar correlation reader (`tls-events.jsonl`).
 *
 * Hard rules (WAVE3-CONTRACT-20261127.md Appendix A):
 * 1. Missing `tcp_seq` / `snd_cwnd` / `srtt_us` MUST remain `null` (NEVER fabricate `0`).
 * 2. When `tcp_diag` and `tcp_probe` are both `disabled_by_user` (or degraded with no samples),
 *    surface an explicit Chinese notice so UI does not render a fake empty chart.
 * 3. `tls-events.jsonl` is strictly optional: when absent, return `available: false` silently
 *    with zero errors, zero warnings, and zero side effects on default captures.
 */

import fs from 'node:fs'
import path from 'node:path'
import { END_DROP, STAGE_DROP, STAGE_NAMES } from './wire/consts.ts'
import type { WireEvent } from './wire/wire.ts'
import type { SampleGraph, Session } from './reconstruct/model.ts'
import { normalizeWave3Manifest, resolveDropReason } from './manifest-health.ts'

export type TcpProbeAvailability =
  | 'attached'
  | 'disabled_by_user'
  | 'unavailable_in_kernel'
  | 'attach_failed'
  | 'legacy_unknown'

export interface FlowFiveTuple {
  proto: string
  src_ip: string
  dst_ip: string
  src_port: number | null
  dst_port: number | null
}

export interface TcpTimeSequencePoint {
  ts_ns: string
  rel_ms: number
  sample_id: string
  seq: number | null
  rel_seq: number | null
  payload_len: number | null
  event_kind: 'normal' | 'retransmit' | 'drop'
  site_name: string
  stage: string
  drop_reason: number | null
  drop_reason_label: string | null
}

export interface TcpCwndRttPoint {
  ts_ns: string
  rel_ms: number
  sample_id: string
  snd_cwnd: number | null
  srtt_us: number | null
  srtt_ms: number | null
  site_name: string
}

export interface FlowTcpSeriesStats {
  total_points: number
  seq_points: number
  retransmit_count: number
  drop_count: number
  cwnd_points: number
  rtt_points: number
  base_seq: number | null
  min_cwnd: number | null
  max_cwnd: number | null
  min_srtt_us: number | null
  max_srtt_us: number | null
}

export interface FlowTcpSeriesResult {
  flow_key: string | null
  five_tuple: FlowFiveTuple | null
  tcp_probes_enabled: boolean
  tcp_probe_status: TcpProbeAvailability
  notice: string | null
  sample_ids: string[]
  time_sequence: TcpTimeSequencePoint[]
  cwnd_rtt: TcpCwndRttPoint[]
  stats: FlowTcpSeriesStats
}

export interface TlsConnHint {
  fd: number | null
  src_ip: string | null
  dst_ip: string | null
  src_port: number | null
  dst_port: number | null
}

export interface TlsSidecarEvent {
  schema_version: number
  ts_ns: string
  pid: number | null
  tid: number | null
  uid: number | null
  comm: string
  direction: 'write' | 'read' | 'unknown'
  library: 'boringssl' | 'openssl' | 'conscrypt' | 'unknown'
  conn_hint: TlsConnHint | null
  plaintext_len: number
  plaintext_preview: string
  truncated: boolean
}

export type TlsMatchConfidence =
  | 'five_tuple_and_pid'
  | 'five_tuple'
  | 'pid_time_window'
  | 'unmatched'

export interface CorrelatedTlsEvent extends TlsSidecarEvent {
  match_confidence: TlsMatchConfidence
  matched_flow_keys: string[]
  matched_sample_ids: string[]
  delta_ms: number | null
}

export interface TlsCorrelationResult {
  available: boolean
  total_events: number
  matched_events: number
  parse_errors: number
  window_ms: number
  events: CorrelatedTlsEvent[]
}

export interface TlsSidecarSummary {
  available: boolean
  total_events: number
  matched_events: number
  parse_errors: number
}

function numOrNull(v: unknown): number | null {
  if (typeof v === 'number' && Number.isFinite(v)) return v
  if (typeof v === 'bigint') return Number(v)
  return null
}

function strOrNull(v: unknown): string | null {
  if (typeof v === 'string' && v.trim() !== '') return v.trim()
  return null
}

function extractSampleTuple(sg: SampleGraph): FlowFiveTuple | null {
  let summ: WireEvent | undefined
  for (const br of sg.branches) {
    if (br.summaries.length > 0) {
      summ = br.summaries[0]
      break
    }
  }
  if (!summ) return null
  const sip = summ.str('src_ip') ?? ''
  const dip = summ.str('dst_ip') ?? ''
  if (!sip && !dip) return null
  const l4 = summ.get('l4_proto')
  const proto = l4 === 6n ? 'TCP' : l4 === 17n ? 'UDP' : l4 !== undefined ? `PROTO_${l4}` : 'UNKNOWN'
  const sp = summ.get('src_port')
  const dp = summ.get('dst_port')
  return {
    proto,
    src_ip: sip,
    dst_ip: dip,
    src_port: sp !== undefined ? Number(sp) : null,
    dst_port: dp !== undefined ? Number(dp) : null,
  }
}

export function formatFlowKey(t: FlowFiveTuple | null): string | null {
  if (!t || (!t.src_ip && !t.dst_ip)) return null
  const src = t.src_port !== null ? `${t.src_ip}:${t.src_port}` : t.src_ip
  const dst = t.dst_port !== null ? `${t.dst_ip}:${t.dst_port}` : t.dst_ip
  return `${t.proto} ${src} -> ${dst}`
}

function tuplesMatch(a: FlowFiveTuple, b: FlowFiveTuple, bidirectional = true): boolean {
  if (a.src_ip === b.src_ip && a.dst_ip === b.dst_ip && a.src_port === b.src_port && a.dst_port === b.dst_port) {
    return true
  }
  if (
    bidirectional &&
    a.src_ip === b.dst_ip &&
    a.dst_ip === b.src_ip &&
    a.src_port === b.dst_port &&
    a.dst_port === b.src_port
  ) {
    return true
  }
  return false
}

function detectTcpProbeStatus(session: Session): { enabled: boolean; status: TcpProbeAvailability; notice: string | null } {
  const norm = normalizeWave3Manifest(session.manifest)
  if (!norm.present) {
    return { enabled: true, status: 'legacy_unknown', notice: null }
  }
  const tcpProbes = norm.probe_inventory.filter(
    (p) => p.group === 'tcp_diag' || p.group === 'tcp_probe',
  )
  const hasRequestedGroup =
    norm.requested_groups.includes('tcp_diag') ||
    norm.requested_groups.includes('tcp_probe') ||
    norm.effective_groups.includes('tcp_diag') ||
    norm.effective_groups.includes('tcp_probe')

  if (tcpProbes.length === 0) {
    if (hasRequestedGroup) {
      return { enabled: true, status: 'attached', notice: null }
    }
    return {
      enabled: false,
      status: 'disabled_by_user',
      notice: '未开启 TCP 详细探针，请在插件设置中开启「TCP 详细诊断」后重新采集。',
    }
  }
  if (tcpProbes.some((p) => p.status === 'attached')) {
    return { enabled: true, status: 'attached', notice: null }
  }
  if (tcpProbes.some((p) => p.status === 'attach_failed')) {
    return {
      enabled: false,
      status: 'attach_failed',
      notice: 'TCP 详细探针未能生效，无法展示拥塞窗口与延迟曲线（可在技术详情查看失败原因）。',
    }
  }
  if (tcpProbes.some((p) => p.status === 'unavailable_in_kernel')) {
    return {
      enabled: false,
      status: 'unavailable_in_kernel',
      notice: '当前设备内核不支持 TCP 详细探针，无法展示拥塞窗口与延迟曲线。',
    }
  }
  return {
    enabled: false,
    status: 'disabled_by_user',
    notice: '未开启 TCP 详细探针，请在插件设置中开启「TCP 详细诊断」后重新采集。',
  }
}

function isRetransmitSite(siteName: string, siteSymbol: string): boolean {
  const lower = `${siteName} ${siteSymbol}`.toLowerCase()
  return lower.includes('retransmit') || lower.includes('retrans')
}

export function buildFlowTcpSeries(
  session: Session,
  opts?: { flow_key?: string; sample_id?: string | bigint },
): FlowTcpSeriesResult {
  const normalizedManifest = normalizeWave3Manifest(session.manifest)
  const probeState = detectTcpProbeStatus(session)

  let targetTuple: FlowFiveTuple | null = null
  let targetFlowKey: string | null = opts?.flow_key?.trim() || null
  let explicitSampleId: bigint | null = null

  if (opts?.sample_id !== undefined && opts.sample_id !== '') {
    try {
      explicitSampleId = typeof opts.sample_id === 'bigint' ? opts.sample_id : BigInt(opts.sample_id)
    } catch {
      explicitSampleId = null
    }
  }

  if (explicitSampleId !== null) {
    const sg = session.samples.get(explicitSampleId)
    if (sg) {
      targetTuple = extractSampleTuple(sg)
      if (!targetFlowKey) targetFlowKey = formatFlowKey(targetTuple)
    }
  }

  // Select matching samples belonging to this flow (or the single sample if tuple missing)
  const matchedSamples: SampleGraph[] = []
  for (const sg of session.samples.values()) {
    const tuple = extractSampleTuple(sg)
    const fk = formatFlowKey(tuple)
    if (targetTuple && tuple) {
      if (tuplesMatch(targetTuple, tuple, false)) {
        matchedSamples.push(sg)
      }
    } else if (targetFlowKey && fk) {
      if (fk === targetFlowKey) {
        matchedSamples.push(sg)
        if (!targetTuple) targetTuple = tuple
      }
    } else if (explicitSampleId !== null && sg.sample_id === explicitSampleId) {
      matchedSamples.push(sg)
    }
  }

  // Fallback: if neither flow_key nor sample_id was provided, pick all TCP samples
  if (!targetFlowKey && explicitSampleId === null && matchedSamples.length === 0) {
    for (const sg of session.samples.values()) {
      const tuple = extractSampleTuple(sg)
      if (tuple?.proto === 'TCP') {
        matchedSamples.push(sg)
        if (!targetTuple) {
          targetTuple = tuple
          targetFlowKey = formatFlowKey(tuple)
        }
      }
    }
  }

  matchedSamples.sort((a, b) =>
    a.first_ts_ns < b.first_ts_ns ? -1 : a.first_ts_ns > b.first_ts_ns ? 1 : a.sample_id < b.sample_id ? -1 : 1,
  )

  interface RawStepRow {
    ts_ns: bigint
    seq_order: bigint
    sample_id: string
    tcp_seq: number | null
    snd_cwnd: number | null
    srtt_us: number | null
    payload_len: number | null
    site_name: string
    site_symbol: string
    stage_code: number
    stage_name: string
    is_drop: boolean
    drop_reason: number | null
    drop_reason_label: string | null
  }

  const rawRows: RawStepRow[] = []
  const sampleIds: string[] = []

  for (const sg of matchedSamples) {
    const sidStr = sg.sample_id.toString()
    sampleIds.push(sidStr)

    // Summary-level tcp_seq & pkt_len fallback (never fabricated as 0)
    let summSeq: number | null = null
    let summPayloadLen: number | null = null
    for (const br of sg.branches) {
      for (const sm of br.summaries) {
        const sSeq = sm.get('tcp_seq')
        if (sSeq !== undefined && summSeq === null) {
          summSeq = Number(sSeq & 0xffffffffn) >>> 0
        }
        const sEnd = sm.get('tcp_seq_end')
        if (sSeq !== undefined && sEnd !== undefined && summPayloadLen === null) {
          summPayloadLen = Number((sEnd - sSeq) & 0xffffffffn) >>> 0
        } else {
          const pl = sm.get('pkt_len')
          if (pl !== undefined && summPayloadLen === null) {
            summPayloadLen = Number(pl)
          }
        }
      }
    }

    for (const br of sg.branches) {
      const brDropCode = br.drop_reason !== undefined ? Number(br.drop_reason & 0xffffffffn) >>> 0 : null
      const brDropResolved =
        brDropCode !== null ? resolveDropReason(brDropCode, normalizedManifest) : null

      for (const st of br.steps) {
        const site = session.resolveSite(st.site_dict_idx)
        const siteName = site?.name || `site_${st.site_dict_idx}`
        const siteSymbol = site?.symbol || site?.target || ''
        const stageCode = Number(st.u('stage'))
        const isDropStep = stageCode === STAGE_DROP || (br.end_reason === END_DROP && st === br.steps[br.steps.length - 1])

        // Strict A.1 missing semantics: omitted TLV => null, NEVER 0
        const stepSeqRaw = st.get('tcp_seq')
        const stepCwndRaw = st.get('snd_cwnd')
        const stepSrttRaw = st.get('srtt_us')

        const tcp_seq =
          stepSeqRaw !== undefined
            ? Number(stepSeqRaw & 0xffffffffn) >>> 0
            : summSeq
        const snd_cwnd =
          stepCwndRaw !== undefined ? Number(stepCwndRaw & 0xffffffffn) >>> 0 : null
        const srtt_us =
          stepSrttRaw !== undefined ? Number(stepSrttRaw & 0xffffffffn) >>> 0 : null

        const hasAnyMetric =
          tcp_seq !== null ||
          snd_cwnd !== null ||
          srtt_us !== null ||
          isDropStep ||
          isRetransmitSite(siteName, siteSymbol)

        if (!hasAnyMetric) continue

        rawRows.push({
          ts_ns: st.ts_ns,
          seq_order: st.seq,
          sample_id: sidStr,
          tcp_seq,
          snd_cwnd,
          srtt_us,
          payload_len: summPayloadLen,
          site_name: siteName,
          site_symbol: siteSymbol,
          stage_code: stageCode,
          stage_name: STAGE_NAMES[stageCode] ?? `STAGE_${stageCode}`,
          is_drop: isDropStep,
          drop_reason: isDropStep ? brDropCode : null,
          drop_reason_label: isDropStep ? (brDropResolved?.label ?? null) : null,
        })
      }
    }
  }

  rawRows.sort((a, b) =>
    a.ts_ns < b.ts_ns ? -1 : a.ts_ns > b.ts_ns ? 1 : a.seq_order < b.seq_order ? -1 : 1,
  )

  const baseTs = rawRows.length > 0 ? rawRows[0]!.ts_ns : 0n
  let baseSeq: number | null = null
  let maxSeenSeq: number | null = null

  const time_sequence: TcpTimeSequencePoint[] = []
  const cwnd_rtt: TcpCwndRttPoint[] = []

  let seqPoints = 0
  let retransmitCount = 0
  let dropCount = 0
  let cwndPoints = 0
  let rttPoints = 0
  let minCwnd: number | null = null
  let maxCwnd: number | null = null
  let minSrttUs: number | null = null
  let maxSrttUs: number | null = null

  for (const r of rawRows) {
    const rel_ms = Number(r.ts_ns - baseTs) / 1_000_000

    let event_kind: 'normal' | 'retransmit' | 'drop' = 'normal'
    if (r.is_drop) {
      event_kind = 'drop'
      dropCount += 1
    } else if (isRetransmitSite(r.site_name, r.site_symbol)) {
      event_kind = 'retransmit'
      retransmitCount += 1
    } else if (r.tcp_seq !== null && maxSeenSeq !== null) {
      // Signed 32-bit modular comparison for TCP sequence regression
      const diff = (r.tcp_seq - maxSeenSeq) | 0
      if (diff < 0) {
        event_kind = 'retransmit'
        retransmitCount += 1
      }
    }

    if (r.tcp_seq !== null) {
      seqPoints += 1
      if (baseSeq === null) baseSeq = r.tcp_seq
      if (maxSeenSeq === null || (((r.tcp_seq - maxSeenSeq) | 0) > 0)) {
        maxSeenSeq = r.tcp_seq
      }
    }

    const rel_seq =
      r.tcp_seq !== null && baseSeq !== null ? ((r.tcp_seq - baseSeq) >>> 0) : null

    if (r.tcp_seq !== null || event_kind === 'drop' || event_kind === 'retransmit') {
      time_sequence.push({
        ts_ns: r.ts_ns.toString(),
        rel_ms: Math.round(rel_ms * 1000) / 1000,
        sample_id: r.sample_id,
        seq: r.tcp_seq,
        rel_seq,
        payload_len: r.payload_len,
        event_kind,
        site_name: r.site_name,
        stage: r.stage_name,
        drop_reason: r.drop_reason,
        drop_reason_label: r.drop_reason_label,
      })
    }

    if (r.snd_cwnd !== null || r.srtt_us !== null) {
      if (r.snd_cwnd !== null) {
        cwndPoints += 1
        minCwnd = minCwnd === null ? r.snd_cwnd : Math.min(minCwnd, r.snd_cwnd)
        maxCwnd = maxCwnd === null ? r.snd_cwnd : Math.max(maxCwnd, r.snd_cwnd)
      }
      if (r.srtt_us !== null) {
        rttPoints += 1
        minSrttUs = minSrttUs === null ? r.srtt_us : Math.min(minSrttUs, r.srtt_us)
        maxSrttUs = maxSrttUs === null ? r.srtt_us : Math.max(maxSrttUs, r.srtt_us)
      }
      cwnd_rtt.push({
        ts_ns: r.ts_ns.toString(),
        rel_ms: Math.round(rel_ms * 1000) / 1000,
        sample_id: r.sample_id,
        snd_cwnd: r.snd_cwnd,
        srtt_us: r.srtt_us,
        srtt_ms: r.srtt_us !== null ? Math.round((r.srtt_us / 1000) * 1000) / 1000 : null,
        site_name: r.site_name,
      })
    }
  }

  // If probes were disabled/degraded and no real cwnd/rtt/seq points exist, preserve explicit notice
  let notice = probeState.notice
  if (probeState.enabled && time_sequence.length === 0 && cwnd_rtt.length === 0) {
    notice = '当前流的时间窗口内未记录到 TCP 序号或拥塞窗口/延迟数据。'
  }

  return {
    flow_key: targetFlowKey,
    five_tuple: targetTuple,
    tcp_probes_enabled: probeState.enabled,
    tcp_probe_status: probeState.status,
    notice,
    sample_ids: sampleIds,
    time_sequence,
    cwnd_rtt,
    stats: {
      total_points: rawRows.length,
      seq_points: seqPoints,
      retransmit_count: retransmitCount,
      drop_count: dropCount,
      cwnd_points: cwndPoints,
      rtt_points: rttPoints,
      base_seq: baseSeq,
      min_cwnd: minCwnd,
      max_cwnd: maxCwnd,
      min_srtt_us: minSrttUs,
      max_srtt_us: maxSrttUs,
    },
  }
}

/* ============================ Optional TLS sidecar ============================ */

const TLS_SIDECAR_FILENAME = 'tls-events.jsonl'
const DEFAULT_TLS_WINDOW_MS = 2_000

function parseTsNsString(raw: unknown): string | null {
  if (typeof raw === 'string' && /^\d+$/.test(raw.trim())) return raw.trim()
  if (typeof raw === 'number' && Number.isFinite(raw) && raw >= 0) return Math.trunc(raw).toString()
  if (typeof raw === 'bigint' && raw >= 0n) return raw.toString()
  return null
}

function parseRawTsFromJsonLine(line: string): string | null {
  // Extract raw integer literal for ts_ns before JSON.parse truncates > 2^53-1
  const m = /"ts_ns"\s*:\s*"?(\d+)"?/.exec(line)
  return m ? m[1]! : null
}

export function readTlsEventsSidecar(sessionDir: string): {
  available: boolean
  events: TlsSidecarEvent[]
  parse_errors: number
} {
  const filePath = path.join(sessionDir, TLS_SIDECAR_FILENAME)
  if (!fs.existsSync(filePath)) {
    return { available: false, events: [], parse_errors: 0 }
  }
  let stat: fs.Stats
  try {
    stat = fs.statSync(filePath)
    if (!stat.isFile()) return { available: false, events: [], parse_errors: 0 }
  } catch {
    return { available: false, events: [], parse_errors: 0 }
  }

  const rawText = fs.readFileSync(filePath, 'utf8')
  const events: TlsSidecarEvent[] = []
  let parse_errors = 0

  for (const rawLine of rawText.split(/\r?\n/)) {
    const line = rawLine.trim()
    if (!line) continue
    let obj: Record<string, unknown>
    try {
      const parsed = JSON.parse(line)
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        parse_errors += 1
        continue
      }
      obj = parsed as Record<string, unknown>
    } catch {
      parse_errors += 1
      continue
    }

    const tsStr = parseRawTsFromJsonLine(line) ?? parseTsNsString(obj['ts_ns'])
    if (!tsStr) {
      parse_errors += 1
      continue
    }

    const dirRaw = typeof obj['direction'] === 'string' ? obj['direction'].trim() : ''
    const direction: 'write' | 'read' | 'unknown' =
      dirRaw === 'write' || dirRaw === 'read' ? dirRaw : 'unknown'

    const libRaw = typeof obj['library'] === 'string' ? obj['library'].trim() : ''
    const library: 'boringssl' | 'openssl' | 'conscrypt' | 'unknown' =
      libRaw === 'boringssl' || libRaw === 'openssl' || libRaw === 'conscrypt'
        ? libRaw
        : 'unknown'

    let conn_hint: TlsConnHint | null = null
    if (obj['conn_hint'] && typeof obj['conn_hint'] === 'object' && !Array.isArray(obj['conn_hint'])) {
      const ch = obj['conn_hint'] as Record<string, unknown>
      conn_hint = {
        fd: numOrNull(ch['fd']),
        src_ip: strOrNull(ch['src_ip']),
        dst_ip: strOrNull(ch['dst_ip']),
        src_port: numOrNull(ch['src_port']),
        dst_port: numOrNull(ch['dst_port']),
      }
    }

    events.push({
      schema_version: typeof obj['schema_version'] === 'number' ? obj['schema_version'] : 1,
      ts_ns: tsStr,
      pid: numOrNull(obj['pid']),
      tid: numOrNull(obj['tid']),
      uid: numOrNull(obj['uid']),
      comm: typeof obj['comm'] === 'string' ? obj['comm'] : '',
      direction,
      library,
      conn_hint,
      plaintext_len: typeof obj['plaintext_len'] === 'number' && Number.isFinite(obj['plaintext_len']) ? obj['plaintext_len'] : 0,
      plaintext_preview: typeof obj['plaintext_preview'] === 'string' ? obj['plaintext_preview'] : '',
      truncated: Boolean(obj['truncated']),
    })
  }

  return { available: true, events, parse_errors }
}

function connHintMatchesTuple(hint: TlsConnHint | null, tuple: FlowFiveTuple | null): boolean {
  if (!hint || !tuple) return false
  if (!hint.src_ip || !hint.dst_ip || hint.src_port === null || hint.dst_port === null) return false
  if (!tuple.src_ip || !tuple.dst_ip || tuple.src_port === null || tuple.dst_port === null) return false
  const forward =
    hint.src_ip === tuple.src_ip &&
    hint.dst_ip === tuple.dst_ip &&
    hint.src_port === tuple.src_port &&
    hint.dst_port === tuple.dst_port
  const reverse =
    hint.src_ip === tuple.dst_ip &&
    hint.dst_ip === tuple.src_ip &&
    hint.src_port === tuple.dst_port &&
    hint.dst_port === tuple.src_port
  return forward || reverse
}

export function correlateTlsEvents(
  session: Session,
  sessionDir: string,
  opts?: { flow_key?: string; sample_id?: string | bigint; window_ms?: number },
): TlsCorrelationResult {
  const window_ms =
    opts?.window_ms !== undefined && Number.isFinite(opts.window_ms) && opts.window_ms > 0
      ? opts.window_ms
      : DEFAULT_TLS_WINDOW_MS
  const windowNs = BigInt(Math.round(window_ms * 1_000_000))

  const sidecar = readTlsEventsSidecar(sessionDir)
  if (!sidecar.available) {
    return {
      available: false,
      total_events: 0,
      matched_events: 0,
      parse_errors: 0,
      window_ms,
      events: [],
    }
  }

  // Pre-index session samples for fast matching
  interface IndexedSample {
    sample_id: string
    flow_key: string | null
    tuple: FlowFiveTuple | null
    pid: number | null
    uid: number | null
    first_ts_ns: bigint
    last_ts_ns: bigint
  }
  const indexed: IndexedSample[] = []
  for (const sg of session.samples.values()) {
    const tuple = extractSampleTuple(sg)
    indexed.push({
      sample_id: sg.sample_id.toString(),
      flow_key: formatFlowKey(tuple),
      tuple,
      pid: sg.attr.tgid !== undefined ? Number(sg.attr.tgid) : null,
      uid: sg.attr.uid !== undefined ? Number(sg.attr.uid) : null,
      first_ts_ns: sg.first_ts_ns,
      last_ts_ns: sg.last_ts_ns,
    })
  }

  const filterSampleId =
    opts?.sample_id !== undefined && opts.sample_id !== '' ? String(opts.sample_id) : null
  let filterFlowKey = opts?.flow_key?.trim() || null
  if (!filterFlowKey && filterSampleId) {
    const hit = indexed.find((s) => s.sample_id === filterSampleId)
    if (hit?.flow_key) filterFlowKey = hit.flow_key
  }

  const correlated: CorrelatedTlsEvent[] = []
  let matched_events = 0

  for (const ev of sidecar.events) {
    const evTs = BigInt(ev.ts_ns)
    let bestConfidence: TlsMatchConfidence = 'unmatched'
    let bestDeltaNs: bigint | null = null
    const matchedFlows = new Set<string>()
    const matchedSamples: string[] = []

    const rankOf = (c: TlsMatchConfidence): number =>
      c === 'five_tuple_and_pid' ? 3 : c === 'five_tuple' ? 2 : c === 'pid_time_window' ? 1 : 0

    for (const s of indexed) {
      let deltaNs = 0n
      if (evTs < s.first_ts_ns) deltaNs = s.first_ts_ns - evTs
      else if (evTs > s.last_ts_ns) deltaNs = evTs - s.last_ts_ns

      if (deltaNs > windowNs) continue

      const tupleHit = connHintMatchesTuple(ev.conn_hint, s.tuple)
      const pidHit = ev.pid !== null && s.pid !== null && ev.pid === s.pid

      let conf: TlsMatchConfidence = 'unmatched'
      if (tupleHit && pidHit) conf = 'five_tuple_and_pid'
      else if (tupleHit) conf = 'five_tuple'
      else if (pidHit) conf = 'pid_time_window'

      if (conf === 'unmatched') continue

      if (rankOf(conf) > rankOf(bestConfidence)) {
        bestConfidence = conf
      }
      if (bestDeltaNs === null || deltaNs < bestDeltaNs) {
        bestDeltaNs = deltaNs
      }
      if (s.flow_key) matchedFlows.add(s.flow_key)
      if (matchedSamples.length < 20) matchedSamples.push(s.sample_id)
    }

    if (bestConfidence !== 'unmatched') {
      matched_events += 1
    }

    const row: CorrelatedTlsEvent = {
      ...ev,
      match_confidence: bestConfidence,
      matched_flow_keys: [...matchedFlows].sort(),
      matched_sample_ids: matchedSamples,
      delta_ms: bestDeltaNs !== null ? Math.round((Number(bestDeltaNs) / 1_000_000) * 1000) / 1000 : null,
    }

    if (filterFlowKey || filterSampleId) {
      const flowMatch = filterFlowKey ? row.matched_flow_keys.includes(filterFlowKey) : false
      const sampleMatch = filterSampleId ? row.matched_sample_ids.includes(filterSampleId) : false
      if (!flowMatch && !sampleMatch) continue
    }

    correlated.push(row)
  }

  return {
    available: true,
    total_events: sidecar.events.length,
    matched_events,
    parse_errors: sidecar.parse_errors,
    window_ms,
    events: correlated,
  }
}

export function summarizeTlsSidecar(session: Session, sessionDir: string): TlsSidecarSummary | null {
  const filePath = path.join(sessionDir, TLS_SIDECAR_FILENAME)
  if (!fs.existsSync(filePath)) return null
  const res = correlateTlsEvents(session, sessionDir)
  if (!res.available) return null
  return {
    available: true,
    total_events: res.total_events,
    matched_events: res.matched_events,
    parse_errors: res.parse_errors,
  }
}
