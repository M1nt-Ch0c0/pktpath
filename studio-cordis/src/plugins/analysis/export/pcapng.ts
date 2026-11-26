// Pure TypeScript multi-IDB .pcapng exporter (erasableSyntaxOnly).
// Ported 1:1 from studio/pkg/export/pcapng.go.

import { writeFileAtomic } from '../session-store.ts'
import { validateExportOutPath } from '../exporter-csv-report.ts'
import { reconstruct } from '../reconstruct/index.ts'
import type { ObjectNode, Session } from '../reconstruct/model.ts'
import {
  DIR_RX,
  DIR_TX,
  EVIDENCE_LABELS_ZH,
  EVIDENCE_NAMES,
  STAGE_ENTRY,
  STAGE_NAMES,
} from '../wire/consts.ts'
import { asInt, formatUUID, loadSession } from '../wire/wire.ts'
import type { WireEvent } from '../wire/wire.ts'
import { Redactor } from './redact.ts'

const SHB_TYPE = 0x0a0d0d0a
const IDB_TYPE = 0x00000001
const EPB_TYPE = 0x00000006
const PCAPNG_BOM_LE = 0x1a2b3c4d

const OPT_END_OF_OPT = 0
const OPT_COMMENT = 1
const SHB_USER_APPL = 4
const IF_NAME_OPT = 2
const IF_DESC_OPT = 3
const IF_TS_RESOL_OPT = 9
const EPB_FLAGS_OPT = 2
const DEFAULT_SNAPLEN = 262144

interface PcapOpt {
  code: number
  val: Uint8Array
}

interface IdbKey {
  netns: bigint
  ifindex: bigint
  devGen: bigint
  stage: number
  linktype: number
}

function idbKeyStr(k: IdbKey): string {
  return `${k.netns}|${k.ifindex}|${k.devGen}|${k.stage}|${k.linktype}`
}

function pad4(b: Uint8Array): Buffer {
  const rem = b.length % 4
  if (rem === 0) return Buffer.from(b)
  const out = Buffer.alloc(b.length + (4 - rem))
  out.set(b, 0)
  return out
}

function packOptions(opts: PcapOpt[]): Buffer {
  if (opts.length === 0) return Buffer.alloc(0)
  const chunks: Buffer[] = []
  for (const o of opts) {
    const hdr = Buffer.alloc(4)
    hdr.writeUInt16LE(o.code & 0xffff, 0)
    hdr.writeUInt16LE(o.val.length & 0xffff, 2)
    chunks.push(hdr, pad4(o.val))
  }
  const end = Buffer.alloc(4)
  end.writeUInt16LE(OPT_END_OF_OPT, 0)
  end.writeUInt16LE(0, 2)
  chunks.push(end)
  return Buffer.concat(chunks)
}

function wrapPcapngBlock(btype: number, body: Uint8Array): Buffer {
  const pb = pad4(body)
  const total = (12 + pb.length) >>> 0
  const out = Buffer.alloc(8 + pb.length + 4)
  out.writeUInt32LE(btype >>> 0, 0)
  out.writeUInt32LE(total, 4)
  pb.copy(out, 8)
  out.writeUInt32LE(total, 8 + pb.length)
  return out
}

function manifestOrDefault(m: Record<string, unknown>, key: string, def: string): string {
  if (!(key in m)) return def
  const v = m[key]
  if (v === null || v === undefined) return 'None'
  return String(v)
}

function buildSHB(sess: Session, redacted: boolean): Buffer {
  const comment = `session_uuid=${formatUUID(sess.loaded.session_uuid)} scope=${manifestOrDefault(sess.manifest, 'scope', 'tc-egress')} clock_domain=${manifestOrDefault(sess.manifest, 'clock_domain', 'CLOCK_BOOTTIME')} redacted=${redacted}`
  const opts = packOptions([
    { code: OPT_COMMENT, val: Buffer.from(comment, 'utf8') },
    { code: SHB_USER_APPL, val: Buffer.from('pktpath-v3', 'utf8') },
  ])
  const fixed = Buffer.alloc(16)
  fixed.writeUInt32LE(PCAPNG_BOM_LE, 0)
  fixed.writeUInt16LE(1, 4)
  fixed.writeUInt16LE(0, 6)
  fixed.writeBigUInt64LE(0xffffffffffffffffn, 8)
  return wrapPcapngBlock(SHB_TYPE, Buffer.concat([fixed, opts]))
}

function buildIDB(devName: string, k: IdbKey): Buffer {
  const stageName = STAGE_NAMES[k.stage] ?? `STAGE_${k.stage}`
  const ifName = `${devName}@ns${k.netns}:gen${k.devGen}:${stageName}`
  const ifDesc = `netns=${k.netns} ifindex=${k.ifindex} dev_gen=${k.devGen} stage=${stageName}(${k.stage}) linktype=${k.linktype}`
  const opts = packOptions([
    { code: IF_NAME_OPT, val: Buffer.from(ifName, 'utf8') },
    { code: IF_DESC_OPT, val: Buffer.from(ifDesc, 'utf8') },
    { code: IF_TS_RESOL_OPT, val: Uint8Array.of(0x09) },
  ])
  const fixed = Buffer.alloc(8)
  fixed.writeUInt16LE(k.linktype & 0xffff, 0)
  fixed.writeUInt16LE(0, 2)
  fixed.writeUInt32LE(DEFAULT_SNAPLEN, 4)
  return wrapPcapngBlock(IDB_TYPE, Buffer.concat([fixed, opts]))
}

function buildEPB(
  ifID: number,
  tsNs: bigint,
  pkt: Uint8Array,
  origLen: number,
  dirOpt: bigint | undefined,
  comment: string,
): Buffer {
  const tsU = tsNs > 0n ? BigInt.asUintN(64, tsNs) : 0n
  const tsHigh = Number((tsU >> 32n) & 0xffffffffn) >>> 0
  const tsLow = Number(tsU & 0xffffffffn) >>> 0
  const capLen = pkt.length >>> 0
  const effOrig = (capLen > origLen ? capLen : origLen) >>> 0

  const optList: PcapOpt[] = [{ code: OPT_COMMENT, val: Buffer.from(comment, 'utf8') }]
  if (dirOpt !== undefined) {
    const f = Buffer.alloc(4)
    if (Number(dirOpt) === DIR_RX) {
      f.writeUInt32LE(1, 0)
      optList.push({ code: EPB_FLAGS_OPT, val: f })
    } else if (Number(dirOpt) === DIR_TX) {
      f.writeUInt32LE(2, 0)
      optList.push({ code: EPB_FLAGS_OPT, val: f })
    }
  }
  const opts = packOptions(optList)
  const fixed = Buffer.alloc(20)
  fixed.writeUInt32LE(ifID >>> 0, 0)
  fixed.writeUInt32LE(tsHigh, 4)
  fixed.writeUInt32LE(tsLow, 8)
  fixed.writeUInt32LE(capLen, 12)
  fixed.writeUInt32LE(effOrig, 16)
  return wrapPcapngBlock(EPB_TYPE, Buffer.concat([fixed, pad4(pkt), opts]))
}

function absDiffU64(a: bigint, b: bigint): bigint {
  return a >= b ? a - b : b - a
}

function inferSummaryHookContext(sess: Session, obj: ObjectNode, summ: WireEvent): IdbKey {
  let ifidx = summ.u('ifindex')
  const site = sess.resolveSite(summ.site_dict_idx)
  let stage = STAGE_ENTRY
  if (site && site.stage !== undefined) {
    stage = site.stage
  }

  let bestStep: WireEvent | undefined
  let bestDist = 0n
  for (const st of obj.steps) {
    const d = absDiffU64(st.ts_ns, summ.ts_ns)
    if (!bestStep || d < bestDist) {
      bestDist = d
      bestStep = st
    }
  }

  let defaultNetns = 0n
  const eps = sess.dict['topology_epochs']
  if (Array.isArray(eps) && eps.length > 0 && typeof eps[0] === 'object' && eps[0] !== null) {
    const n = asInt((eps[0] as Record<string, unknown>)['netns_inum'])
    if (n !== undefined) defaultNetns = BigInt(n)
  }

  let netns = defaultNetns
  let devGen = 1n
  if (bestStep) {
    const n = bestStep.u('netns_inum')
    if (n !== 0n) netns = n
    const dg = bestStep.u('dev_gen')
    if (dg !== 0n) devGen = dg
    if (ifidx === 0n) ifidx = bestStep.u('ifindex')
    if (!site && bestStep.has('stage')) {
      stage = bestStep.num('stage')
    }
  }

  const ltVal = summ.get('linktype')
  const linktype = ltVal !== undefined ? Number(ltVal) : sess.resolveDevLinktype(ifidx, devGen)
  return { netns, ifindex: ifidx, devGen, stage, linktype }
}

export function buildPcapngBuffer(sess: Session, redact = false, key = ''): { buffer: Buffer; exportedPackets: number } {
  const red = redact ? new Redactor(key) : undefined
  const chunks: Buffer[] = [buildSHB(sess, redact)]

  const oids = [...sess.objects.keys()].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
  const idbMap = new Map<string, number>()
  const idbBlocks: Buffer[] = []
  const epbs: Array<{ ts: bigint; seq: bigint; raw: Buffer }> = []

  for (const oid of oids) {
    const obj = sess.objects.get(oid)!
    for (const summ of obj.summaries) {
      const hdr = summ.bin('hdr_bytes')
      if (!hdr || hdr.length === 0) continue
      const k = inferSummaryHookContext(sess, obj, summ)
      const ks = idbKeyStr(k)
      let ifID = idbMap.get(ks)
      if (ifID === undefined) {
        ifID = idbMap.size
        idbMap.set(ks, ifID)
        const devName = sess.resolveDevName(k.ifindex, k.devGen, k.netns)
        idbBlocks.push(buildIDB(devName, k))
      }

      const outHdr = red ? red.redactHdrBytes(hdr, k.linktype) : hdr
      const cal = sess.calibrateBoottimeToRealtime(summ.ts_ns)
      const errTxt = cal.calibrated ? cal.err_ns.toString() : 'uncalibrated'
      const evName = EVIDENCE_NAMES[summ.evidence_level] ?? String(summ.evidence_level)
      const evZH = EVIDENCE_LABELS_ZH[summ.evidence_level] ?? ''
      const snaplen = outHdr.length
      const pl = summ.u('pkt_len')
      const origLen = pl > 0n ? Number(pl) : snaplen
      const dirOpt = summ.get('dir')
      const comment = `event_id=${summ.eventId()} object_id=${summ.object_id} sample_id=${obj.primary_sample_id} evidence_level=${evName}(${summ.evidence_level}:${evZH}) snaplen=${snaplen} clock_err_ns=${errTxt}`
      const epb = buildEPB(ifID, cal.realtime_ns, outHdr, origLen, dirOpt, comment)
      epbs.push({ ts: summ.ts_ns, seq: summ.seq, raw: epb })
    }
  }

  epbs.sort((a, b) => {
    if (a.ts !== b.ts) return a.ts < b.ts ? -1 : 1
    if (a.seq !== b.seq) return a.seq < b.seq ? -1 : 1
    return 0
  })

  for (const b of idbBlocks) chunks.push(b)
  for (const e of epbs) chunks.push(e.raw)
  return { buffer: Buffer.concat(chunks), exportedPackets: epbs.length }
}

export function exportPcapng(sessionDir: string, outPath: string, redact = false, key = ''): number {
  const safeOut = validateExportOutPath(outPath, sessionDir)
  const sess = reconstruct(loadSession(sessionDir))
  const { buffer, exportedPackets } = buildPcapngBuffer(sess, redact, key)
  writeFileAtomic(safeOut, buffer)
  return exportedPackets
}
