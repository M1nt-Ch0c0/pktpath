// Pure TypeScript port of studio/pkg/reconstruct/tcpdump.go (erasableSyntaxOnly).

import * as fs from 'node:fs'
import {
  DIR_RX,
  DIR_TX,
  EVIDENCE_ANNOTATION,
  STAGE_XMIT_RET,
  STAGE_XMIT_START,
} from '../wire/consts.ts'
import { formatIP } from '../wire/wire.ts'
import type { WireEvent } from '../wire/wire.ts'

const LINKTYPE_ETHERNET = 1
const LINKTYPE_RAW = 101
const LINKTYPE_LINUX_SLL = 113
const LINKTYPE_IPV4 = 228
const LINKTYPE_IPV6 = 229
const LINKTYPE_SLL2 = 276

const NETDEV_TX_BUSY = 0x10n

export interface PcapPacket {
  frame_index: number
  realtime_ns: bigint
  captured_len: number
  orig_len: number
  linktype: number
  direction?: bigint
  ifindex?: bigint
  ip_version?: bigint
  ip_total_len?: bigint
  ip_id?: bigint
  frag_offset: number
  is_fragment: boolean
  l4_proto?: bigint
  src_ip: string
  dst_ip: string
  src_port?: bigint
  dst_port?: bigint
  tcp_seq?: bigint
  tcp_seq_end?: bigint
  tcp_flags?: bigint
  tcp_payload_len?: bigint
  raw_bytes: Uint8Array
}

export interface TcpdumpCandidate {
  frame_index: number
  realtime_ns: bigint
  est_boottime_ns: bigint
  delta_from_xmit_ns: bigint
  clock_err_ns: bigint
  evidence_level: number
  match_kind: string
  is_busy_duplicate: boolean
  is_superframe: boolean
  is_gso_segment: boolean
  attempt_index?: number
  orig_len: number
  src_ip?: string
  dst_ip?: string
  src_port?: bigint
  dst_port?: bigint
  tcp_seq?: bigint
  tcp_seq_end?: bigint
  note: string
}

function dissectFrame(
  idx: number,
  rtNs: bigint,
  origLen: number,
  linktype: number,
  raw: Uint8Array,
  epbDir?: bigint,
): PcapPacket {
  const b = Buffer.from(raw.buffer, raw.byteOffset, raw.byteLength)
  const p: PcapPacket = {
    frame_index: idx,
    realtime_ns: rtNs,
    captured_len: b.length,
    orig_len: origLen,
    linktype,
    direction: epbDir,
    frag_offset: 0,
    is_fragment: false,
    src_ip: '',
    dst_ip: '',
    raw_bytes: new Uint8Array(b),
  }
  const n = b.length
  let pos = 0
  let ethertype = -1

  switch (linktype) {
    case LINKTYPE_ETHERNET:
      if (n >= 14) {
        ethertype = b.readUInt16BE(12)
        pos = 14
        while ((ethertype === 0x8100 || ethertype === 0x88a8 || ethertype === 0x9100) && pos + 4 <= n) {
          ethertype = b.readUInt16BE(pos + 2)
          pos += 4
        }
      }
      break
    case LINKTYPE_RAW:
    case LINKTYPE_IPV4:
    case LINKTYPE_IPV6:
      if (n >= 1) {
        const ver = b[0]! >> 4
        if (ver === 4) ethertype = 0x0800
        else if (ver === 6) ethertype = 0x86dd
      }
      break
    case LINKTYPE_LINUX_SLL:
      if (n >= 16) {
        const pkttype = b.readUInt16BE(0)
        ethertype = b.readUInt16BE(14)
        pos = 16
        if (pkttype === 4) p.direction = BigInt(DIR_TX)
        else if (pkttype <= 2) p.direction = BigInt(DIR_RX)
      }
      break
    case LINKTYPE_SLL2:
      if (n >= 20) {
        ethertype = b.readUInt16BE(0)
        p.ifindex = BigInt(b.readUInt32BE(4))
        const pkttype = b[10]!
        pos = 20
        if (pkttype === 4) p.direction = BigInt(DIR_TX)
        else if (pkttype <= 2) p.direction = BigInt(DIR_RX)
      }
      break
  }

  let l4Expected = -1
  if (ethertype === 0x0800 && pos + 20 <= n) {
    const vihl = b[pos]!
    if (vihl >> 4 === 4) {
      const ihl = (vihl & 0x0f) * 4
      if (ihl >= 20 && pos + ihl <= n) {
        p.ip_version = 4n
        let totLen = b.readUInt16BE(pos + 2)
        if (totLen <= 0 && origLen > pos) totLen = origLen - pos
        p.ip_total_len = BigInt(totLen)
        p.ip_id = BigInt(b.readUInt16BE(pos + 4))
        const frag = b.readUInt16BE(pos + 6)
        p.frag_offset = (frag & 0x1fff) * 8
        p.is_fragment = (frag & 0x2000) !== 0 || p.frag_offset > 0
        p.l4_proto = BigInt(b[pos + 9]!)
        p.src_ip = formatIP(b.subarray(pos + 12, pos + 16))
        p.dst_ip = formatIP(b.subarray(pos + 16, pos + 20))
        l4Expected = totLen >= ihl ? totLen - ihl : 0
        pos += ihl
      }
    }
  } else if (ethertype === 0x86dd && pos + 40 <= n) {
    if (b[pos]! >> 4 === 6) {
      p.ip_version = 6n
      let plen = b.readUInt16BE(pos + 4)
      if (plen <= 0 && origLen > pos + 40) plen = origLen - pos - 40
      p.ip_total_len = BigInt(40 + plen)
      let nxt = b[pos + 6]!
      p.src_ip = formatIP(b.subarray(pos + 8, pos + 24))
      p.dst_ip = formatIP(b.subarray(pos + 24, pos + 40))
      pos += 40
      let ext = 0
      while ((nxt === 0 || nxt === 43 || nxt === 44 || nxt === 60) && pos + 8 <= n) {
        if (nxt === 44) {
          const nxtHdr = b[pos]!
          const fo = b.readUInt16BE(pos + 2)
          p.frag_offset = fo & 0xfff8
          p.is_fragment = (fo & 0x0001) !== 0 || p.frag_offset > 0
          p.ip_id = BigInt(b.readUInt32BE(pos + 4) & 0xffff)
          nxt = nxtHdr
          pos += 8
          ext += 8
        } else {
          const nxtHdr = b[pos]!
          const hlen = (b[pos + 1]! + 1) * 8
          if (hlen <= 0 || pos + hlen > n) break
          nxt = nxtHdr
          pos += hlen
          ext += hlen
        }
      }
      p.l4_proto = BigInt(nxt)
      l4Expected = plen >= ext ? plen - ext : 0
    }
  }

  if (p.ip_version !== undefined && p.frag_offset === 0 && p.l4_proto !== undefined) {
    if (p.l4_proto === 6n) {
      if (pos + 14 <= n) {
        p.src_port = BigInt(b.readUInt16BE(pos))
        p.dst_port = BigInt(b.readUInt16BE(pos + 2))
        const seq = b.readUInt32BE(pos + 4)
        let thl = ((b[pos + 12]! >> 4) & 0x0f) * 4
        if (thl < 20) thl = 20
        p.tcp_seq = BigInt(seq)
        p.tcp_flags = BigInt(b[pos + 13]!)
        if (l4Expected >= 0) {
          const pay = l4Expected > thl ? l4Expected - thl : 0
          p.tcp_payload_len = BigInt(pay)
          p.tcp_seq_end = BigInt((seq + pay) >>> 0)
        }
      }
    } else if (p.l4_proto === 17n) {
      if (pos + 8 <= n) {
        p.src_port = BigInt(b.readUInt16BE(pos))
        p.dst_port = BigInt(b.readUInt16BE(pos + 2))
      }
    }
  }
  return p
}

function readU16(b: Buffer, off: number, le: boolean): number {
  return le ? b.readUInt16LE(off) : b.readUInt16BE(off)
}
function readU32(b: Buffer, off: number, le: boolean): number {
  return le ? b.readUInt32LE(off) : b.readUInt32BE(off)
}

function parseClassicPcap(b: Buffer, le: boolean, subToNs: bigint): PcapPacket[] {
  if (b.length < 24) throw new Error('truncated classic pcap header')
  const linktype = readU32(b, 20, le)
  let pos = 24
  let idx = 0
  const out: PcapPacket[] = []
  while (pos + 16 <= b.length) {
    const sec = BigInt(readU32(b, pos, le))
    const sub = BigInt(readU32(b, pos + 4, le))
    const incl = readU32(b, pos + 8, le)
    const orig = readU32(b, pos + 12, le)
    pos += 16
    if (incl < 0 || pos + incl > b.length) break
    const raw = b.subarray(pos, pos + incl)
    pos += incl
    idx++
    out.push(dissectFrame(idx, sec * 1_000_000_000n + sub * subToNs, orig, linktype, raw))
  }
  return out
}

function decodeTsResol(byteVal: number): { num: bigint; den: bigint } {
  const p = byteVal & 0x7f
  if ((byteVal & 0x80) !== 0) {
    const shift = p > 62 ? 62 : p
    return { num: 1_000_000_000n, den: 1n << BigInt(shift) }
  }
  if (p <= 9) {
    let n = 1n
    for (let i = 0; i < 9 - p; i++) n *= 10n
    return { num: n, den: 1n }
  }
  let d = 1n
  for (let i = 0; i < p - 9 && i < 18; i++) d *= 10n
  return { num: 1n, den: d }
}

function parsePcapngBytes(b: Buffer): PcapPacket[] {
  let le = true
  const ifaces: Array<{ lt: number; num: bigint; den: bigint }> = []
  const out: PcapPacket[] = []
  let pos = 0
  const n = b.length
  let idx = 0

  while (pos + 12 <= n) {
    if (b.readUInt32LE(pos) === 0x0a0d0d0a) {
      if (pos + 16 > n) break
      const bom = b.readUInt32LE(pos + 8)
      if (bom === 0x1a2b3c4d) le = true
      else if (bom === 0x4d3c2b1a) le = false
      else throw new Error(`invalid pcapng BOM 0x${bom.toString(16).padStart(8, '0')}`)
      ifaces.length = 0
    }
    const btype = readU32(b, pos, le)
    const blen = readU32(b, pos + 4, le)
    if (blen < 12 || pos + blen > n) break
    const bs = pos + 8
    const be = pos + blen - 4

    if (btype === 0x00000001) {
      if (bs + 8 <= be) {
        const lt = readU16(b, bs, le)
        let num = 1000n
        let den = 1n
        let op = bs + 8
        while (op + 4 <= be) {
          const oc = readU16(b, op, le)
          const ol = readU16(b, op + 2, le)
          op += 4
          if (oc === 0) break
          if (oc === 9 && ol >= 1 && op < be) {
            const r = decodeTsResol(b[op]!)
            num = r.num
            den = r.den
          }
          op += (ol + 3) & ~3
        }
        ifaces.push({ lt, num, den })
      }
    } else if (btype === 0x00000006) {
      if (bs + 20 <= be) {
        const ifID = readU32(b, bs, le)
        const tsH = BigInt(readU32(b, bs + 4, le))
        const tsL = BigInt(readU32(b, bs + 8, le))
        const capL = readU32(b, bs + 12, le)
        const origL = readU32(b, bs + 16, le)
        const ps = bs + 20
        if (capL >= 0 && ps + capL <= be) {
          const raw = b.subarray(ps, ps + capL)
          let op = ps + ((capL + 3) & ~3)
          let dir: bigint | undefined
          while (op + 4 <= be) {
            const oc = readU16(b, op, le)
            const ol = readU16(b, op + 2, le)
            op += 4
            if (oc === 0) break
            if (oc === 2 && ol >= 4 && op + 4 <= be) {
              const bits = readU32(b, op, le) & 0x03
              if (bits === 1) dir = BigInt(DIR_RX)
              else if (bits === 2) dir = BigInt(DIR_TX)
            }
            op += (ol + 3) & ~3
          }
          const ii = ifID >= 0 && ifID < ifaces.length ? ifaces[ifID]! : { lt: LINKTYPE_ETHERNET, num: 1000n, den: 1n }
          const ts64 = (tsH << 32n) | tsL
          const rtNs = ii.num === 1n && ii.den === 1n ? ts64 : (ts64 * ii.num) / ii.den
          idx++
          out.push(dissectFrame(idx, rtNs, origL, ii.lt, raw, dir))
        }
      }
    } else if (btype === 0x00000003) {
      if (bs + 4 <= be) {
        const origL = readU32(b, bs, le)
        const lt = ifaces.length > 0 ? ifaces[0]!.lt : LINKTYPE_ETHERNET
        idx++
        out.push(dissectFrame(idx, 0n, origL, lt, b.subarray(bs + 4, be)))
      }
    }
    pos += blen
  }
  return out
}

export function parseCaptureBytes(data: Uint8Array): PcapPacket[] {
  const b = Buffer.from(data.buffer, data.byteOffset, data.byteLength)
  if (b.length < 4) throw new Error(`capture buffer too small (${b.length} B)`)
  const m = b.readUInt32LE(0)
  if (m === 0xa1b2c3d4) return parseClassicPcap(b, true, 1000n)
  if (m === 0xd4c3b2a1) return parseClassicPcap(b, false, 1000n)
  if (m === 0xa1b23c4d) return parseClassicPcap(b, true, 1n)
  if (m === 0x4d3cb2a1) return parseClassicPcap(b, false, 1n)
  if (m === 0x0a0d0d0a) return parsePcapngBytes(b)
  throw new Error(`unrecognized capture magic 0x${m.toString(16).padStart(8, '0')}`)
}

export function parseCaptureFile(filePath: string): PcapPacket[] {
  const st = fs.statSync(filePath)
  if (!st.isFile()) throw new Error(`not a regular file: ${filePath}`)
  return parseCaptureBytes(fs.readFileSync(filePath))
}

function tcpSeqLE(a: number, b: number): boolean {
  return ((b - a) >>> 0) < 0x80000000
}

function tcpRangesOverlap(s1: number, e1: number, s2: number, e2: number): boolean {
  if (s1 === s2) return true
  if (e1 === s1) return tcpSeqLE(s2, s1) && tcpSeqLE(s1, e2)
  if (e2 === s2) return tcpSeqLE(s1, s2) && tcpSeqLE(s2, e1)
  return tcpSeqLE(s1, e2) && s1 !== e2 && tcpSeqLE(s2, e1) && s2 !== e1
}

export interface BranchLikeForTcpdump {
  start_ts_ns: bigint
  end_ts_ns: bigint
  requeue_count: number
  steps: WireEvent[]
  summaries: WireEvent[]
}

export function matchBranchPackets(
  calibrate: (bt: bigint) => { realtime_ns: bigint; err_ns: bigint; calibrated: boolean },
  br: BranchLikeForTcpdump,
  packets: PcapPacket[],
  marginNs = 50_000_000n,
): TcpdumpCandidate[] {
  if (br.summaries.length === 0) return []
  const cS = calibrate(br.start_ts_ns)
  const cE = calibrate(br.end_ts_ns)
  const errNs = cE.err_ns > cS.err_ns ? cE.err_ns : cS.err_ns
  const winLo = cS.realtime_ns - errNs - marginNs
  const winHi = cE.realtime_ns + errNs + marginNs

  const xmits: WireEvent[] = []
  let busy = br.requeue_count > 0
  for (const st of br.steps) {
    const stage = st.num('stage')
    if (stage === STAGE_XMIT_START) {
      xmits.push(st)
    } else if (stage === STAGE_XMIT_RET) {
      const rc = st.i('raw_ret')
      if (rc !== undefined && rc === NETDEV_TX_BUSY) busy = true
    }
  }
  if (xmits.length > 1) busy = true
  const anchorBt = xmits.length > 0 ? xmits[xmits.length - 1]!.ts_ns : br.end_ts_ns
  const anchorRt = calibrate(anchorBt).realtime_ns

  const hits: Array<{ pkt: PcapPacket; super: boolean; gsoSeg: boolean }> = []
  const seen = new Set<number>()

  for (const pkt of packets) {
    if (seen.has(pkt.frame_index)) continue
    if (pkt.realtime_ns > 0n && (pkt.realtime_ns < winLo || pkt.realtime_ns > winHi)) continue
    for (const summ of br.summaries) {
      const sd = summ.get('dir')
      if (
        sd !== undefined &&
        pkt.direction !== undefined &&
        (sd === BigInt(DIR_RX) || sd === BigInt(DIR_TX)) &&
        pkt.direction !== sd
      ) {
        continue
      }
      const iv = summ.get('ip_version')
      if (iv !== undefined && (pkt.ip_version === undefined || pkt.ip_version !== iv)) continue
      const proto = summ.get('l4_proto')
      if (proto !== undefined && (pkt.l4_proto === undefined || pkt.l4_proto !== proto)) continue
      const sip = summ.str('src_ip')
      if (sip !== undefined && pkt.src_ip !== sip) continue
      const dip = summ.str('dst_ip')
      if (dip !== undefined && pkt.dst_ip !== dip) continue
      if (proto !== undefined && (proto === 6n || proto === 17n)) {
        const sp = summ.get('src_port')
        if (sp !== undefined && (pkt.src_port === undefined || pkt.src_port !== sp)) continue
        const dp = summ.get('dst_port')
        if (dp !== undefined && (pkt.dst_port === undefined || pkt.dst_port !== dp)) continue
      }
      const sLen = summ.num('pkt_len')
      let isSuper = false
      let isSeg = false
      if (proto === 6n) {
        const bs = summ.get('tcp_seq')
        if (bs !== undefined && pkt.tcp_seq !== undefined) {
          const bev = summ.get('tcp_seq_end')
          const be = bev !== undefined && bev !== 0n ? bev : bs
          const ps = Number(pkt.tcp_seq & 0xffffffffn) >>> 0
          const pe = pkt.tcp_seq_end !== undefined ? (Number(pkt.tcp_seq_end & 0xffffffffn) >>> 0) : ps
          const bs32 = Number(bs & 0xffffffffn) >>> 0
          const be32 = Number(be & 0xffffffffn) >>> 0
          if (!tcpRangesOverlap(bs32, be32, ps, pe)) continue
          const bSpan = (be32 - bs32) >>> 0
          const pSpan = (pe - ps) >>> 0
          if (pSpan > bSpan && bSpan > 0) isSuper = true
          else if (bSpan > pSpan && pSpan > 0) isSeg = true
        }
      }
      if (sLen > 0 && pkt.ip_total_len !== undefined) {
        if (Number(pkt.ip_total_len) > sLen + 32) isSuper = true
        else if (sLen > pkt.orig_len + 32) isSeg = true
      }
      seen.add(pkt.frame_index)
      hits.push({ pkt, super: isSuper, gsoSeg: isSeg })
      break
    }
  }

  const multi = hits.length > 1
  const out: TcpdumpCandidate[] = []
  for (let i = 0; i < hits.length; i++) {
    const h = hits[i]!
    const attempt = i + 1
    let estBt = anchorBt
    let delta = 0n
    if (cS.calibrated || h.pkt.realtime_ns > 0n) {
      delta = h.pkt.realtime_ns - anchorRt
      if (anchorBt + delta > 0n) estBt = anchorBt + delta
    }
    const isBusyDup = busy && multi && !h.gsoSeg
    let mkind: string
    let note: string
    if (isBusyDup) {
      mkind = 'XMIT_BUSY_DUPLICATE'
      note = `xmit_one()/dev_queue_xmit_nit() BUSY 重试产生第 ${attempt}/${hits.length} 条外部抓包副本 (仅作辅助旁注，不新建对象身份)`
    } else if (h.super) {
      mkind = 'GSO_GRO_SUPERFRAME'
      note = '外部 pcap 捕获到 GSO/GRO 聚合超大帧 (仅作辅助旁注)'
    } else if (h.gsoSeg) {
      mkind = 'GSO_SEGMENT_FRAME'
      note = '外部 pcap 捕获到分段后子帧 (仅作辅助旁注)'
    } else if (multi) {
      mkind = 'AMBIGUOUS_MULTI_CANDIDATE'
      note = `同五元组/序号存在 ${hits.length} 个候选帧 (#${attempt}/${hits.length}，仅作辅助旁注，不反向连边)`
    } else {
      mkind = 'EXACT_CANDIDATE'
      note = '外部 tcpdump 候选匹配 (仅作辅助旁注)'
    }
    out.push({
      frame_index: h.pkt.frame_index,
      realtime_ns: h.pkt.realtime_ns,
      est_boottime_ns: estBt,
      delta_from_xmit_ns: delta,
      clock_err_ns: errNs,
      evidence_level: EVIDENCE_ANNOTATION,
      match_kind: mkind,
      is_busy_duplicate: isBusyDup,
      is_superframe: h.super,
      is_gso_segment: h.gsoSeg,
      attempt_index: isBusyDup ? attempt : undefined,
      orig_len: h.pkt.orig_len,
      src_ip: h.pkt.src_ip || undefined,
      dst_ip: h.pkt.dst_ip || undefined,
      src_port: h.pkt.src_port,
      dst_port: h.pkt.dst_port,
      tcp_seq: h.pkt.tcp_seq,
      tcp_seq_end: h.pkt.tcp_seq_end,
      note,
    })
  }
  return out
}
