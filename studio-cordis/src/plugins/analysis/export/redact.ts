// Pure TypeScript keyed HMAC-SHA256 session redactor (erasableSyntaxOnly).
// Ported 1:1 from studio/pkg/export/redact.go (hmac-sha256-trunc-v1).
// Enforces WAVE1-CONTRACT.md v1.2 safety rules:
// - Never mutates original session_dir
// - Hard-forbids outDir equal to or inside inDir
// - Never copies .pktpath_analysis_cache.json into outDir.

import { createHash, createHmac, randomBytes } from 'node:crypto'
import fs from 'node:fs'
import net from 'node:net'
import path from 'node:path'
import { isPathInsideDir } from '../exporter-csv-report.ts'
import {
  BLOCK_FLAG_ZSTD,
  KIND_SUMMARY,
  LINK_TYPE_ETHERNET,
  LINK_TYPE_RAW_IP,
  TLV_SUM_DST_IP,
  TLV_SUM_DST_PORT,
  TLV_SUM_HDR_BYTES,
  TLV_SUM_SRC_IP,
  TLV_SUM_SRC_PORT,
  TLV_SUM_UID,
} from '../wire/consts.ts'
import {
  WireEvent,
  asInt,
  encodeBlock,
  encodeEvent,
  formatIP,
  loadSession,
} from '../wire/wire.ts'
import type { Tlv } from '../wire/wire.ts'

function parseIPv4Bytes(s: string): Uint8Array | null {
  const parts = s.split('.')
  if (parts.length !== 4) return null
  const out = new Uint8Array(4)
  for (let i = 0; i < 4; i++) {
    if (!/^\d+$/.test(parts[i]!)) return null
    const v = Number(parts[i])
    if (v < 0 || v > 255) return null
    out[i] = v
  }
  return out
}

function parseIPv6Bytes(s: string): Uint8Array | null {
  if (net.isIPv6(s) === false) return null
  const halves = s.split('::')
  if (halves.length > 2) return null
  const parsePart = (part: string): number[] | null => {
    if (!part) return []
    const segs = part.split(':')
    const words: number[] = []
    for (let i = 0; i < segs.length; i++) {
      const seg = segs[i]!
      if (seg.includes('.')) {
        const v4 = parseIPv4Bytes(seg)
        if (!v4) return null
        words.push((v4[0]! << 8) | v4[1]!, (v4[2]! << 8) | v4[3]!)
      } else {
        const w = Number.parseInt(seg, 16)
        if (!Number.isFinite(w) || w < 0 || w > 0xffff) return null
        words.push(w)
      }
    }
    return words
  }
  const left = parsePart(halves[0]!)
  const right = halves.length === 2 ? parsePart(halves[1]!) : []
  if (!left || !right) return null
  const zeros = 8 - left.length - right.length
  if (zeros < 0) return null
  const all = [...left, ...new Array<number>(zeros).fill(0), ...right]
  if (all.length !== 8) return null
  const out = new Uint8Array(16)
  for (let i = 0; i < 8; i++) {
    out[i * 2] = (all[i]! >>> 8) & 0xff
    out[i * 2 + 1] = all[i]! & 0xff
  }
  return out
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}

export class Redactor {
  private readonly key: Buffer

  constructor(key = '') {
    if (!key) {
      this.key = randomBytes(32)
    } else {
      this.key = createHash('sha256').update(key, 'utf8').digest()
    }
  }

  private prf(domain: string, data: Uint8Array): Buffer {
    return createHmac('sha256', this.key)
      .update(domain, 'utf8')
      .update(':', 'utf8')
      .update(data)
      .digest()
  }

  redactIPBytes(ip: Uint8Array): Uint8Array {
    if (ip.length === 4) {
      const d = this.prf('ipv4', ip)
      const out = new Uint8Array([d[0]!, d[1]!, d[2]!, d[3]!])
      if (out[0] === 0 || out[0] === 127 || out[0]! >= 224) {
        out[0] = 10
      }
      if (bytesEqual(out, ip)) {
        out[3] = out[3]! ^ 0x01
      }
      return out
    }
    if (ip.length === 16) {
      const d = this.prf('ipv6', ip)
      const out = new Uint8Array(16)
      out[0] = 0xfd // ULA fd00::/8
      out.set(d.subarray(0, 15), 1)
      if (bytesEqual(out, ip)) {
        out[15] = out[15]! ^ 0x01
      }
      return out
    }
    return new Uint8Array(ip)
  }

  redactIPStr(s: string): string {
    const trimmed = s.trim()
    const v4 = parseIPv4Bytes(trimmed)
    if (v4) return formatIP(this.redactIPBytes(v4))
    const v6 = parseIPv6Bytes(trimmed)
    if (v6) return formatIP(this.redactIPBytes(v6))
    throw new Error(`invalid IP address: ${s}`)
  }

  redactPort(port: number): number {
    const p = port & 0xffff
    if (p === 0) return 0
    const pb = Buffer.alloc(2)
    pb.writeUInt16LE(p, 0)
    const d = this.prf('port', pb)
    let v = 1024 + (d.readUInt16LE(0) % 64511)
    if (v === p) {
      v = 1024 + ((v - 1024 + 1) % 64511)
    }
    return v & 0xffff
  }

  redactUID(uid: number): number {
    const u = uid >>> 0
    if (u === 0xffffffff) return u
    const ub = Buffer.alloc(4)
    ub.writeUInt32LE(u, 0)
    const d = this.prf('uid', ub)
    let v = (100000 + (d.readUInt32LE(0) % 800000)) >>> 0
    if (v === u) {
      v = (v + 1) >>> 0
    }
    return v
  }

  redactHdrBytes(hdr: Uint8Array, linktype: number): Uint8Array {
    const buf = Buffer.from(hdr)
    const n = buf.length
    let pos = 0
    let ethertype = -1

    if (linktype === LINK_TYPE_ETHERNET) {
      if (n < 14) return new Uint8Array(buf)
      const dstH = this.prf('mac', buf.subarray(0, 6))
      const srcH = this.prf('mac', buf.subarray(6, 12))
      buf[0] = (buf[0]! & 0x01) | 0x02
      dstH.copy(buf, 1, 0, 5)
      buf[6] = (buf[6]! & 0x01) | 0x02
      srcH.copy(buf, 7, 0, 5)
      ethertype = buf.readUInt16BE(12)
      pos = 14
      while ((ethertype === 0x8100 || ethertype === 0x88a8 || ethertype === 0x9100) && pos + 4 <= n) {
        ethertype = buf.readUInt16BE(pos + 2)
        pos += 4
      }
    } else if (linktype === LINK_TYPE_RAW_IP) {
      if (n >= 1) {
        const ver = buf[0]! >> 4
        if (ver === 4) ethertype = 0x0800
        else if (ver === 6) ethertype = 0x86dd
      }
    }

    let l4Proto = -1
    let fragOff = 0

    if (ethertype === 0x0800 && pos + 20 <= n) {
      const ihl = (buf[pos]! & 0x0f) * 4
      if (ihl >= 20 && pos + ihl <= n) {
        l4Proto = buf[pos + 9]!
        const fragField = buf.readUInt16BE(pos + 6)
        fragOff = (fragField & 0x1fff) * 8
        buf.set(this.redactIPBytes(buf.subarray(pos + 12, pos + 16)), pos + 12)
        buf.set(this.redactIPBytes(buf.subarray(pos + 16, pos + 20)), pos + 16)
        buf[pos + 10] = 0
        buf[pos + 11] = 0
        pos += ihl
      }
    } else if (ethertype === 0x86dd && pos + 40 <= n) {
      let nxt = buf[pos + 6]!
      buf.set(this.redactIPBytes(buf.subarray(pos + 8, pos + 24)), pos + 8)
      buf.set(this.redactIPBytes(buf.subarray(pos + 24, pos + 40)), pos + 24)
      pos += 40
      while ((nxt === 0 || nxt === 43 || nxt === 44 || nxt === 60) && pos + 8 <= n) {
        if (nxt === 44) {
          const nxtHdr = buf[pos]!
          const fragOffM = buf.readUInt16BE(pos + 2)
          fragOff = fragOffM & 0xfff8
          nxt = nxtHdr
          pos += 8
        } else {
          const nxtHdr = buf[pos]!
          const hlen = (buf[pos + 1]! + 1) * 8
          if (hlen <= 0 || pos + hlen > n) break
          nxt = nxtHdr
          pos += hlen
        }
      }
      l4Proto = nxt
    }

    if (l4Proto >= 0 && fragOff === 0) {
      if (l4Proto === 6 && pos + 4 <= n) {
        const sp = buf.readUInt16BE(pos)
        const dp = buf.readUInt16BE(pos + 2)
        buf.writeUInt16BE(this.redactPort(sp), pos)
        buf.writeUInt16BE(this.redactPort(dp), pos + 2)
        if (pos + 18 <= n) {
          buf[pos + 16] = 0
          buf[pos + 17] = 0
        }
        let doff = 20
        if (pos + 13 <= n) {
          const d = ((buf[pos + 12]! >> 4) & 0x0f) * 4
          if (d > 20) doff = d
        }
        for (let k = pos + doff; k < n; k++) buf[k] = 0
      } else if (l4Proto === 17 && pos + 4 <= n) {
        const sp = buf.readUInt16BE(pos)
        const dp = buf.readUInt16BE(pos + 2)
        buf.writeUInt16BE(this.redactPort(sp), pos)
        buf.writeUInt16BE(this.redactPort(dp), pos + 2)
        if (pos + 8 <= n) {
          buf[pos + 6] = 0
          buf[pos + 7] = 0
        }
        for (let k = pos + 8; k < n; k++) buf[k] = 0
      }
    }

    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
  }

  redactEvent(ev: WireEvent, defaultLinktype: number): WireEvent {
    if (ev.kind !== KIND_SUMMARY) return ev
    const out = new WireEvent({
      kind: ev.kind,
      object_type: ev.object_type,
      evidence_level: ev.evidence_level,
      site_dict_idx: ev.site_dict_idx,
      cpu: ev.cpu,
      flags: ev.flags,
      seq: ev.seq,
      ts_ns: ev.ts_ns,
      object_id: ev.object_id,
      block_no: ev.block_no,
      epoch: ev.epoch,
      producer_type: ev.producer_type,
    })
    for (const [k, v] of ev.nums) out.nums.set(k, v)
    for (const [k, v] of ev.strs) out.strs.set(k, v)
    for (const [k, v] of ev.bins) out.bins.set(k, new Uint8Array(v))
    out.unknown_optional = [...ev.unknown_optional]
    out.unknown_must = [...ev.unknown_must]

    const ltVal = ev.get('linktype')
    const ltype = ltVal !== undefined && ltVal !== 0n ? Number(ltVal) : defaultLinktype

    const newTLVs: Tlv[] = []
    for (const t of ev.raw_tlvs) {
      const base = t.tag & 0x7fff
      if (base === TLV_SUM_SRC_IP && (t.val.length === 4 || t.val.length === 16)) {
        const rv = this.redactIPBytes(t.val)
        newTLVs.push({ tag: t.tag, val: rv })
        out.bins.set('src_ip_raw', rv)
        out.strs.set('src_ip', formatIP(rv))
      } else if (base === TLV_SUM_DST_IP && (t.val.length === 4 || t.val.length === 16)) {
        const rv = this.redactIPBytes(t.val)
        newTLVs.push({ tag: t.tag, val: rv })
        out.bins.set('dst_ip_raw', rv)
        out.strs.set('dst_ip', formatIP(rv))
      } else if (base === TLV_SUM_SRC_PORT && t.val.length === 2) {
        const rp = this.redactPort(Buffer.from(t.val).readUInt16LE(0))
        const b = Buffer.alloc(2)
        b.writeUInt16LE(rp, 0)
        newTLVs.push({ tag: t.tag, val: new Uint8Array(b) })
        out.nums.set('src_port', BigInt(rp))
      } else if (base === TLV_SUM_DST_PORT && t.val.length === 2) {
        const rp = this.redactPort(Buffer.from(t.val).readUInt16LE(0))
        const b = Buffer.alloc(2)
        b.writeUInt16LE(rp, 0)
        newTLVs.push({ tag: t.tag, val: new Uint8Array(b) })
        out.nums.set('dst_port', BigInt(rp))
      } else if (base === TLV_SUM_UID && t.val.length === 4) {
        const ru = this.redactUID(Buffer.from(t.val).readUInt32LE(0))
        const b = Buffer.alloc(4)
        b.writeUInt32LE(ru, 0)
        newTLVs.push({ tag: t.tag, val: new Uint8Array(b) })
        out.nums.set('uid', BigInt(ru))
      } else if (base === TLV_SUM_HDR_BYTES) {
        const rh = this.redactHdrBytes(t.val, ltype)
        newTLVs.push({ tag: t.tag, val: rh })
        out.bins.set('hdr_bytes', rh)
      } else {
        newTLVs.push({ tag: t.tag, val: new Uint8Array(t.val) })
      }
    }
    out.raw_tlvs = newTLVs
    return out
  }
}

export function redactSession(inDir: string, outDir: string, key = ''): void {
  const srcAbs = path.resolve(inDir)
  const dstAbs = path.resolve(outDir)
  if (isPathInsideDir(dstAbs, srcAbs)) {
    throw new Error(`refusing to write redacted session inside input session_dir: ${dstAbs}`)
  }
  if (isPathInsideDir(srcAbs, dstAbs)) {
    throw new Error(`refusing to write redacted session as ancestor of input session_dir: ${dstAbs}`)
  }
  const loaded = loadSession(srcAbs, false)
  const red = new Redactor(key)
  fs.mkdirSync(dstAbs, { recursive: true })

  const redManifest = JSON.parse(JSON.stringify(loaded.manifest)) as Record<string, unknown>
  redManifest['redacted'] = true
  redManifest['redaction_scheme'] = 'hmac-sha256-trunc-v1'
  const flt = redManifest['filters']
  if (typeof flt === 'object' && flt !== null && !Array.isArray(flt)) {
    const fm = flt as Record<string, unknown>
    for (const k of ['src_ip', 'dst_ip']) {
      if (typeof fm[k] === 'string' && fm[k] !== '') {
        const ipPart = (fm[k] as string).split('/')[0]!
        try {
          fm[k] = red.redactIPStr(ipPart)
        } catch {
          // ignore non-IP filter expression
        }
      }
    }
    for (const k of ['src_port', 'dst_port']) {
      if (fm[k] !== undefined && fm[k] !== null) {
        const p = asInt(fm[k])
        if (p !== undefined) fm[k] = red.redactPort(p)
      }
    }
    if (fm['uid'] !== undefined && fm['uid'] !== null) {
      const u = asInt(fm['uid'])
      if (u !== undefined) fm['uid'] = red.redactUID(u)
    }
  }
  fs.writeFileSync(path.join(dstAbs, 'manifest.json'), JSON.stringify(redManifest, null, 2), 'utf8')

  const srcDict = path.join(srcAbs, 'dict.json')
  if (fs.existsSync(srcDict)) {
    fs.writeFileSync(path.join(dstAbs, 'dict.json'), fs.readFileSync(srcDict))
  } else {
    fs.writeFileSync(path.join(dstAbs, 'dict.json'), JSON.stringify(loaded.dictionary, null, 2), 'utf8')
  }

  const devLinktypes = new Map<bigint, number>()
  const eps = loaded.dictionary['topology_epochs']
  if (Array.isArray(eps)) {
    for (const ep of eps) {
      if (typeof ep !== 'object' || ep === null) continue
      const devs = (ep as Record<string, unknown>)['devices']
      if (!Array.isArray(devs)) continue
      for (const dv of devs) {
        if (typeof dv !== 'object' || dv === null) continue
        const dm = dv as Record<string, unknown>
        const ifx = asInt(dm['ifindex'])
        const lt = asInt(dm['linktype'])
        if (ifx !== undefined && lt !== undefined) {
          devLinktypes.set(BigInt(ifx), lt)
        }
      }
    }
  }

  // Group blocks by source_file so multi-block .pktb files preserve all blocks
  const byFile = new Map<string, Uint8Array[]>()
  for (let idx = 0; idx < loaded.blocks.length; idx++) {
    const blk = loaded.blocks[idx]!
    let payload: Uint8Array
    if (blk.meta_payload !== undefined) {
      payload = Buffer.from(JSON.stringify(blk.meta_payload), 'utf8')
    } else {
      const chunks: Uint8Array[] = []
      for (const ev of blk.events) {
        if (ev.kind === KIND_SUMMARY) {
          const defLT = devLinktypes.get(ev.u('ifindex')) ?? LINK_TYPE_ETHERNET
          const rev = red.redactEvent(ev, defLT)
          chunks.push(encodeEvent(rev))
        } else {
          chunks.push(encodeEvent(ev))
        }
      }
      payload = Buffer.concat(chunks)
    }
    const nh = {
      ...blk.header,
      flags: blk.header.flags & ~BLOCK_FLAG_ZSTD,
      payload_len: payload.length,
    }
    const rawBlk = encodeBlock(nh, payload)
    const outName = blk.source_file ? path.basename(blk.source_file) : `block_${String(idx).padStart(6, '0')}.pktb`
    const arr = byFile.get(outName)
    if (arr) arr.push(rawBlk)
    else byFile.set(outName, [rawBlk])
  }

  for (const [outName, parts] of byFile.entries()) {
    fs.writeFileSync(path.join(dstAbs, outName), Buffer.concat(parts))
  }
}
