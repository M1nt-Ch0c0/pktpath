// Pure TypeScript port of studio/pkg/wire/wire.go (erasableSyntaxOnly).
// Zero external dependencies; uses Node 24 built-in zlib.crc32 (IEEE CRC32).

import * as fs from 'node:fs'
import * as path from 'node:path'
import * as zlib from 'node:zlib'
import {
  BLOCK_DICT_DELTA,
  BLOCK_END_MARKER,
  BLOCK_FLAG_ZSTD,
  BLOCK_HDR_SIZE,
  BLOCK_MAGIC,
  BLOCK_QUALITY_CHECKPOINT,
  CRC32_SIZE,
  EVENT_HDR_SIZE,
  KNOWN_TLVS,
  MAX_PAYLOAD_LEN,
  TLV_HDR_SIZE,
  TLV_MUST_UNDERSTAND,
  TLV_QUAL_SITE_DICT_IDX,
  WIRE_MAJOR,
} from './consts.ts'
import type { TlvCodec } from './consts.ts'

export type WireErrorKind =
  | 'wire'
  | 'magic'
  | 'version'
  | 'payload_too_large'
  | 'crc'
  | 'truncated'
  | 'uuid_mismatch'
  | 'zstd_unsupported'

export class WireError extends Error {
  readonly kind: WireErrorKind

  constructor(kind: WireErrorKind, message: string) {
    super(message)
    this.name = 'WireError'
    this.kind = kind
  }
}

export interface Tlv {
  tag: number
  val: Uint8Array
}

export interface UnknownTlv {
  tag: number
  length: number
  raw: Uint8Array
  must_understand: boolean
}

export function unknownTlvRawHex(u: UnknownTlv): string {
  return Buffer.from(u.raw).toString('hex')
}

export function unknownTlvTagHex(u: UnknownTlv): string {
  return '0x' + u.tag.toString(16).padStart(4, '0')
}

export interface DedupKey {
  producer: number
  cpu: number
  seq: bigint
}

export class WireEvent {
  total_len: number
  kind: number
  object_type: number
  evidence_level: number
  site_dict_idx: number
  cpu: number
  flags: number
  seq: bigint
  ts_ns: bigint
  object_id: bigint
  producer_type: number
  epoch: number
  block_no: number

  readonly nums: Map<string, bigint>
  readonly strs: Map<string, string>
  readonly bins: Map<string, Uint8Array>

  raw_tlvs: Tlv[]
  unknown_optional: UnknownTlv[]
  unknown_must: UnknownTlv[]

  constructor(init?: Partial<{
    total_len: number
    kind: number
    object_type: number
    evidence_level: number
    site_dict_idx: number
    cpu: number
    flags: number
    seq: bigint
    ts_ns: bigint
    object_id: bigint
    producer_type: number
    epoch: number
    block_no: number
  }>) {
    this.total_len = init?.total_len ?? 0
    this.kind = init?.kind ?? 0
    this.object_type = init?.object_type ?? 0
    this.evidence_level = init?.evidence_level ?? 0
    this.site_dict_idx = init?.site_dict_idx ?? 0
    this.cpu = init?.cpu ?? 0
    this.flags = init?.flags ?? 0
    this.seq = init?.seq ?? 0n
    this.ts_ns = init?.ts_ns ?? 0n
    this.object_id = init?.object_id ?? 0n
    this.producer_type = init?.producer_type ?? 0
    this.epoch = init?.epoch ?? 0
    this.block_no = init?.block_no ?? 0

    this.nums = new Map<string, bigint>()
    this.strs = new Map<string, string>()
    this.bins = new Map<string, Uint8Array>()
    this.raw_tlvs = []
    this.unknown_optional = []
    this.unknown_must = []
  }

  eventId(): string {
    return `p${this.producer_type}:c${this.cpu}:s${this.seq.toString()}`
  }

  dedupKey(): string {
    return `${this.producer_type}:${this.cpu}:${this.seq.toString()}`
  }

  get(name: string): bigint | undefined {
    return this.nums.get(name)
  }

  u(name: string): bigint {
    return this.nums.get(name) ?? 0n
  }

  num(name: string): number {
    return Number(this.nums.get(name) ?? 0n)
  }

  i(name: string): bigint | undefined {
    const v = this.nums.get(name)
    if (v === undefined) return undefined
    // Interpret stored u64 two's complement as signed i64.
    return BigInt.asIntN(64, v)
  }

  has(name: string): boolean {
    return this.nums.has(name) || this.strs.has(name) || this.bins.has(name)
  }

  str(name: string): string | undefined {
    return this.strs.get(name)
  }

  bin(name: string): Uint8Array | undefined {
    return this.bins.get(name)
  }

  addUnknown(u: UnknownTlv): void {
    if (u.must_understand) {
      this.unknown_must.push(u)
    } else {
      this.unknown_optional.push(u)
    }
  }
}

export interface BlockHeader {
  magic: number
  major: number
  minor: number
  block_type: number
  producer_type: number
  flags: number
  payload_len: number
  epoch: number
  block_no: number
  reserved: number
  session_uuid: Uint8Array // 16 bytes
  min_ts_ns: bigint
  max_ts_ns: bigint
}

export interface BlockRecord {
  header: BlockHeader
  crc32: number
  source_file: string
  events: WireEvent[]
  meta_payload?: Record<string, unknown>
}

export interface LoadedSession {
  run_dir: string
  manifest: Record<string, unknown>
  dictionary: Record<string, unknown>
  blocks: BlockRecord[]
  events: WireEvent[]
  session_uuid: Uint8Array // 16 bytes
  has_end_marker: boolean
  has_corrupted_tail: boolean
  tail_errors: string[]
  last_quality_checkpoint_ts_ns: bigint
}

export function isUncleanTail(ls: LoadedSession): boolean {
  return !ls.has_end_marker || ls.has_corrupted_tail
}

export function formatUUID(u: Uint8Array): string {
  const h = Buffer.from(u.subarray(0, 16)).toString('hex')
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`
}

export function parseUUID(s: string): Uint8Array {
  let c = s.trim().toLowerCase()
  if (c.startsWith('urn:uuid:')) c = c.slice(9)
  c = c.replace(/^\{+|\}+$/g, '').replace(/-/g, '')
  if (c.length !== 32 || !/^[0-9a-f]{32}$/.test(c)) {
    throw new WireError('wire', `badly formed hexadecimal UUID string: ${JSON.stringify(s)}`)
  }
  return new Uint8Array(Buffer.from(c, 'hex'))
}

function uuidEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== 16 || b.length !== 16) return false
  for (let i = 0; i < 16; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}

export function formatIP(b: Uint8Array): string {
  if (b.length === 4) {
    return `${b[0]}.${b[1]}.${b[2]}.${b[3]}`
  }
  if (b.length === 16) {
    // Check IPv4-mapped IPv6 ::ffff:a.b.c.d (RFC 5952 / Go netip)
    let isV4Mapped = true
    for (let i = 0; i < 10; i++) {
      if (b[i] !== 0) {
        isV4Mapped = false
        break
      }
    }
    if (isV4Mapped && b[10] === 0xff && b[11] === 0xff) {
      return `::ffff:${b[12]}.${b[13]}.${b[14]}.${b[15]}`
    }
    const groups: number[] = []
    for (let i = 0; i < 16; i += 2) {
      groups.push((b[i]! << 8) | b[i + 1]!)
    }
    // Find longest run of zeros (length >= 2)
    let bestStart = -1
    let bestLen = 0
    let curStart = -1
    let curLen = 0
    for (let i = 0; i < 8; i++) {
      if (groups[i] === 0) {
        if (curStart === -1) curStart = i
        curLen++
        if (curLen > bestLen) {
          bestLen = curLen
          bestStart = curStart
        }
      } else {
        curStart = -1
        curLen = 0
      }
    }
    if (bestLen < 2) {
      bestStart = -1
      bestLen = 0
    }
    const parts: string[] = []
    for (let i = 0; i < 8; ) {
      if (i === bestStart) {
        parts.push('')
        if (i === 0) parts.push('')
        i += bestLen
        if (i === 8) parts.push('')
      } else {
        parts.push(groups[i]!.toString(16))
        i++
      }
    }
    return parts.join(':')
  }
  return Buffer.from(b).toString('hex')
}

export function decodeBlockHeader(buf: Uint8Array): BlockHeader {
  const b = Buffer.from(buf.buffer, buf.byteOffset, buf.byteLength)
  if (b.length < BLOCK_HDR_SIZE) {
    if (b.length >= 4) {
      const m = b.readUInt32LE(0)
      if (m !== BLOCK_MAGIC) {
        throw new WireError(
          'magic',
          `Invalid block magic 0x${m.toString(16).padStart(8, '0')} (expected 0x${BLOCK_MAGIC.toString(16).padStart(8, '0')})`,
        )
      }
    }
    throw new WireError('truncated', `Truncated block header: expected ${BLOCK_HDR_SIZE} bytes, got ${b.length}`)
  }
  const magic = b.readUInt32LE(0)
  const major = b.readUInt16LE(4)
  const minor = b.readUInt16LE(6)
  const block_type = b.readUInt16LE(8)
  const producer_type = b.readUInt16LE(10)
  const flags = b.readUInt32LE(12)
  const payload_len = b.readUInt32LE(16)
  const epoch = b.readUInt32LE(20)
  const block_no = b.readUInt32LE(24)
  const reserved = b.readUInt32LE(28)
  const session_uuid = new Uint8Array(16)
  session_uuid.set(b.subarray(32, 48))
  const min_ts_ns = b.readBigUInt64LE(48)
  const max_ts_ns = b.readBigUInt64LE(56)

  if (magic !== BLOCK_MAGIC) {
    throw new WireError(
      'magic',
      `Invalid block magic 0x${magic.toString(16).padStart(8, '0')} (expected 0x${BLOCK_MAGIC.toString(16).padStart(8, '0')})`,
    )
  }
  if (major !== WIRE_MAJOR) {
    throw new WireError('version', `Incompatible wire major version ${major}.${minor} (expected major=${WIRE_MAJOR})`)
  }
  if (payload_len > MAX_PAYLOAD_LEN) {
    throw new WireError('payload_too_large', `Block payload_len ${payload_len} exceeds 16 MiB cap (${MAX_PAYLOAD_LEN})`)
  }
  return {
    magic,
    major,
    minor,
    block_type,
    producer_type,
    flags,
    payload_len,
    epoch,
    block_no,
    reserved,
    session_uuid,
    min_ts_ns,
    max_ts_ns,
  }
}

export function encodeBlockHeader(h: BlockHeader): Uint8Array {
  const b = Buffer.alloc(BLOCK_HDR_SIZE)
  b.writeUInt32LE(h.magic >>> 0, 0)
  b.writeUInt16LE(h.major & 0xffff, 4)
  b.writeUInt16LE(h.minor & 0xffff, 6)
  b.writeUInt16LE(h.block_type & 0xffff, 8)
  b.writeUInt16LE(h.producer_type & 0xffff, 10)
  b.writeUInt32LE(h.flags >>> 0, 12)
  b.writeUInt32LE(h.payload_len >>> 0, 16)
  b.writeUInt32LE(h.epoch >>> 0, 20)
  b.writeUInt32LE(h.block_no >>> 0, 24)
  b.writeUInt32LE(h.reserved >>> 0, 28)
  b.set(h.session_uuid.subarray(0, 16), 32)
  b.writeBigUInt64LE(BigInt.asUintN(64, h.min_ts_ns), 48)
  b.writeBigUInt64LE(BigInt.asUintN(64, h.max_ts_ns), 56)
  return new Uint8Array(b.buffer, b.byteOffset, b.byteLength)
}

function scalarLen(codec: TlvCodec): number {
  switch (codec) {
    case 'u8':
      return 1
    case 'u16':
      return 2
    case 'u32':
    case 's32':
      return 4
    case 'u64':
      return 8
    default:
      return -1
  }
}

export function decodeEvent(
  buf: Uint8Array,
  offset: number,
  producerType: number,
  epoch: number,
  blockNo: number,
): { event: WireEvent; nextOffset: number } {
  const rem = buf.length - offset
  if (rem < EVENT_HDR_SIZE) {
    throw new WireError('truncated', `Truncated event header at offset ${offset}: ${rem} < ${EVENT_HDR_SIZE}`)
  }
  const b = Buffer.from(buf.buffer, buf.byteOffset + offset, rem)
  const ev = new WireEvent({
    total_len: b.readUInt16LE(0),
    kind: b.readUInt16LE(2),
    object_type: b[4]!,
    evidence_level: b[5]!,
    site_dict_idx: b.readUInt16LE(6),
    cpu: b.readUInt32LE(8),
    flags: b.readUInt32LE(12),
    seq: b.readBigUInt64LE(16),
    ts_ns: b.readBigUInt64LE(24),
    object_id: b.readBigUInt64LE(32),
    producer_type: producerType,
    epoch,
    block_no: blockNo,
  })
  const total = ev.total_len
  if (total < EVENT_HDR_SIZE) {
    throw new WireError('wire', `Invalid event total_len ${total} (< ${EVENT_HDR_SIZE})`)
  }
  if (total > rem) {
    throw new WireError('truncated', `Truncated event payload at offset ${offset}: need ${total}, have ${rem}`)
  }

  let pos = EVENT_HDR_SIZE
  while (pos < total) {
    if (total - pos < TLV_HDR_SIZE) {
      throw new WireError('truncated', `Truncated TLV header at byte ${offset + pos}`)
    }
    const tag = b.readUInt16LE(pos)
    const tlen = b.readUInt16LE(pos + 2)
    pos += TLV_HDR_SIZE
    if (total - pos < tlen) {
      throw new WireError(
        'truncated',
        `Truncated TLV 0x${tag.toString(16).padStart(4, '0')} value: need ${tlen}, have ${total - pos}`,
      )
    }
    const val = new Uint8Array(tlen)
    val.set(b.subarray(pos, pos + tlen))
    pos += tlen
    ev.raw_tlvs.push({ tag, val })

    const must = (tag & TLV_MUST_UNDERSTAND) !== 0
    const base = tag & 0x7fff
    const unk: UnknownTlv = { tag, length: tlen, raw: val, must_understand: must }
    const spec = KNOWN_TLVS.get(base)
    if (!spec) {
      ev.addUnknown(unk)
      continue
    }

    const vb = Buffer.from(val.buffer, val.byteOffset, val.byteLength)
    switch (spec.codec) {
      case 'u8':
      case 'u16':
      case 'u32':
      case 's32':
      case 'u64': {
        if (tlen !== scalarLen(spec.codec)) {
          ev.addUnknown(unk)
          continue
        }
        let v: bigint
        switch (spec.codec) {
          case 'u8':
            v = BigInt(vb[0]!)
            break
          case 'u16':
            v = BigInt(vb.readUInt16LE(0))
            break
          case 'u32':
            v = BigInt(vb.readUInt32LE(0))
            break
          case 's32':
            v = BigInt.asUintN(64, BigInt(vb.readInt32LE(0)))
            break
          case 'u64':
            v = vb.readBigUInt64LE(0)
            break
        }
        ev.nums.set(spec.name, v)
        if (base === TLV_QUAL_SITE_DICT_IDX && !ev.nums.has('site_dict_idx')) {
          ev.nums.set('site_dict_idx', v)
        }
        break
      }
      case 'ip': {
        if (tlen === 4 || tlen === 16) {
          ev.strs.set(spec.name, formatIP(val))
          ev.bins.set(spec.name + '_raw', val)
        } else {
          ev.addUnknown(unk)
        }
        break
      }
      case 'comm': {
        ev.bins.set('comm_raw', val)
        let nul = val.indexOf(0)
        const slice = nul >= 0 ? val.subarray(0, nul) : val
        ev.strs.set(spec.name, new TextDecoder('utf-8', { fatal: false }).decode(slice))
        break
      }
      case 'bytes': {
        ev.bins.set(spec.name, val)
        break
      }
    }
  }
  return { event: ev, nextOffset: offset + total }
}

export function encodeEvent(ev: WireEvent, tlvs?: Tlv[]): Uint8Array {
  const list = tlvs ?? ev.raw_tlvs
  let bodyLen = 0
  for (const t of list) {
    bodyLen += TLV_HDR_SIZE + t.val.length
  }
  const totalLen = EVENT_HDR_SIZE + bodyLen
  const out = Buffer.alloc(totalLen)
  out.writeUInt16LE(totalLen & 0xffff, 0)
  out.writeUInt16LE(ev.kind & 0xffff, 2)
  out[4] = ev.object_type & 0xff
  out[5] = ev.evidence_level & 0xff
  out.writeUInt16LE(ev.site_dict_idx & 0xffff, 6)
  out.writeUInt32LE(ev.cpu >>> 0, 8)
  out.writeUInt32LE(ev.flags >>> 0, 12)
  out.writeBigUInt64LE(BigInt.asUintN(64, ev.seq), 16)
  out.writeBigUInt64LE(BigInt.asUintN(64, ev.ts_ns), 24)
  out.writeBigUInt64LE(BigInt.asUintN(64, ev.object_id), 32)
  let pos = EVENT_HDR_SIZE
  for (const t of list) {
    out.writeUInt16LE(t.tag & 0xffff, pos)
    out.writeUInt16LE(t.val.length & 0xffff, pos + 2)
    pos += TLV_HDR_SIZE
    out.set(t.val, pos)
    pos += t.val.length
  }
  return new Uint8Array(out.buffer, out.byteOffset, out.byteLength)
}

export function encodeBlock(header: BlockHeader, payload: Uint8Array): Uint8Array {
  if (payload.length > MAX_PAYLOAD_LEN) {
    throw new WireError('payload_too_large', `Payload length ${payload.length} exceeds ${MAX_PAYLOAD_LEN}`)
  }
  const hdr: BlockHeader = { ...header, payload_len: payload.length }
  const hdrBytes = encodeBlockHeader(hdr)
  const out = Buffer.alloc(BLOCK_HDR_SIZE + payload.length + CRC32_SIZE)
  out.set(hdrBytes, 0)
  out.set(payload, BLOCK_HDR_SIZE)
  const crc = zlib.crc32(out.subarray(0, BLOCK_HDR_SIZE + payload.length)) >>> 0
  out.writeUInt32LE(crc, BLOCK_HDR_SIZE + payload.length)
  return new Uint8Array(out.buffer, out.byteOffset, out.byteLength)
}

function decodeJSONObject(buf: Uint8Array): Record<string, unknown> {
  let s = Buffer.from(buf).toString('utf8')
  if (s.charCodeAt(0) === 0xfeff) s = s.slice(1)
  const parsed = JSON.parse(s) as unknown
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('JSON root is not an object')
  }
  return parsed as Record<string, unknown>
}

export function decodeBlocksFromBuffer(
  data: Uint8Array,
  sourceName: string,
): { blocks: BlockRecord[]; error?: WireError } {
  const blocks: BlockRecord[] = []
  let off = 0
  const b = Buffer.from(data.buffer, data.byteOffset, data.byteLength)
  while (off < b.length) {
    const rem = b.length - off
    let header: BlockHeader
    try {
      header = decodeBlockHeader(b.subarray(off, Math.min(b.length, off + BLOCK_HDR_SIZE)))
    } catch (err) {
      return { blocks, error: err instanceof WireError ? err : new WireError('wire', String(err)) }
    }
    const need = BLOCK_HDR_SIZE + header.payload_len + CRC32_SIZE
    if (rem < BLOCK_HDR_SIZE + header.payload_len) {
      return {
        blocks,
        error: new WireError(
          'truncated',
          `Truncated block payload in ${sourceName}: expected ${header.payload_len}, got ${rem - BLOCK_HDR_SIZE}`,
        ),
      }
    }
    if (rem < need) {
      return {
        blocks,
        error: new WireError('truncated', `Truncated block CRC32 trailer in ${sourceName}`),
      }
    }
    const blockBody = b.subarray(off, off + BLOCK_HDR_SIZE + header.payload_len)
    const payload = b.subarray(off + BLOCK_HDR_SIZE, off + BLOCK_HDR_SIZE + header.payload_len)
    const expected = b.readUInt32LE(off + BLOCK_HDR_SIZE + header.payload_len)
    const actual = zlib.crc32(blockBody) >>> 0
    if (actual !== expected) {
      return {
        blocks,
        error: new WireError(
          'crc',
          `CRC32 mismatch in ${sourceName} block #${header.block_no}: expected 0x${expected.toString(16).padStart(8, '0')}, computed 0x${actual.toString(16).padStart(8, '0')}`,
        ),
      }
    }
    if ((header.flags & BLOCK_FLAG_ZSTD) !== 0) {
      return {
        blocks,
        error: new WireError(
          'zstd_unsupported',
          `Block has ZSTD flag set in ${sourceName}, but zstd decompression is unavailable`,
        ),
      }
    }
    const rec: BlockRecord = {
      header,
      crc32: expected,
      source_file: sourceName,
      events: [],
    }
    if (payload.length > 0) {
      const isMeta =
        header.block_type === BLOCK_DICT_DELTA ||
        header.block_type === BLOCK_END_MARKER ||
        header.block_type === BLOCK_QUALITY_CHECKPOINT
      if (isMeta && payload[0] === 0x7b) {
        try {
          rec.meta_payload = decodeJSONObject(payload)
        } catch (err) {
          return {
            blocks,
            error: new WireError('wire', `Malformed JSON payload in ${sourceName}: ${String(err)}`),
          }
        }
      } else {
        let evOff = 0
        while (evOff < payload.length) {
          try {
            const { event, nextOffset } = decodeEvent(
              payload,
              evOff,
              header.producer_type,
              header.epoch,
              header.block_no,
            )
            rec.events.push(event)
            evOff = nextOffset
          } catch (err) {
            return { blocks, error: err instanceof WireError ? err : new WireError('wire', String(err)) }
          }
        }
      }
    }
    blocks.push(rec)
    off += need
  }
  return { blocks }
}

export function decodeBlock(data: Uint8Array, sourceName = '<mem>'): BlockRecord {
  if (data.length === 0) {
    throw new WireError('truncated', `Empty block buffer in ${sourceName}`)
  }
  const { blocks, error } = decodeBlocksFromBuffer(data, sourceName)
  if (error) throw error
  if (blocks.length === 0) {
    throw new WireError('truncated', `Empty block buffer in ${sourceName}`)
  }
  return blocks[0]!
}

export function isRegularFile(p: string): boolean {
  try {
    const st = fs.statSync(p)
    return st.isFile()
  } catch {
    return false
  }
}

function readRegularJSONFile(p: string): Record<string, unknown> {
  if (!isRegularFile(p)) {
    throw new Error(`not a regular file: ${p}`)
  }
  const b = fs.readFileSync(p)
  try {
    return decodeJSONObject(b)
  } catch (err) {
    throw new Error(`${path.basename(p)}: ${String(err)}`)
  }
}

function mergeDictDelta(d: Record<string, unknown>, delta: Record<string, unknown>): void {
  if (Array.isArray(delta['sites'])) {
    const existing = new Map<number, Record<string, unknown>>()
    const add = (s: unknown): void => {
      if (typeof s !== 'object' || s === null || Array.isArray(s)) return
      const m = s as Record<string, unknown>
      const idx = asInt(m['site_idx'])
      if (idx === undefined) return
      existing.set(idx, m)
    }
    if (Array.isArray(d['sites'])) {
      for (const s of d['sites']) add(s)
    }
    for (const s of delta['sites']) add(s)
    const keys = [...existing.keys()].sort((a, b) => a - b)
    d['sites'] = keys.map((k) => existing.get(k)!)
  }
  if (Array.isArray(delta['topology_epochs'])) {
    const cur = Array.isArray(d['topology_epochs']) ? d['topology_epochs'] : []
    d['topology_epochs'] = [...cur, ...delta['topology_epochs']]
  }
}

export function asInt(v: unknown): number | undefined {
  if (typeof v === 'number' && Number.isFinite(v)) return Math.trunc(v)
  if (typeof v === 'bigint') return Number(v)
  if (typeof v === 'boolean') return v ? 1 : 0
  if (typeof v === 'string' && v.trim() !== '') {
    const n = Number(v.trim())
    if (Number.isFinite(n)) return Math.trunc(n)
  }
  return undefined
}

export function asBigInt(v: unknown): bigint | undefined {
  if (typeof v === 'bigint') return v
  if (typeof v === 'number' && Number.isFinite(v)) return BigInt(Math.trunc(v))
  if (typeof v === 'boolean') return v ? 1n : 0n
  if (typeof v === 'string' && /^-?\d+$/.test(v.trim())) {
    return BigInt(v.trim())
  }
  return undefined
}

export function intOr(v: unknown, def: number): number {
  const n = asInt(v)
  return n !== undefined ? n : def
}

export function truthy(v: unknown): boolean {
  if (v === null || v === undefined) return false
  if (typeof v === 'boolean') return v
  if (typeof v === 'string') return v.length > 0
  if (typeof v === 'number') return v !== 0
  if (typeof v === 'bigint') return v !== 0n
  if (Array.isArray(v)) return v.length > 0
  if (typeof v === 'object') return Object.keys(v as Record<string, unknown>).length > 0
  return true
}

export function loadSession(runDir: string, strictTail = false): LoadedSession {
  let st: fs.Stats
  try {
    st = fs.statSync(runDir)
  } catch {
    throw new Error(`session directory not found: ${runDir}`)
  }
  if (!st.isDirectory()) {
    throw new Error(`session directory not found: ${runDir}`)
  }

  let manifest: Record<string, unknown> = {}
  const manifestPath = path.join(runDir, 'manifest.json')
  if (isRegularFile(manifestPath)) {
    manifest = readRegularJSONFile(manifestPath)
  }

  const dictionary: Record<string, unknown> = { sites: [], topology_epochs: [] }
  const dictPath = path.join(runDir, 'dict.json')
  if (isRegularFile(dictPath)) {
    const dm = readRegularJSONFile(dictPath)
    for (const [k, v] of Object.entries(dm)) {
      dictionary[k] = v
    }
  }

  let expected: Uint8Array | undefined
  if (typeof manifest['session_uuid'] === 'string' && manifest['session_uuid'] !== '') {
    expected = parseUUID(manifest['session_uuid'])
  }

  const entries = fs.readdirSync(runDir, { withFileTypes: true })
  const regularNames = entries
    .filter((e) => !e.isDirectory() && isRegularFile(path.join(runDir, e.name)))
    .map((e) => e.name)
    .sort()

  let blockNames = regularNames.filter((n) => n.startsWith('block_') && n.endsWith('.pktb'))
  if (blockNames.length === 0) {
    blockNames = regularNames.filter((n) => n.endsWith('.pktb'))
  }

  const ls: LoadedSession = {
    run_dir: runDir,
    manifest,
    dictionary,
    blocks: [],
    events: [],
    session_uuid: new Uint8Array(16),
    has_end_marker: false,
    has_corrupted_tail: false,
    tail_errors: [],
    last_quality_checkpoint_ts_ns: 0n,
  }

  const tmpNames = regularNames.filter((n) => n.endsWith('.tmp'))
  if (tmpNames.length > 0) {
    ls.tail_errors.push(`Uncommitted temporary files present: ${tmpNames.join(', ')}`)
  }

  for (let fileIdx = 0; fileIdx < blockNames.length; fileIdx++) {
    const name = blockNames[fileIdx]!
    const isLast = fileIdx === blockNames.length - 1
    const fullPath = path.join(runDir, name)
    const buf = fs.readFileSync(fullPath)
    if (buf.length === 0) {
      if (strictTail) {
        throw new WireError('truncated', `Zero-length block file ${name}`)
      }
      ls.has_corrupted_tail = true
      ls.tail_errors.push(`Zero-length trailing block file ${name}`)
      break
    }

    const { blocks, error } = decodeBlocksFromBuffer(buf, name)
    for (const blk of blocks) {
      if (!expected) {
        expected = blk.header.session_uuid
      } else if (!uuidEqual(blk.header.session_uuid, expected)) {
        throw new WireError(
          'uuid_mismatch',
          `Session UUID mismatch in ${name}: got ${formatUUID(blk.header.session_uuid)}, expected ${formatUUID(expected)}`,
        )
      }
      ls.blocks.push(blk)
      for (const ev of blk.events) ls.events.push(ev)
      switch (blk.header.block_type) {
        case BLOCK_QUALITY_CHECKPOINT:
          if (blk.header.max_ts_ns > ls.last_quality_checkpoint_ts_ns) {
            ls.last_quality_checkpoint_ts_ns = blk.header.max_ts_ns
          }
          for (const ev of blk.events) {
            if (ev.ts_ns > ls.last_quality_checkpoint_ts_ns) {
              ls.last_quality_checkpoint_ts_ns = ev.ts_ns
            }
            const w = ev.u('win_end_ns')
            if (w > ls.last_quality_checkpoint_ts_ns) {
              ls.last_quality_checkpoint_ts_ns = w
            }
          }
          break
        case BLOCK_DICT_DELTA:
          if (blk.meta_payload) {
            mergeDictDelta(ls.dictionary, blk.meta_payload)
          }
          break
        case BLOCK_END_MARKER:
          ls.has_end_marker = true
          if (blk.meta_payload && 'admissions' in blk.meta_payload && !truthy(ls.manifest['admissions'])) {
            ls.manifest['admissions'] = blk.meta_payload['admissions']
          }
          break
      }
    }

    if (error) {
      if (error.kind === 'crc' || error.kind === 'truncated') {
        if (strictTail) throw error
        if (isLast || ls.blocks.length > 0) {
          ls.has_corrupted_tail = true
          ls.tail_errors.push(error.message)
          break
        }
      }
      throw error
    }
  }

  if (expected) {
    ls.session_uuid = expected
  }
  return ls
}
