import { describe, it } from 'node:test'
import * as assert from 'node:assert/strict'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'

import {
  BLOCK_END_MARKER,
  BLOCK_EVENT_BATCH,
  BLOCK_MAGIC,
  DIR_TX,
  END_TX_OK,
  EVIDENCE_DIRECT,
  KIND_OBJECT,
  KIND_STEP,
  KIND_SUMMARY,
  LINK_TYPE_RAW_IP,
  OBJ_SKB,
  PROD_CONTROLLER,
  PROD_KERNEL_BPF,
  STAGE_XMIT_RET,
  TLV_MUST_UNDERSTAND,
  TLV_OBJ_END_REASON,
  TLV_OBJ_SAMPLE_ID,
  TLV_STEP_RAW_RET,
  TLV_STEP_STAGE,
  TLV_SUM_COMM,
  TLV_SUM_DST_IP,
  TLV_SUM_LINKTYPE,
  TLV_SUM_PKT_LEN,
  TLV_SUM_SRC_IP,
  WIRE_MAJOR,
  WIRE_MINOR,
} from '../../src/plugins/analysis/wire/consts.ts'
import {
  WireError,
  WireEvent,
  decodeBlock,
  encodeBlock,
  encodeEvent,
  formatIP,
  formatUUID,
  isUncleanTail,
  loadSession,
  parseUUID,
} from '../../src/plugins/analysis/wire/wire.ts'

function u8(v: number): Uint8Array {
  return Uint8Array.of(v & 0xff)
}
function u16(v: number): Uint8Array {
  const b = Buffer.alloc(2)
  b.writeUInt16LE(v & 0xffff, 0)
  return new Uint8Array(b)
}
function u32(v: number): Uint8Array {
  const b = Buffer.alloc(4)
  b.writeUInt32LE(v >>> 0, 0)
  return new Uint8Array(b)
}
function s32(v: number): Uint8Array {
  const b = Buffer.alloc(4)
  b.writeInt32LE(v, 0)
  return new Uint8Array(b)
}
function u64(v: bigint): Uint8Array {
  const b = Buffer.alloc(8)
  b.writeBigUInt64LE(BigInt.asUintN(64, v), 0)
  return new Uint8Array(b)
}

describe('wire binary codec (pure TS / Node 24)', () => {
  it('round-trips block/event/TLV including u64 > 2^53-1 and signed raw_ret', () => {
    const uuidStr = '12345678-1234-4123-8123-123456789abc'
    const uuid = parseUUID(uuidStr)
    assert.equal(formatUUID(uuid), uuidStr)

    const hugeSampleId = 18446744073709551613n // > Number.MAX_SAFE_INTEGER
    const hugeObjId = 9007199254740995n
    const evObj = new WireEvent({
      kind: KIND_OBJECT,
      object_type: OBJ_SKB,
      evidence_level: EVIDENCE_DIRECT,
      cpu: 2,
      seq: 100n,
      ts_ns: 1700000000123456789n,
      object_id: hugeObjId,
    })
    const b1 = encodeEvent(evObj, [
      { tag: TLV_OBJ_SAMPLE_ID, val: u64(hugeSampleId) },
      { tag: TLV_OBJ_END_REASON, val: u16(END_TX_OK) },
    ])

    const evStep = new WireEvent({
      kind: KIND_STEP,
      object_type: OBJ_SKB,
      evidence_level: EVIDENCE_DIRECT,
      cpu: 2,
      seq: 101n,
      ts_ns: 1700000000123457000n,
      object_id: hugeObjId,
    })
    const b2 = encodeEvent(evStep, [
      { tag: TLV_STEP_STAGE, val: u8(STAGE_XMIT_RET) },
      { tag: TLV_STEP_RAW_RET, val: s32(-16) }, // -EBUSY
      { tag: 0x07fe | TLV_MUST_UNDERSTAND, val: Uint8Array.of(0xde, 0xad) },
    ])

    const evSum = new WireEvent({
      kind: KIND_SUMMARY,
      object_type: OBJ_SKB,
      evidence_level: EVIDENCE_DIRECT,
      cpu: 2,
      seq: 102n,
      ts_ns: 1700000000123457100n,
      object_id: hugeObjId,
    })
    const b3 = encodeEvent(evSum, [
      { tag: TLV_SUM_PKT_LEN, val: u32(1420) },
      { tag: TLV_SUM_SRC_IP, val: Uint8Array.of(10, 0, 0, 1) },
      { tag: TLV_SUM_DST_IP, val: Uint8Array.of(0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1) },
      { tag: TLV_SUM_COMM, val: Buffer.from('curl\0\0\0\0') },
      { tag: TLV_SUM_LINKTYPE, val: u16(LINK_TYPE_RAW_IP) },
    ])

    const payload = Buffer.concat([b1, b2, b3])
    const blkBytes = encodeBlock(
      {
        magic: BLOCK_MAGIC,
        major: WIRE_MAJOR,
        minor: WIRE_MINOR,
        block_type: BLOCK_EVENT_BATCH,
        producer_type: PROD_KERNEL_BPF,
        flags: 0,
        payload_len: 0,
        epoch: 1,
        block_no: 1,
        reserved: 0,
        session_uuid: uuid,
        min_ts_ns: 1700000000123456789n,
        max_ts_ns: 1700000000123457100n,
      },
      payload,
    )

    const decoded = decodeBlock(blkBytes, 'test.pktb')
    assert.equal(decoded.events.length, 3)
    assert.equal(decoded.events[0]!.u('sample_id'), hugeSampleId)
    assert.equal(decoded.events[0]!.object_id, hugeObjId)
    assert.equal(decoded.events[0]!.ts_ns, 1700000000123456789n)
    assert.equal(decoded.events[1]!.i('raw_ret'), -16n)
    assert.equal(decoded.events[1]!.unknown_must.length, 1)
    assert.equal(decoded.events[2]!.str('src_ip'), '10.0.0.1')
    assert.equal(decoded.events[2]!.str('dst_ip'), '2001:db8::1')
    assert.equal(decoded.events[2]!.str('comm'), 'curl')
    assert.equal(decoded.events[2]!.num('pkt_len'), 1420)

    // Corrupt 1 byte -> must fail CRC32
    const bad = new Uint8Array(blkBytes)
    bad[bad.length - 10]! ^= 0xff
    assert.throws(() => decodeBlock(bad, 'bad.pktb'), (err: unknown) => {
      return err instanceof WireError && err.kind === 'crc'
    })
  })

  it('formats IPv4, IPv6, and IPv4-mapped IPv6 identically to Go netip', () => {
    assert.equal(formatIP(Uint8Array.of(192, 168, 1, 1)), '192.168.1.1')
    assert.equal(formatIP(new Uint8Array(16)), '::')
    assert.equal(
      formatIP(Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1)),
      '::ffff:192.0.2.1',
    )
    assert.equal(
      formatIP(Uint8Array.of(0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)),
      'fe80::1',
    )
  })

  it('tolerates corrupted trailing block when strictTail=false and rejects when strictTail=true', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pktpath-wire-test-'))
    try {
      const uuidStr = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
      const uuid = parseUUID(uuidStr)
      fs.writeFileSync(path.join(tmp, 'manifest.json'), JSON.stringify({ session_uuid: uuidStr, dev: 'eth0' }))
      const ev = encodeEvent(
        new WireEvent({ kind: KIND_OBJECT, object_type: OBJ_SKB, evidence_level: EVIDENCE_DIRECT, seq: 1n, ts_ns: 1000n, object_id: 1n }),
        [{ tag: TLV_OBJ_SAMPLE_ID, val: u64(1n) }, { tag: TLV_OBJ_END_REASON, val: u16(END_TX_OK) }],
      )
      const blk1 = encodeBlock(
        {
          magic: BLOCK_MAGIC, major: WIRE_MAJOR, minor: WIRE_MINOR,
          block_type: BLOCK_EVENT_BATCH, producer_type: PROD_KERNEL_BPF,
          flags: 0, payload_len: 0, epoch: 1, block_no: 1, reserved: 0,
          session_uuid: uuid, min_ts_ns: 1000n, max_ts_ns: 1000n,
        },
        ev,
      )
      fs.writeFileSync(path.join(tmp, 'block_000001.pktb'), blk1)
      // Truncated trailing block
      fs.writeFileSync(path.join(tmp, 'block_000002.pktb'), blk1.subarray(0, 20))

      const tolerant = loadSession(tmp, false)
      assert.equal(tolerant.events.length, 1)
      assert.equal(tolerant.has_corrupted_tail, true)
      assert.equal(isUncleanTail(tolerant), true)

      assert.throws(() => loadSession(tmp, true), (err: unknown) => err instanceof WireError && err.kind === 'truncated')

      // Replace with clean END_MARKER
      const blkEnd = encodeBlock(
        {
          magic: BLOCK_MAGIC, major: WIRE_MAJOR, minor: WIRE_MINOR,
          block_type: BLOCK_END_MARKER, producer_type: PROD_CONTROLLER,
          flags: 0, payload_len: 0, epoch: 1, block_no: 2, reserved: 0,
          session_uuid: uuid, min_ts_ns: 1000n, max_ts_ns: 1000n,
        },
        new Uint8Array(0),
      )
      fs.writeFileSync(path.join(tmp, 'block_000002.pktb'), blkEnd)
      const clean = loadSession(tmp, true)
      assert.equal(clean.has_end_marker, true)
      assert.equal(isUncleanTail(clean), false)
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true })
    }
  })
})
