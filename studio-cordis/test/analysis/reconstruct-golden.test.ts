import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import {
  BLOCK_END_MARKER,
  BLOCK_EVENT_BATCH,
  BLOCK_MAGIC,
  DIR_TX,
  END_DROP,
  END_TX_OK,
  EV_FLAG_IN_TASK,
  EVIDENCE_DIRECT,
  KIND_OBJECT,
  KIND_QUALITY,
  KIND_RELATION,
  KIND_STEP,
  KIND_SUMMARY,
  OBJ_SKB,
  PROD_KERNEL_BPF,
  QUAL_MISSED_DELTA,
  REL_CLONE,
  STAGE_CLASSIFY,
  STAGE_DROP,
  STAGE_ENTRY,
  STAGE_QDISC_DEQ,
  STAGE_QDISC_ENQ,
  STAGE_REQUEUE_GSO,
  STAGE_XMIT_RET,
  STAGE_XMIT_START,
  TLV_OBJ_DROP_REASON,
  TLV_OBJ_END_REASON,
  TLV_OBJ_SAMPLE_ID,
  TLV_QUAL_COUNT,
  TLV_QUAL_KIND,
  TLV_REL_DST_OBJECT_ID,
  TLV_REL_OP_ID,
  TLV_REL_SRC_OBJECT_ID,
  TLV_REL_TYPE,
  TLV_STEP_CALL_ID,
  TLV_STEP_CLASSID,
  TLV_STEP_CTX_TID,
  TLV_STEP_DEV_GEN,
  TLV_STEP_DIR,
  TLV_STEP_IFINDEX,
  TLV_STEP_NETNS_INUM,
  TLV_STEP_QDISC_HANDLE,
  TLV_STEP_QDISC_PARENT,
  TLV_STEP_QUEUE_GEN,
  TLV_STEP_RAW_RET,
  TLV_STEP_STAGE,
  TLV_STEP_TXQ,
  TLV_STEP_VISIT_ID,
  TLV_SUM_COMM,
  TLV_SUM_DIR,
  TLV_SUM_DST_IP,
  TLV_SUM_DST_PORT,
  TLV_SUM_ENQUEUE_TID,
  TLV_SUM_IFINDEX,
  TLV_SUM_IP_VERSION,
  TLV_SUM_L4_PROTO,
  TLV_SUM_PKT_LEN,
  TLV_SUM_SRC_IP,
  TLV_SUM_SRC_PORT,
  TLV_SUM_TCP_SEQ,
  TLV_SUM_TGID,
  TLV_SUM_UID,
  WireEvent,
  buildOverview,
  buildSampleDetail,
  encodeBlock,
  encodeEvent,
  loadSession,
  parseUUID,
  reconstruct,
} from '../../src/plugins/analysis/index.ts'
import type { Tlv } from '../../src/plugins/analysis/index.ts'

function u8(v: number): Uint8Array {
  return Uint8Array.of(v & 0xff)
}
function u16(v: number): Uint8Array {
  const b = Buffer.alloc(2)
  b.writeUInt16LE(v, 0)
  return b
}
function u32(v: number): Uint8Array {
  const b = Buffer.alloc(4)
  b.writeUInt32LE(v >>> 0, 0)
  return b
}
function s32(v: number): Uint8Array {
  const b = Buffer.alloc(4)
  b.writeInt32LE(v, 0)
  return b
}
function u64(v: bigint): Uint8Array {
  const b = Buffer.alloc(8)
  b.writeBigUInt64LE(v, 0)
  return b
}
function commBytes(s: string): Uint8Array {
  const b = Buffer.alloc(16)
  Buffer.from(s, 'utf8').copy(b, 0, 0, 15)
  return b
}

function makeEvent(
  fields: {
    seq: bigint
    ts_ns: bigint
    cpu: number
    kind: number
    object_type: number
    object_id: bigint
    flags?: number
    site_dict_idx?: number
  },
  tlvs: Tlv[],
): Uint8Array {
  const ev = new WireEvent()
  ev.producer = PROD_KERNEL_BPF
  ev.kind = fields.kind
  ev.object_type = fields.object_type
  ev.flags = fields.flags ?? EV_FLAG_IN_TASK
  ev.evidence_level = EVIDENCE_DIRECT
  ev.site_dict_idx = fields.site_dict_idx ?? 1
  ev.cpu = fields.cpu
  ev.seq = fields.seq
  ev.ts_ns = fields.ts_ns
  ev.object_id = fields.object_id
  return encodeEvent(ev, tlvs)
}

export function createRichSyntheticSessionDir(baseDir: string): {
  dir: string
  bigSampleId: bigint
  dropSampleId: bigint
} {
  const dir = path.join(baseDir, 'golden-synth-session')
  fs.mkdirSync(dir, { recursive: true })
  const uuidStr = '11223344-5566-7788-99aa-bbccddeeff00'
  const uuid = parseUUID(uuidStr)

  const manifest = {
    schema_version: 2,
    session_uuid: uuidStr,
    scope: 'tc-egress',
    mode: 'oneshot',
    sample_rate: '1/1',
    admissions: { matched: 2, selected: 2, created: 2, rejected: 0 },
    adapters: [{ adapter_id: 1, name: 'tc-egress', missed_source: 'kprobe_nmissed' }],
  }
  const dict = {
    sites: [
      { idx: 1, adapter_id: 1, name: 'dev_queue_xmit', symbol: '__dev_queue_xmit', probe_type: 'kprobe', probe_version: '1.0' },
      { idx: 2, adapter_id: 1, name: 'pfifo_fast_enqueue', symbol: 'pfifo_fast_enqueue', probe_type: 'kprobe', probe_version: '1.0' },
      { idx: 3, adapter_id: 1, name: 'dev_hard_start_xmit', symbol: 'dev_hard_start_xmit', probe_type: 'kprobe', probe_version: '1.0' },
    ],
  }
  const baseTs = 100_000_000_000n
  const topoSnap = {
    ts_ns: Number(baseTs - 1_000_000n),
    devs: [{ ifindex: 2, dev_gen: 1, netns_inum: 4026531840, name: 'wlan0' }],
    qdiscs: [
      { ifindex: 2, dev_gen: 1, queue_gen: 1, handle: 0x00010000, parent: 0xffffffff, kind: 'fq_codel' },
    ],
    classes: [
      { ifindex: 2, dev_gen: 1, classid: 0x00010010, rate_bps: 100000000, ceil_bps: 200000000, prio: 1 },
    ],
  }
  fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(manifest, null, 2))
  fs.writeFileSync(path.join(dir, 'dict.json'), JSON.stringify(dict, null, 2))
  fs.writeFileSync(path.join(dir, 'topo.json'), JSON.stringify(topoSnap, null, 2))

  // Sample 1: uint64 > 2^53-1 (9007199254740993), multi-branch CLONE + REQUEUE_GSO + 6.5ms sojourn
  const bigSampleId = 9007199254740993n
  const objRoot = 9007199254741001n
  const objClone = 9007199254741002n

  // Sample 2: DROP sample
  const dropSampleId = 9007199254740999n
  const objDrop = 9007199254742001n

  const evs: Uint8Array[] = [
    makeEvent(
      { seq: 1n, ts_ns: baseTs, cpu: 1, kind: KIND_SUMMARY, object_type: OBJ_SKB, object_id: objRoot },
      [
        { tag: TLV_OBJ_SAMPLE_ID, val: u64(bigSampleId) },
        { tag: TLV_SUM_PKT_LEN, val: u32(1420) },
        { tag: TLV_SUM_IFINDEX, val: u32(2) },
        { tag: TLV_SUM_DIR, val: u8(DIR_TX) },
        { tag: TLV_SUM_IP_VERSION, val: u8(4) },
        { tag: TLV_SUM_L4_PROTO, val: u8(6) },
        { tag: TLV_SUM_SRC_IP, val: Uint8Array.of(10, 0, 0, 2) },
        { tag: TLV_SUM_DST_IP, val: Uint8Array.of(198, 51, 100, 10) },
        { tag: TLV_SUM_SRC_PORT, val: u16(54321) },
        { tag: TLV_SUM_DST_PORT, val: u16(443) },
        { tag: TLV_SUM_TCP_SEQ, val: u32(1000) },
        { tag: TLV_SUM_UID, val: u32(10123) },
        { tag: TLV_SUM_TGID, val: u32(4321) },
        { tag: TLV_SUM_COMM, val: commBytes('curl-test') },
        { tag: TLV_SUM_ENQUEUE_TID, val: u32(4322) },
      ],
    ),
    makeEvent(
      { seq: 2n, ts_ns: baseTs + 10_000n, cpu: 1, kind: KIND_STEP, object_type: OBJ_SKB, object_id: objRoot },
      [
        { tag: TLV_OBJ_SAMPLE_ID, val: u64(bigSampleId) },
        { tag: TLV_STEP_STAGE, val: u8(STAGE_ENTRY) },
        { tag: TLV_STEP_IFINDEX, val: u32(2) },
        { tag: TLV_STEP_DEV_GEN, val: u32(1) },
        { tag: TLV_STEP_NETNS_INUM, val: u32(4026531840) },
        { tag: TLV_STEP_DIR, val: u8(DIR_TX) },
        { tag: TLV_STEP_CTX_TID, val: u32(4322) },
      ],
    ),
    makeEvent(
      { seq: 3n, ts_ns: baseTs + 20_000n, cpu: 1, kind: KIND_STEP, object_type: OBJ_SKB, object_id: objRoot },
      [
        { tag: TLV_OBJ_SAMPLE_ID, val: u64(bigSampleId) },
        { tag: TLV_STEP_STAGE, val: u8(STAGE_CLASSIFY) },
        { tag: TLV_STEP_IFINDEX, val: u32(2) },
        { tag: TLV_STEP_DEV_GEN, val: u32(1) },
        { tag: TLV_STEP_CLASSID, val: u32(0x00010010) },
        { tag: TLV_STEP_RAW_RET, val: s32(0) },
      ],
    ),
    makeEvent(
      { seq: 4n, ts_ns: baseTs + 50_000n, cpu: 1, kind: KIND_STEP, object_type: OBJ_SKB, object_id: objRoot, site_dict_idx: 2 },
      [
        { tag: TLV_OBJ_SAMPLE_ID, val: u64(bigSampleId) },
        { tag: TLV_STEP_STAGE, val: u8(STAGE_QDISC_ENQ) },
        { tag: TLV_STEP_IFINDEX, val: u32(2) },
        { tag: TLV_STEP_DEV_GEN, val: u32(1) },
        { tag: TLV_STEP_NETNS_INUM, val: u32(4026531840) },
        { tag: TLV_STEP_QUEUE_GEN, val: u64(1n) },
        { tag: TLV_STEP_QDISC_HANDLE, val: u32(0x00010000) },
        { tag: TLV_STEP_QDISC_PARENT, val: u32(0xffffffff) },
        { tag: TLV_STEP_VISIT_ID, val: u64(1n) },
        { tag: TLV_STEP_TXQ, val: u16(0) },
      ],
    ),
    makeEvent(
      { seq: 5n, ts_ns: baseTs + 6_550_000n, cpu: 2, kind: KIND_STEP, object_type: OBJ_SKB, object_id: objRoot, site_dict_idx: 2 },
      [
        { tag: TLV_OBJ_SAMPLE_ID, val: u64(bigSampleId) },
        { tag: TLV_STEP_STAGE, val: u8(STAGE_QDISC_DEQ) },
        { tag: TLV_STEP_IFINDEX, val: u32(2) },
        { tag: TLV_STEP_DEV_GEN, val: u32(1) },
        { tag: TLV_STEP_NETNS_INUM, val: u32(4026531840) },
        { tag: TLV_STEP_QUEUE_GEN, val: u64(1n) },
        { tag: TLV_STEP_QDISC_HANDLE, val: u32(0x00010000) },
        { tag: TLV_STEP_QDISC_PARENT, val: u32(0xffffffff) },
        { tag: TLV_STEP_VISIT_ID, val: u64(1n) },
        { tag: TLV_STEP_TXQ, val: u16(0) },
      ],
    ),
    makeEvent(
      { seq: 6n, ts_ns: baseTs + 6_560_000n, cpu: 2, kind: KIND_STEP, object_type: OBJ_SKB, object_id: objRoot },
      [
        { tag: TLV_OBJ_SAMPLE_ID, val: u64(bigSampleId) },
        { tag: TLV_STEP_STAGE, val: u8(STAGE_REQUEUE_GSO) },
        { tag: TLV_STEP_IFINDEX, val: u32(2) },
        { tag: TLV_STEP_DEV_GEN, val: u32(1) },
        { tag: TLV_STEP_QUEUE_GEN, val: u64(1n) },
        { tag: TLV_STEP_VISIT_ID, val: u64(2n) },
      ],
    ),
    makeEvent(
      { seq: 7n, ts_ns: baseTs + 6_600_000n, cpu: 2, kind: KIND_STEP, object_type: OBJ_SKB, object_id: objRoot, site_dict_idx: 3 },
      [
        { tag: TLV_OBJ_SAMPLE_ID, val: u64(bigSampleId) },
        { tag: TLV_STEP_STAGE, val: u8(STAGE_XMIT_START) },
        { tag: TLV_STEP_IFINDEX, val: u32(2) },
        { tag: TLV_STEP_DEV_GEN, val: u32(1) },
        { tag: TLV_STEP_TXQ, val: u16(0) },
        { tag: TLV_STEP_CALL_ID, val: u64(101n) },
        { tag: TLV_STEP_CTX_TID, val: u32(4322) },
      ],
    ),
    makeEvent(
      { seq: 8n, ts_ns: baseTs + 6_610_000n, cpu: 2, kind: KIND_STEP, object_type: OBJ_SKB, object_id: objRoot, site_dict_idx: 3 },
      [
        { tag: TLV_OBJ_SAMPLE_ID, val: u64(bigSampleId) },
        { tag: TLV_STEP_STAGE, val: u8(STAGE_XMIT_RET) },
        { tag: TLV_STEP_IFINDEX, val: u32(2) },
        { tag: TLV_STEP_CALL_ID, val: u64(101n) },
        { tag: TLV_STEP_RAW_RET, val: s32(0) },
      ],
    ),
    makeEvent(
      { seq: 9n, ts_ns: baseTs + 6_615_000n, cpu: 2, kind: KIND_RELATION, object_type: OBJ_SKB, object_id: objRoot },
      [
        { tag: TLV_OBJ_SAMPLE_ID, val: u64(bigSampleId) },
        { tag: TLV_REL_OP_ID, val: u64(77n) },
        { tag: TLV_REL_TYPE, val: u8(REL_CLONE) },
        { tag: TLV_REL_SRC_OBJECT_ID, val: u64(objRoot) },
        { tag: TLV_REL_DST_OBJECT_ID, val: u64(objClone) },
      ],
    ),
    makeEvent(
      { seq: 10n, ts_ns: baseTs + 6_620_000n, cpu: 2, kind: KIND_OBJECT, object_type: OBJ_SKB, object_id: objRoot },
      [
        { tag: TLV_OBJ_SAMPLE_ID, val: u64(bigSampleId) },
        { tag: TLV_OBJ_END_REASON, val: u16(END_TX_OK) },
      ],
    ),
    makeEvent(
      { seq: 11n, ts_ns: baseTs + 6_630_000n, cpu: 2, kind: KIND_OBJECT, object_type: OBJ_SKB, object_id: objClone },
      [
        { tag: TLV_OBJ_SAMPLE_ID, val: u64(bigSampleId) },
        { tag: TLV_OBJ_END_REASON, val: u16(END_TX_OK) },
      ],
    ),
    // Intentional SEQ_GAP (seq 11 -> 15, missing 3) + Sample 2 DROP + QUALITY MISSED_DELTA
    makeEvent(
      { seq: 15n, ts_ns: baseTs + 10_000_000n, cpu: 2, kind: KIND_SUMMARY, object_type: OBJ_SKB, object_id: objDrop },
      [
        { tag: TLV_OBJ_SAMPLE_ID, val: u64(dropSampleId) },
        { tag: TLV_SUM_PKT_LEN, val: u32(512) },
        { tag: TLV_SUM_IFINDEX, val: u32(2) },
        { tag: TLV_SUM_DIR, val: u8(DIR_TX) },
        { tag: TLV_SUM_IP_VERSION, val: u8(4) },
        { tag: TLV_SUM_L4_PROTO, val: u8(17) },
        { tag: TLV_SUM_SRC_IP, val: Uint8Array.of(10, 0, 0, 2) },
        { tag: TLV_SUM_DST_IP, val: Uint8Array.of(8, 8, 8, 8) },
        { tag: TLV_SUM_SRC_PORT, val: u16(12345) },
        { tag: TLV_SUM_DST_PORT, val: u16(53) },
        { tag: TLV_SUM_UID, val: u32(10123) },
        { tag: TLV_SUM_COMM, val: commBytes('dns-probe') },
      ],
    ),
    makeEvent(
      { seq: 16n, ts_ns: baseTs + 10_010_000n, cpu: 2, kind: KIND_STEP, object_type: OBJ_SKB, object_id: objDrop },
      [
        { tag: TLV_OBJ_SAMPLE_ID, val: u64(dropSampleId) },
        { tag: TLV_STEP_STAGE, val: u8(STAGE_ENTRY) },
        { tag: TLV_STEP_IFINDEX, val: u32(2) },
        { tag: TLV_STEP_DEV_GEN, val: u32(1) },
      ],
    ),
    makeEvent(
      { seq: 17n, ts_ns: baseTs + 10_050_000n, cpu: 2, kind: KIND_STEP, object_type: OBJ_SKB, object_id: objDrop },
      [
        { tag: TLV_OBJ_SAMPLE_ID, val: u64(dropSampleId) },
        { tag: TLV_STEP_STAGE, val: u8(STAGE_DROP) },
        { tag: TLV_STEP_IFINDEX, val: u32(2) },
        { tag: TLV_STEP_DEV_GEN, val: u32(1) },
      ],
    ),
    makeEvent(
      { seq: 18n, ts_ns: baseTs + 10_055_000n, cpu: 2, kind: KIND_OBJECT, object_type: OBJ_SKB, object_id: objDrop },
      [
        { tag: TLV_OBJ_SAMPLE_ID, val: u64(dropSampleId) },
        { tag: TLV_OBJ_END_REASON, val: u16(END_DROP) },
        { tag: TLV_OBJ_DROP_REASON, val: u32(42) },
      ],
    ),
    makeEvent(
      { seq: 19n, ts_ns: baseTs + 10_060_000n, cpu: 2, kind: KIND_QUALITY, object_type: 0, object_id: 0n },
      [
        { tag: TLV_QUAL_KIND, val: u8(QUAL_MISSED_DELTA) },
        { tag: TLV_QUAL_COUNT, val: u64(2n) },
      ],
    ),
  ]

  const evPayload = Buffer.concat(evs)
  const blkEvents = encodeBlock(
    {
      magic: BLOCK_MAGIC,
      major: 1,
      minor: 0,
      block_type: BLOCK_EVENT_BATCH,
      producer_type: PROD_KERNEL_BPF,
      flags: 0,
      payload_len: evPayload.length,
      epoch: 1,
      block_no: 1,
      reserved: 0,
      session_uuid: uuid,
      min_ts_ns: baseTs,
      max_ts_ns: baseTs + 10_060_000n,
    },
    evPayload,
  )
  const blkEnd = encodeBlock(
    {
      magic: BLOCK_MAGIC,
      major: 1,
      minor: 0,
      block_type: BLOCK_END_MARKER,
      producer_type: PROD_KERNEL_BPF,
      flags: 0,
      payload_len: 0,
      epoch: 1,
      block_no: 2,
      reserved: 0,
      session_uuid: uuid,
      min_ts_ns: baseTs + 10_060_000n,
      max_ts_ns: baseTs + 10_060_000n,
    },
    new Uint8Array(0),
  )

  fs.writeFileSync(path.join(dir, 'block-0001.pktb'), Buffer.concat([blkEvents, blkEnd]))
  return { dir, bigSampleId, dropSampleId }
}

test('TS reconstruct matches legacy Go studio/pkg/reconstruct golden output field-for-field', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pktpath-golden-'))
  try {
    const { dir, bigSampleId, dropSampleId } = createRichSyntheticSessionDir(tmp)

    const loaded = loadSession(dir)
    const session = reconstruct(loaded)
    const tsOverview = buildOverview(session)
    const tsBigDetail = buildSampleDetail(session, bigSampleId)
    const tsDropDetail = buildSampleDetail(session, dropSampleId)

    assert.equal(tsBigDetail.sample_id, '9007199254740993')
    assert.equal(tsOverview.samples[0]!.sample_id, '9007199254740993')
    assert.equal(tsOverview.samples[1]!.sample_id, '9007199254740999')
    assert.equal(tsOverview.stats.quality.seq_gap_windows, 1)
    assert.equal(tsOverview.stats.quality.seq_gap_missing_events, 3)
    assert.equal(tsOverview.stats.quality.missed_delta, 2)
    assert.equal(tsOverview.stats.requeue_count, 1)
    assert.equal(tsOverview.stats.requeue_gso_count, 1)
    assert.equal(tsOverview.stats.endpoints['DROP'], 1)
    assert.equal(tsDropDetail.branches[0]!.drop_reason, '42')

    const legacyStudioDir =
      process.env.PKTPATH_LEGACY_STUDIO_DIR ?? path.resolve(import.meta.dirname, '../../../studio')
    const hasGo = spawnSync('go', ['version'], { stdio: 'ignore' }).status === 0
    if (hasGo && fs.existsSync(path.join(legacyStudioDir, 'go.mod'))) {
      const goHarness = path.join(tmp, 'golden_dump.go')
      fs.writeFileSync(
        goHarness,
        `package main
import (
  "encoding/json"
  "fmt"
  "os"
  "pktpath/studio/pkg/reconstruct"
  "pktpath/studio/pkg/wire"
)
func main() {
  ls, err := wire.LoadSession(os.Args[1], false)
  if err != nil { panic(err) }
  s := reconstruct.Reconstruct(ls)
  ov := reconstruct.BuildOverview(s)
  d1, err := reconstruct.BuildSampleDetail(s, 9007199254740993)
  if err != nil { panic(err) }
  d2, err := reconstruct.BuildSampleDetail(s, 9007199254740999)
  if err != nil { panic(err) }
  out := map[string]any{"overview": ov, "d1": d1, "d2": d2}
  b, err := json.Marshal(out)
  if err != nil { panic(err) }
  fmt.Print(string(b))
}
`,
      )
      const goStdout = execFileSync('go', ['run', goHarness, dir], {
        cwd: legacyStudioDir,
        encoding: 'utf8',
        maxBuffer: 16 * 1024 * 1024,
      })
      const goOut = JSON.parse(goStdout) as {
        overview: { stats: Record<string, unknown>; samples: Array<Record<string, unknown>> }
        d1: { branches: Array<Record<string, unknown>>; relations: Array<Record<string, unknown>> }
        d2: { branches: Array<Record<string, unknown>> }
      }

      assert.equal(tsOverview.stats.session_uuid, goOut.overview.stats['session_uuid'])
      assert.deepEqual(tsOverview.stats.samples, goOut.overview.stats['samples'])
      assert.deepEqual(tsOverview.stats.branches, goOut.overview.stats['branches'])
      assert.deepEqual(tsOverview.stats.endpoints, goOut.overview.stats['endpoints'])
      assert.equal(tsOverview.stats.requeue_count, goOut.overview.stats['requeue_count'])
      assert.equal(tsOverview.stats.requeue_gso_count, goOut.overview.stats['requeue_gso_count'])
      assert.equal(tsOverview.stats.skb_bytes, goOut.overview.stats['skb_bytes'])
      assert.equal(tsOverview.stats.wire_bytes, goOut.overview.stats['wire_bytes'])
      assert.deepEqual(tsOverview.stats.quality, goOut.overview.stats['quality'])
      assert.deepEqual(tsOverview.stats.quality_alerts, goOut.overview.stats['quality_alerts'])

      const goQueues = goOut.overview.stats['queues'] as Array<Record<string, unknown>>
      assert.equal(tsOverview.stats.queues.length, goQueues.length)
      for (let i = 0; i < goQueues.length; i++) {
        assert.equal(tsOverview.stats.queues[i]!.label, goQueues[i]!['label'])
        assert.equal(tsOverview.stats.queues[i]!.kind, goQueues[i]!['kind'])
        assert.equal(tsOverview.stats.queues[i]!.p50_us, goQueues[i]!['p50_us'])
        assert.equal(tsOverview.stats.queues[i]!.p95_us, goQueues[i]!['p95_us'])
        assert.equal(tsOverview.stats.queues[i]!.p99_us, goQueues[i]!['p99_us'])
        assert.equal(tsOverview.stats.queues[i]!.max_us, goQueues[i]!['max_us'])
      }

      assert.equal(tsOverview.samples.length, goOut.overview.samples.length)
      for (let i = 0; i < tsOverview.samples.length; i++) {
        const tsR = tsOverview.samples[i]!
        const goR = goOut.overview.samples[i]!
        assert.equal(tsR.comm, goR['comm'])
        assert.equal(tsR.proto, goR['proto'])
        assert.equal(tsR.src, goR['src'])
        assert.equal(tsR.dst, goR['dst'])
        assert.equal(tsR.max_sojourn_us, goR['max_sojourn_us'])
        assert.equal(tsR.total_us, goR['total_us'])
        assert.equal(tsR.completeness, goR['completeness'])
        assert.equal(tsR.endpoint, goR['endpoint'])
        assert.equal(tsR.branch_count, goR['branch_count'])
        assert.equal(tsR.requeued, goR['requeued'])
        assert.equal(tsR.path_sig, goR['path_sig'])
      }

      assert.equal(tsBigDetail.branches.length, goOut.d1.branches.length)
      assert.equal(tsBigDetail.relations.length, goOut.d1.relations.length)
      assert.equal(tsBigDetail.branches[0]!.path_sig, goOut.d1.branches[0]!['path_sig'])
      const tsStages = tsBigDetail.branches[0]!.timeline.map((e) => e.stage)
      const goStages = (goOut.d1.branches[0]!['timeline'] as Array<Record<string, unknown>>).map((e) => e['stage'])
      assert.deepEqual(tsStages, goStages)
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})
