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
  END_TX_OK,
  EV_FLAG_IN_TASK,
  EVIDENCE_DIRECT,
  KIND_OBJECT,
  KIND_STEP,
  KIND_SUMMARY,
  LINK_TYPE_ETHERNET,
  OBJ_SKB,
  PROD_KERNEL_BPF,
  STAGE_ENTRY,
  TLV_OBJ_END_REASON,
  TLV_OBJ_SAMPLE_ID,
  TLV_STEP_DEV_GEN,
  TLV_STEP_IFINDEX,
  TLV_STEP_NETNS_INUM,
  TLV_STEP_STAGE,
  TLV_SUM_COMM,
  TLV_SUM_DIR,
  TLV_SUM_DST_IP,
  TLV_SUM_DST_PORT,
  TLV_SUM_HDR_BYTES,
  TLV_SUM_IFINDEX,
  TLV_SUM_IP_VERSION,
  TLV_SUM_L4_PROTO,
  TLV_SUM_LINKTYPE,
  TLV_SUM_PKT_LEN,
  TLV_SUM_SRC_IP,
  TLV_SUM_SRC_PORT,
  TLV_SUM_UID,
  WireEvent,
  encodeBlock,
  encodeEvent,
  exportPcapng,
  loadSession,
  parseUUID,
  redactSession,
} from '../../src/plugins/analysis/index.ts'

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
function u64(v: bigint): Uint8Array {
  const b = Buffer.alloc(8)
  b.writeBigUInt64LE(v, 0)
  return b
}

function makeEthIpv4TcpFrame(): Buffer {
  // 14B Ethernet + 20B IPv4 + 20B TCP + 8B secret payload = 62B
  const b = Buffer.alloc(62)
  // dst MAC + src MAC + ethertype 0x0800
  Buffer.from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]).copy(b, 0)
  Buffer.from([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]).copy(b, 6)
  b.writeUInt16BE(0x0800, 12)
  // IPv4: ver=4, ihl=5 (20B), proto=6 (TCP), src=10.1.2.3, dst=198.51.100.42
  b[14] = 0x45
  b.writeUInt16BE(48, 16)
  b[23] = 6
  b.writeUInt16BE(0x1234, 24) // checksum (should be zeroed after redact)
  Buffer.from([10, 1, 2, 3]).copy(b, 26)
  Buffer.from([198, 51, 100, 42]).copy(b, 30)
  // TCP: sport=51234, dport=443, data offset=5 (20B), csum=0xabcd
  b.writeUInt16BE(51234, 34)
  b.writeUInt16BE(443, 36)
  b[46] = 0x50
  b.writeUInt16BE(0xabcd, 50)
  // L4 payload ("SECRET!!") -> must be zeroed after redact
  Buffer.from('SECRET!!', 'ascii').copy(b, 54)
  return b
}

function createPacketSessionDir(baseDir: string): string {
  const dir = path.join(baseDir, 'pkt-export-session')
  fs.mkdirSync(dir, { recursive: true })
  const uuidStr = '22334455-6677-8899-aabb-ccddeeff0011'
  const uuid = parseUUID(uuidStr)

  const manifest = {
    schema_version: 2,
    session_uuid: uuidStr,
    scope: 'tc-egress',
    mode: 'oneshot',
    clock_domain: 'CLOCK_BOOTTIME',
    filters: { src_ip: '10.1.2.3/32', dst_ip: '198.51.100.42', src_port: 51234, dst_port: 443, uid: 10086 },
  }
  const dict = {
    topology_epochs: [
      {
        epoch_id: 1,
        netns_inum: 4026531840,
        devices: [{ ifindex: 2, dev_gen: 1, name: 'wlan0', linktype: LINK_TYPE_ETHERNET }],
      },
    ],
    sites: [{ idx: 1, name: 'dev_queue_xmit', stage: STAGE_ENTRY }],
  }
  fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(manifest, null, 2))
  fs.writeFileSync(path.join(dir, 'dict.json'), JSON.stringify(dict, null, 2))
  // Plant a cache file to verify redactSession does NOT leak/copy it
  fs.writeFileSync(path.join(dir, '.pktpath_analysis_cache.json'), '{"secret":"do-not-copy"}')

  const baseTs = 200_000_000_000n
  const sampleId = 9007199254741234n
  const objId = 9007199254749999n
  const frame = makeEthIpv4TcpFrame()

  const ev1 = new WireEvent({
    kind: KIND_SUMMARY,
    object_type: OBJ_SKB,
    evidence_level: EVIDENCE_DIRECT,
    site_dict_idx: 1,
    cpu: 0,
    flags: EV_FLAG_IN_TASK,
    seq: 1n,
    ts_ns: baseTs,
    object_id: objId,
  })
  const ev2 = new WireEvent({
    kind: KIND_STEP,
    object_type: OBJ_SKB,
    evidence_level: EVIDENCE_DIRECT,
    site_dict_idx: 1,
    cpu: 0,
    flags: EV_FLAG_IN_TASK,
    seq: 2n,
    ts_ns: baseTs + 5_000n,
    object_id: objId,
  })
  const ev3 = new WireEvent({
    kind: KIND_OBJECT,
    object_type: OBJ_SKB,
    evidence_level: EVIDENCE_DIRECT,
    site_dict_idx: 1,
    cpu: 0,
    flags: EV_FLAG_IN_TASK,
    seq: 3n,
    ts_ns: baseTs + 10_000n,
    object_id: objId,
  })

  const comm = Buffer.alloc(16)
  Buffer.from('my-secret-app').copy(comm)

  const payload = Buffer.concat([
    encodeEvent(ev1, [
      { tag: TLV_OBJ_SAMPLE_ID, val: u64(sampleId) },
      { tag: TLV_SUM_PKT_LEN, val: u32(128) },
      { tag: TLV_SUM_IFINDEX, val: u32(2) },
      { tag: TLV_SUM_DIR, val: u8(DIR_TX) },
      { tag: TLV_SUM_IP_VERSION, val: u8(4) },
      { tag: TLV_SUM_L4_PROTO, val: u8(6) },
      { tag: TLV_SUM_SRC_IP, val: Uint8Array.of(10, 1, 2, 3) },
      { tag: TLV_SUM_DST_IP, val: Uint8Array.of(198, 51, 100, 42) },
      { tag: TLV_SUM_SRC_PORT, val: u16(51234) },
      { tag: TLV_SUM_DST_PORT, val: u16(443) },
      { tag: TLV_SUM_UID, val: u32(10086) },
      { tag: TLV_SUM_COMM, val: comm },
      { tag: TLV_SUM_LINKTYPE, val: u16(LINK_TYPE_ETHERNET) },
      { tag: TLV_SUM_HDR_BYTES, val: frame },
    ]),
    encodeEvent(ev2, [
      { tag: TLV_OBJ_SAMPLE_ID, val: u64(sampleId) },
      { tag: TLV_STEP_STAGE, val: u8(STAGE_ENTRY) },
      { tag: TLV_STEP_IFINDEX, val: u32(2) },
      { tag: TLV_STEP_DEV_GEN, val: u32(1) },
      { tag: TLV_STEP_NETNS_INUM, val: u32(4026531840) },
    ]),
    encodeEvent(ev3, [
      { tag: TLV_OBJ_SAMPLE_ID, val: u64(sampleId) },
      { tag: TLV_OBJ_END_REASON, val: u16(END_TX_OK) },
    ]),
  ])

  const blk1 = encodeBlock(
    {
      magic: BLOCK_MAGIC,
      major: 1,
      minor: 0,
      block_type: BLOCK_EVENT_BATCH,
      producer_type: PROD_KERNEL_BPF,
      flags: 0,
      payload_len: payload.length,
      epoch: 1,
      block_no: 1,
      reserved: 0,
      session_uuid: uuid,
      min_ts_ns: baseTs,
      max_ts_ns: baseTs + 10_000n,
    },
    payload,
  )
  const blk2 = encodeBlock(
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
      min_ts_ns: baseTs + 10_000n,
      max_ts_ns: baseTs + 10_000n,
    },
    new Uint8Array(0),
  )
  fs.writeFileSync(path.join(dir, 'block_000001.pktb'), blk1)
  fs.writeFileSync(path.join(dir, 'block_000002.pktb'), blk2)
  return dir
}

test('TS pcapng and redact match legacy Go studio/pkg/export byte-for-byte', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pktpath-export-golden-'))
  try {
    const dir = createPacketSessionDir(tmp)
    const origManifestBefore = fs.readFileSync(path.join(dir, 'manifest.json'))
    const origBlockBefore = fs.readFileSync(path.join(dir, 'block_000001.pktb'))

    // 1. TS pcapng (plain + redacted) & redactSession
    const tsPlainPcap = path.join(tmp, 'ts-plain.pcapng')
    const tsRedPcap = path.join(tmp, 'ts-red.pcapng')
    const tsRedDir = path.join(tmp, 'ts-redacted-dir')
    assert.equal(exportPcapng(dir, tsPlainPcap, false, ''), 1)
    assert.equal(exportPcapng(dir, tsRedPcap, true, 'golden-key-2026'), 1)
    redactSession(dir, tsRedDir, 'golden-key-2026')

    // Original session untouched
    assert.equal(Buffer.compare(fs.readFileSync(path.join(dir, 'manifest.json')), origManifestBefore), 0)
    assert.equal(Buffer.compare(fs.readFileSync(path.join(dir, 'block_000001.pktb')), origBlockBefore), 0)
    // Cache file NOT copied into redacted session dir
    assert.equal(fs.existsSync(path.join(tsRedDir, '.pktpath_analysis_cache.json')), false)

    // Hard-forbid exporting into session_dir
    assert.throws(() => exportPcapng(dir, path.join(dir, 'bad.pcapng'), false, ''), /inside session_dir/)
    assert.throws(() => redactSession(dir, path.join(dir, 'nested-redacted'), 'k'), /inside input session_dir/)
    assert.throws(() => redactSession(dir, dir, 'k'), /inside input session_dir/)

    // Verify redacted session loads cleanly and anonymized IP/port/UID/payload
    const redLoaded = loadSession(tsRedDir)
    assert.equal(redLoaded.manifest['redacted'], true)
    assert.equal(redLoaded.manifest['redaction_scheme'], 'hmac-sha256-trunc-v1')
    const redSummary = redLoaded.events.find((e) => e.kind === KIND_SUMMARY)!
    assert.notEqual(redSummary.str('src_ip'), '10.1.2.3')
    assert.notEqual(redSummary.str('dst_ip'), '198.51.100.42')
    assert.notEqual(redSummary.num('src_port'), 51234)
    assert.notEqual(redSummary.num('dst_port'), 443)
    assert.notEqual(redSummary.num('uid'), 10086)
    const redHdr = Buffer.from(redSummary.bin('hdr_bytes')!)
    assert.equal(redHdr.includes(Buffer.from('SECRET!!', 'ascii')), false)

    // 2. Compare byte-for-byte with real legacy Go studio/pkg/export
    const legacyStudioDir =
      process.env.PKTPATH_LEGACY_STUDIO_DIR ?? path.resolve(import.meta.dirname, '../../../studio')
    const hasGo = spawnSync('go', ['version'], { stdio: 'ignore' }).status === 0
    if (hasGo && fs.existsSync(path.join(legacyStudioDir, 'go.mod'))) {
      const goPlainPcap = path.join(tmp, 'go-plain.pcapng')
      const goRedPcap = path.join(tmp, 'go-red.pcapng')
      const goRedDir = path.join(tmp, 'go-redacted-dir')
      const goHarness = path.join(tmp, 'export_golden.go')
      fs.writeFileSync(
        goHarness,
        `package main
import (
  "os"
  "pktpath/studio/pkg/export"
)
func main() {
  if _, err := export.ExportPcapng(os.Args[1], os.Args[2], false, ""); err != nil { panic(err) }
  if _, err := export.ExportPcapng(os.Args[1], os.Args[3], true, "golden-key-2026"); err != nil { panic(err) }
  if err := export.RedactSession(os.Args[1], os.Args[4], "golden-key-2026"); err != nil { panic(err) }
}
`,
      )
      execFileSync('go', ['run', goHarness, dir, goPlainPcap, goRedPcap, goRedDir], {
        cwd: legacyStudioDir,
        encoding: 'utf8',
      })

      // Byte-for-byte equality on BOTH plain and redacted .pcapng!
      {
        const tsB = fs.readFileSync(tsPlainPcap), goB = fs.readFileSync(goPlainPcap)
        if (Buffer.compare(tsB, goB) !== 0) {
          let i = 0; while (i < Math.min(tsB.length, goB.length) && tsB[i] === goB[i]) i++
          throw new Error('plain diff at ' + i + ' tsLen=' + tsB.length + ' goLen=' + goB.length + ' ts=' + JSON.stringify(tsB.subarray(Math.max(0,i-16), i+64).toString('utf8')) + ' go=' + JSON.stringify(goB.subarray(Math.max(0,i-16), i+64).toString('utf8')))
        }
      }
      assert.equal(Buffer.compare(fs.readFileSync(tsRedPcap), fs.readFileSync(goRedPcap)), 0, 'redacted .pcapng must match Go byte-for-byte')

      // Redacted summary fields must match Go 1:1
      const goRedLoaded = loadSession(goRedDir)
      const goRedSummary = goRedLoaded.events.find((e) => e.kind === KIND_SUMMARY)!
      assert.equal(redSummary.str('src_ip'), goRedSummary.str('src_ip'))
      assert.equal(redSummary.str('dst_ip'), goRedSummary.str('dst_ip'))
      assert.equal(redSummary.num('src_port'), goRedSummary.num('src_port'))
      assert.equal(redSummary.num('dst_port'), goRedSummary.num('dst_port'))
      assert.equal(redSummary.num('uid'), goRedSummary.num('uid'))
      assert.equal(Buffer.compare(Buffer.from(redSummary.bin('hdr_bytes')!), Buffer.from(goRedSummary.bin('hdr_bytes')!)), 0)
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})
