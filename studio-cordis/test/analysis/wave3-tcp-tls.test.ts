import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import {
  BLOCK_END_MARKER,
  BLOCK_EVENT_BATCH,
  BLOCK_MAGIC,
  WIRE_MAJOR,
  WIRE_MINOR,
  DIR_TX,
  END_DROP,
  END_TX_OK,
  EVIDENCE_DIRECT,
  KIND_OBJECT,
  KIND_STEP,
  KIND_SUMMARY,
  OBJ_SKB,
  PROD_CONTROLLER,
  PROD_KERNEL_BPF,
  SessionStore,
  STAGE_DROP,
  STAGE_ENTRY,
  STAGE_XMIT_START,
  TLV_OBJ_DROP_REASON,
  TLV_OBJ_END_REASON,
  TLV_OBJ_SAMPLE_ID,
  TLV_STEP_DIR,
  TLV_STEP_IFINDEX,
  TLV_STEP_SND_CWND,
  TLV_STEP_SRTT_US,
  TLV_STEP_STAGE,
  TLV_STEP_TCP_SEQ,
  TLV_SUM_DIR,
  TLV_SUM_DST_IP,
  TLV_SUM_DST_PORT,
  TLV_SUM_IFINDEX,
  TLV_SUM_IP_VERSION,
  TLV_SUM_L4_PROTO,
  TLV_SUM_PKT_LEN,
  TLV_SUM_SRC_IP,
  TLV_SUM_SRC_PORT,
  TLV_SUM_TGID,
  TLV_SUM_UID,
  WireEvent,
  buildFlowTcpSeries,
  correlateTlsEvents,
  encodeBlock,
  encodeEvent,
  loadSession,
  reconstruct,
} from '../../src/plugins/analysis/index.ts'
import type { BlockHeader, Tlv } from '../../src/plugins/analysis/index.ts'

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
function u64(v: bigint): Uint8Array {
  const b = Buffer.alloc(8)
  b.writeBigUInt64LE(v, 0)
  return new Uint8Array(b)
}
function ipv4Bytes(ip: string): Uint8Array {
  return Uint8Array.from(ip.split('.').map((x) => Number(x) & 0xff))
}

function makeWireEvent(opts: {
  ts_ns: bigint
  seq: bigint
  kind: number
  site_dict_idx: number
  object_id: bigint
  tlvs: Tlv[]
}): Uint8Array {
  const ev = new WireEvent()
  ev.ts_ns = opts.ts_ns
  ev.seq = opts.seq
  ev.object_id = opts.object_id
  ev.kind = opts.kind
  ev.object_type = OBJ_SKB
  ev.evidence_level = EVIDENCE_DIRECT
  ev.producer_type = PROD_KERNEL_BPF
  ev.cpu = 0
  ev.site_dict_idx = opts.site_dict_idx
  ev.flags = 0
  return encodeEvent(ev, opts.tlvs)
}

function writeSessionFiles(
  dir: string,
  manifest: Record<string, unknown>,
  encodedEvents: Uint8Array[],
  tlsLines?: string[],
): void {
  fs.mkdirSync(dir, { recursive: true })
  const dict = {
    sites: [
      { id: 1, name: 'tcp_transmit_skb', symbol: 'tcp_transmit_skb', stage: STAGE_ENTRY },
      { id: 2, name: 'tcp_retransmit_skb', symbol: 'tcp_retransmit_skb', stage: STAGE_ENTRY },
      { id: 3, name: 'kfree_skb', symbol: 'kfree_skb', stage: STAGE_DROP },
      { id: 4, name: 'dev_hard_start_xmit', symbol: 'dev_hard_start_xmit', stage: STAGE_XMIT_START },
    ],
    devs: [{ ifindex: 2, dev_gen: 1, netns_inum: 4026531992, name: 'wlan0' }],
    qdiscs: [],
  }
  fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(manifest, null, 2))
  fs.writeFileSync(path.join(dir, 'dict.json'), JSON.stringify(dict, null, 2))
  const sessionUuid = new Uint8Array(16)
  sessionUuid[0] = 0x5a
  const hdr: BlockHeader = {
    magic: BLOCK_MAGIC,
    major: WIRE_MAJOR,
    minor: WIRE_MINOR,
    block_type: BLOCK_EVENT_BATCH,
    producer_type: PROD_KERNEL_BPF,
    block_no: 1,
    flags: 0,
    reserved: 0,
    session_uuid: sessionUuid,
    min_ts_ns: 1_732_700_000_000_000_000n,
    max_ts_ns: 1_732_700_000_500_000_000n,
  }
  const batch = encodeBlock(hdr, Buffer.concat(encodedEvents))
  const end = encodeBlock(
    { ...hdr, block_type: BLOCK_END_MARKER, producer_type: PROD_CONTROLLER, block_no: 2 },
    new Uint8Array(0),
  )
  fs.writeFileSync(path.join(dir, 'events-0001.pktb'), Buffer.concat([batch, end]))
  if (tlsLines) {
    fs.writeFileSync(path.join(dir, 'tls-events.jsonl'), `${tlsLines.join('\n')}\n`, 'utf8')
  }
}

function makeHostPaths(tmpRoot: string) {
  const appDir = path.join(tmpRoot, 'app')
  return {
    appDir,
    sessionsRoot: tmpRoot,
    runtimeDir: path.join(appDir, 'runtime'),
    pluginsDir: path.join(appDir, 'plugins'),
    configPath: path.join(appDir, 'kernel-config.json'),
  }
}

test('Appendix A.1: buildFlowTcpSeries builds time-sequence (normal/retransmit/drop) and cwnd/RTT without fabricating 0 for missing TLVs', async () => {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'pktpath-wave3-tcp-'))
  try {
    const baseTs = 1_732_700_000_000_000_000n
    const mkSummary = (seqNo: bigint, oid: bigint, ts: bigint) =>
      makeWireEvent({
        ts_ns: ts,
        seq: seqNo,
        kind: KIND_SUMMARY,
        site_dict_idx: 1,
        object_id: oid,
        tlvs: [
          { tag: TLV_SUM_IFINDEX, val: u32(2) },
          { tag: TLV_SUM_DIR, val: u8(DIR_TX) },
          { tag: TLV_SUM_IP_VERSION, val: u8(4) },
          { tag: TLV_SUM_L4_PROTO, val: u8(6) },
          { tag: TLV_SUM_SRC_IP, val: ipv4Bytes('10.0.2.15') },
          { tag: TLV_SUM_DST_IP, val: ipv4Bytes('93.184.216.34') },
          { tag: TLV_SUM_SRC_PORT, val: u16(54321) },
          { tag: TLV_SUM_DST_PORT, val: u16(443) },
          { tag: TLV_SUM_PKT_LEN, val: u32(1400) },
          { tag: TLV_SUM_TGID, val: u32(12345) },
          { tag: TLV_SUM_UID, val: u32(10248) },
        ],
      })

    const events: Uint8Array[] = [
      // Sample 1: normal packet with tcp_seq=1000, snd_cwnd=10, srtt_us=25000 (25ms)
      makeWireEvent({
        ts_ns: baseTs,
        seq: 1n,
        kind: KIND_OBJECT,
        site_dict_idx: 1,
        object_id: 101n,
        tlvs: [
          { tag: TLV_OBJ_SAMPLE_ID, val: u64(101n) },
          { tag: TLV_OBJ_END_REASON, val: u16(END_TX_OK) },
        ],
      }),
      mkSummary(2n, 101n, baseTs + 100n),
      makeWireEvent({
        ts_ns: baseTs + 1_000_000n,
        seq: 3n,
        kind: KIND_STEP,
        site_dict_idx: 1,
        object_id: 101n,
        tlvs: [
          { tag: TLV_STEP_STAGE, val: u8(STAGE_ENTRY) },
          { tag: TLV_STEP_IFINDEX, val: u32(2) },
          { tag: TLV_STEP_DIR, val: u8(DIR_TX) },
          { tag: TLV_STEP_TCP_SEQ, val: u32(1000) },
          { tag: TLV_STEP_SND_CWND, val: u32(10) },
          { tag: TLV_STEP_SRTT_US, val: u32(25000) },
        ],
      }),

      // Sample 2: next packet with tcp_seq=2400, snd_cwnd=12, srtt_us OMITTED (must stay null, NOT 0!)
      makeWireEvent({
        ts_ns: baseTs + 10_000_000n,
        seq: 4n,
        kind: KIND_OBJECT,
        site_dict_idx: 1,
        object_id: 102n,
        tlvs: [
          { tag: TLV_OBJ_SAMPLE_ID, val: u64(102n) },
          { tag: TLV_OBJ_END_REASON, val: u16(END_TX_OK) },
        ],
      }),
      mkSummary(5n, 102n, baseTs + 10_000_100n),
      makeWireEvent({
        ts_ns: baseTs + 11_000_000n,
        seq: 6n,
        kind: KIND_STEP,
        site_dict_idx: 1,
        object_id: 102n,
        tlvs: [
          { tag: TLV_STEP_STAGE, val: u8(STAGE_ENTRY) },
          { tag: TLV_STEP_IFINDEX, val: u32(2) },
          { tag: TLV_STEP_DIR, val: u8(DIR_TX) },
          { tag: TLV_STEP_TCP_SEQ, val: u32(2400) },
          { tag: TLV_STEP_SND_CWND, val: u32(12) },
        ],
      }),

      // Sample 3: retransmit of seq=1000 via tcp_retransmit_skb, then dropped with reason 2
      makeWireEvent({
        ts_ns: baseTs + 30_000_000n,
        seq: 7n,
        kind: KIND_OBJECT,
        site_dict_idx: 2,
        object_id: 103n,
        tlvs: [
          { tag: TLV_OBJ_SAMPLE_ID, val: u64(103n) },
          { tag: TLV_OBJ_END_REASON, val: u16(END_DROP) },
          { tag: TLV_OBJ_DROP_REASON, val: u32(2) },
        ],
      }),
      mkSummary(8n, 103n, baseTs + 30_000_100n),
      makeWireEvent({
        ts_ns: baseTs + 31_000_000n,
        seq: 9n,
        kind: KIND_STEP,
        site_dict_idx: 2,
        object_id: 103n,
        tlvs: [
          { tag: TLV_STEP_STAGE, val: u8(STAGE_ENTRY) },
          { tag: TLV_STEP_IFINDEX, val: u32(2) },
          { tag: TLV_STEP_DIR, val: u8(DIR_TX) },
          { tag: TLV_STEP_TCP_SEQ, val: u32(1000) },
          { tag: TLV_STEP_SND_CWND, val: u32(6) },
          { tag: TLV_STEP_SRTT_US, val: u32(40000) },
        ],
      }),
      makeWireEvent({
        ts_ns: baseTs + 32_000_000n,
        seq: 10n,
        kind: KIND_STEP,
        site_dict_idx: 3,
        object_id: 103n,
        tlvs: [
          { tag: TLV_STEP_STAGE, val: u8(STAGE_DROP) },
          { tag: TLV_STEP_IFINDEX, val: u32(2) },
          { tag: TLV_STEP_DIR, val: u8(DIR_TX) },
          { tag: TLV_STEP_TCP_SEQ, val: u32(1000) },
        ],
      }),
    ]

    const sessDir = path.join(tmpRoot, 's-tcp')
    writeSessionFiles(
      sessDir,
      {
        session_id: 's-tcp',
        probe_preset: 'tcp-diag',
        requested_groups: ['core_drop', 'tcp_diag', 'tcp_probe'],
        effective_groups: ['core_drop', 'tcp_diag', 'tcp_probe'],
        probe_inventory: [
          { id: 'builtin.tcp_retransmit', group: 'tcp_diag', source: 'builtin', target: 'tcp:tcp_retransmit_skb', status: 'attached' },
          { id: 'builtin.tcp_probe', group: 'tcp_probe', source: 'builtin', target: 'tcp:tcp_probe', status: 'attached' },
        ],
        capabilities: {
          btf_available: true,
          drop_reason_available: true,
          drop_reason_source: 'vmlinux_btf',
          stack_symbolize_available: true,
        },
        drop_reason_map: {
          '2': 'SKB_DROP_REASON_NOT_SPECIFIED',
        },
      },
      events,
    )

    const session = reconstruct(loadSession(sessDir))
    const series = buildFlowTcpSeries(session, { sample_id: '101' })

    assert.equal(series.tcp_probes_enabled, true)
    assert.equal(series.tcp_probe_status, 'attached')
    assert.equal(series.notice, null)
    assert.equal(series.flow_key, 'TCP 10.0.2.15:54321 -> 93.184.216.34:443')
    assert.deepEqual(series.sample_ids, ['101', '102', '103'])

    // Time-sequence checks: 4 points -> normal(1000), normal(2400), retransmit(1000), drop(1000)
    assert.equal(series.time_sequence.length, 4)
    assert.equal(series.time_sequence[0]!.event_kind, 'normal')
    assert.equal(series.time_sequence[0]!.seq, 1000)
    assert.equal(series.time_sequence[0]!.rel_seq, 0)
    assert.equal(series.time_sequence[1]!.event_kind, 'normal')
    assert.equal(series.time_sequence[1]!.rel_seq, 1400)
    assert.equal(series.time_sequence[2]!.event_kind, 'retransmit')
    assert.equal(series.time_sequence[3]!.event_kind, 'drop')
    assert.equal(series.time_sequence[3]!.drop_reason, 2)
    assert.equal(series.time_sequence[3]!.drop_reason_label, 'SKB_DROP_REASON_NOT_SPECIFIED (2)')

    // cwnd/RTT checks: point 2 omitted srtt_us -> MUST be null, never 0!
    assert.equal(series.cwnd_rtt.length, 3)
    assert.equal(series.cwnd_rtt[0]!.snd_cwnd, 10)
    assert.equal(series.cwnd_rtt[0]!.srtt_us, 25000)
    assert.equal(series.cwnd_rtt[0]!.srtt_ms, 25)
    assert.equal(series.cwnd_rtt[1]!.snd_cwnd, 12)
    assert.equal(series.cwnd_rtt[1]!.srtt_us, null)
    assert.equal(series.cwnd_rtt[1]!.srtt_ms, null)
    assert.equal(series.cwnd_rtt[2]!.snd_cwnd, 6)
    assert.equal(series.cwnd_rtt[2]!.srtt_us, 40000)

    assert.equal(series.stats.retransmit_count, 1)
    assert.equal(series.stats.drop_count, 1)
    assert.equal(series.stats.cwnd_points, 3)
    assert.equal(series.stats.rtt_points, 2)
    assert.equal(series.stats.min_cwnd, 6)
    assert.equal(series.stats.max_cwnd, 12)
    assert.equal(series.stats.min_srtt_us, 25000)
    assert.equal(series.stats.max_srtt_us, 40000)

    // Verify disabled tcp_diag / tcp_probe surfaces explicit Chinese notice
    const disabledDir = path.join(tmpRoot, 's-no-tcp-probe')
    writeSessionFiles(
      disabledDir,
      {
        session_id: 's-no-tcp-probe',
        probe_preset: 'egress',
        requested_groups: ['core_drop', 'egress_tc'],
        effective_groups: ['core_drop', 'egress_tc'],
        probe_inventory: [
          { id: 'builtin.tcp_retransmit', group: 'tcp_diag', source: 'builtin', target: 'tcp:tcp_retransmit_skb', status: 'disabled_by_user' },
          { id: 'builtin.tcp_probe', group: 'tcp_probe', source: 'builtin', target: 'tcp:tcp_probe', status: 'disabled_by_user' },
        ],
        capabilities: {
          btf_available: true,
          drop_reason_available: true,
          drop_reason_source: 'vmlinux_btf',
          stack_symbolize_available: true,
        },
      },
      [
        makeWireEvent({
          ts_ns: baseTs,
          seq: 1n,
          kind: KIND_OBJECT,
          site_dict_idx: 4,
          object_id: 201n,
          tlvs: [
            { tag: TLV_OBJ_SAMPLE_ID, val: u64(201n) },
            { tag: TLV_OBJ_END_REASON, val: u16(END_TX_OK) },
          ],
        }),
        mkSummary(2n, 201n, baseTs + 100n),
      ],
    )
    const disabledSeries = buildFlowTcpSeries(reconstruct(loadSession(disabledDir)), { sample_id: '201' })
    assert.equal(disabledSeries.tcp_probes_enabled, false)
    assert.equal(disabledSeries.tcp_probe_status, 'disabled_by_user')
    assert.match(String(disabledSeries.notice), /未开启 TCP 详细探针/)
    assert.equal(disabledSeries.cwnd_rtt.length, 0)
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true })
  }
})

test('Appendix A.3: optional tls-events.jsonl reader is silent when absent and correlates by 5-tuple/pid/time-window when present', async () => {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'pktpath-wave3-tls-'))
  try {
    const baseTs = 1_732_700_000_000_000_000n
    const baseEvents: Uint8Array[] = [
      makeWireEvent({
        ts_ns: baseTs,
        seq: 1n,
        kind: KIND_OBJECT,
        site_dict_idx: 1,
        object_id: 301n,
        tlvs: [
          { tag: TLV_OBJ_SAMPLE_ID, val: u64(301n) },
          { tag: TLV_OBJ_END_REASON, val: u16(END_TX_OK) },
        ],
      }),
      makeWireEvent({
        ts_ns: baseTs + 1_000n,
        seq: 2n,
        kind: KIND_SUMMARY,
        site_dict_idx: 1,
        object_id: 301n,
        tlvs: [
          { tag: TLV_SUM_IFINDEX, val: u32(2) },
          { tag: TLV_SUM_DIR, val: u8(DIR_TX) },
          { tag: TLV_SUM_IP_VERSION, val: u8(4) },
          { tag: TLV_SUM_L4_PROTO, val: u8(6) },
          { tag: TLV_SUM_SRC_IP, val: ipv4Bytes('10.0.2.15') },
          { tag: TLV_SUM_DST_IP, val: ipv4Bytes('93.184.216.34') },
          { tag: TLV_SUM_SRC_PORT, val: u16(54321) },
          { tag: TLV_SUM_DST_PORT, val: u16(443) },
          { tag: TLV_SUM_TGID, val: u32(12345) },
          { tag: TLV_SUM_UID, val: u32(10248) },
        ],
      }),
    ]

    // 1. Default session WITHOUT tls-events.jsonl -> silent, zero impact
    const noTlsDir = path.join(tmpRoot, 's-no-tls')
    writeSessionFiles(noTlsDir, { session_id: 's-no-tls' }, baseEvents)

    const store = new SessionStore(makeHostPaths(tmpRoot))
    const ovNoTls = await store.getOverview('s-no-tls')
    assert.equal('tls_sidecar' in ovNoTls, false)
    const sampleNoTls = await store.getSample('s-no-tls', '301')
    assert.equal('tls_correlation' in sampleNoTls, false)
    const directNoTls = await store.getTlsCorrelations('s-no-tls')
    assert.equal(directNoTls.available, false)
    assert.equal(directNoTls.events.length, 0)

    // 2. Session WITH tls-events.jsonl -> correlates 5-tuple+pid, pid fallback, ignores out-of-window, survives malformed line
    const withTlsDir = path.join(tmpRoot, 's-with-tls')
    writeSessionFiles(withTlsDir, { session_id: 's-with-tls' }, baseEvents, [
      JSON.stringify({
        schema_version: 1,
        ts_ns: '1732700000005000000',
        pid: 12345,
        tid: 12346,
        uid: 10248,
        comm: 'com.example.app',
        direction: 'write',
        library: 'boringssl',
        conn_hint: { fd: 42, src_ip: '10.0.2.15', dst_ip: '93.184.216.34', src_port: 54321, dst_port: 443 },
        plaintext_len: 44,
        plaintext_preview: 'GET /api/v1/health HTTP/1.1\r\nHost: example.com',
        truncated: false,
      }),
      // Reverse tuple (read response) within window
      JSON.stringify({
        schema_version: 1,
        ts_ns: '1732700000020000000',
        pid: 99999,
        tid: 99999,
        uid: 10248,
        comm: 'com.example.app',
        direction: 'read',
        library: 'conscrypt',
        conn_hint: { fd: 42, src_ip: '93.184.216.34', dst_ip: '10.0.2.15', src_port: 443, dst_port: 54321 },
        plaintext_len: 17,
        plaintext_preview: 'HTTP/1.1 200 OK\r\n',
        truncated: false,
      }),
      // PID + time window fallback (no conn_hint)
      JSON.stringify({
        schema_version: 1,
        ts_ns: '1732700000100000000',
        pid: 12345,
        tid: 12346,
        uid: 10248,
        comm: 'com.example.app',
        direction: 'write',
        library: 'openssl',
        plaintext_len: 10,
        plaintext_preview: 'PING\r\n',
        truncated: false,
      }),
      // Out of time window (10s later) -> unmatched
      JSON.stringify({
        schema_version: 1,
        ts_ns: '1732700010000000000',
        pid: 12345,
        tid: 12346,
        uid: 10248,
        comm: 'com.example.app',
        direction: 'write',
        library: 'boringssl',
        conn_hint: { fd: 42, src_ip: '10.0.2.15', dst_ip: '93.184.216.34', src_port: 54321, dst_port: 443 },
        plaintext_len: 5,
        plaintext_preview: 'LATE',
        truncated: false,
      }),
      // Malformed JSONL line -> counted in parse_errors, does not throw
      '{not-valid-json',
    ])

    const ovWithTls = await store.getOverview('s-with-tls')
    const sidecarSummary = ovWithTls['tls_sidecar'] as Record<string, unknown>
    assert.ok(sidecarSummary)
    assert.equal(sidecarSummary['available'], true)
    assert.equal(sidecarSummary['total_events'], 4)
    assert.equal(sidecarSummary['matched_events'], 3)
    assert.equal(sidecarSummary['parse_errors'], 1)

    const allCorr = await store.getTlsCorrelations('s-with-tls')
    assert.equal(allCorr.available, true)
    assert.equal(allCorr.events.length, 4)
    assert.equal(allCorr.events[0]!.ts_ns, '1732700000005000000')
    assert.equal(allCorr.events[0]!.match_confidence, 'five_tuple_and_pid')
    assert.equal(allCorr.events[1]!.match_confidence, 'five_tuple')
    assert.equal(allCorr.events[2]!.match_confidence, 'pid_time_window')
    assert.equal(allCorr.events[3]!.match_confidence, 'unmatched')

    // Sample-filtered correlation returns only the 3 matched events for sample 301
    const sampleWithTls = await store.getSample('s-with-tls', '301')
    const sampleTls = sampleWithTls['tls_correlation'] as ReturnType<typeof correlateTlsEvents>
    assert.ok(sampleTls)
    assert.equal(sampleTls.available, true)
    assert.equal(sampleTls.events.length, 3)
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true })
  }
})
