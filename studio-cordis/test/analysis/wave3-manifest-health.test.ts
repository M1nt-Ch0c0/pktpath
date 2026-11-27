import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import { CordisHost } from '../../src/kernel/host.ts'
import { registerWave1Builtins } from '../../src/plugins/register.ts'
import {
  SessionStore,
  buildSampleDetail,
  buildSessionHealth,
  createAnalysisWave1Builtins,
  loadSession,
  normalizeWave3Manifest,
  reconstruct,
  resolveDropReason,
  BLOCK_END_MARKER,
  BLOCK_EVENT_BATCH,
  BLOCK_MAGIC,
  WIRE_MAJOR,
  WIRE_MINOR,
  WireEvent,
  DIR_TX,
  END_DROP,
  END_TX_OK,
  EVIDENCE_DIRECT,
  KIND_OBJECT,
  KIND_QUALITY,
  KIND_STEP,
  KIND_SUMMARY,
  OBJ_SKB,
  PROD_CONTROLLER,
  PROD_KERNEL_BPF,
  QUAL_MISSED_DELTA,
  STAGE_DROP,
  STAGE_ENTRY,
  STAGE_XMIT_START,
  TLV_OBJ_DROP_REASON,
  TLV_OBJ_END_REASON,
  TLV_OBJ_SAMPLE_ID,
  TLV_QUAL_COUNT,
  TLV_QUAL_KIND,
  TLV_QUAL_WIN_END_NS,
  TLV_QUAL_WIN_START_NS,
  TLV_STEP_DIR,
  TLV_STEP_IFINDEX,
  TLV_STEP_STAGE,
  TLV_SUM_DIR,
  TLV_SUM_IFINDEX,
  TLV_SUM_L4_PROTO,
  encodeBlock,
  encodeEvent,
} from '../../src/plugins/analysis/index.ts'
import type { BlockHeader, Tlv } from '../../src/plugins/analysis/index.ts'

function u16(v: number): Uint8Array {
  const b = Buffer.alloc(2)
  b.writeUInt16LE(v & 0xffff, 0)
  return b
}
function u8(v: number): Uint8Array {
  return Uint8Array.of(v & 0xff)
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

function makeWireEvent(opts: {
  ts_ns: bigint
  seq: bigint
  cpu: number
  kind: number
  site_dict_idx: number
  object_id: bigint
  tlvs: Tlv[]
  producer_type?: number
}): Uint8Array {
  const ev = new WireEvent()
  ev.ts_ns = opts.ts_ns
  ev.seq = opts.seq
  ev.object_id = opts.object_id
  ev.kind = opts.kind
  ev.object_type = OBJ_SKB
  ev.evidence_level = EVIDENCE_DIRECT
  ev.producer_type = opts.producer_type ?? PROD_KERNEL_BPF
  ev.cpu = opts.cpu
  ev.site_dict_idx = opts.site_dict_idx
  ev.flags = 0
  return encodeEvent(ev, opts.tlvs)
}

function makeHostPaths(tmpRoot: string) {
  const appDir = path.join(tmpRoot, 'app')
  return {
    appDir,
    sessionsRoot: tmpRoot,
    pluginsDir: path.join(tmpRoot, 'plugins'),
    exportsDir: path.join(tmpRoot, 'exports'),
    collectorsDir: path.join(tmpRoot, 'collectors'),
    webDir: path.join(tmpRoot, 'web'),
  }
}

function writeSyntheticSession(
  dir: string,
  manifest: Record<string, unknown>,
  dict: Record<string, unknown>,
  encodedEvents: Uint8Array[],
): void {
  fs.mkdirSync(dir, { recursive: true })
  fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(manifest, null, 2), 'utf8')
  fs.writeFileSync(path.join(dir, 'dict.json'), JSON.stringify(dict, null, 2), 'utf8')
  const sessionUuid = new Uint8Array(16).fill(0x33)
  const baseHdr: BlockHeader = {
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
    session_uuid: sessionUuid,
    min_ts_ns: 1_000_000_000n,
    max_ts_ns: 1_000_005_000n,
  }
  const batchBlock = encodeBlock(baseHdr, Buffer.concat(encodedEvents))
  const endBlock = encodeBlock(
    { ...baseHdr, block_type: BLOCK_END_MARKER, producer_type: PROD_CONTROLLER, block_no: 2 },
    new Uint8Array(0),
  )
  fs.writeFileSync(path.join(dir, 'events-0001.pktb'), Buffer.concat([batchBlock, endBlock]))
}

function makeBaseEvents(opts?: {
  dropReason?: number
  externalSiteId?: number
  missedDelta?: number
  openUnfinished?: boolean
}): Uint8Array[] {
  const baseTs = 1_000_000_000n
  const evs: Uint8Array[] = [
    makeWireEvent({
      ts_ns: baseTs,
      seq: 1n,
      cpu: 0,
      kind: KIND_OBJECT,
      site_dict_idx: 1,
      object_id: 100n,
      tlvs: [{ tag: TLV_OBJ_SAMPLE_ID, val: u64(100n) }],
    }),
    makeWireEvent({
      ts_ns: baseTs + 100n,
      seq: 2n,
      cpu: 0,
      kind: KIND_SUMMARY,
      site_dict_idx: 1,
      object_id: 100n,
      tlvs: [
        { tag: TLV_SUM_IFINDEX, val: u32(2) },
        { tag: TLV_SUM_DIR, val: u8(DIR_TX) },
        { tag: TLV_SUM_L4_PROTO, val: u8(6) },
      ],
    }),
    makeWireEvent({
      ts_ns: baseTs + 1000n,
      seq: 3n,
      cpu: 0,
      kind: KIND_STEP,
      site_dict_idx: opts?.externalSiteId ?? 1,
      object_id: 100n,
      tlvs: [
        { tag: TLV_STEP_STAGE, val: u8(STAGE_ENTRY) },
        { tag: TLV_STEP_IFINDEX, val: u32(2) },
        { tag: TLV_STEP_DIR, val: u8(DIR_TX) },
      ],
    }),
  ]

  if (opts?.dropReason !== undefined) {
    evs.push(
      makeWireEvent({
        ts_ns: baseTs + 3000n,
        seq: 4n,
        cpu: 0,
        kind: KIND_STEP,
        site_dict_idx: 2,
        object_id: 100n,
        tlvs: [
          { tag: TLV_STEP_STAGE, val: u8(STAGE_DROP) },
          { tag: TLV_STEP_IFINDEX, val: u32(2) },
          { tag: TLV_STEP_DIR, val: u8(DIR_TX) },
        ],
      }),
      makeWireEvent({
        ts_ns: baseTs + 4000n,
        seq: 5n,
        cpu: 0,
        kind: KIND_OBJECT,
        site_dict_idx: 2,
        object_id: 100n,
        tlvs: [
          { tag: TLV_OBJ_SAMPLE_ID, val: u64(100n) },
          { tag: TLV_OBJ_END_REASON, val: u16(END_DROP) },
          { tag: TLV_OBJ_DROP_REASON, val: u32(opts.dropReason) },
        ],
      }),
    )
  } else if (!opts?.openUnfinished) {
    evs.push(
      makeWireEvent({
        ts_ns: baseTs + 3000n,
        seq: 4n,
        cpu: 0,
        kind: KIND_STEP,
        site_dict_idx: 3,
        object_id: 100n,
        tlvs: [
          { tag: TLV_STEP_STAGE, val: u8(STAGE_XMIT_START) },
          { tag: TLV_STEP_IFINDEX, val: u32(2) },
          { tag: TLV_STEP_DIR, val: u8(DIR_TX) },
        ],
      }),
      makeWireEvent({
        ts_ns: baseTs + 4000n,
        seq: 5n,
        cpu: 0,
        kind: KIND_OBJECT,
        site_dict_idx: 3,
        object_id: 100n,
        tlvs: [
          { tag: TLV_OBJ_SAMPLE_ID, val: u64(100n) },
          { tag: TLV_OBJ_END_REASON, val: u16(END_TX_OK) },
        ],
      }),
    )
  }

  evs.push(
    makeWireEvent({
      ts_ns: baseTs + 5000n,
      seq: 1n,
      cpu: 0xffffffff,
      kind: KIND_QUALITY,
      site_dict_idx: 0,
      object_id: 0n,
      producer_type: PROD_CONTROLLER,
      tlvs: [
        { tag: TLV_QUAL_KIND, val: u8(QUAL_MISSED_DELTA) },
        { tag: TLV_QUAL_WIN_START_NS, val: u64(baseTs) },
        { tag: TLV_QUAL_WIN_END_NS, val: u64(baseTs + 5000n) },
        { tag: TLV_QUAL_COUNT, val: u64(BigInt(opts?.missedDelta ?? 0)) },
      ],
    }),
  )

  return evs
}

const BASE_DICT: Record<string, unknown> = {
  adapters: [{ adapter_id: 'kernel', name: 'Linux eBPF' }],
  sites: [
    { site_idx: 1, adapter_id: 'kernel', name: 'entry', symbol: 'dev_queue_xmit', probe_type: 'kprobe', stage: STAGE_ENTRY, group: 'egress_tc' },
    { site_idx: 2, adapter_id: 'kernel', name: 'kfree_skb', symbol: 'skb:kfree_skb', probe_type: 'tracepoint', stage: STAGE_DROP, group: 'core_drop' },
    { site_idx: 3, adapter_id: 'kernel', name: 'xmit', symbol: 'net_dev_start_xmit', probe_type: 'tracepoint', stage: STAGE_XMIT_START, group: 'egress_tc' },
  ],
  topology_epochs: [
    {
      epoch_id: 1,
      ts_ns: 900_000_000,
      devices: [{ ifindex: 2, dev_gen: 1, name: 'eth0', linktype: 1 }],
    },
  ],
}

test('resolveDropReason enforces vmlinux_btf exact lookup, subsystem single-entry fallback without low-16-bit truncation, and unavailable fallback', () => {
  const btfManifest = normalizeWave3Manifest({
    capabilities: {
      btf_available: true,
      drop_reason_available: true,
      drop_reason_source: 'vmlinux_btf',
      stack_symbolize_available: true,
    },
    drop_reason_map: {
      '2': 'SKB_DROP_REASON_NOT_SPECIFIED',
      '13': 'SKB_DROP_REASON_TCP_CSUM',
      '196609': 'NFT_DROP_REASON_RULE',
    },
  })

  // Exact hit in main enum
  const hitMain = resolveDropReason(13, btfManifest)!
  assert.equal(hitMain.verified, true)
  assert.equal(hitMain.name, 'SKB_DROP_REASON_TCP_CSUM')
  assert.equal(hitMain.subsystem_unmapped, false)
  assert.equal(hitMain.label, 'SKB_DROP_REASON_TCP_CSUM (13)')

  // Exact hit in subsystem enum (3 << 16 | 1 = 196609)
  const hitSub = resolveDropReason(196609, btfManifest)!
  assert.equal(hitSub.verified, true)
  assert.equal(hitSub.name, 'NFT_DROP_REASON_RULE')
  assert.equal(hitSub.subsystem, 3)

  // Missing subsystem enum whose low 16 bits (13) EXIST in main enum:
  // MUST NOT truncate to 13 / SKB_DROP_REASON_TCP_CSUM!
  const unmappedSubCode = ((3 << 16) | 13) >>> 0 // 196621
  const missSub = resolveDropReason(unmappedSubCode, btfManifest)!
  assert.equal(missSub.verified, false)
  assert.equal(missSub.name, null)
  assert.equal(missSub.subsystem, 3)
  assert.equal(missSub.subsystem_unmapped, true)
  assert.match(missSub.label, /196621/)
  assert.match(missSub.label, /子系统枚举未在 vmlinux BTF 中/)
  assert.doesNotMatch(missSub.label, /TCP_CSUM/)

  // drop_reason_source === 'unavailable' MUST ignore even a populated drop_reason_map
  const unavailableManifest = normalizeWave3Manifest({
    capabilities: {
      btf_available: false,
      drop_reason_available: false,
      drop_reason_source: 'unavailable',
      stack_symbolize_available: false,
    },
    drop_reason_map: {
      '13': 'SKB_DROP_REASON_TCP_CSUM',
    },
  })
  assert.deepEqual(unavailableManifest.drop_reason_map, {})
  const unverified = resolveDropReason(13, unavailableManifest)!
  assert.equal(unverified.verified, false)
  assert.equal(unverified.name, null)
  assert.equal(unverified.source, 'unavailable')
  assert.equal(unverified.label, '13（未验证枚举）')
})

test('4-state probe_inventory health banner: only green when attached + healthy capabilities + zero loss; yellow/red on degradation or loss', async () => {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'pktpath-wave3-health-'))
  try {
    // Case 1: Clean attached + disabled_by_user + zero loss -> green banner, "已观测，窗口内 0 次触发"
    const cleanDir = path.join(tmpRoot, 's-clean')
    writeSyntheticSession(
      cleanDir,
      {
        session_id: 's-clean',
        scope: 'tc-egress',
        probe_preset: 'egress',
        requested_groups: ['core_drop', 'egress_tc'],
        effective_groups: ['core_drop', 'egress_tc'],
        probe_inventory: [
          { id: 'kfree_skb', group: 'core_drop', source: 'builtin', target: 'tracepoint/skb/kfree_skb', status: 'attached' },
          { id: 'dev_queue_xmit', group: 'egress_tc', source: 'builtin', target: 'kprobe/dev_queue_xmit', status: 'attached' },
          { id: 'nf_hook_slow', group: 'netfilter_nat', source: 'builtin', target: 'kprobe/nf_hook_slow', status: 'disabled_by_user' },
        ],
        capabilities: {
          btf_available: true,
          drop_reason_available: true,
          drop_reason_source: 'vmlinux_btf',
          stack_symbolize_available: true,
          notes: [],
        },
        drop_reason_map: { '13': 'SKB_DROP_REASON_TCP_CSUM' },
        admissions: { admitted: 1, rejected: 0 },
      },
      BASE_DICT,
      makeBaseEvents(),
    )

    // Case 2: All attached, 0 drops, BUT admissions.rejected > 0 -> yellow banner + "0 命中（存在丢样，不保证未发生）"
    const lossyDir = path.join(tmpRoot, 's-lossy')
    writeSyntheticSession(
      lossyDir,
      {
        session_id: 's-lossy',
        scope: 'tc-egress',
        probe_preset: 'egress',
        requested_groups: ['core_drop', 'egress_tc'],
        effective_groups: ['core_drop', 'egress_tc'],
        probe_inventory: [
          { id: 'kfree_skb', group: 'core_drop', source: 'builtin', target: 'tracepoint/skb/kfree_skb', status: 'attached' },
          { id: 'dev_queue_xmit', group: 'egress_tc', source: 'builtin', target: 'kprobe/dev_queue_xmit', status: 'attached' },
        ],
        capabilities: {
          btf_available: true,
          drop_reason_available: true,
          drop_reason_source: 'vmlinux_btf',
          stack_symbolize_available: true,
        },
        admissions: { admitted: 1, rejected: 7 },
      },
      BASE_DICT,
      makeBaseEvents({ missedDelta: 3 }),
    )

    // Case 3: External .bpf.o attach_failed (verifier error) + unavailable_in_kernel -> red banner, never silent green
    const failedDir = path.join(tmpRoot, 's-failed')
    const longVerifierLog = 'R1 invalid mem access ' + 'X'.repeat(3000) + ' END_VERIFIER_LOG'
    writeSyntheticSession(
      failedDir,
      {
        session_id: 's-failed',
        scope: 'full-path',
        probe_preset: 'custom',
        requested_groups: ['core_drop', 'egress_tc', 'netfilter_nat'],
        effective_groups: ['core_drop', 'egress_tc'],
        probe_inventory: [
          { id: 'kfree_skb', group: 'core_drop', source: 'builtin', target: 'tracepoint/skb/kfree_skb', status: 'attached' },
          { id: 'dev_queue_xmit', group: 'egress_tc', source: 'builtin', target: 'kprobe/dev_queue_xmit', status: 'attached' },
          {
            id: 'nf_hook_slow_ret',
            group: 'netfilter_nat',
            source: 'builtin',
            target: 'kretprobe/nf_hook_slow',
            status: 'unavailable_in_kernel',
            reason: 'symbol nf_hook_slow not available in kallsyms',
          },
          {
            id: 'ext_nf_trace',
            group: 'netfilter_nat',
            source: 'external_bpf',
            plugin_id: 'official.ebpf.nf-trace',
            bpf_sha256: 'deadbeef0123456789',
            target: 'kprobe/nf_hook_slow',
            status: 'attach_failed',
            reason: longVerifierLog,
          },
        ],
        capabilities: {
          btf_available: true,
          drop_reason_available: false,
          drop_reason_source: 'unavailable',
          stack_symbolize_available: false,
          notes: ['kallsyms_restricted'],
        },
      },
      BASE_DICT,
      makeBaseEvents(),
    )

    const paths = makeHostPaths(tmpRoot)
    const store = new SessionStore(paths)
    const host = new CordisHost(paths, 'wave3-health-test')
    registerWave1Builtins(host, createAnalysisWave1Builtins(store))
    store.bindHost(host)
    await host.start()
    try {
      // Verify Case 1 (clean)
      const ovClean = await store.getOverview('s-clean')
      const hClean = ovClean['probe_health'] as Record<string, unknown>
      const bClean = hClean['banner'] as Record<string, unknown>
      assert.equal(bClean['severity'], 'ok')
      assert.equal(bClean['zero_hit_verdict'], '已观测，窗口内 0 次触发')
      const disabled = bClean['disabled_groups'] as Array<Record<string, unknown>>
      assert.equal(disabled.length, 1)
      assert.equal(disabled[0]!['group_id'], 'netfilter_nat')
      assert.equal(disabled[0]!['display_status'], '未开启（未观测）')
      const notesClean = ovClean['plugin_notes'] as string[]
      assert.ok(notesClean.some((n) => n.includes('未开启（未观测）')))
      const insightsClean = ovClean['plugin_insights'] as Array<Record<string, unknown>>
      const radarHealthy = insightsClean.find((i) => i['id'] === 'radar.healthy')
      assert.ok(radarHealthy, 'clean session should emit radar.healthy')
      assert.match(String(radarHealthy['summary']), /已观测，窗口内 0 次触发/)

      // Verify Case 2 (lossy)
      const ovLossy = await store.getOverview('s-lossy')
      const hLossy = ovLossy['probe_health'] as Record<string, unknown>
      const bLossy = hLossy['banner'] as Record<string, unknown>
      assert.equal(bLossy['severity'], 'warn')
      assert.equal(bLossy['zero_hit_verdict'], '0 命中（存在丢样，不保证未发生）')
      const insightsLossy = ovLossy['plugin_insights'] as Array<Record<string, unknown>>
      assert.equal(insightsLossy.find((i) => i['id'] === 'radar.healthy'), undefined)
      const degLossy = insightsLossy.find((i) => i['id'] === 'radar.probe_health_degraded')
      assert.ok(degLossy)
      assert.equal(degLossy['severity'], 'warn')
      const kpisLossy = ovLossy['plugin_kpis'] as Array<Record<string, unknown>>
      const radarKpiLossy = kpisLossy.find((k) => k['analyzer_id'] === 'anomaly-radar')!
      assert.equal(radarKpiLossy['tone'], 'warn')
      assert.match(String(radarKpiLossy['sub']), /0 命中（存在丢样，不保证未发生）/)

      // Verify Case 3 (attach_failed + unavailable + degraded capabilities)
      const ovFailed = await store.getOverview('s-failed')
      const hFailed = ovFailed['probe_health'] as Record<string, unknown>
      const bFailed = hFailed['banner'] as Record<string, unknown>
      assert.equal(bFailed['severity'], 'error')
      const degProbes = bFailed['degraded_probes'] as Array<Record<string, unknown>>
      assert.equal(degProbes.length, 2)
      const extFailed = degProbes.find((p) => p['plugin_id'] === 'official.ebpf.nf-trace')!
      assert.equal(extFailed['status'], 'attach_failed')
      assert.equal(extFailed['bpf_sha256'], 'deadbeef0123456789')
      assert.match(String(extFailed['reason']), /truncated/)
      assert.match(String(extFailed['reason']), /END_VERIFIER_LOG/)
      const insightsFailed = ovFailed['plugin_insights'] as Array<Record<string, unknown>>
      const degInsight = insightsFailed.find((i) => i['id'] === 'radar.probe_health_degraded')!
      assert.equal(degInsight['severity'], 'critical')
      const kpisFailed = ovFailed['plugin_kpis'] as Array<Record<string, unknown>>
      const radarKpiFailed = kpisFailed.find((k) => k['analyzer_id'] === 'anomaly-radar')!
      assert.equal(radarKpiFailed['tone'], 'bad')
    } finally {
      await host.shutdown()
    }
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true })
  }
})

test('external .bpf.o plugin events (0x2000..0xFFFE), plugin_id attribution, drop_reason_resolved, and disabled-probe non-misdiagnosis', async () => {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'pktpath-wave3-ext-'))
  try {
    const extDir = path.join(tmpRoot, 's-ext')
    const subDropCode = ((3 << 16) | 13) >>> 0 // 196621: subsystem 3, low 16 bits = 13
    writeSyntheticSession(
      extDir,
      {
        session_id: 's-ext',
        scope: 'drop-pwru',
        probe_preset: 'drop-pwru',
        requested_groups: ['core_drop', 'l3_route', 'netfilter_nat', 'drop_stack'],
        effective_groups: ['core_drop', 'l3_route', 'netfilter_nat', 'drop_stack'],
        sites: [
          {
            site_id: 0x2000,
            plugin_id: 'official.ebpf.nf-trace',
            group: 'netfilter_nat',
            source: 'external_bpf',
            name: 'nf_trace_hook',
            target: 'kprobe/nf_hook_slow',
            stage: STAGE_ENTRY,
          },
        ],
        probe_inventory: [
          { id: 'kfree_skb', group: 'core_drop', source: 'builtin', target: 'tracepoint/skb/kfree_skb', status: 'attached' },
          {
            id: 'nf_trace_hook',
            group: 'netfilter_nat',
            source: 'external_bpf',
            plugin_id: 'official.ebpf.nf-trace',
            bpf_sha256: 'abc1234567890def',
            target: 'kprobe/nf_hook_slow',
            status: 'attached',
          },
          { id: 'dev_queue_xmit', group: 'egress_tc', source: 'builtin', target: 'kprobe/dev_queue_xmit', status: 'disabled_by_user' },
        ],
        capabilities: {
          btf_available: true,
          drop_reason_available: true,
          drop_reason_source: 'vmlinux_btf',
          stack_symbolize_available: true,
        },
        drop_reason_map: {
          '13': 'SKB_DROP_REASON_TCP_CSUM',
        },
      },
      BASE_DICT,
      makeBaseEvents({ dropReason: subDropCode, externalSiteId: 0x2000 }),
    )

    // Also test OPEN_UNFINISHED with disabled probe group does NOT fabricate SEQ_GAP or DROP
    const openDir = path.join(tmpRoot, 's-open')
    writeSyntheticSession(
      openDir,
      {
        session_id: 's-open',
        scope: 'drop-pwru',
        probe_preset: 'drop-pwru',
        requested_groups: ['core_drop', 'l3_route'],
        effective_groups: ['core_drop', 'l3_route'],
        probe_inventory: [
          { id: 'kfree_skb', group: 'core_drop', source: 'builtin', target: 'tracepoint/skb/kfree_skb', status: 'attached' },
          { id: 'dev_queue_xmit', group: 'egress_tc', source: 'builtin', target: 'kprobe/dev_queue_xmit', status: 'disabled_by_user' },
        ],
        capabilities: {
          btf_available: true,
          drop_reason_available: true,
          drop_reason_source: 'vmlinux_btf',
          stack_symbolize_available: true,
        },
      },
      BASE_DICT,
      makeBaseEvents({ openUnfinished: true }),
    )

    const paths = makeHostPaths(tmpRoot)
    const store = new SessionStore(paths)
    const host = new CordisHost(paths, 'wave3-health-test')
    registerWave1Builtins(host, createAnalysisWave1Builtins(store))
    store.bindHost(host)
    await host.start()
    try {
      const ovExt = await store.getOverview('s-ext')
      const extPlugins = ovExt['external_bpf_plugins'] as Array<Record<string, unknown>>
      assert.equal(extPlugins.length, 1)
      assert.equal(extPlugins[0]!['plugin_id'], 'official.ebpf.nf-trace')
      assert.equal(extPlugins[0]!['bpf_sha256'], 'abc1234567890def')
      assert.equal(extPlugins[0]!['hit_count'], 1)
      assert.deepEqual(extPlugins[0]!['sample_ids'], ['100'])

      // Verify dag-reconstruct analyzer emits external plugin hit attribution insight
      const insights = ovExt['plugin_insights'] as Array<Record<string, unknown>>
      const extInsight = insights.find((i) => i['id'] === 'dag.external_bpf.official.ebpf.nf-trace')
      assert.ok(extInsight, 'dag-reconstruct should attribute external .bpf.o hits by plugin_id')
      assert.deepEqual(extInsight['sample_ids'], ['100'])

      // Verify drop_reasons_summary obeys subsystem fallback without low-16-bit truncation
      const dropSummary = ovExt['drop_reasons_summary'] as Array<Record<string, unknown>>
      assert.equal(dropSummary.length, 1)
      assert.equal(dropSummary[0]!['code'], subDropCode)
      const resolved = dropSummary[0]!['resolved'] as Record<string, unknown>
      assert.equal(resolved['subsystem_unmapped'], true)
      assert.equal(resolved['name'], null)
      assert.match(String(resolved['label']), /子系统枚举未在 vmlinux BTF 中/)

      // Verify sample detail timeline carries external plugin metadata & resolved drop reason
      const detail = await store.getSample('s-ext', '100')
      const branches = detail['branches'] as Array<Record<string, unknown>>
      assert.equal(branches.length, 1)
      const b0 = branches[0]!
      const timeline = b0['timeline'] as Array<Record<string, unknown>>
      const extEv = timeline.find((ev) => ev['plugin_id'] === 'official.ebpf.nf-trace')
      assert.ok(extEv, 'timeline event should expose external .bpf.o plugin_id')
      assert.equal(extEv['probe_source'], 'external_bpf')
      assert.equal(extEv['probe_group'], 'netfilter_nat')
      assert.match(String(b0['boundary_note']), /子系统枚举未在 vmlinux BTF 中/)
      assert.doesNotMatch(String(b0['boundary_note']), /TCP_CSUM/)

      // Verify OPEN_UNFINISHED with disabled probe group does not fabricate SEQ_GAP or DROP
      const openSession = reconstruct(loadSession(openDir))
      const openDetail = buildSampleDetail(openSession, 100n)
      assert.equal(openDetail.branches[0]!.endpoint, 'OPEN')
      assert.ok(!openDetail.branches[0]!.gap_reasons.includes('SEQ_GAP'))
      assert.match(openDetail.branches[0]!.boundary_note, /路径空白不视为丢包/)
      const openHealth = buildSessionHealth(openSession)
      assert.ok(openHealth.unobserved_groups.includes('egress_tc'))
    } finally {
      await host.shutdown()
    }
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true })
  }
})
