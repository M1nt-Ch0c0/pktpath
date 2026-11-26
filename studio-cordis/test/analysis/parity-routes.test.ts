import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { CordisHost } from '../../src/kernel/host.ts'
import { registerWave1Builtins } from '../../src/plugins/register.ts'
import { startStudioApp } from '../../src/server/app.ts'
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
  TLV_SUM_HDR_BYTES,
  WireEvent,
  createAnalysisWave1Builtins,
  encodeBlock,
  encodeEvent,
  parseUUID,
} from '../../src/plugins/analysis/index.ts'
import { handleSessionRoute } from '../../src/routes/session-routes.ts'

function buildSampleEthIpv4Tcp(): Uint8Array {
  const buf = Buffer.alloc(14 + 20 + 20)
  buf[0] = 0xaa; buf[1] = 0xbb; buf[2] = 0xcc; buf[3] = 0xdd; buf[4] = 0xee; buf[5] = 0xff
  buf[6] = 0x12; buf[7] = 0x34; buf[8] = 0x56; buf[9] = 0x78; buf[10] = 0x9a; buf[11] = 0xbc
  buf.writeUInt16BE(0x0800, 12)
  buf[14] = 0x45
  buf.writeUInt16BE(40, 16)
  buf[23] = 6
  buf[26] = 10; buf[27] = 20; buf[28] = 30; buf[29] = 40
  buf[30] = 198; buf[31] = 51; buf[32] = 100; buf[33] = 7
  buf.writeUInt16BE(43210, 34)
  buf.writeUInt16BE(443, 36)
  buf[46] = 0x50
  return new Uint8Array(buf)
}

function writeParitySession(
  dir: string,
  opts: { withManifest?: boolean; dev?: string; kernelRelease?: string; realtimeNs?: string } = {},
): void {
  fs.mkdirSync(dir, { recursive: true })
  const uuidBytes = parseUUID('22222222-3333-4444-5555-666666666666')
  const hdr = buildSampleEthIpv4Tcp()
  const baseTs = 1_000_000_000n

  const e1 = new WireEvent({
    kind: KIND_OBJECT,
    object_type: OBJ_SKB,
    evidence_level: EVIDENCE_DIRECT,
    site_dict_idx: 1,
    cpu: 0,
    flags: EV_FLAG_IN_TASK,
    seq: 1n,
    ts_ns: baseTs,
    object_id: 1001n,
    producer_type: PROD_KERNEL_BPF,
  })
  e1.nums.set("sample_id", 1001n)
  e1.nums.set("end_reason", BigInt(END_TX_OK))

  const e2 = new WireEvent({
    kind: KIND_STEP,
    object_type: OBJ_SKB,
    evidence_level: EVIDENCE_DIRECT,
    site_dict_idx: 1,
    cpu: 0,
    flags: EV_FLAG_IN_TASK,
    seq: 2n,
    ts_ns: baseTs + 50_000n,
    object_id: 1001n,
    producer_type: PROD_KERNEL_BPF,
  })
  e2.nums.set("stage", BigInt(STAGE_ENTRY))
  e2.nums.set("sample_id", 1001n)
  e2.nums.set("ifindex", 3n)
  e2.nums.set("dev_gen", 1n)
  e2.nums.set("netns_inum", 4026531992n)

  const e3 = new WireEvent({
    kind: KIND_SUMMARY,
    object_type: OBJ_SKB,
    evidence_level: EVIDENCE_DIRECT,
    site_dict_idx: 1,
    cpu: 0,
    flags: EV_FLAG_IN_TASK,
    seq: 3n,
    ts_ns: baseTs + 120_000n,
    object_id: 1001n,
    producer_type: PROD_KERNEL_BPF,
  })
  e3.nums.set("dir", BigInt(DIR_TX))
  e3.nums.set("l4_proto", 6n)
  e3.strs.set("src_ip", "10.20.30.40")
  e3.strs.set("dst_ip", "198.51.100.7")
  e3.nums.set("src_port", 43210n)
  e3.nums.set("dst_port", 443n)
  e3.nums.set("uid", 10001n)
  e3.nums.set("pkt_len", 54n)
  e3.bins.set("hdr_bytes", hdr)

  const evBytes = Buffer.concat([
    encodeEvent(e1),
    encodeEvent(e2),
    encodeEvent(e3, [
      { tag: TLV_SUM_HDR_BYTES, val: hdr },
    ]),
  ])
  const b1 = encodeBlock(
    {
      magic: BLOCK_MAGIC,
      major: 1,
      minor: 0,
      block_type: BLOCK_EVENT_BATCH,
      producer_type: PROD_KERNEL_BPF,
      flags: 0,
      payload_len: evBytes.length,
      epoch: 1,
      block_no: 1,
      reserved: 0,
      session_uuid: uuidBytes,
      min_ts_ns: baseTs,
      max_ts_ns: baseTs + 120_000n,
    },
    evBytes,
  )
  const b2 = encodeBlock(
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
      session_uuid: uuidBytes,
      min_ts_ns: 0n,
      max_ts_ns: 0n,
    },
    Buffer.alloc(0),
  )
  fs.writeFileSync(path.join(dir, 'block_000001.pktb'), b1)
  fs.writeFileSync(path.join(dir, 'block_000002.pktb'), b2)
  fs.writeFileSync(
    path.join(dir, 'dict.json'),
    JSON.stringify({
      sites: [{ idx: 1, name: 'tc_egress_entry', stage: STAGE_ENTRY, hook: 'tc-egress' }],
      topology_epochs: [
        {
          epoch: 1,
          devices: [{ ifindex: 3, dev_gen: 1, name: opts.dev ?? 'wlan0', linktype: LINK_TYPE_ETHERNET, netns_inum: 4026531992 }],
        },
      ],
    }),
  )
  if (opts.withManifest !== false) {
    fs.writeFileSync(
      path.join(dir, 'manifest.json'),
      JSON.stringify({
        schema_version: 1,
        session_uuid: '22222222-3333-4444-5555-666666666666',
        dev: opts.dev ?? 'wlan0',
        scope: 'tc-egress',
        mode: 'oneshot',
        kernel_release: opts.kernelRelease ?? '6.1.75-android14-11',
        admissions: { selected: 1, created: 1 },
        calibrations: [
          {
            mono_ns: 1_000_000_000,
            realtime_ns: Number(opts.realtimeNs ?? '1764200000000000000'),
            err_ns: 100,
          },
        ],
      }),
    )
  }
}

async function fetchJson(url: string, init?: RequestInit): Promise<{ status: number; data: Record<string, unknown> }> {
  const res = await fetch(url, init)
  const data = (await res.json()) as Record<string, unknown>
  return { status: res.status, data }
}

test('Go vs Cordis parity: P1-6, P1-7, P1-8, P1-9, P2-7, P2-8', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pktpath-shan-parity-'))
  const appDir = path.join(tmp, 'app')
  const sessionsRoot = path.join(appDir, 'sessions')
  const exportsDir = path.join(appDir, 'exports')
  const pluginsDir = path.join(appDir, 'plugins')
  const collectorsDir = path.join(appDir, 'collectors')
  const webDir = path.join(tmp, 'web')
  fs.mkdirSync(webDir, { recursive: true })
  fs.writeFileSync(path.join(webDir, 'index.html'), '<!doctype html><html><body>ok</body></html>')

  const managedDir = path.join(sessionsRoot, 'run_oneshot_wlan0')
  const pullingDir = path.join(sessionsRoot, '.pulling_12345')
  const extManifestDir = path.join(tmp, 'external_with_manifest')
  const extPktbOnlyDir = path.join(tmp, 'external_pktb_only')

  writeParitySession(managedDir, {
    dev: 'wlan0',
    kernelRelease: '6.1.75-android14-11',
    realtimeNs: '1764200000000000000',
  })
  writeParitySession(pullingDir, { dev: 'rmnet0' })
  writeParitySession(extManifestDir, {
    dev: 'eth0',
    kernelRelease: '6.6.12-test',
    realtimeNs: '1764200100000000000',
  })
  writeParitySession(extPktbOnlyDir, { withManifest: false })

  const host = new CordisHost({
    appDir,
    sessionsRoot,
    pluginsDir,
    exportsDir,
    collectorsDir,
    webDir,
  })
  registerWave1Builtins(host, createAnalysisWave1Builtins())
  await host.start()

  const app = await startStudioApp({
    host,
    listenPort: 0,
    extraRouteHandlers: [handleSessionRoute],
  })

  try {
    // 1. P1-6 & P2-7: GET /api/sessions includes sessions_root, Go item fields, skips .pulling_*
    const list1 = await fetchJson(`${app.url}/api/sessions`)
    assert.equal(list1.status, 200)
    assert.equal(list1.data['ok'], true)
    assert.equal(list1.data['sessions_root'], sessionsRoot)
    const items1 = list1.data['sessions'] as Array<Record<string, unknown>>
    assert.equal(items1.length, 1, 'dot-prefixed .pulling_* directory must be skipped')
    const mItem = items1[0]!
    assert.equal(mItem['id'], 'run_oneshot_wlan0')
    assert.equal(mItem['dev'], 'wlan0')
    assert.equal(mItem['scope'], 'tc-egress')
    assert.equal(mItem['mode'], 'oneshot')
    assert.equal(mItem['kernel_release'], '6.1.75-android14-11')
    assert.equal(mItem['sample_count'], 1)
    assert.equal(mItem['external'], false)
    assert.equal(mItem['created_unix_ms'], 1764200000000)
    assert.match(String(mItem['created_at']), /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/)

    // 2. P1-7: POST /api/sessions/open accepts file path (dirname), returns session_id & session_path aliases
    const openByFile = await fetchJson(`${app.url}/api/sessions/open`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ path: path.join(extManifestDir, 'manifest.json') }),
    })
    assert.equal(openByFile.status, 200, JSON.stringify(openByFile.data))
    assert.equal(openByFile.data['ok'], true)
    assert.equal(openByFile.data['session_id'], openByFile.data['id'])
    assert.equal(openByFile.data['session_path'], extManifestDir)
    assert.equal(openByFile.data['path'], extManifestDir)
    assert.ok(openByFile.data['overview'])

    // Also supports .pktb-only folder via file path
    const openPktbOnly = await fetchJson(`${app.url}/api/sessions/open`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ path: path.join(extPktbOnlyDir, 'block_000001.pktb') }),
    })
    assert.equal(openPktbOnly.status, 200, JSON.stringify(openPktbOnly.data))
    assert.equal(openPktbOnly.data['session_path'], extPktbOnlyDir)

    // External session now shows external: true and dev: 'eth0' in GET /api/sessions
    const list2 = await fetchJson(`${app.url}/api/sessions`)
    const items2 = list2.data['sessions'] as Array<Record<string, unknown>>
    const extEntry = items2.find((x) => x['path'] === extManifestDir)
    assert.ok(extEntry)
    assert.equal(extEntry['external'], true)
    assert.equal(extEntry['dev'], 'eth0')
    assert.equal(extEntry['kernel_release'], '6.6.12-test')
    assert.equal(extEntry['sample_count'], 1)

    // 3. P1-8: overview supports session_id alias and refresh=1 (as well as force/reanalyze)
    const ov1 = await fetchJson(`${app.url}/api/session/overview?session_id=run_oneshot_wlan0`)
    assert.equal(ov1.status, 200)
    assert.equal((ov1.data['analysis_cache'] as { state: string }).state, 'computed')

    const ov2 = await fetchJson(`${app.url}/api/session/overview?id=run_oneshot_wlan0`)
    assert.equal(ov2.status, 200)
    assert.equal((ov2.data['analysis_cache'] as { state: string }).state, 'memory_hit')

    const ovRefresh = await fetchJson(`${app.url}/api/session/overview?id=run_oneshot_wlan0&refresh=1`)
    assert.equal(ovRefresh.status, 200)
    assert.equal((ovRefresh.data['analysis_cache'] as { state: string }).state, 'computed')

    const ovForce = await fetchJson(`${app.url}/api/session/overview?session_id=run_oneshot_wlan0&force=1`)
    assert.equal(ovForce.status, 200)
    assert.equal((ovForce.data['analysis_cache'] as { state: string }).state, 'computed')

    // sample also accepts session_id alias
    const smp = await fetchJson(`${app.url}/api/session/sample?session_id=run_oneshot_wlan0&sample_id=1001`)
    assert.equal(smp.status, 200)
    assert.equal(smp.data['sample_id'], '1001')

    // 4. P1-9: GET /api/session/export-pcapng binary download
    const getPcapRes = await fetch(`${app.url}/api/session/export-pcapng?session_id=run_oneshot_wlan0&redact=1&key=parity`)
    assert.equal(getPcapRes.status, 200)
    assert.equal(getPcapRes.headers.get('content-type'), 'application/x-pcapng')
    assert.match(getPcapRes.headers.get('content-disposition') ?? '', /trace_run_oneshot_wlan0_redacted\.pcapng/)
    const pcapBuf = Buffer.from(await getPcapRes.arrayBuffer())
    assert.ok(pcapBuf.length > 64)
    assert.equal(pcapBuf.readUInt32LE(0), 0x0a0d0d0a)

    const getPcap404 = await fetch(`${app.url}/api/session/export-pcapng?id=nonexistent_session`)
    assert.equal(getPcap404.status, 404)

    // 5. P1-9: POST /api/session/export-pcapng
    const pcapOut = path.join(exportsDir, 'alias_out.pcapng')
    const postPcap = await fetchJson(`${app.url}/api/session/export-pcapng`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        session_id: 'run_oneshot_wlan0',
        out_path: pcapOut,
        redact: true,
        key: 'parity',
      }),
    })
    assert.equal(postPcap.status, 200, JSON.stringify(postPcap.data))
    assert.equal(postPcap.data['ok'], true)
    assert.equal(postPcap.data['out_path'], pcapOut)
    assert.equal(postPcap.data['redact'], true)
    assert.equal(postPcap.data["exported_packets"], 1, JSON.stringify(postPcap.data))
    assert.ok(fs.existsSync(pcapOut))

    // Guard still blocks writing inside session_dir via legacy alias
    const postPcapBad = await fetchJson(`${app.url}/api/session/export-pcapng`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        id: 'run_oneshot_wlan0',
        out_path: path.join(managedDir, 'evil.pcapng'),
      }),
    })
    assert.equal(postPcapBad.status, 400)

    // 6. P1-9: POST /api/session/redact writes & registers redacted session
    const postRedact = await fetchJson(`${app.url}/api/session/redact`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        id: 'run_oneshot_wlan0',
        key: 'parity',
      }),
    })
    assert.equal(postRedact.status, 200, JSON.stringify(postRedact.data))
    assert.equal(postRedact.data['ok'], true)
    const redactedId = String(postRedact.data['session_id'])
    const redactedDir = String(postRedact.data['out_dir'])
    assert.ok(redactedId)
    assert.ok(fs.existsSync(path.join(redactedDir, 'manifest.json')))
    const redOv = await fetchJson(`${app.url}/api/session/overview?session_id=${encodeURIComponent(redactedId)}`)
    assert.equal(redOv.status, 200)

    // 7. P2-8: POST /api/session/export-csv alias
    const csvOut = path.join(exportsDir, 'alias_report.csv')
    const postCsv = await fetchJson(`${app.url}/api/session/export-csv`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        session_id: 'run_oneshot_wlan0',
        out_path: csvOut,
      }),
    })
    assert.equal(postCsv.status, 200, JSON.stringify(postCsv.data))
    assert.equal(postCsv.data['ok'], true)
    assert.ok(fs.existsSync(csvOut))
  } finally {
    await app.close()
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})
