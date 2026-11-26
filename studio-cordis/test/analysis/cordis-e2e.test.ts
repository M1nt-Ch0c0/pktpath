import assert from 'node:assert/strict'
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
  WireEvent,
  createAnalysisWave1Builtins,
  encodeBlock,
  encodeEvent,
  parseUUID,
} from '../../src/plugins/analysis/index.ts'
import { handleSessionRoute } from '../../src/routes/session-routes.ts'

import { CordisHost } from '../../src/kernel/host.ts'
import { registerWave1Builtins } from '../../src/plugins/register.ts'
import { startStudioApp } from '../../src/server/app.ts'

const BIG_SAMPLE_ID = 9007199254740993n // > Number.MAX_SAFE_INTEGER
const BIG_OBJECT_ID = BIG_SAMPLE_ID

function buildSampleEthIpv4Tcp(): Uint8Array {
  const buf = Buffer.alloc(14 + 20 + 20)
  buf[0] = 0xaa; buf[1] = 0xbb; buf[2] = 0xcc; buf[3] = 0xdd; buf[4] = 0xee; buf[5] = 0xff
  buf[6] = 0x12; buf[7] = 0x34; buf[8] = 0x56; buf[9] = 0x78; buf[10] = 0x9a; buf[11] = 0xbc
  buf.writeUInt16BE(0x0800, 12)
  buf[14] = 0x45
  buf.writeUInt16BE(40, 16)
  buf[23] = 6
  buf[26] = 10; buf[27] = 1; buf[28] = 2; buf[29] = 3
  buf[30] = 198; buf[31] = 51; buf[32] = 100; buf[33] = 42
  buf.writeUInt16BE(54321, 34)
  buf.writeUInt16BE(443, 36)
  buf[46] = 0x50
  return new Uint8Array(buf)
}

function createFixtureSession(dir: string, sessionUuid = '11223344-5566-7788-99aa-bbccddeeff00'): string {
  fs.mkdirSync(dir, { recursive: true })
  const uuid = parseUUID(sessionUuid)
  const baseTs = 1_700_000_000_000_000_000n
  fs.writeFileSync(
    path.join(dir, 'manifest.json'),
    JSON.stringify(
      {
        session_uuid: sessionUuid,
        scope: 'tc-egress',
        clock_domain: 'CLOCK_BOOTTIME',
        capture_mode: 'oneshot',
        filters: { src_ip: '10.1.2.3', dst_port: 443, uid: 10086 },
      },
      null,
      2,
    ),
  )
  fs.writeFileSync(
    path.join(dir, 'dict.json'),
    JSON.stringify(
      {
        sites: [
          { idx: 1, name: 'tc_egress_entry', stage: STAGE_ENTRY, hook: 'tc-egress' },
        ],
        topology_epochs: [
          {
            epoch: 1,
            devices: [{ ifindex: 2, dev_gen: 1, name: 'wlan0', linktype: LINK_TYPE_ETHERNET, netns_inum: 4026531992 }],
          },
        ],
      },
      null,
      2,
    ),
  )

  const e1 = new WireEvent({
    kind: KIND_OBJECT,
    object_type: OBJ_SKB,
    evidence_level: EVIDENCE_DIRECT,
    site_dict_idx: 1,
    cpu: 0,
    flags: EV_FLAG_IN_TASK,
    seq: 1n,
    ts_ns: baseTs,
    object_id: BIG_OBJECT_ID,
    producer_type: PROD_KERNEL_BPF,
  })
  e1.nums.set('sample_id', BIG_SAMPLE_ID)
  e1.nums.set('end_reason', BigInt(END_TX_OK))

  const e2 = new WireEvent({
    kind: KIND_STEP,
    object_type: OBJ_SKB,
    evidence_level: EVIDENCE_DIRECT,
    site_dict_idx: 1,
    cpu: 0,
    flags: EV_FLAG_IN_TASK,
    seq: 2n,
    ts_ns: baseTs + 5_000n,
    object_id: BIG_OBJECT_ID,
    producer_type: PROD_KERNEL_BPF,
  })
  e2.nums.set('stage', BigInt(STAGE_ENTRY))
  e2.nums.set('sample_id', BIG_SAMPLE_ID)
  e2.nums.set('ifindex', 2n)
  e2.nums.set('dev_gen', 1n)
  e2.nums.set('netns_inum', 4026531992n)

  const e3 = new WireEvent({
    kind: KIND_SUMMARY,
    object_type: OBJ_SKB,
    evidence_level: EVIDENCE_DIRECT,
    site_dict_idx: 1,
    cpu: 0,
    flags: EV_FLAG_IN_TASK,
    seq: 3n,
    ts_ns: baseTs + 8_000n,
    object_id: BIG_OBJECT_ID,
    producer_type: PROD_KERNEL_BPF,
  })
  e3.nums.set('dir', BigInt(DIR_TX))
  e3.nums.set('l4_proto', 6n)
  e3.strs.set('src_ip', '10.1.2.3')
  e3.strs.set('dst_ip', '198.51.100.42')
  e3.nums.set('src_port', 54321n)
  e3.nums.set('dst_port', 443n)
  e3.nums.set('uid', 10086n)
  e3.nums.set('pkt_len', 128n)
  e3.bins.set('hdr_bytes', buildSampleEthIpv4Tcp())

  const payload = Buffer.concat([encodeEvent(e1), encodeEvent(e2), encodeEvent(e3)])
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
      max_ts_ns: baseTs + 8_000n,
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

async function fetchJson(url: string, init?: RequestInit): Promise<{ status: number; data: Record<string, unknown> }> {
  const res = await fetch(url, init)
  const data = (await res.json()) as Record<string, unknown>
  return { status: res.status, data }
}

test('End-to-end integration with Lin locked CordisHost 52fa69d8 (all 10 Wave 1 plugins, persistence, isolation, exports)', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pktpath-shan-e2e-'))
  const appDir = path.join(tmp, 'app')
  const sessionsRoot = path.join(tmp, 'sessions')
  const pluginsDir = path.join(tmp, 'plugins')
  const exportsDir = path.join(tmp, 'exports')
  const webDir = path.join(tmp, 'web')
  fs.mkdirSync(webDir, { recursive: true })
  fs.writeFileSync(path.join(webDir, 'index.html'), '<!doctype html><html><body>ok</body></html>')

  const localSessDir = createFixtureSession(path.join(sessionsRoot, 'sess-local'))
  const externalSessDir = createFixtureSession(path.join(tmp, 'external-sess'), '22334455-6677-8899-aabb-ccddeeff0011')
  const roSessDir = createFixtureSession(path.join(sessionsRoot, 'sess-readonly'), '33445566-7788-99aa-bbcc-ddeeff001122')

  const collectorsDir = path.join(tmp, 'collectors'); fs.mkdirSync(collectorsDir, { recursive: true }); const paths = { appDir, sessionsRoot, pluginsDir, exportsDir, webDir, collectorsDir }

  let app: Awaited<ReturnType<typeof startStudioApp>> | undefined
  try {
    // 1. Boot real CordisHost + all 10 mandatory Wave 1 built-ins
    const host = new CordisHost(paths, 'cordis-wave1-e2e')
    registerWave1Builtins(host, createAnalysisWave1Builtins())
    await host.start()
    app = await startStudioApp({
      host,
      listenPort: 0,
      extraRouteHandlers: [handleSessionRoute],
    })

    // Verify all 10 mandatory plugins are registered & active
    const stateRes = await fetchJson(`${app.url}/api/kernel/state`)
    assert.equal(stateRes.status, 200)
    const plugins = ((stateRes.data['state'] as Record<string, unknown>)['plugins']) as Array<{ id: string; status: string }>
    const byId = new Map(plugins.map((p) => [p.id, p.status]))
    const expected10 = [
      'builtin.transport.android-adb',
      'builtin.collector.ebpf-tc',
      'builtin.mode.oneshot',
      'builtin.mode.daemon',
      'builtin.transport.offline',
      'builtin.analyzer.dag-reconstruct',
      'builtin.analyzer.anomaly-radar',
      'builtin.exporter.csv-report',
      'builtin.exporter.pcapng',
      'builtin.exporter.redact',
    ]
    for (const id of expected10) {
      assert.equal(byId.get(id), 'active', `expected plugin ${id} to be active`)
    }

    // 2. Sessions list + open external session
    const list1 = await fetchJson(`${app.url}/api/sessions`)
    assert.equal(list1.status, 200)
    const items1 = list1.data['sessions'] as Array<{ id: string }>
    assert.ok(items1.some((s) => s.id === 'sess-local'))

    const openRes = await fetchJson(`${app.url}/api/sessions/open`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ path: externalSessDir }),
    })
    assert.equal(openRes.status, 200, JSON.stringify(openRes.data))
    assert.equal(openRes.data['ok'], true)
    const extId = openRes.data['id'] as string
    assert.ok(extId.length > 0)

    // 3. Overview: big u64 string fidelity + analyzer results + disk cache write
    const ov1 = await fetchJson(`${app.url}/api/session/overview?id=sess-local`)
    assert.equal(ov1.status, 200)
    assert.equal(ov1.data['ok'], true)
    const samples = ov1.data['samples'] as Array<{ sample_id: string }>
    assert.equal(samples.length, 1)
    assert.equal(samples[0]!.sample_id, BIG_SAMPLE_ID.toString())
    const cacheMeta1 = ov1.data['analysis_cache'] as { state: string; storage?: string }
    assert.equal(cacheMeta1.state, 'computed')
    assert.equal(cacheMeta1.storage, 'session_disk')
    assert.ok(fs.existsSync(path.join(localSessDir, '.pktpath_analysis_cache.json')))

    // 4. Sample detail with big u64 + invalid u64 400
    const smpRes = await fetchJson(`${app.url}/api/session/sample?id=sess-local&sample_id=${BIG_SAMPLE_ID.toString()}`)
    assert.equal(smpRes.status, 200)
    assert.equal(smpRes.data['sample_id'], BIG_SAMPLE_ID.toString())

    const badSmp = await fetchJson(`${app.url}/api/session/sample?id=sess-local&sample_id=not-a-u64`)
    assert.equal(badSmp.status, 400)

    // 5. Exports via POST /api/kernel/export (csv-report default + guard, pcapng, redact)
    const csvRes = await fetchJson(`${app.url}/api/kernel/export`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ exporter_id: 'builtin.exporter.csv-report', session_id: 'sess-local' }),
    })
    assert.equal(csvRes.status, 200, JSON.stringify(csvRes.data))
    assert.equal(csvRes.data['ok'], true)
    const expectedCsvPath = path.join(exportsDir, 'sess-local-report.csv')
    assert.equal(csvRes.data['out_path'], expectedCsvPath)
    assert.ok(fs.existsSync(expectedCsvPath))
    const csvBuf = fs.readFileSync(expectedCsvPath)
    assert.equal(csvBuf[0], 0xef)
    assert.equal(csvBuf[1], 0xbb)
    assert.equal(csvBuf[2], 0xbf)
    const mdOut = path.join(exportsDir, 'sess-local-report.md')
    const mdRes = await fetchJson(app.url + '/api/kernel/export', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ exporter_id: 'builtin.exporter.csv-report', session_id: 'sess-local', out_path: mdOut, params: { format: 'markdown' } }),
    })
    assert.equal(mdRes.status, 200, JSON.stringify(mdRes.data))
    assert.ok(fs.existsSync(mdOut))

    // Guard: refuse out_path inside session_dir
    const csvBad = await fetchJson(`${app.url}/api/kernel/export`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        exporter_id: 'builtin.exporter.csv-report',
        session_id: 'sess-local',
        out_path: path.join(localSessDir, 'evil.csv'),
      }),
    })
    assert.equal(csvBad.status, 400)

    // Guard (Y-W1-SHAN-02): refuse symlink pointing into session_dir (dir symlink & dangling file symlink)
    const symlinkToSess = path.join(tmp, 'link-to-session')
    fs.symlinkSync(localSessDir, symlinkToSess, 'dir')
    const csvViaLink = await fetchJson(`${app.url}/api/kernel/export`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        exporter_id: 'builtin.exporter.csv-report',
        session_id: 'sess-local',
        out_path: path.join(symlinkToSess, 'sub', 'evil-via-link.csv'),
      }),
    })
    assert.equal(csvViaLink.status, 400)
    const danglingLinkToSess = path.join(tmp, 'dangling-link.csv')
    fs.symlinkSync(path.join(localSessDir, 'dangling-evil.csv'), danglingLinkToSess)
    const csvViaDanglingLink = await fetchJson(`${app.url}/api/kernel/export`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        exporter_id: 'builtin.exporter.csv-report',
        session_id: 'sess-local',
        out_path: danglingLinkToSess,
      }),
    })
    assert.equal(csvViaDanglingLink.status, 400)
    const redactViaLink = await fetchJson(`${app.url}/api/kernel/export`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        exporter_id: 'builtin.exporter.redact',
        session_id: 'sess-local',
        out_path: path.join(symlinkToSess, 'redacted-escape'),
        params: { key: 'e2e-key' },
      }),
    })
    assert.equal(redactViaLink.status, 400)

    // pcapng export
    const pcapOut = path.join(exportsDir, 'sess-local.pcapng')
    const pcapRes = await fetchJson(`${app.url}/api/kernel/export`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        exporter_id: 'builtin.exporter.pcapng',
        session_id: 'sess-local',
        out_path: pcapOut,
        params: { redact: true, key: 'e2e-key' },
      }),
    })
    assert.equal(pcapRes.status, 200, JSON.stringify(pcapRes.data))
    assert.ok(fs.existsSync(pcapOut))
    assert.ok(fs.statSync(pcapOut).size > 64)

    // redact export -> refuse inside session_dir, succeed outside, re-openable
    const redBad = await fetchJson(`${app.url}/api/kernel/export`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        exporter_id: 'builtin.exporter.redact',
        session_id: 'sess-local',
        out_path: path.join(localSessDir, 'nested-redacted'),
        params: { key: 'e2e-key' },
      }),
    })
    assert.equal(redBad.status, 400)

    const redOutDir = path.join(exportsDir, 'sess-local-redacted')
    const redRes = await fetchJson(`${app.url}/api/kernel/export`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        exporter_id: 'builtin.exporter.redact',
        session_id: 'sess-local',
        out_path: redOutDir,
        params: { key: 'e2e-key' },
      }),
    })
    assert.equal(redRes.status, 200, JSON.stringify(redRes.data))
    assert.ok(fs.existsSync(path.join(redOutDir, 'manifest.json')))
    assert.ok(!fs.existsSync(path.join(redOutDir, '.pktpath_analysis_cache.json')))

    const openRed = await fetchJson(`${app.url}/api/sessions/open`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ path: redOutDir }),
    })
    assert.equal(openRed.status, 200)
    const ovRed = await fetchJson(`${app.url}/api/session/overview?id=${encodeURIComponent(openRed.data['id'] as string)}`)
    assert.equal(ovRed.status, 200)
    assert.equal((ovRed.data['samples'] as Array<{ sample_id: string }>).length, 1)

    // Legacy POST /api/session/export-csv route
    const legCsvPath = path.join(exportsDir, 'legacy-route.csv')
    const legCsv = await fetchJson(`${app.url}/api/session/export-csv`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ id: 'sess-local', out_path: legCsvPath }),
    })
    assert.equal(legCsv.status, 200)
    assert.ok(fs.existsSync(legCsvPath))

    // 6. Read-only session directory falls back to <appDir>/analysis_cache
    fs.chmodSync(roSessDir, 0o555)
    try {
      const ovRo = await fetchJson(`${app.url}/api/session/overview?id=sess-readonly`)
      assert.equal(ovRo.status, 200)
      const roMeta = ovRo.data['analysis_cache'] as { state: string; storage?: string }
      assert.equal(roMeta.state, 'computed')
      assert.equal(roMeta.storage, 'app_cache')
      assert.ok(fs.readdirSync(path.join(appDir, 'analysis_cache')).some((f) => f.endsWith('.json')))
    } finally {
      fs.chmodSync(roSessDir, 0o755)
    }

    // 7. Close & restart a brand-new CordisHost -> verify:
    //    (a) opened_sessions.json restored external session
    //    (b) .pktpath_analysis_cache.json yields disk_hit: true
    //    (c) updating analyzer config invalidates disk cache
    await app.close()
    app = undefined

    const host2 = new CordisHost(paths, 'cordis-wave1-e2e')
    registerWave1Builtins(host2, createAnalysisWave1Builtins())
    await host2.start()
    app = await startStudioApp({
      host: host2,
      listenPort: 0,
      extraRouteHandlers: [handleSessionRoute],
    })

    const list2 = await fetchJson(`${app.url}/api/sessions`)
    const items2 = list2.data['sessions'] as Array<{ id: string }>
    assert.ok(items2.some((s) => s.id === extId), 'opened external session must survive restart')

    const ovHit = await fetchJson(`${app.url}/api/session/overview?id=sess-local`)
    assert.equal(ovHit.status, 200)
    assert.equal((ovHit.data['analysis_cache'] as { state: string }).state, 'disk_hit')

    // Update anomaly-radar config -> cache must invalidate
    const cfgRes = await fetchJson(`${app.url}/api/kernel/plugins/config`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ id: 'builtin.analyzer.anomaly-radar', config: { drop_warn_count: 3, sojourn_warn_ms: 42 } }),
    })
    assert.equal(cfgRes.status, 200)
    const ovAfterCfg = await fetchJson(`${app.url}/api/session/overview?id=sess-local`)
    assert.equal(ovAfterCfg.status, 200)
    assert.equal((ovAfterCfg.data['analysis_cache'] as { state: string }).state, 'computed')

    // 8. Faulty analyzer isolation: throwing analyzer does not break overview and does not persist cache
    await app.close()
    app = undefined

    const host3 = new CordisHost(paths, 'cordis-wave1-e2e')
    const throwingPlugin = {
      meta: {
        id: 'test.analyzer.boom',
        name: 'Boom Analyzer',
        version: '0.0.1',
        kind: 'analyzer' as const,
        description: 'always throws',
        builtin: true,
        required: false,
      },
      schema: { fields: [] },
      apply(ctx: { registerExtension: (point: string, value: unknown) => void }) {
        ctx.registerExtension('analyzer', {
          id: 'test.analyzer.boom',
          name: 'Boom Analyzer',
          analyze() {
            throw new Error('intentional boom')
          },
        })
      },
    }
    registerWave1Builtins(host3, [...createAnalysisWave1Builtins(), throwingPlugin as never])
    await host3.start()
    app = await startStudioApp({
      host: host3,
      listenPort: 0,
      extraRouteHandlers: [handleSessionRoute],
    })

    const cacheFile = path.join(localSessDir, '.pktpath_analysis_cache.json')
    if (fs.existsSync(cacheFile)) fs.unlinkSync(cacheFile)

    const ovBoom = await fetchJson(`${app.url}/api/session/overview?id=sess-local`)
    assert.equal(ovBoom.status, 200)
    assert.equal(ovBoom.data['ok'], true)
    const boomMeta = ovBoom.data['analysis_cache'] as { state: string; storage?: string }
    assert.notEqual(boomMeta.storage, 'session_disk')
    const notes = ovBoom.data['plugin_notes'] as string[]
    assert.ok(Array.isArray(notes) && notes.some((n) => n.includes('分析失败')))
    assert.ok(!fs.existsSync(cacheFile), 'faulty analyzer run must not persist cache to disk')
  } finally {
    if (app) await app.close()
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})
