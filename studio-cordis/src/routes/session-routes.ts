// Pure TypeScript HTTP routes for session & analysis endpoints (erasableSyntaxOnly).
// Signature matches Lin's studio-cordis/src/server/app.ts ExtraRouteHandler:
//   (host, method, url, req, res) => Promise<boolean>

import fs from 'node:fs'
import path from 'node:path'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { buildPcapngBuffer } from '../plugins/analysis/export/pcapng.ts'
import type { Session } from '../plugins/analysis/reconstruct/model.ts'
import type { AnalysisHostLike, SessionProvider } from '../plugins/analysis/types.ts'

function sendJson(res: ServerResponse, status: number, payload: unknown): void {
  const body = JSON.stringify(payload)
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  })
  res.end(body)
}

async function readJsonBody(req: IncomingMessage, maxBytes = 1024 * 1024): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = []
  let total = 0
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
    total += buf.length
    if (total > maxBytes) throw new Error('request body too large')
    chunks.push(buf)
  }
  const raw = Buffer.concat(chunks).toString('utf8').trim()
  if (!raw) return {}
  const parsed = JSON.parse(raw) as unknown
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('JSON body must be an object')
  }
  return parsed as Record<string, unknown>
}

function getProvider(host: AnalysisHostLike): SessionProvider | undefined {
  const sp =
    (typeof host.getSessionProvider === 'function' ? host.getSessionProvider() : undefined) ??
    host.getService<SessionProvider>('session.provider')
  if (sp && typeof (sp as { bindHost?: (h: AnalysisHostLike) => void }).bindHost === 'function') {
    ;(sp as { bindHost: (h: AnalysisHostLike) => void }).bindHost(host)
  }
  return sp
}

function sessionIdFromQuery(url: URL): string {
  const id = (url.searchParams.get('id') ?? '').trim()
  if (id) return id
  return (url.searchParams.get('session_id') ?? '').trim()
}

function sessionIdFromBody(body: Record<string, unknown>): string {
  if (typeof body['id'] === 'string' && body['id'].trim() !== '') return body['id'].trim()
  if (typeof body['session_id'] === 'string' && body['session_id'].trim() !== '') return body['session_id'].trim()
  return ''
}

function parseBoolParam(raw: string | null): boolean {
  if (!raw) return false
  const v = raw.trim().toLowerCase()
  return v === '1' || v === 'true' || v === 'yes'
}

function sanitizeFileToken(raw: string): string {
  const cleaned = raw.replace(/[^a-zA-Z0-9._-]/g, '_').replace(/^_+|_+$/g, '')
  return cleaned || 'session'
}

function uniquePath(basePath: string): string {
  if (!fs.existsSync(basePath)) return basePath
  for (let i = 2; i < 1000; i++) {
    const cand = `${basePath}_${i}`
    if (!fs.existsSync(cand)) return cand
  }
  return `${basePath}_${Date.now()}`
}

export async function handleSessionRoute(
  host: AnalysisHostLike,
  method: string,
  url: URL,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<boolean> {
  const pathname = url.pathname

  if (method === 'GET' && pathname === '/api/sessions') {
    const sp = getProvider(host)
    if (!sp) {
      sendJson(res, 503, { ok: false, error: '「本地会话存储与加载」插件未启用，无法读取本地会话。请先在插件页确认该插件已启用。' })
      return true
    }
    try {
      const sessions = await sp.listSessions()
      sendJson(res, 200, {
        ok: true,
        sessions_root: host.paths.sessionsRoot,
        sessions,
      })
    } catch (err) {
      sendJson(res, 500, { ok: false, error: err instanceof Error ? err.message : String(err) })
    }
    return true
  }

  if (method === 'POST' && pathname === '/api/sessions/open') {
    const sp = getProvider(host)
    if (!sp) {
      sendJson(res, 503, { ok: false, error: '「本地会话存储与加载」插件未启用，无法读取本地会话。请先在插件页确认该插件已启用。' })
      return true
    }
    try {
      const body = await readJsonBody(req)
      const dirPath = typeof body['path'] === 'string' ? body['path'].trim() : ''
      if (!dirPath) {
        sendJson(res, 400, { ok: false, error: 'path is required' })
        return true
      }
      const opened = await sp.openSession(dirPath)
      sendJson(res, 200, { ok: true, ...opened })
    } catch (err) {
      sendJson(res, 400, { ok: false, error: err instanceof Error ? err.message : String(err) })
    }
    return true
  }

  if (method === 'GET' && pathname === '/api/session/overview') {
    const sp = getProvider(host)
    if (!sp) {
      sendJson(res, 503, { ok: false, error: '「本地会话存储与加载」插件未启用，无法读取本地会话。请先在插件页确认该插件已启用。' })
      return true
    }
    const id = sessionIdFromQuery(url)
    if (!id) {
      sendJson(res, 400, { ok: false, error: 'query parameter id is required' })
      return true
    }
    const force =
      parseBoolParam(url.searchParams.get('refresh')) ||
      parseBoolParam(url.searchParams.get('force')) ||
      parseBoolParam(url.searchParams.get('reanalyze'))
    try {
      const overview = await sp.getOverview(id, { forceReanalyze: force })
      sendJson(res, 200, { ok: true, ...overview })
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      const status = msg.includes('not found') ? 404 : 400
      sendJson(res, status, { ok: false, error: msg })
    }
    return true
  }

  if (method === 'GET' && pathname === '/api/session/sample') {
    const sp = getProvider(host)
    if (!sp) {
      sendJson(res, 503, { ok: false, error: '「本地会话存储与加载」插件未启用，无法读取本地会话。请先在插件页确认该插件已启用。' })
      return true
    }
    const id = sessionIdFromQuery(url)
    const sampleId = (url.searchParams.get('sample_id') ?? '').trim()
    if (!id || !sampleId) {
      sendJson(res, 400, { ok: false, error: 'query parameters id and sample_id are required' })
      return true
    }
    try {
      const detail = await sp.getSample(id, sampleId)
      sendJson(res, 200, { ok: true, ...detail })
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      const status = msg.includes('not found') ? 404 : 400
      sendJson(res, status, { ok: false, error: msg })
    }
    return true
  }

  // Legacy Go alias (P1-9): GET /api/session/export-pcapng streams binary application/x-pcapng
  if (method === 'GET' && pathname === '/api/session/export-pcapng') {
    const sp = getProvider(host)
    if (!sp) {
      sendJson(res, 503, { ok: false, error: '「本地会话存储与加载」插件未启用，无法读取本地会话。请先在插件页确认该插件已启用。' })
      return true
    }
    const id = sessionIdFromQuery(url)
    if (!id) {
      sendJson(res, 400, { ok: false, error: 'missing id query parameter' })
      return true
    }
    const redact = parseBoolParam(url.searchParams.get('redact'))
    const key = (url.searchParams.get('key') ?? '').trim()
    try {
      const data = await sp.getSessionForExport(id)
      const sess = data.session as Session | undefined
      if (!sess) {
        sendJson(res, 500, { ok: false, error: 'reconstructed session unavailable for pcapng export' })
        return true
      }
      const { buffer } = buildPcapngBuffer(sess, redact, key)
      const safe = sanitizeFileToken(data.session_id || id)
      const fname = redact ? `trace_${safe}_redacted.pcapng` : `trace_${safe}.pcapng`
      res.writeHead(200, {
        'Content-Type': 'application/x-pcapng',
        'Content-Disposition': `attachment; filename="${fname}"`,
        'Content-Length': String(buffer.length),
        'Cache-Control': 'no-store',
      })
      res.end(buffer)
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      const status = msg.includes('not found') ? 404 : 500
      sendJson(res, status, { ok: false, error: msg })
    }
    return true
  }

  // Legacy Go alias (P1-9): POST /api/session/export-pcapng delegates to builtin.exporter.pcapng
  if (method === 'POST' && pathname === '/api/session/export-pcapng') {
    if (typeof host.runExport !== 'function') {
      sendJson(res, 503, { ok: false, error: '当前导出服务暂不可用，请重启 Studio 后重试。' })
      return true
    }
    try {
      const body = await readJsonBody(req)
      const sessionId = sessionIdFromBody(body)
      if (!sessionId) {
        sendJson(res, 400, { ok: false, error: 'missing id' })
        return true
      }
      const baseParams =
        typeof body['params'] === 'object' && body['params'] !== null && !Array.isArray(body['params'])
          ? ({ ...(body['params'] as Record<string, unknown>) })
          : {}
      const redact = typeof body['redact'] === 'boolean'
        ? body['redact']
        : typeof baseParams['redact'] === 'boolean'
          ? (baseParams['redact'] as boolean)
          : false
      baseParams['redact'] = redact
      if (typeof body['key'] === 'string' && body['key'].trim() !== '') {
        baseParams['key'] = body['key'].trim()
      }
      let outPath = typeof body['out_path'] === 'string' ? body['out_path'].trim() : ''
      if (!outPath) {
        fs.mkdirSync(host.paths.exportsDir, { recursive: true })
        const safe = sanitizeFileToken(sessionId)
        outPath = path.join(host.paths.exportsDir, redact ? `trace_${safe}_redacted.pcapng` : `trace_${safe}.pcapng`)
      }
      const out = await host.runExport({
        exporter_id: 'builtin.exporter.pcapng',
        session_id: sessionId,
        out_path: outPath,
        params: baseParams,
      })
      if (!out.ok) {
        const errText = out.error ?? 'export pcapng failed'
        const status = errText.includes('not found') ? 404 : 400
        sendJson(res, status, { ok: false, error: errText })
        return true
      }
      const exportedPackets =
        typeof out.details?.['exported_packets'] === 'number'
          ? (out.details['exported_packets'] as number)
          : 0
      sendJson(res, 200, {
        ok: true,
        id: sessionId,
        session_id: sessionId,
        out_path: out.out_path,
        exported_packets: exportedPackets,
        redact,
        summary: out.summary,
      })
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      const status = msg.includes('not found') ? 404 : 400
      sendJson(res, status, { ok: false, error: msg })
    }
    return true
  }

  // Legacy Go alias (P1-9): POST /api/session/redact delegates to builtin.exporter.redact
  if (method === 'POST' && pathname === '/api/session/redact') {
    if (typeof host.runExport !== 'function') {
      sendJson(res, 503, { ok: false, error: 'exporter runner unavailable on host' })
      return true
    }
    const sp = getProvider(host)
    try {
      const body = await readJsonBody(req)
      const sessionId = sessionIdFromBody(body)
      if (!sessionId) {
        sendJson(res, 400, { ok: false, error: 'missing id' })
        return true
      }
      const baseParams =
        typeof body['params'] === 'object' && body['params'] !== null && !Array.isArray(body['params'])
          ? ({ ...(body['params'] as Record<string, unknown>) })
          : {}
      if (typeof body['key'] === 'string' && body['key'].trim() !== '') {
        baseParams['key'] = body['key'].trim()
      }
      let outDir =
        typeof body['out_dir'] === 'string' && body['out_dir'].trim() !== ''
          ? body['out_dir'].trim()
          : typeof body['out_path'] === 'string' && body['out_path'].trim() !== ''
            ? body['out_path'].trim()
            : ''
      if (!outDir) {
        fs.mkdirSync(host.paths.sessionsRoot, { recursive: true })
        outDir = uniquePath(path.join(host.paths.sessionsRoot, `${sanitizeFileToken(sessionId)}_redacted`))
      }
      const out = await host.runExport({
        exporter_id: 'builtin.exporter.redact',
        session_id: sessionId,
        out_path: outDir,
        params: baseParams,
      })
      if (!out.ok) {
        const errText = out.error ?? 'redact session failed'
        const status = errText.includes('not found') ? 404 : 400
        sendJson(res, status, { ok: false, error: errText })
        return true
      }
      let newId = ''
      if (sp && typeof (sp as { registerSessionDir?: (d: string) => string }).registerSessionDir === 'function') {
        newId = (sp as { registerSessionDir: (d: string) => string }).registerSessionDir(out.out_path)
      }
      sendJson(res, 200, {
        ok: true,
        id: sessionId,
        out_dir: out.out_path,
        out_path: out.out_path,
        path: out.out_path,
        session_id: newId || sessionId,
        summary: out.summary,
      })
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      const status = msg.includes('not found') ? 404 : 400
      sendJson(res, status, { ok: false, error: msg })
    }
    return true
  }

  // Documented convenience alias (P2-8): POST /api/session/export-csv delegates to builtin.exporter.csv-report
  if (method === 'POST' && pathname === '/api/session/export-csv') {
    if (typeof host.runExport !== 'function') {
      sendJson(res, 503, { ok: false, error: 'exporter runner unavailable on host' })
      return true
    }
    try {
      const body = await readJsonBody(req)
      const sessionId = sessionIdFromBody(body)
      if (!sessionId) {
        sendJson(res, 400, { ok: false, error: 'session_id (or id) is required' })
        return true
      }
      const outPath = typeof body['out_path'] === 'string' ? body['out_path'] : undefined
      const params =
        typeof body['params'] === 'object' && body['params'] !== null && !Array.isArray(body['params'])
          ? (body['params'] as Record<string, unknown>)
          : {}
      const out = await host.runExport({
        exporter_id: 'builtin.exporter.csv-report',
        session_id: sessionId,
        out_path: outPath,
        params,
      })
      sendJson(res, out.ok ? 200 : 400, out)
    } catch (err) {
      sendJson(res, 400, { ok: false, error: err instanceof Error ? err.message : String(err) })
    }
    return true
  }

  return false
}
