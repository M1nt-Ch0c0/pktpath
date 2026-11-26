// Pure TypeScript HTTP routes for session & analysis endpoints (erasableSyntaxOnly).
// Signature matches Lin's studio-cordis/src/server/app.ts ExtraRouteHandler:
//   (host, method, url, req, res) => Promise<boolean>

import type { IncomingMessage, ServerResponse } from 'node:http'
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
      sendJson(res, 503, { ok: false, error: 'session.provider service is not active' })
      return true
    }
    try {
      const sessions = await sp.listSessions()
      sendJson(res, 200, { ok: true, sessions })
    } catch (err) {
      sendJson(res, 500, { ok: false, error: err instanceof Error ? err.message : String(err) })
    }
    return true
  }

  if (method === 'POST' && pathname === '/api/sessions/open') {
    const sp = getProvider(host)
    if (!sp) {
      sendJson(res, 503, { ok: false, error: 'session.provider service is not active' })
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
      sendJson(res, 503, { ok: false, error: 'session.provider service is not active' })
      return true
    }
    const id = (url.searchParams.get('id') ?? '').trim()
    if (!id) {
      sendJson(res, 400, { ok: false, error: 'query parameter id is required' })
      return true
    }
    const force = url.searchParams.get('force') === '1' || url.searchParams.get('reanalyze') === '1'
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
      sendJson(res, 503, { ok: false, error: 'session.provider service is not active' })
      return true
    }
    const id = (url.searchParams.get('id') ?? '').trim()
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

  if (method === 'POST' && pathname === '/api/session/export-csv') {
    if (typeof host.runExport !== 'function') {
      sendJson(res, 503, { ok: false, error: 'exporter runner unavailable on host' })
      return true
    }
    try {
      const body = await readJsonBody(req)
      const sessionId = typeof body['id'] === 'string'
        ? body['id'].trim()
        : typeof body['session_id'] === 'string'
          ? body['session_id'].trim()
          : ''
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
