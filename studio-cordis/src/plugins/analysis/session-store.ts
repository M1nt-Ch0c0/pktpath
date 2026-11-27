// Pure TypeScript SessionStore & SessionProvider implementation (erasableSyntaxOnly).
// Ported from studio/pkg/server/sessions.go and studio/pkg/server/analysis_cache.go.
// - Persists opened external session directories in <appDir>/opened_sessions.json.
// - Persists analyzer results in <session_dir>/.pktpath_analysis_cache.json with
//   automatic fallback to <appDir>/analysis_cache/<sha256>.json for read-only dirs.
// - Never caches failed/isolated analyzer outputs (notes containing isolation marker).
// - Strict uint64 decimal-string parsing for sample_id.

import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { buildOverview, buildSampleDetail, reconstruct } from './reconstruct/index.ts'
import type { Session, SessionOverview } from './reconstruct/index.ts'
import { buildSessionHealth } from './manifest-health.ts'
import type {
  AnalysisHostLike,
  AnalyzerOutput,
  HostPaths,
  OpenedSessionMeta,
  SessionExportData,
  SessionProvider,
  SessionSummary,
} from './types.ts'
import { isRegularFile, loadSession } from './wire/wire.ts'

export const ANALYSIS_CACHE_FILE_NAME = '.pktpath_analysis_cache.json'
export const ANALYSIS_CACHE_SCHEMA_VER = 1
export const OPENED_SESSIONS_FILE_NAME = 'opened_sessions.json'
export const OPENED_SESSIONS_SCHEMA_VER = 1

export type AnalysisStorageKind = 'session_disk' | 'app_cache'

interface PersistedAnalysisCache {
  schema_version: number
  session_fingerprint: string
  analyzer_fingerprint: string
  saved_at: string
  storage?: AnalysisStorageKind
  plugin_insights: AnalyzerOutput['insights']
  plugin_kpis: AnalyzerOutput['kpis']
  plugin_notes?: string[]
}

interface PersistedOpenedSessions {
  schema_version: number
  updated_at: string
  dirs: string[]
}

interface BaseCacheEntry {
  sessionFP: string
  session: Session
  overview: SessionOverview
}

interface AnalysisCacheEntry {
  sessionFP: string
  analyzerFP: string
  storage: AnalysisStorageKind
  out: AnalyzerOutput
}

function isSessionSourceFile(name: string): boolean {
  return name === 'manifest.json' || name === 'dict.json' || name.endsWith('.pktb')
}

export function isValidSessionDir(dir: string): boolean {
  try {
    const st = fs.statSync(dir)
    if (!st.isDirectory()) return false
    const manifestPath = path.join(dir, 'manifest.json')
    if (isRegularFile(manifestPath)) return true
    const entries = fs.readdirSync(dir)
    return entries.some((name) => name.endsWith('.pktb') && isRegularFile(path.join(dir, name)))
  } catch {
    return false
  }
}

export function sessionSourceFingerprint(dir: string): string {
  const entries = fs.readdirSync(dir, { withFileTypes: true })
  const names = entries
    .filter((e) => !e.isDirectory() && isSessionSourceFile(e.name))
    .map((e) => e.name)
    .sort()
  const h = crypto.createHash('sha256')
  for (const name of names) {
    try {
      const st = fs.statSync(path.join(dir, name))
      h.update(`${name}|${st.size}|${st.mtimeMs}\n`)
    } catch {
      // ignore vanishing file
    }
  }
  return h.digest('hex')
}

export function writeFileAtomic(target: string, data: string | Buffer): void {
  const parent = path.dirname(target)
  fs.mkdirSync(parent, { recursive: true })
  const rand = crypto.randomBytes(6).toString('hex')
  const tmpPath = path.join(parent, `.pktpath-tmp-${process.pid}-${rand}`)
  let fd: number | undefined
  try {
    fd = fs.openSync(tmpPath, 'wx', 0o644)
    fs.writeFileSync(fd, data)
    fs.fsyncSync(fd)
    fs.closeSync(fd)
    fd = undefined
    fs.renameSync(tmpPath, target)
  } catch (err) {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd)
      } catch {
        // ignore
      }
    }
    try {
      fs.unlinkSync(tmpPath)
    } catch {
      // ignore
    }
    throw err
  }
}

function canonicalStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return '[' + value.map((v) => canonicalStringify(v)).join(',') + ']'
  const keys = Object.keys(value as Record<string, unknown>).sort()
  return (
    '{' +
    keys.map((k) => JSON.stringify(k) + ':' + canonicalStringify((value as Record<string, unknown>)[k])).join(',') +
    '}'
  )
}

export function parseSampleIdStrict(raw: string): bigint {
  const trimmed = raw.trim()
  if (!/^\d+$/.test(trimmed)) {
    throw new Error(`invalid sample_id: expected unsigned decimal integer, got ${JSON.stringify(raw)}`)
  }
  const val = BigInt(trimmed)
  if (val > 0xffffffffffffffffn) {
    throw new Error(`sample_id exceeds uint64 range: ${trimmed}`)
  }
  return val
}

function hasIsolatedAnalyzerError(out: AnalyzerOutput): boolean {
  return out.notes.some(
    (n) => n.includes('分析失败（已隔离）') || n.includes('timed out') || n.includes('isolated error'),
  )
}

export class SessionStore implements SessionProvider {
  private readonly paths: HostPaths
  private host?: AnalysisHostLike
  private readonly openedDirs = new Map<string, string>() // id -> absPath
  private readonly baseCache = new Map<string, BaseCacheEntry>() // absPath -> base
  private readonly analysisCache = new Map<string, AnalysisCacheEntry>() // absPath -> analysis

  constructor(paths: HostPaths, host?: AnalysisHostLike) {
    this.paths = paths
    this.host = host
    this.loadOpenedSessionsFromDisk()
  }

  bindHost(host: AnalysisHostLike): void {
    this.host = host
  }

  private openedSessionsPath(): string {
    return path.join(this.paths.appDir, OPENED_SESSIONS_FILE_NAME)
  }

  private appCacheDir(): string {
    return path.join(this.paths.appDir, 'analysis_cache')
  }

  private appFallbackCachePath(sessionDir: string): string {
    const key = crypto.createHash('sha256').update(path.resolve(sessionDir)).digest('hex').slice(0, 32)
    return path.join(this.appCacheDir(), `${key}.json`)
  }

  private sessionIdForExternalDir(absDir: string): string {
    const base = path.basename(absDir).replace(/[^a-zA-Z0-9._-]/g, '_') || 'session'
    const digest = crypto.createHash('sha256').update(absDir).digest('hex').slice(0, 8)
    return `ext-${base}-${digest}`
  }

  private loadOpenedSessionsFromDisk(): void {
    const file = this.openedSessionsPath()
    if (!isRegularFile(file)) return
    try {
      const raw = JSON.parse(fs.readFileSync(file, 'utf8')) as Partial<PersistedOpenedSessions>
      if (!Array.isArray(raw.dirs)) return
      for (const d of raw.dirs) {
        if (typeof d !== 'string' || d.trim() === '') continue
        const abs = path.resolve(d)
        if (!isValidSessionDir(abs)) continue
        const id = this.sessionIdForExternalDir(abs)
        this.openedDirs.set(id, abs)
      }
    } catch {
      // ignore corrupted opened_sessions.json
    }
  }

  private saveOpenedSessionsToDisk(): void {
    const payload: PersistedOpenedSessions = {
      schema_version: OPENED_SESSIONS_SCHEMA_VER,
      updated_at: new Date().toISOString(),
      dirs: [...this.openedDirs.values()].sort(),
    }
    try {
      writeFileAtomic(this.openedSessionsPath(), JSON.stringify(payload, null, 2))
    } catch {
      // non-fatal
    }
  }

  private formatLocalTimestamp(ms: number): string {
    const d = new Date(ms)
    const pad = (n: number): string => String(n).padStart(2, '0')
    return (
      `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
      `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
    )
  }

  private readSessionSummary(id: string, dir: string, source: 'managed' | 'opened'): SessionSummary {
    const summary: SessionSummary = {
      id,
      name: path.basename(dir),
      path: dir,
      source,
      external: source === 'opened',
      created_at: '',
      created_unix_ms: 0,
      scope: '',
      dev: '',
      mode: '',
      sample_count: 0,
    }
    const manifestPath = path.join(dir, 'manifest.json')
    let fallbackMs = 0
    try {
      const st = fs.statSync(isRegularFile(manifestPath) ? manifestPath : dir)
      fallbackMs = Math.trunc(st.mtimeMs)
      summary['created_unix_ms'] = fallbackMs
      summary.created_at = this.formatLocalTimestamp(fallbackMs)
      summary['mtime_ms'] = st.mtimeMs
    } catch {
      // ignore
    }
    if (isRegularFile(manifestPath)) {
      try {
        const m = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as Record<string, unknown>
        if (typeof m['created_at'] === 'string' && m['created_at'].trim() !== '') {
          summary.created_at = m['created_at']
        }
        if (typeof m['scope'] === 'string') summary['scope'] = m['scope']
        if (typeof m['mode'] === 'string') summary['mode'] = m['mode']
        if (typeof m['dev'] === 'string' && m['dev'].trim() !== '') {
          summary['dev'] = m['dev']
        } else if (typeof m['device'] === 'string' && m['device'].trim() !== '') {
          summary['dev'] = m['device']
        }
        if (typeof m['device'] === 'string') summary['device'] = m['device']
        if (typeof m['kernel_release'] === 'string' && m['kernel_release'].trim() !== '') {
          summary['kernel_release'] = m['kernel_release']
        }
        if (typeof m['session_uuid'] === 'string') summary['session_uuid'] = m['session_uuid']
        const admissions = m['admissions']
        if (typeof admissions === 'object' && admissions !== null) {
          const adm = admissions as Record<string, unknown>
          const created = typeof adm['created'] === 'number' ? Math.trunc(adm['created']) : 0
          const selected = typeof adm['selected'] === 'number' ? Math.trunc(adm['selected']) : 0
          if (created > 0) summary.sample_count = created
          else if (selected > 0) summary.sample_count = selected
        }
        // Match Go sessions.go:375-382: prefer calibration realtime_ns when in sane epoch range (2020..2035)
        const cals = m['calibrations']
        if (Array.isArray(cals) && cals.length > 0 && typeof cals[0] === 'object' && cals[0] !== null) {
          const rawRt = (cals[0] as Record<string, unknown>)['realtime_ns']
          let rtNs: bigint | null = null
          if (typeof rawRt === 'number' && Number.isFinite(rawRt)) rtNs = BigInt(Math.trunc(rawRt))
          else if (typeof rawRt === 'string' && /^\d+$/.test(rawRt.trim())) rtNs = BigInt(rawRt.trim())
          if (rtNs !== null && rtNs > 1577836800_000000000n && rtNs < 2051222400_000000000n) {
            const ms = Number(rtNs / 1_000_000n)
            summary['created_unix_ms'] = ms
            summary.created_at = this.formatLocalTimestamp(ms)
          }
        }
      } catch {
        // ignore invalid manifest preview
      }
    }
    const cached = this.baseCache.get(dir)
    if (cached) {
      summary.sample_count = cached.overview.samples.length
    }
    return summary
  }

  resolveSessionDir(sessionId: string): string {
    const id = sessionId.trim()
    if (!id) throw new Error('session id is required')
    const ext = this.openedDirs.get(id)
    if (ext && isValidSessionDir(ext)) return ext

    // Check managed sessionsRoot (prevent path traversal)
    if (!id.includes('/') && !id.includes('\\') && id !== '.' && id !== '..') {
      const candidate = path.resolve(this.paths.sessionsRoot, id)
      const rootResolved = path.resolve(this.paths.sessionsRoot)
      if (candidate.startsWith(rootResolved + path.sep) && isValidSessionDir(candidate)) {
        return candidate
      }
    }
    // Allow passing an existing valid session directory path directly (matches Go resolveDir)
    if (path.isAbsolute(id) && isValidSessionDir(id)) {
      this.registerSessionDir(id)
      return path.resolve(id)
    }
    throw new Error(`session not found: ${sessionId}`)
  }

  registerSessionDir(dirPath: string): string {
    const abs = path.resolve(dirPath)
    const rootResolved = path.resolve(this.paths.sessionsRoot)
    const rel = path.relative(rootResolved, abs)
    if (rel && !rel.startsWith('..') && !path.isAbsolute(rel) && !rel.includes(path.sep)) {
      return rel
    }
    const id = this.sessionIdForExternalDir(abs)
    this.openedDirs.set(id, abs)
    this.saveOpenedSessionsToDisk()
    return id
  }

  async listSessions(): Promise<SessionSummary[]> {
    const items: SessionSummary[] = []
    const seenPaths = new Set<string>()

    // 1. Managed sessions under sessionsRoot
    try {
      if (fs.existsSync(this.paths.sessionsRoot) && fs.statSync(this.paths.sessionsRoot).isDirectory()) {
        const entries = fs.readdirSync(this.paths.sessionsRoot, { withFileTypes: true })
        for (const e of entries) {
          if (!e.isDirectory() || e.name.startsWith('.')) continue
          const full = path.resolve(this.paths.sessionsRoot, e.name)
          if (!isValidSessionDir(full)) continue
          seenPaths.add(full)
          items.push(this.readSessionSummary(e.name, full, 'managed'))
        }
      }
    } catch {
      // ignore missing sessionsRoot
    }

    // 2. External opened sessions
    for (const [id, dir] of this.openedDirs.entries()) {
      if (seenPaths.has(dir)) continue
      if (!isValidSessionDir(dir)) continue
      seenPaths.add(dir)
      items.push(this.readSessionSummary(id, dir, 'opened'))
    }

    items.sort((a, b) => {
      const ca = typeof a['created_unix_ms'] === 'number' ? (a['created_unix_ms'] as number) : 0
      const cb = typeof b['created_unix_ms'] === 'number' ? (b['created_unix_ms'] as number) : 0
      if (ca !== cb) return cb - ca
      return a.id > b.id ? -1 : a.id < b.id ? 1 : 0
    })
    return items
  }

  async openSession(dirPath: string): Promise<OpenedSessionMeta> {
    const raw = dirPath.trim()
    if (!raw) throw new Error('path is required')
    let abs = path.resolve(raw)
    if (!fs.existsSync(abs)) {
      throw new Error(`path does not exist: ${abs}`)
    }
    if (!fs.statSync(abs).isDirectory()) {
      abs = path.dirname(abs)
    }
    if (!isValidSessionDir(abs)) {
      throw new Error(`not a PktPath session folder (manifest.json or .pktb missing): ${abs}`)
    }
    const id = this.registerSessionDir(abs)
    const overview = await this.getOverview(id)
    return {
      id,
      session_id: id,
      name: path.basename(abs),
      path: abs,
      session_path: abs,
      overview,
    }
  }

  private loadBase(dir: string): BaseCacheEntry {
    const fp = sessionSourceFingerprint(dir)
    const cached = this.baseCache.get(dir)
    if (cached && cached.sessionFP === fp) return cached
    const loaded = loadSession(dir)
    const session = reconstruct(loaded)
    const overview = buildOverview(session)
    const entry: BaseCacheEntry = { sessionFP: fp, session, overview }
    this.baseCache.set(dir, entry)
    return entry
  }

  private computeAnalyzerFingerprint(): string {
    if (!this.host || typeof this.host.snapshot !== 'function') return 'no-host'
    const snap = this.host.snapshot()
    const analyzerPluginIds = new Set<string>()
    for (const a of snap.analyzers) {
      if (typeof a['plugin_id'] === 'string') analyzerPluginIds.add(a['plugin_id'])
    }
    const activeAnalyzers = snap.plugins
      .filter((p) => p.enabled && p.status === 'active' && analyzerPluginIds.has(p.id))
      .map((p) => ({
        id: p.id,
        version: p.version,
        config: p.config,
        source_path: p.source_path ?? '',
      }))
      .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
    return crypto.createHash('sha256').update(canonicalStringify(activeAnalyzers)).digest('hex')
  }

  private readPersistedAnalysisCache(
    dir: string,
    sessionFP: string,
    analyzerFP: string,
  ): { out: AnalyzerOutput; storage: AnalysisStorageKind } | undefined {
    const candidates: Array<{ file: string; storage: AnalysisStorageKind }> = [
      { file: path.join(dir, ANALYSIS_CACHE_FILE_NAME), storage: 'session_disk' },
      { file: this.appFallbackCachePath(dir), storage: 'app_cache' },
    ]
    for (const c of candidates) {
      if (!isRegularFile(c.file)) continue
      try {
        const parsed = JSON.parse(fs.readFileSync(c.file, 'utf8')) as Partial<PersistedAnalysisCache>
        if (
          parsed.schema_version === ANALYSIS_CACHE_SCHEMA_VER &&
          parsed.session_fingerprint === sessionFP &&
          parsed.analyzer_fingerprint === analyzerFP &&
          Array.isArray(parsed.plugin_insights) &&
          Array.isArray(parsed.plugin_kpis)
        ) {
          return {
            out: {
              insights: parsed.plugin_insights,
              kpis: parsed.plugin_kpis,
              notes: Array.isArray(parsed.plugin_notes) ? parsed.plugin_notes : [],
            },
            storage: c.storage,
          }
        }
      } catch {
        // ignore corrupted cache
      }
    }
    return undefined
  }

  private persistAnalysisCache(
    dir: string,
    sessionFP: string,
    analyzerFP: string,
    out: AnalyzerOutput,
  ): AnalysisStorageKind {
    const basePayload: PersistedAnalysisCache = {
      schema_version: ANALYSIS_CACHE_SCHEMA_VER,
      session_fingerprint: sessionFP,
      analyzer_fingerprint: analyzerFP,
      saved_at: new Date().toISOString(),
      plugin_insights: out.insights,
      plugin_kpis: out.kpis,
      ...(out.notes.length > 0 ? { plugin_notes: out.notes } : {}),
    }
    const primaryPath = path.join(dir, ANALYSIS_CACHE_FILE_NAME)
    try {
      writeFileAtomic(primaryPath, JSON.stringify({ ...basePayload, storage: 'session_disk' }, null, 2))
      return 'session_disk'
    } catch {
      const fallbackPath = this.appFallbackCachePath(dir)
      try {
        writeFileAtomic(fallbackPath, JSON.stringify({ ...basePayload, storage: 'app_cache' }, null, 2))
      } catch {
        // non-fatal if even app cache is unwritable
      }
      return 'app_cache'
    }
  }

  async getOverview(sessionId: string, opts?: { forceReanalyze?: boolean }): Promise<Record<string, unknown>> {
    const dir = this.resolveSessionDir(sessionId)
    const base = this.loadBase(dir)
    const analyzerFP = this.computeAnalyzerFingerprint()
    const force = Boolean(opts?.forceReanalyze)

    let analysisOut: AnalyzerOutput | undefined
    let cacheState: 'memory_hit' | 'disk_hit' | 'computed' = 'computed'
    let storage: AnalysisStorageKind = 'session_disk'

    if (!force) {
      const mem = this.analysisCache.get(dir)
      if (mem && mem.sessionFP === base.sessionFP && mem.analyzerFP === analyzerFP) {
        analysisOut = mem.out
        storage = mem.storage
        cacheState = 'memory_hit'
      } else {
        const disk = this.readPersistedAnalysisCache(dir, base.sessionFP, analyzerFP)
        if (disk) {
          analysisOut = disk.out
          storage = disk.storage
          cacheState = 'disk_hit'
          this.analysisCache.set(dir, {
            sessionFP: base.sessionFP,
            analyzerFP,
            storage,
            out: analysisOut,
          })
        }
      }
    }

    const probeHealth = buildSessionHealth(base.session, base.overview)

    if (!analysisOut) {
      const baseRecord: Record<string, unknown> = {
        ...(base.overview as unknown as Record<string, unknown>),
        probe_health: probeHealth,
        external_bpf_plugins: probeHealth.external_bpf_plugins,
        drop_reasons_summary: probeHealth.drop_reasons_summary,
      }
      analysisOut = this.host && typeof this.host.runAnalyzers === 'function'
        ? await this.host.runAnalyzers(sessionId, dir, baseRecord)
        : { insights: [], kpis: [], notes: [] }
      if (!hasIsolatedAnalyzerError(analysisOut)) {
        storage = this.persistAnalysisCache(dir, base.sessionFP, analyzerFP, analysisOut)
        this.analysisCache.set(dir, {
          sessionFP: base.sessionFP,
          analyzerFP,
          storage,
          out: analysisOut,
        })
      } else {
        storage = 'memory_only'
      }
    }

    return {
      ...base.overview,
      session_id: sessionId,
      session_dir: dir,
      probe_health: probeHealth,
      external_bpf_plugins: probeHealth.external_bpf_plugins,
      drop_reasons_summary: probeHealth.drop_reasons_summary,
      plugin_insights: analysisOut.insights,
      plugin_kpis: analysisOut.kpis,
      plugin_notes: analysisOut.notes,
      analysis_cache: {
        state: cacheState,
        storage,
        session_fingerprint: base.sessionFP,
        analyzer_fingerprint: analyzerFP,
      },
    }
  }

  async getSample(sessionId: string, sampleId: string): Promise<Record<string, unknown>> {
    const dir = this.resolveSessionDir(sessionId)
    const sid = parseSampleIdStrict(sampleId)
    const base = this.loadBase(dir)
    const detail = buildSampleDetail(base.session, sid)
    return detail as unknown as Record<string, unknown>
  }

  async getSessionForExport(sessionId: string): Promise<SessionExportData> {
    const dir = this.resolveSessionDir(sessionId)
    const base = this.loadBase(dir)
    const overview = await this.getOverview(sessionId)
    return {
      session_id: sessionId,
      session_dir: dir,
      overview,
      session: base.session,
    }
  }

  invalidateAnalysisCache(sessionId?: string): void {
    if (!sessionId) {
      this.analysisCache.clear()
      return
    }
    try {
      const dir = this.resolveSessionDir(sessionId)
      this.analysisCache.delete(dir)
    } catch {
      this.analysisCache.clear()
    }
  }
}
