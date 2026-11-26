// Frozen Wave 1 v1.2 contract types for the pure Cordis analysis slice.
// Structurally 100% compatible with Lin's studio-cordis/src/kernel/types.ts
// (erasableSyntaxOnly, zero external runtime dependencies).

export type PluginCategory = 'transport' | 'collector' | 'analyzer' | 'exporter' | 'external'
export type ExtensionPoint = 'transport' | 'collector' | 'capture.mode' | 'analyzer' | 'exporter' | 'ui.slot'
export type PluginStatus = 'active' | 'disabled' | 'error'

export interface ConfigField {
  key: string
  label: string
  type: 'string' | 'number' | 'boolean' | 'select'
  default?: unknown
  description?: string
  min?: number
  max?: number
  options?: Array<{ value: string; label: string }>
}

export interface ConfigSchema {
  fields: ConfigField[]
}

export interface PluginMeta {
  id: string
  name: string
  version: string
  author?: string
  description: string
  category: PluginCategory
  icon?: string
  builtin: boolean
  source_path?: string
  capabilities: string[]
  provides?: string[]
  requires?: string[]
  tags?: string[]
}

export interface HostPaths {
  readonly appDir: string
  readonly sessionsRoot: string
  readonly pluginsDir: string
  readonly exportsDir: string
  readonly collectorsDir: string
  readonly webDir: string
  readonly adbPath?: string
}

export interface SessionSummary {
  id: string
  name: string
  path: string
  created_at?: string
  sample_count?: number
  [key: string]: unknown
}

export interface OpenedSessionMeta {
  id: string
  path: string
  [key: string]: unknown
}

export interface SessionExportData {
  session_id: string
  session_dir: string
  overview: Record<string, unknown>
  session?: unknown
}

export interface SessionProvider {
  listSessions(): Promise<SessionSummary[]>
  openSession(dirPath: string): Promise<OpenedSessionMeta>
  getOverview(sessionId: string, opts?: { forceReanalyze?: boolean }): Promise<Record<string, unknown>>
  getSample(sessionId: string, sampleId: string): Promise<Record<string, unknown>>
  getSessionForExport(sessionId: string): Promise<SessionExportData>
  invalidateAnalysisCache(sessionId?: string): void
}

export interface AnalyzerInsight {
  id?: string
  plugin_id?: string
  analyzer_id?: string
  title: string
  summary?: string
  detail?: string
  severity: 'ok' | 'info' | 'warn' | 'critical'
  sample_ids?: string[]
  [key: string]: unknown
}

export interface AnalyzerKpi {
  id?: string
  plugin_id?: string
  analyzer_id?: string
  label: string
  value: string | number
  sub?: string
  tone?: 'default' | 'ok' | 'warn' | 'bad'
  [key: string]: unknown
}

export interface AnalyzerInput {
  action: 'analyze'
  plugin_id: string
  analyzer_id: string
  config: Record<string, unknown>
  session_id: string
  session_dir: string
  overview: Record<string, unknown>
}

export interface AnalyzerOutput {
  insights: AnalyzerInsight[]
  kpis: AnalyzerKpi[]
  notes: string[]
}

export interface AnalyzerRegistration {
  id: string
  plugin_id: string
  name: string
  description?: string
  run: (input: AnalyzerInput) => Promise<AnalyzerOutput> | AnalyzerOutput
}

export interface ExporterInput {
  action: 'export'
  plugin_id: string
  exporter_id: string
  config: Record<string, unknown>
  session_id: string
  session_dir: string
  overview: Record<string, unknown>
  session?: unknown
  out_path: string
  params: Record<string, unknown>
}

export interface ExporterOutput {
  ok: boolean
  out_path: string
  is_directory?: boolean
  summary: string
  details?: Record<string, unknown>
  error?: string
}

export interface ExporterRegistration {
  id: string
  plugin_id: string
  name: string
  description?: string
  default_ext?: string
  run: (input: ExporterInput) => Promise<ExporterOutput> | ExporterOutput
}

export interface HostServices {
  readonly paths: HostPaths
  readonly version: string
  getService<T = unknown>(name: string): T | undefined
  provideService(pluginId: string, name: string, impl: unknown): () => void
  getSessionProvider(): SessionProvider | undefined
}

export interface PluginContext {
  readonly pluginId: string
  readonly host: HostServices
  readonly cordis?: unknown
  provide(name: string, impl: unknown): void
  inject<T = unknown>(name: string): T | undefined
  registerExtension<T = unknown>(point: ExtensionPoint, value: T): void
  effect(fn: () => void | (() => void | Promise<void>)): void
  onDispose(fn: () => void | Promise<void>): void
}

export interface BuiltinPlugin {
  readonly meta: PluginMeta
  readonly schema: ConfigSchema
  apply(ctx: PluginContext, cfg: Record<string, unknown>): void | Promise<void>
}

// Structural subset of CordisHost needed by SessionStore and session-routes.ts.
export interface AnalysisHostLike {
  readonly paths: HostPaths
  readonly version?: string
  getService<T = unknown>(name: string): T | undefined
  getSessionProvider?(): SessionProvider | undefined
  runAnalyzers(
    sessionId: string,
    sessionDir: string,
    overview: Record<string, unknown>,
    timeoutMs?: number,
  ): Promise<AnalyzerOutput>
  runExport?(req: {
    exporter_id: string
    session_id: string
    out_path?: string
    params?: Record<string, unknown>
  }): Promise<ExporterOutput>
  snapshot(): {
    plugins: Array<{
      id: string
      version: string
      enabled: boolean
      status: string
      config: Record<string, unknown>
      source_path?: string
    }>
    analyzers: Array<Record<string, unknown>>
    [key: string]: unknown
  }
}
