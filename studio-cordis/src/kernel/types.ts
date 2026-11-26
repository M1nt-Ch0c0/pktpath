import type { Context } from '@cordisjs/core';

export type PluginCategory = 'transport' | 'collector' | 'analyzer' | 'exporter' | 'ui' | 'external';
export type ExtensionPoint = 'transport' | 'collector' | 'capture.mode' | 'analyzer' | 'exporter' | 'ui.slot';
export type PluginStatus = 'active' | 'disabled' | 'error';

export interface ConfigField {
  key: string;
  label: string;
  type: 'string' | 'number' | 'boolean' | 'select';
  default?: unknown;
  description?: string;
  min?: number;
  max?: number;
  options?: Array<{ value: string; label: string }>;
}

export interface ConfigSchema {
  fields: ConfigField[];
}

export interface PluginMeta {
  id: string;
  name: string;
  version: string;
  author?: string;
  description: string;
  category: PluginCategory;
  icon?: string;
  builtin: boolean;
  source_path?: string;
  capabilities: string[];
  provides?: string[];
  requires?: string[];
  tags?: string[];
}

export interface HostPaths {
  readonly appDir: string;
  readonly sessionsRoot: string;
  readonly pluginsDir: string;
  readonly exportsDir: string;
  readonly collectorsDir: string;
  readonly webDir: string;
  readonly adbPath?: string;
}

export interface SessionSummary {
  id: string;
  name: string;
  path: string;
  created_at?: string;
  sample_count?: number;
  [key: string]: unknown;
}

export interface OpenedSessionMeta {
  id: string;
  path: string;
  [key: string]: unknown;
}

export interface SessionExportData {
  session_id: string;
  session_dir: string;
  overview: Record<string, unknown>;
  session?: unknown;
}

export interface SessionProvider {
  listSessions(): Promise<SessionSummary[]>;
  openSession(dirPath: string): Promise<OpenedSessionMeta>;
  getOverview(sessionId: string, opts?: { forceReanalyze?: boolean }): Promise<Record<string, unknown>>;
  getSample(sessionId: string, sampleId: string): Promise<Record<string, unknown>>;
  getSessionForExport(sessionId: string): Promise<SessionExportData>;
  invalidateAnalysisCache(sessionId?: string): void;
}

export interface AnalyzerInsight {
  plugin_id?: string;
  analyzer_id?: string;
  title: string;
  detail?: string;
  severity: 'ok' | 'info' | 'warn' | 'critical';
  sample_ids?: string[];
  [key: string]: unknown;
}

export interface AnalyzerKpi {
  plugin_id?: string;
  analyzer_id?: string;
  label: string;
  value: string | number;
  tone?: 'default' | 'ok' | 'warn' | 'bad';
  [key: string]: unknown;
}

export interface AnalyzerInput {
  action: 'analyze';
  plugin_id: string;
  analyzer_id: string;
  config: Record<string, unknown>;
  session_id: string;
  session_dir: string;
  overview: Record<string, unknown>;
}

export interface AnalyzerOutput {
  insights: AnalyzerInsight[];
  kpis: AnalyzerKpi[];
  notes: string[];
}

export interface AnalyzerRegistration {
  id: string;
  plugin_id: string;
  name: string;
  description?: string;
  run: (input: AnalyzerInput) => Promise<AnalyzerOutput> | AnalyzerOutput;
}

export interface ExporterInput {
  action: 'export';
  plugin_id: string;
  exporter_id: string;
  config: Record<string, unknown>;
  session_id: string;
  session_dir: string;
  overview: Record<string, unknown>;
  session?: unknown;
  out_path: string;
  params: Record<string, unknown>;
}

export interface ExporterOutput {
  ok: boolean;
  out_path: string;
  is_directory?: boolean;
  summary: string;
  details?: Record<string, unknown>;
  error?: string;
}

export interface ExporterRegistration {
  id: string;
  plugin_id: string;
  name: string;
  description?: string;
  default_ext?: string;
  run: (input: ExporterInput) => Promise<ExporterOutput> | ExporterOutput;
}

export interface HostServices {
  readonly paths: HostPaths;
  readonly version: string;
  getService<T = unknown>(name: string): T | undefined;
  provideService(pluginId: string, name: string, impl: unknown): () => void;
  getSessionProvider(): SessionProvider | undefined;
}

export interface PluginContext {
  readonly pluginId: string;
  readonly host: HostServices;
  readonly cordis: Context;
  provide(name: string, impl: unknown): void;
  inject<T = unknown>(name: string): T | undefined;
  registerExtension<T = unknown>(point: ExtensionPoint, value: T): void;
  effect(fn: () => void | (() => void | Promise<void>)): void;
  onDispose(fn: () => void | Promise<void>): void;
}

export interface BuiltinPlugin {
  readonly meta: PluginMeta;
  readonly schema: ConfigSchema;
  apply(ctx: PluginContext, cfg: Record<string, unknown>): void | Promise<void>;
}

export interface PluginSnapshotItem {
  id: string;
  name: string;
  version: string;
  author?: string;
  description: string;
  category: PluginCategory;
  icon?: string;
  builtin: boolean;
  source_path?: string;
  enabled: boolean;
  status: PluginStatus;
  error?: string;
  capabilities: string[];
  provides: string[];
  requires: string[];
  tags: string[];
  schema: ConfigSchema;
  config: Record<string, unknown>;
}

export interface KernelSnapshot {
  version: string;
  plugin_runtime: {
    engine: 'cordis-node';
    cordis_version: string;
    node_version: string;
    in_process: true;
  };
  plugins_dir: string;
  config_path: string;
  total_plugins: number;
  active_plugins: number;
  builtin_count: number;
  external_count: number;
  plugins: PluginSnapshotItem[];
  transports: Record<string, unknown>[];
  collector: Record<string, unknown>;
  capture_modes: Record<string, unknown>[];
  exporters: Record<string, unknown>[];
  analyzers: Record<string, unknown>[];
  ui_slots: Record<string, unknown>[];
  extension_counts: Record<string, number>;
}
