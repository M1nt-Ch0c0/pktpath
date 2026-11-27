import fs from 'node:fs';
import path from 'node:path';
import { Context } from '@cordisjs/core';
import { attachCleanupWait, type CleanupWaitHandle } from './cleanup-wait.ts';
import {
  discoverExternalPlugins,
  importExternalModule,
  installExternalPackage,
  normalizeAnalyzerOutput,
  normalizeExporterOutput,
  previewExternalPackage,
  type LoadedExternalPlugin,
} from './external-loader.ts';
import type {
  AnalyzerInsight,
  AnalyzerKpi,
  AnalyzerOutput,
  AnalyzerRegistration,
  BuiltinPlugin,
  ConfigSchema,
  ExporterOutput,
  ExporterRegistration,
  ExtensionPoint,
  HostPaths,
  HostServices,
  KernelSnapshot,
  PluginContext,
  PluginMeta,
  PluginSnapshotItem,
  PluginStatus,
  SessionProvider,
} from './types.ts';

interface PersistedKernelConfig {
  enabled: Record<string, boolean>;
  configs: Record<string, Record<string, unknown>>;
}

interface ExtensionEntry {
  pluginId: string;
  point: ExtensionPoint;
  value: unknown;
}

interface PluginRecord {
  meta: PluginMeta;
  schema: ConfigSchema;
  builtin?: BuiltinPlugin;
  external?: LoadedExternalPlugin;
  enabled: boolean;
  status: PluginStatus;
  error?: string;
  config: Record<string, unknown>;
  fork?: { dispose(): void };
}

const CORDIS_VERSION = '3.18.1';
const DEFAULT_ANALYZER_TIMEOUT_MS = 15_000;

function defaultsFromSchema(schema: ConfigSchema): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const field of schema.fields) {
    if (field.default !== undefined) {
      out[field.key] = field.default;
    }
  }
  return out;
}

function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`${label} timed out after ${ms}ms`));
    }, ms);
    promise.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (err: unknown) => {
        clearTimeout(timer);
        reject(err);
      },
    );
  });
}

export class CordisHost {
  readonly paths: HostPaths;
  readonly version: string;
  readonly configPath: string;
  readonly rootCtx: Context;

  private readonly cleanupWait: CleanupWaitHandle;
  private lifecycleQueue: Promise<unknown> = Promise.resolve();

  private runLifecycleExclusive<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.lifecycleQueue.then(fn, fn);
    this.lifecycleQueue = next.then(() => undefined, () => undefined);
    return next;
  }
  private readonly records = new Map<string, PluginRecord>();
  private readonly services = new Map<string, { pluginId: string; impl: unknown }>();
  private readonly extensions: ExtensionEntry[] = [];
  private persisted: PersistedKernelConfig = { enabled: {}, configs: {} };
  private configHealed = false;
  private reloadSeq = 0;
  private started = false;

  constructor(paths: HostPaths, version = 'cordis-wave1') {
    this.paths = paths;
    this.version = version;
    this.configPath = path.join(paths.appDir, 'kernel-config.json');
    this.rootCtx = new Context();
    this.cleanupWait = attachCleanupWait(this.rootCtx);

    fs.mkdirSync(paths.appDir, { recursive: true });
    fs.mkdirSync(paths.sessionsRoot, { recursive: true });
    fs.mkdirSync(paths.pluginsDir, { recursive: true });
    fs.mkdirSync(paths.exportsDir, { recursive: true });

    this.services.set('paths', { pluginId: 'host', impl: paths });
    this.loadPersistedConfig();
  }

  get hostServices(): HostServices {
    return {
      paths: this.paths,
      version: this.version,
      getService: <T = unknown>(name: string) => this.getService<T>(name),
      provideService: (pluginId: string, name: string, impl: unknown) => this.provideService(pluginId, name, impl),
      getSessionProvider: () => this.getService<SessionProvider>('session.provider'),
    };
  }

  getService<T = unknown>(name: string): T | undefined {
    return this.services.get(name)?.impl as T | undefined;
  }

  provideService(pluginId: string, name: string, impl: unknown): () => void {
    this.services.set(name, { pluginId, impl });
    return () => {
      const cur = this.services.get(name);
      if (cur && cur.pluginId === pluginId && cur.impl === impl) {
        this.services.delete(name);
      }
    };
  }

  getExtensions<T = unknown>(point: ExtensionPoint): T[] {
    return this.extensions.filter((e) => e.point === point).map((e) => e.value as T);
  }

  registerBuiltin(plugin: BuiltinPlugin): void {
    if (this.records.has(plugin.meta.id)) {
      throw new Error(`duplicate plugin id: ${plugin.meta.id}`);
    }
    const persistedEnabled = this.persisted.enabled[plugin.meta.id];
    const enabled = plugin.meta.required ? true : (persistedEnabled ?? true);
    if (plugin.meta.required && persistedEnabled === false) {
      this.configHealed = true;
    }
    const config = {
      ...defaultsFromSchema(plugin.schema),
      ...(this.persisted.configs[plugin.meta.id] ?? {}),
    };
    this.records.set(plugin.meta.id, {
      meta: plugin.meta,
      schema: plugin.schema,
      builtin: plugin,
      enabled,
      status: enabled ? 'disabled' : 'disabled',
      config,
    });
  }

  async start(): Promise<void> {
    if (this.started) return;
    this.started = true;

    const discovered = discoverExternalPlugins(this.paths.pluginsDir);
    for (const ext of discovered.loaded) {
      if (this.records.has(ext.manifest.id)) continue;
      const enabled = this.persisted.enabled[ext.manifest.id] ?? true;
      const config = {
        ...defaultsFromSchema(ext.manifest.schema),
        ...(this.persisted.configs[ext.manifest.id] ?? {}),
      };
      this.records.set(ext.manifest.id, {
        meta: ext.meta,
        schema: ext.manifest.schema,
        external: ext,
        enabled,
        status: 'disabled',
        config,
      });
    }

    // Activate in topological order: plugins with no requires first, then dependents.
    const ordered = [...this.records.values()].sort((a, b) => {
      const ra = a.meta.requires?.length ?? 0;
      const rb = b.meta.requires?.length ?? 0;
      if (ra !== rb) return ra - rb;
      if (a.meta.builtin !== b.meta.builtin) return a.meta.builtin ? -1 : 1;
      return a.meta.id.localeCompare(b.meta.id);
    });

    for (const rec of ordered) {
      if (rec.enabled) {
        await this.activateRecord(rec);
      }
    }
    if (this.configHealed) {
      this.savePersistedConfig();
      this.configHealed = false;
    }
  }

  private loadPersistedConfig(): void {
    if (!fs.existsSync(this.configPath)) return;
    try {
      const parsed = JSON.parse(fs.readFileSync(this.configPath, 'utf8')) as Partial<PersistedKernelConfig>;
      this.persisted = {
        enabled: parsed.enabled && typeof parsed.enabled === 'object' ? parsed.enabled : {},
        configs: parsed.configs && typeof parsed.configs === 'object' ? parsed.configs : {},
      };
    } catch {
      this.persisted = { enabled: {}, configs: {} };
    }
  }

  private savePersistedConfig(): void {
    const enabled: Record<string, boolean> = {};
    const configs: Record<string, Record<string, unknown>> = {};
    for (const [id, rec] of this.records) {
      enabled[id] = rec.enabled;
      configs[id] = rec.config;
    }
    this.persisted = { enabled, configs };
    fs.mkdirSync(path.dirname(this.configPath), { recursive: true });
    fs.writeFileSync(this.configPath, JSON.stringify(this.persisted, null, 2), 'utf8');
  }

  private invalidateSessionCache(): void {
    const sp = this.getService<SessionProvider>('session.provider');
    sp?.invalidateAnalysisCache();
  }

  private createPluginContext(rec: PluginRecord, cordisCtx: Context): PluginContext {
    const pluginId = rec.meta.id;
    return {
      pluginId,
      host: this.hostServices,
      cordis: cordisCtx,
      provide: (name: string, impl: unknown) => {
        const unreg = this.provideService(pluginId, name, impl);
        cordisCtx.on('dispose', unreg);
      },
      inject: <T = unknown>(name: string) => this.getService<T>(name),
      registerExtension: <T = unknown>(point: ExtensionPoint, value: T) => {
        const entry: ExtensionEntry = { pluginId, point, value };
        this.extensions.push(entry);
        cordisCtx.on('dispose', () => {
          const idx = this.extensions.indexOf(entry);
          if (idx >= 0) this.extensions.splice(idx, 1);
        });
      },
      effect: (fn) => {
        cordisCtx.effect(fn as () => void | (() => void));
      },
      onDispose: (fn) => {
        cordisCtx.on('dispose', fn as () => void);
      },
    };
  }

  private async activateRecord(rec: PluginRecord): Promise<void> {
    await this.deactivateRecord(rec);

    // Check required services
    const missing = (rec.meta.requires ?? []).filter((req) => !this.services.has(req));
    if (missing.length > 0) {
      rec.status = 'error';
      rec.error = `依赖插件未启用：${missing.map((s) => this.describeService(s)).join('、')}`;
      return;
    }

    const host = this;
    let applyPromise: Promise<void> | undefined;
    try {
      const fork = this.rootCtx.plugin({
        name: rec.meta.id,
        apply(ctx: Context) {
          const pctx = host.createPluginContext(rec, ctx);
          if (rec.builtin) {
            const ret = rec.builtin.apply(pctx, { ...rec.config });
            if (ret && typeof (ret as Promise<void>).then === 'function') {
              applyPromise = ret as Promise<void>;
            }
          } else if (rec.external) {
            applyPromise = host.applyExternalPlugin(rec, rec.external, pctx, ctx);
          }
        },
      });
      rec.fork = fork as unknown as { dispose(): void };
      if (applyPromise) {
        await applyPromise;
      }
      rec.status = 'active';
      rec.error = undefined;
    } catch (err) {
      rec.status = 'error';
      rec.error = err instanceof Error ? err.message : String(err);
      if (rec.fork) {
        rec.fork.dispose();
        rec.fork = undefined;
        await this.cleanupWait.wait();
      }
    }
  }

  private async applyExternalPlugin(
    rec: PluginRecord,
    ext: LoadedExternalPlugin,
    pctx: PluginContext,
    cordisCtx: Context,
  ): Promise<void> {
    this.reloadSeq += 1;
    const mod = await importExternalModule(ext.modulePath, this.reloadSeq);

    if (ext.manifest.analyzers.length > 0 && !mod.analyze) {
      throw new Error(`external plugin ${ext.manifest.id} declares analyzers but exports no analyze()`);
    }
    if (ext.manifest.exporters.length > 0 && !mod.exportSession) {
      throw new Error(`external plugin ${ext.manifest.id} declares exporters but exports no exportSession()`);
    }

    if (mod.setup) {
      await mod.setup(cordisCtx, { ...rec.config });
    }

    for (const a of ext.manifest.analyzers) {
      const reg: AnalyzerRegistration = {
        id: a.id,
        plugin_id: ext.manifest.id,
        name: a.name,
        description: a.description,
        run: async (input) => {
          const raw = await mod.analyze!(input);
          return normalizeAnalyzerOutput(raw, ext.manifest.id, a.id);
        },
      };
      pctx.registerExtension('analyzer', reg);
    }

    for (const e of ext.manifest.exporters) {
      const reg: ExporterRegistration = {
        id: e.id,
        plugin_id: ext.manifest.id,
        name: e.name,
        description: e.description,
        default_ext: e.default_ext,
        run: async (input) => {
          const raw = await mod.exportSession!(input);
          return normalizeExporterOutput(raw, input.out_path);
        },
      };
      pctx.registerExtension('exporter', reg);
    }
  }

  private async deactivateRecord(rec: PluginRecord): Promise<string[]> {
    if (!rec.fork) {
      rec.status = 'disabled';
      return [];
    }
    const fork = rec.fork;
    rec.fork = undefined;
    fork.dispose();
    const errors = await this.cleanupWait.wait();
    // Safety cleanup of any leftover extensions/services registered by this plugin
    for (let i = this.extensions.length - 1; i >= 0; i--) {
      if (this.extensions[i].pluginId === rec.meta.id) {
        this.extensions.splice(i, 1);
      }
    }
    for (const [k, v] of this.services) {
      if (v.pluginId === rec.meta.id) {
        this.services.delete(k);
      }
    }
    if (errors.length > 0) {
      rec.status = 'error';
      rec.error = `cleanup error: ${errors.join('; ')}`;
    } else {
      rec.status = 'disabled';
      rec.error = undefined;
    }
    return errors;
  }

  async toggle(id: string, enabled: boolean): Promise<{ ok: boolean; error?: string; state: KernelSnapshot }> {
    return this.runLifecycleExclusive(async () => {
    const rec = this.records.get(id);
    if (!rec) {
      return { ok: false, error: `未找到插件：${id}`, state: this.snapshot() };
    }
    if (rec.meta.required && !enabled) {
      return {
        ok: false,
        error: `核心插件「${rec.meta.name}」为系统必备组件，不可关闭。`,
        state: this.snapshot(),
      };
    }
    rec.enabled = enabled;
    let errMsg: string | undefined;
    if (enabled) {
      await this.activateRecord(rec);
      if (rec.status === 'error') errMsg = rec.error;
      // Re-attempt activating enabled dependents that were previously missing this service
      for (const other of this.records.values()) {
        if (other.enabled && other.status === 'error' && other.meta.id !== id) {
          await this.activateRecord(other);
        }
      }
    } else {
      const cleanupErrs = await this.deactivateRecord(rec);
      if (cleanupErrs.length > 0) errMsg = rec.error;
      // Deactivate active dependents whose required service was just removed
      for (const other of this.records.values()) {
        if (other.status === 'active' && (other.meta.requires ?? []).some((r) => !this.services.has(r))) {
          await this.deactivateRecord(other);
          other.status = 'error';
          other.error = `因「${rec.meta.name}」已关闭，当前插件暂时停用`;
        }
      }
    }
    this.savePersistedConfig();
    this.invalidateSessionCache();
    return { ok: !errMsg, ...(errMsg ? { error: errMsg } : {}), state: this.snapshot() };
      });
  }

  async updateConfig(id: string, config: Record<string, unknown>): Promise<{ ok: boolean; error?: string; state: KernelSnapshot }> {
    return this.runLifecycleExclusive(async () => {
    const rec = this.records.get(id);
    if (!rec) {
      return { ok: false, error: `plugin not found: ${id}`, state: this.snapshot() };
    }
    rec.config = { ...rec.config, ...config };
    this.savePersistedConfig();
    if (rec.enabled) {
      await this.activateRecord(rec);
    }
    this.invalidateSessionCache();
    return {
      ok: rec.status !== 'error',
      ...(rec.error ? { error: rec.error } : {}),
      state: this.snapshot(),
    };
      });
  }

  async resetConfig(id: string): Promise<{ ok: boolean; error?: string; state: KernelSnapshot }> {
    return this.runLifecycleExclusive(async () => {
    const rec = this.records.get(id);
    if (!rec) {
      return { ok: false, error: `plugin not found: ${id}`, state: this.snapshot() };
    }
    rec.config = defaultsFromSchema(rec.schema);
    this.savePersistedConfig();
    if (rec.enabled) {
      await this.activateRecord(rec);
    }
    this.invalidateSessionCache();
    return {
      ok: rec.status !== 'error',
      ...(rec.error ? { error: rec.error } : {}),
      state: this.snapshot(),
    };
      });
  }

  async reload(id: string): Promise<{ ok: boolean; error?: string; state: KernelSnapshot }> {
    return this.runLifecycleExclusive(async () => {
    const rec = this.records.get(id);
    if (!rec) {
      return { ok: false, error: `plugin not found: ${id}`, state: this.snapshot() };
    }
    const cleanupErrs = await this.deactivateRecord(rec);
    if (cleanupErrs.length > 0) {
      return { ok: false, error: rec.error, state: this.snapshot() };
    }
    if (rec.external) {
      const reparsed = discoverExternalPlugins(this.paths.pluginsDir).loaded.find((x) => x.manifest.id === id);
      if (!reparsed) {
        rec.status = 'error';
        rec.error = `external plugin directory missing on reload: ${id}`;
        return { ok: false, error: rec.error, state: this.snapshot() };
      }
      rec.external = reparsed;
      rec.meta = reparsed.meta;
      rec.schema = reparsed.manifest.schema;
    }
    if (rec.enabled) {
      await this.activateRecord(rec);
    }
    this.invalidateSessionCache();
    return {
      ok: rec.status !== 'error',
      ...(rec.error ? { error: rec.error } : {}),
      state: this.snapshot(),
    };
      });
  }

  previewExternal(sourcePath: string) {
    return previewExternalPackage(sourcePath);
  }

  async installExternal(sourcePath: string): Promise<{ ok: boolean; plugin_id?: string; error?: string; state: KernelSnapshot }> {
    return this.runLifecycleExclusive(async () => {
    try {
      const preview = previewExternalPackage(sourcePath);
      const existing = this.records.get(preview.id);
      if (existing) {
        if (existing.meta.builtin) {
          throw new Error(`cannot overwrite builtin plugin: ${preview.id}`);
        }
        const cleanupErrs = await this.deactivateRecord(existing);
        if (cleanupErrs.length > 0) {
          throw new Error(`failed to clean up previous version of ${preview.id}: ${cleanupErrs.join('; ')}`);
        }
      }
      const installed = installExternalPackage(sourcePath, this.paths.pluginsDir);
      const rec: PluginRecord = {
        meta: installed.meta,
        schema: installed.manifest.schema,
        external: installed,
        enabled: true,
        status: 'disabled',
        config: {
          ...defaultsFromSchema(installed.manifest.schema),
          ...(existing?.config ?? {}),
        },
      };
      this.records.set(installed.manifest.id, rec);
      await this.activateRecord(rec);
      this.savePersistedConfig();
      this.invalidateSessionCache();
      return {
        ok: rec.status === 'active',
        plugin_id: installed.manifest.id,
        ...(rec.error ? { error: rec.error } : {}),
        state: this.snapshot(),
      };
    } catch (err) {
      return {
        ok: false,
        error: err instanceof Error ? err.message : String(err),
        state: this.snapshot(),
      };
    }
      });
  }

  async uninstallExternal(id: string): Promise<{ ok: boolean; error?: string; state: KernelSnapshot }> {
    return this.runLifecycleExclusive(async () => {
    const rec = this.records.get(id);
    if (!rec) {
      return { ok: false, error: `plugin not found: ${id}`, state: this.snapshot() };
    }
    if (rec.meta.builtin || !rec.external) {
      return { ok: false, error: `cannot uninstall builtin plugin: ${id}`, state: this.snapshot() };
    }
    const cleanupErrs = await this.deactivateRecord(rec);
    if (cleanupErrs.length > 0) {
      return { ok: false, error: `cleanup failed during uninstall: ${cleanupErrs.join('; ')}`, state: this.snapshot() };
    }
    fs.rmSync(rec.external.dir, { recursive: true, force: true });
    this.records.delete(id);
    this.savePersistedConfig();
    this.invalidateSessionCache();
    return { ok: true, state: this.snapshot() };
      });
  }

  async runAnalyzers(
    sessionId: string,
    sessionDir: string,
    overview: Record<string, unknown>,
    timeoutMs = DEFAULT_ANALYZER_TIMEOUT_MS,
  ): Promise<AnalyzerOutput> {
    const analyzers = this.getExtensions<AnalyzerRegistration>('analyzer');
    const insights: AnalyzerInsight[] = [];
    const kpis: AnalyzerKpi[] = [];
    const notes: string[] = [];

    for (const reg of analyzers) {
      const rec = this.records.get(reg.plugin_id);
      const config = rec ? { ...rec.config } : {};
      try {
        const res = await withTimeout(
          Promise.resolve(
            reg.run({
              action: 'analyze',
              plugin_id: reg.plugin_id,
              analyzer_id: reg.id,
              config,
              session_id: sessionId,
              session_dir: sessionDir,
              overview,
            }),
          ),
          timeoutMs,
          `analyzer ${reg.plugin_id}/${reg.id}`,
        );
        insights.push(...res.insights);
        kpis.push(...res.kpis);
        notes.push(...res.notes);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        notes.push(`[${reg.plugin_id}/${reg.id}] 分析失败（已隔离）: ${msg}`);
      }
    }
    return { insights, kpis, notes };
  }

  private describeService(serviceName: string): string {
    for (const rec of this.records.values()) {
      if ((rec.meta.provides ?? []).includes(serviceName)) {
        return `「${rec.meta.name}」`;
      }
    }
    return serviceName;
  }

  private findExporterPluginName(exporterId: string): string | undefined {
    const exact = this.records.get(exporterId);
    if (exact) return exact.meta.name;
    const byShortId = this.records.get(`builtin.exporter.${exporterId}`);
    if (byShortId) return byShortId.meta.name;
    return undefined;
  }

  async runExport(req: {
    exporter_id: string;
    session_id: string;
    out_path?: string;
    params?: Record<string, unknown>;
  }): Promise<ExporterOutput> {
    const exporters = this.getExtensions<ExporterRegistration>('exporter');
    const reg = exporters.find((e) => e.id === req.exporter_id || e.plugin_id === req.exporter_id);
    if (!reg) {
      const pluginName = this.findExporterPluginName(req.exporter_id);
      return {
        ok: false,
        out_path: '',
        summary: '',
        error: pluginName
          ? `导出插件「${pluginName}」未启用，请先在插件页启用后再导出。`
          : `未找到可用的导出插件（${req.exporter_id}），请确认对应插件已安装并启用。`,
      };
    }
    const sp = this.getService<SessionProvider>('session.provider');
    if (!sp) {
      return {
        ok: false,
        out_path: '',
        summary: '',
        error: '「本地会话存储与加载」插件未启用，无法导出会话。请先在插件页确认该插件已启用。',
      };
    }
    const data = await sp.getSessionForExport(req.session_id);
    const safeSessionId = req.session_id.replace(/[^a-zA-Z0-9._-]/g, '_') || 'session';
    const ext = reg.default_ext || '.txt';
    let outPath = typeof req.out_path === 'string' ? req.out_path.trim() : '';
    if (!outPath) {
      fs.mkdirSync(this.paths.exportsDir, { recursive: true });
      outPath = path.join(this.paths.exportsDir, `${safeSessionId}-report${ext}`);
    } else {
      outPath = path.resolve(outPath);
      if (fs.existsSync(outPath) && fs.lstatSync(outPath).isFIFO()) {
        return { ok: false, out_path: outPath, summary: '', error: 'refusing to export to FIFO pipe' };
      }
    }
    // Never allow exporter output path (including through symlinks) to overwrite or sit inside the source session directory
    if (data.session_dir) {
      const resolveNearestReal = (target: string): string => {
        let cur = path.resolve(target);
        const tail: string[] = [];
        while (!fs.existsSync(cur)) {
          const parent = path.dirname(cur);
          if (parent === cur) break;
          tail.unshift(path.basename(cur));
          cur = parent;
        }
        let base = cur;
        try {
          base = fs.realpathSync(cur);
        } catch {
          base = cur;
        }
        return tail.length > 0 ? path.join(base, ...tail) : base;
      };
      const resolvedSess = resolveNearestReal(data.session_dir);
      const resolvedOut = resolveNearestReal(outPath);
      if (resolvedOut === resolvedSess || resolvedOut.startsWith(resolvedSess + path.sep)) {
        return {
          ok: false,
          out_path: outPath,
          summary: '',
          error: 'out_path must not target or reside inside session_dir',
        };
      }
    }
    const rec = this.records.get(reg.plugin_id);
    const timeoutMs = typeof (req as { timeout_ms?: number }).timeout_ms === 'number'
      ? (req as { timeout_ms?: number }).timeout_ms!
      : 30_000;
    try {
      return await withTimeout(
        reg.run({
          action: 'export',
          plugin_id: reg.plugin_id,
          exporter_id: reg.id,
          config: rec ? { ...rec.config } : {},
          session_id: data.session_id,
          session_dir: data.session_dir,
          overview: data.overview,
          session: data.session,
          out_path: outPath,
          params: req.params ?? {},
        }),
        timeoutMs,
        `exporter ${reg.id}`,
      );
    } catch (err) {
      return {
        ok: false,
        out_path: outPath,
        summary: '',
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  resolvePluginAsset(pluginId: string, relPath: string): string | undefined {
    const rec = this.records.get(pluginId);
    if (!rec || !rec.external) return undefined;
    const norm = relPath.replaceAll('\\', '/').replace(/^\/+/, '');
    if (!norm || norm.split('/').includes('..')) return undefined;
    const rootReal = fs.realpathSync(rec.external.dir);
    const candidate = path.resolve(rootReal, norm);
    if (!candidate.startsWith(rootReal + path.sep) || !fs.existsSync(candidate)) return undefined;
    const real = fs.realpathSync(candidate);
    if (!real.startsWith(rootReal + path.sep) || !fs.statSync(real).isFile()) return undefined;
    return real;
  }

  snapshot(): KernelSnapshot {
    const plugins: PluginSnapshotItem[] = [];
    let activeCount = 0;
    let builtinCount = 0;
    let externalCount = 0;

    for (const rec of this.records.values()) {
      if (rec.status === 'active') activeCount += 1;
      if (rec.meta.builtin) builtinCount += 1;
      else externalCount += 1;

      plugins.push({
        id: rec.meta.id,
        name: rec.meta.name,
        version: rec.meta.version,
        author: rec.meta.author,
        description: rec.meta.description,
        category: rec.meta.category,
        icon: rec.meta.icon,
        builtin: rec.meta.builtin,
        source_path: rec.meta.source_path,
        enabled: rec.enabled,
        status: rec.status,
        error: rec.error,
        capabilities: rec.meta.capabilities,
        provides: rec.meta.provides ?? [],
        requires: rec.meta.requires ?? [],
        required: Boolean(rec.meta.required),
        usedBy: rec.meta.usedBy ? [...rec.meta.usedBy] : [],
        tags: rec.meta.tags ?? [],
        schema: rec.schema,
        config: rec.config,
      });
    }

    const transports = this.getExtensions<Record<string, unknown>>('transport');
    const collectors = this.getExtensions<Record<string, unknown>>('collector');
    const captureModes = this.getExtensions<Record<string, unknown>>('capture.mode');
    const exporters = this.getExtensions<ExporterRegistration>('exporter').map((e) => ({
      id: e.id,
      plugin_id: e.plugin_id,
      name: e.name,
      description: e.description,
      default_ext: e.default_ext,
    }));
    const analyzers = this.getExtensions<AnalyzerRegistration>('analyzer').map((a) => ({
      id: a.id,
      plugin_id: a.plugin_id,
      name: a.name,
      description: a.description,
    }));
    const uiSlots = this.getExtensions<Record<string, unknown>>('ui.slot');

    return {
      version: this.version,
      plugin_runtime: {
        engine: 'cordis-node',
        cordis_version: CORDIS_VERSION,
        node_version: process.version,
        in_process: true,
      },
      plugins_dir: this.paths.pluginsDir,
      config_path: this.configPath,
      total_plugins: plugins.length,
      active_plugins: activeCount,
      builtin_count: builtinCount,
      external_count: externalCount,
      plugins,
      transports,
      collector: collectors[0] ?? {},
      capture_modes: captureModes,
      exporters,
      analyzers,
      ui_slots: uiSlots,
      extension_counts: {
        transport: transports.length,
        collector: collectors.length,
        'capture.mode': captureModes.length,
        exporter: exporters.length,
        analyzer: analyzers.length,
        'ui.slot': uiSlots.length,
      },
    };
  }

  async shutdown(timeoutMs = 5_000): Promise<string[]> {
    return this.runLifecycleExclusive(async () => {
    const errors: string[] = [];
    const recs = [...this.records.values()].reverse();
    await withTimeout(
      (async () => {
        for (const rec of recs) {
          const errs = await this.deactivateRecord(rec);
          errors.push(...errs);
        }
      })(),
      timeoutMs,
      'kernel shutdown',
    ).catch((err: unknown) => {
      errors.push(err instanceof Error ? err.message : String(err));
    });
    return errors;
      });
  }
}
