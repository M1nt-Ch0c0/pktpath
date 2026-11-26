import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import type {
  AnalyzerInput,
  AnalyzerInsight,
  AnalyzerKpi,
  AnalyzerOutput,
  ConfigSchema,
  ExporterInput,
  ExporterOutput,
  PluginMeta,
} from './types.ts';
import { normalizeU64String } from './u64-json.ts';
import { extractZipSafe } from './zip-extract.ts';

export interface ExternalAnalyzerDecl {
  id: string;
  name: string;
  description?: string;
}

export interface ExternalExporterDecl {
  id: string;
  name: string;
  description?: string;
  default_ext?: string;
}

export interface ExternalManifest {
  id: string;
  name: string;
  version: string;
  author?: string;
  description: string;
  icon?: string;
  capabilities: string[];
  tags: string[];
  schema: ConfigSchema;
  entrypoint: {
    module: string;
  };
  analyzers: ExternalAnalyzerDecl[];
  exporters: ExternalExporterDecl[];
}

export interface LoadedExternalPlugin {
  dir: string;
  modulePath: string;
  manifest: ExternalManifest;
  meta: PluginMeta;
}

export interface ExternalModuleExports {
  setup?: (ctx: unknown, config?: Record<string, unknown>) => void | Promise<void>;
  analyze?: (input: AnalyzerInput) => Promise<unknown> | unknown;
  exportSession?: (input: ExporterInput) => Promise<unknown> | unknown;
}

const VALID_ID_RE = /^[a-z0-9][a-z0-9._-]{1,95}$/;
const VALID_SEVERITIES = new Set(['ok', 'info', 'warn', 'critical']);
const VALID_TONES = new Set(['default', 'ok', 'warn', 'bad']);

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function assertInsideRoot(rootDir: string, relPath: string, label: string): string {
  const norm = relPath.replaceAll('\\', '/').trim();
  if (!norm || norm.startsWith('/') || /^[a-zA-Z]:/.test(norm) || norm.split('/').includes('..')) {
    throw new Error(`invalid ${label} path: ${relPath}`);
  }
  const rootReal = fs.realpathSync(rootDir);
  const resolved = path.resolve(rootReal, norm);
  if (resolved !== rootReal && !resolved.startsWith(rootReal + path.sep)) {
    throw new Error(`${label} escapes plugin directory: ${relPath}`);
  }
  if (!fs.existsSync(resolved)) {
    throw new Error(`${label} not found: ${relPath}`);
  }
  const targetReal = fs.realpathSync(resolved);
  if (targetReal !== rootReal && !targetReal.startsWith(rootReal + path.sep)) {
    throw new Error(`${label} symlink escapes plugin directory: ${relPath}`);
  }
  return targetReal;
}

function resolvePackageRoot(extractedDir: string): string {
  if (fs.existsSync(path.join(extractedDir, 'manifest.json'))) {
    return extractedDir;
  }
  const entries = fs.readdirSync(extractedDir, { withFileTypes: true }).filter((e) => !e.name.startsWith('.'));
  if (entries.length === 1 && entries[0].isDirectory()) {
    const nested = path.join(extractedDir, entries[0].name);
    if (fs.existsSync(path.join(nested, 'manifest.json'))) {
      return nested;
    }
  }
  throw new Error('manifest.json not found at plugin package root');
}

export function parseExternalPluginDir(pluginDir: string): LoadedExternalPlugin {
  const manifestPath = path.join(pluginDir, 'manifest.json');
  if (!fs.existsSync(manifestPath)) {
    throw new Error(`manifest.json missing in ${pluginDir}`);
  }
  const raw: unknown = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  if (!isRecord(raw)) {
    throw new Error('manifest.json must be a JSON object');
  }

  const id = typeof raw.id === 'string' ? raw.id.trim() : '';
  if (!VALID_ID_RE.test(id)) {
    throw new Error(`invalid plugin id: "${id}"`);
  }
  if (id.startsWith('builtin.')) {
    throw new Error(`external plugin id cannot start with "builtin.": "${id}"`);
  }

  const name = typeof raw.name === 'string' && raw.name.trim() ? raw.name.trim() : '';
  const version = typeof raw.version === 'string' && raw.version.trim() ? raw.version.trim() : '';
  if (!name || !version) {
    throw new Error('manifest.json requires non-empty "name" and "version"');
  }

  const entrypoint = raw.entrypoint;
  if (!isRecord(entrypoint)) {
    throw new Error('manifest.json requires "entrypoint" object');
  }
  if ('command' in entrypoint && entrypoint.command !== undefined && entrypoint.command !== null) {
    throw new Error('legacy entrypoint.command is forbidden in Wave 1 pure Cordis host; use entrypoint.module');
  }
  const modRel = typeof entrypoint.module === 'string' ? entrypoint.module.trim() : '';
  if (!modRel) {
    throw new Error('manifest.json requires "entrypoint.module"');
  }
  if (!/\.(mjs|js|ts)$/.test(modRel)) {
    throw new Error(`entrypoint.module must end with .mjs, .js, or .ts: ${modRel}`);
  }
  const modulePath = assertInsideRoot(pluginDir, modRel, 'entrypoint.module');

  const analyzers: ExternalAnalyzerDecl[] = [];
  if (Array.isArray(raw.analyzers)) {
    for (const item of raw.analyzers) {
      if (!isRecord(item) || typeof item.id !== 'string' || !item.id.trim()) {
        throw new Error('invalid analyzer declaration in manifest.json');
      }
      analyzers.push({
        id: item.id.trim(),
        name: typeof item.name === 'string' && item.name.trim() ? item.name.trim() : item.id.trim(),
        description: typeof item.description === 'string' ? item.description : undefined,
      });
    }
  }

  const exporters: ExternalExporterDecl[] = [];
  if (Array.isArray(raw.exporters)) {
    for (const item of raw.exporters) {
      if (!isRecord(item) || typeof item.id !== 'string' || !item.id.trim()) {
        throw new Error('invalid exporter declaration in manifest.json');
      }
      exporters.push({
        id: item.id.trim(),
        name: typeof item.name === 'string' && item.name.trim() ? item.name.trim() : item.id.trim(),
        description: typeof item.description === 'string' ? item.description : undefined,
        default_ext: typeof item.default_ext === 'string' ? item.default_ext : undefined,
      });
    }
  }

  const schema: ConfigSchema = isRecord(raw.schema) && Array.isArray(raw.schema.fields)
    ? { fields: raw.schema.fields as ConfigSchema['fields'] }
    : { fields: [] };

  const capabilities = Array.isArray(raw.capabilities)
    ? raw.capabilities.filter((x): x is string => typeof x === 'string')
    : [];
  const tags = Array.isArray(raw.tags)
    ? raw.tags.filter((x): x is string => typeof x === 'string')
    : [];

  const manifest: ExternalManifest = {
    id,
    name,
    version,
    author: typeof raw.author === 'string' ? raw.author : undefined,
    description: typeof raw.description === 'string' ? raw.description : '',
    icon: typeof raw.icon === 'string' ? raw.icon : undefined,
    capabilities,
    tags,
    schema,
    entrypoint: { module: modRel },
    analyzers,
    exporters,
  };

  const meta: PluginMeta = {
    id: manifest.id,
    name: manifest.name,
    version: manifest.version,
    author: manifest.author,
    description: manifest.description,
    category: 'external',
    icon: manifest.icon,
    builtin: false,
    source_path: pluginDir,
    capabilities: manifest.capabilities,
    provides: [],
    requires: [],
    tags: manifest.tags,
  };

  return { dir: pluginDir, modulePath, manifest, meta };
}

function copyDirRecursive(srcDir: string, dstDir: string): void {
  fs.mkdirSync(dstDir, { recursive: true });
  for (const entry of fs.readdirSync(srcDir, { withFileTypes: true })) {
    if (entry.isSymbolicLink()) {
      throw new Error(`symlink not allowed in plugin package: ${entry.name}`);
    }
    const srcPath = path.join(srcDir, entry.name);
    const dstPath = path.join(dstDir, entry.name);
    if (entry.isDirectory()) {
      copyDirRecursive(srcPath, dstPath);
    } else if (entry.isFile()) {
      fs.copyFileSync(srcPath, dstPath);
    }
  }
}

export function previewExternalPackage(sourcePath: string): {
  id: string;
  name: string;
  version: string;
  author?: string;
  description: string;
  capabilities: string[];
  analyzers: ExternalAnalyzerDecl[];
  exporters: ExternalExporterDecl[];
  entrypoint_module: string;
} {
  const resolved = path.resolve(sourcePath);
  if (!fs.existsSync(resolved)) {
    throw new Error(`plugin source path not found: ${sourcePath}`);
  }
  const st = fs.lstatSync(resolved);
  let tempDir: string | undefined;
  try {
    let pkgRoot: string;
    if (st.isDirectory()) {
      pkgRoot = resolvePackageRoot(resolved);
    } else if (st.isFile() && resolved.toLowerCase().endsWith('.zip')) {
      tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pktpath-preview-'));
      extractZipSafe(resolved, tempDir);
      pkgRoot = resolvePackageRoot(tempDir);
    } else {
      throw new Error('plugin source must be a directory or .zip archive');
    }
    const parsed = parseExternalPluginDir(pkgRoot);
    return {
      id: parsed.manifest.id,
      name: parsed.manifest.name,
      version: parsed.manifest.version,
      author: parsed.manifest.author,
      description: parsed.manifest.description,
      capabilities: parsed.manifest.capabilities,
      analyzers: parsed.manifest.analyzers,
      exporters: parsed.manifest.exporters,
      entrypoint_module: parsed.manifest.entrypoint.module,
    };
  } finally {
    if (tempDir) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  }
}

export function installExternalPackage(sourcePath: string, pluginsDir: string): LoadedExternalPlugin {
  const resolved = path.resolve(sourcePath);
  if (!fs.existsSync(resolved)) {
    throw new Error(`plugin source path not found: ${sourcePath}`);
  }
  fs.mkdirSync(pluginsDir, { recursive: true });
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pktpath-install-'));
  try {
    const st = fs.lstatSync(resolved);
    let pkgRoot: string;
    if (st.isDirectory()) {
      copyDirRecursive(resolved, tempDir);
      pkgRoot = resolvePackageRoot(tempDir);
    } else if (st.isFile() && resolved.toLowerCase().endsWith('.zip')) {
      extractZipSafe(resolved, tempDir);
      pkgRoot = resolvePackageRoot(tempDir);
    } else {
      throw new Error('plugin source must be a directory or .zip archive');
    }

    const parsed = parseExternalPluginDir(pkgRoot);
    const targetDir = path.join(pluginsDir, parsed.manifest.id);
    const stagingDir = path.join(pluginsDir, `.staging-${parsed.manifest.id}-${Date.now()}`);
    try {
      copyDirRecursive(pkgRoot, stagingDir);
      fs.rmSync(targetDir, { recursive: true, force: true });
      fs.renameSync(stagingDir, targetDir);
    } catch (err) {
      fs.rmSync(stagingDir, { recursive: true, force: true });
      throw err;
    }
    return parseExternalPluginDir(targetDir);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

export function discoverExternalPlugins(pluginsDir: string): {
  loaded: LoadedExternalPlugin[];
  errors: Array<{ dir: string; error: string }>;
} {
  const loaded: LoadedExternalPlugin[] = [];
  const errors: Array<{ dir: string; error: string }> = [];
  if (!fs.existsSync(pluginsDir)) {
    return { loaded, errors };
  }
  for (const entry of fs.readdirSync(pluginsDir, { withFileTypes: true })) {
    if (!entry.isDirectory() || entry.name.startsWith('.')) {
      continue;
    }
    const full = path.join(pluginsDir, entry.name);
    try {
      loaded.push(parseExternalPluginDir(full));
    } catch (err) {
      errors.push({ dir: full, error: err instanceof Error ? err.message : String(err) });
    }
  }
  loaded.sort((a, b) => a.manifest.id.localeCompare(b.manifest.id));
  return { loaded, errors };
}

export async function importExternalModule(modulePath: string, reloadSeq: number): Promise<ExternalModuleExports> {
  const url = `${pathToFileURL(modulePath).href}?v=${reloadSeq}-${Date.now()}`;
  const mod = (await import(url)) as Record<string, unknown>;
  const defaultObj = isRecord(mod.default) ? mod.default : undefined;
  const setup = typeof mod.setup === 'function'
    ? (mod.setup as ExternalModuleExports['setup'])
    : typeof defaultObj?.setup === 'function'
      ? (defaultObj.setup as ExternalModuleExports['setup'])
      : undefined;
  const analyze = typeof mod.analyze === 'function'
    ? (mod.analyze as ExternalModuleExports['analyze'])
    : typeof defaultObj?.analyze === 'function'
      ? (defaultObj.analyze as ExternalModuleExports['analyze'])
      : undefined;
  const exportSession = typeof mod.exportSession === 'function'
    ? (mod.exportSession as ExternalModuleExports['exportSession'])
    : typeof defaultObj?.exportSession === 'function'
      ? (defaultObj.exportSession as ExternalModuleExports['exportSession'])
      : undefined;
  return { setup, analyze, exportSession };
}

export function normalizeAnalyzerOutput(
  raw: unknown,
  pluginId: string,
  analyzerId: string,
): AnalyzerOutput {
  if (!isRecord(raw)) {
    throw new Error(`analyzer ${analyzerId} returned non-object result`);
  }
  const insights: AnalyzerInsight[] = [];
  if (Array.isArray(raw.insights)) {
    for (const item of raw.insights) {
      if (!isRecord(item) || typeof item.title !== 'string') {
        continue;
      }
      const sev = typeof item.severity === 'string' && VALID_SEVERITIES.has(item.severity)
        ? (item.severity as AnalyzerInsight['severity'])
        : 'info';
      const normalizedIds = Array.isArray(item.sample_ids)
        ? item.sample_ids.map((id) => normalizeU64String(id))
        : undefined;
      insights.push({
        ...item,
        plugin_id: pluginId,
        analyzer_id: analyzerId,
        title: item.title,
        severity: sev,
        ...(normalizedIds ? { sample_ids: normalizedIds } : {}),
      });
    }
  }

  const kpis: AnalyzerKpi[] = [];
  if (Array.isArray(raw.kpis)) {
    for (const item of raw.kpis) {
      if (!isRecord(item) || typeof item.label !== 'string') {
        continue;
      }
      const tone = typeof item.tone === 'string' && VALID_TONES.has(item.tone)
        ? (item.tone as AnalyzerKpi['tone'])
        : 'default';
      const val = typeof item.value === 'bigint'
        ? item.value.toString(10)
        : typeof item.value === 'string' || typeof item.value === 'number'
          ? item.value
          : String(item.value ?? '');
      kpis.push({
        ...item,
        plugin_id: pluginId,
        analyzer_id: analyzerId,
        label: item.label,
        value: val,
        tone,
      });
    }
  }

  const notes: string[] = Array.isArray(raw.notes)
    ? raw.notes.filter((n): n is string => typeof n === 'string')
    : [];

  return { insights, kpis, notes };
}

export function normalizeExporterOutput(raw: unknown, fallbackOutPath: string): ExporterOutput {
  if (!isRecord(raw)) {
    throw new Error('exporter returned non-object result');
  }
  return {
    ok: raw.ok !== false,
    out_path: typeof raw.out_path === 'string' && raw.out_path ? raw.out_path : fallbackOutPath,
    is_directory: typeof raw.is_directory === 'boolean' ? raw.is_directory : undefined,
    summary: typeof raw.summary === 'string' ? raw.summary : '',
    details: isRecord(raw.details) ? raw.details : undefined,
    error: typeof raw.error === 'string' ? raw.error : undefined,
  };
}
