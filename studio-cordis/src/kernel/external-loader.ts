import crypto from 'node:crypto';
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
  KernelProbeArch,
  KernelProbeHookDecl,
  KernelProbeHookType,
  KernelProbeObjectDecl,
  KernelProbesManifest,
  PluginMeta,
} from './types.ts';
import { normalizeU64String } from './u64-json.ts';
import {
  createZipFromDir,
  signPluginPackageDir,
  verifyPluginPackageSignature,
  type PluginSignatureStatus,
  type PluginSignatureTrust,
} from './plugin-signature.ts';
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
  kernel_probes?: KernelProbesManifest;
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
const MAX_BPF_OBJECT_BYTES = 2 * 1024 * 1024;
const SHA256_HEX_RE = /^[a-f0-9]{64}$/;
const VALID_BPF_ARCHES = new Set<KernelProbeArch>(['arm64', 'x86_64']);
const VALID_HOOK_TYPES = new Set<KernelProbeHookType>([
  'tracepoint',
  'fentry',
  'fexit',
  'kprobe',
  'kretprobe',
  'raw_tp',
]);

export function computeFileSha256(filePath: string): string {
  const buf = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(buf).digest('hex');
}

export function validateBpfObjectFile(filePath: string, declaredSha256: string, label = 'bpf object'): string {
  if (!SHA256_HEX_RE.test(declaredSha256)) {
    throw new Error(`invalid ${label} sha256 (must be 64 lowercase hex chars)`);
  }
  const st = fs.statSync(filePath);
  if (!st.isFile()) {
    throw new Error(`${label} is not a regular file: ${filePath}`);
  }
  if (st.size < 64) {
    throw new Error(`${label} too small to be a valid ELF64 object (${st.size} bytes)`);
  }
  if (st.size > MAX_BPF_OBJECT_BYTES) {
    throw new Error(`${label} exceeds 2 MiB limit (${st.size} bytes)`);
  }
  const buf = fs.readFileSync(filePath);
  if (buf[0] !== 0x7f || buf[1] !== 0x45 || buf[2] !== 0x4c || buf[3] !== 0x46) {
    throw new Error(`${label} is not an ELF file (bad magic)`);
  }
  if (buf[4] !== 2) {
    throw new Error(`${label} must be ELF64 (EI_CLASS=2), got ${buf[4]}`);
  }
  if (buf[5] !== 1) {
    throw new Error(`${label} must be little-endian (EI_DATA=1), got ${buf[5]}`);
  }
  const eMachine = buf.readUInt16LE(18);
  if (eMachine !== 247) {
    throw new Error(`${label} must be EM_BPF (247), got e_machine=${eMachine}`);
  }
  const actual = crypto.createHash('sha256').update(buf).digest('hex');
  if (actual !== declaredSha256) {
    throw new Error(`${label} sha256 mismatch: expected ${declaredSha256}, got ${actual}`);
  }
  return actual;
}

function parseKernelProbes(rawProbes: unknown, pluginDir: string): KernelProbesManifest {
  if (!isRecord(rawProbes)) {
    throw new Error('manifest.json "kernel_probes" must be an object');
  }
  if (rawProbes.abi_version !== 1) {
    throw new Error(`unsupported kernel_probes.abi_version: ${String(rawProbes.abi_version)} (expected 1)`);
  }
  if (!isRecord(rawProbes.objects)) {
    throw new Error('kernel_probes.objects must be an object');
  }
  const objects: Partial<Record<KernelProbeArch, KernelProbeObjectDecl>> = {};
  const objKeys = Object.keys(rawProbes.objects);
  if (objKeys.length === 0) {
    throw new Error('kernel_probes.objects must declare at least one arch (arm64 or x86_64)');
  }
  for (const archKey of objKeys) {
    if (!VALID_BPF_ARCHES.has(archKey as KernelProbeArch)) {
      throw new Error(`unsupported kernel_probes.objects arch: "${archKey}" (allowed: arm64, x86_64)`);
    }
    const decl = rawProbes.objects[archKey];
    if (!isRecord(decl)) {
      throw new Error(`kernel_probes.objects.${archKey} must be an object`);
    }
    const objRel = typeof decl.path === 'string' ? decl.path.trim() : '';
    if (!objRel || !objRel.endsWith('.o')) {
      throw new Error(`kernel_probes.objects.${archKey}.path must be a relative .o path`);
    }
    const sha256 = typeof decl.sha256 === 'string' ? decl.sha256.trim() : '';
    const resolvedObj = assertInsideRoot(pluginDir, objRel, `kernel_probes.objects.${archKey}`);
    validateBpfObjectFile(resolvedObj, sha256, `kernel_probes.objects.${archKey}`);
    objects[archKey as KernelProbeArch] = { path: objRel, sha256 };
  }
  if (!Array.isArray(rawProbes.hooks) || rawProbes.hooks.length === 0 || rawProbes.hooks.length > 32) {
    throw new Error('kernel_probes.hooks must be an array with 1..32 items');
  }
  const seenHookIds = new Set<string>();
  const hooks: KernelProbeHookDecl[] = [];
  for (const h of rawProbes.hooks) {
    if (!isRecord(h)) {
      throw new Error('each kernel_probes.hooks entry must be an object');
    }
    const hookId = typeof h.id === 'string' ? h.id.trim() : '';
    const group = typeof h.group === 'string' ? h.group.trim() : '';
    const sec = typeof h.sec === 'string' ? h.sec.trim() : '';
    const target = typeof h.target === 'string' ? h.target.trim() : '';
    const hookType = typeof h.type === 'string' ? h.type.trim() : '';
    if (!hookId || !group || !sec || !target) {
      throw new Error('kernel_probes.hooks entry requires non-empty id, group, sec, and target');
    }
    if (!VALID_HOOK_TYPES.has(hookType as KernelProbeHookType)) {
      throw new Error(`invalid kernel_probes.hooks type: "${hookType}"`);
    }
    if (seenHookIds.has(hookId)) {
      throw new Error(`duplicate kernel_probes.hooks id: "${hookId}"`);
    }
    seenHookIds.add(hookId);
    const stage = typeof h.stage === 'string' && h.stage.trim() ? h.stage.trim() : undefined;
    hooks.push({
      id: hookId,
      group,
      sec,
      type: hookType as KernelProbeHookType,
      target,
      ...(stage ? { stage } : {}),
    });
  }
  return { abi_version: 1, objects, hooks };
}

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

  const hasKernelProbesDecl = raw.kernel_probes !== undefined && raw.kernel_probes !== null;
  let modRel = '';
  let modulePath = '';
  if (raw.entrypoint !== undefined && raw.entrypoint !== null) {
    const entrypoint = raw.entrypoint;
    if (!isRecord(entrypoint)) {
      throw new Error('manifest.json requires "entrypoint" object');
    }
    if ('command' in entrypoint && entrypoint.command !== undefined && entrypoint.command !== null) {
      throw new Error('legacy entrypoint.command is forbidden in Wave 1 pure Cordis host; use entrypoint.module');
    }
    modRel = typeof entrypoint.module === 'string' ? entrypoint.module.trim() : '';
    if (!modRel) {
      throw new Error('manifest.json requires "entrypoint.module"');
    }
    if (!/\.(mjs|js|ts)$/.test(modRel)) {
      throw new Error(`entrypoint.module must end with .mjs, .js, or .ts: ${modRel}`);
    }
    modulePath = assertInsideRoot(pluginDir, modRel, 'entrypoint.module');
  } else if (!hasKernelProbesDecl) {
    throw new Error('manifest.json requires "entrypoint" object');
  }

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
    ? {
        fields: raw.schema.fields as ConfigSchema['fields'],
        ...(Array.isArray(raw.schema.presets) ? { presets: raw.schema.presets as ConfigSchema['presets'] } : {}),
        ...(Array.isArray(raw.schema.groups) ? { groups: raw.schema.groups as ConfigSchema['groups'] } : {}),
      }
    : { fields: [] };

  const kernelProbes = raw.kernel_probes !== undefined
    ? parseKernelProbes(raw.kernel_probes, pluginDir)
    : undefined;

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
    ...(kernelProbes ? { kernel_probes: kernelProbes } : {}),
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

export function previewExternalPackage(
  sourcePath: string,
  opts?: { trustedFingerprints?: readonly string[] },
): {
  id: string;
  name: string;
  version: string;
  author?: string;
  description: string;
  capabilities: string[];
  analyzers: ExternalAnalyzerDecl[];
  exporters: ExternalExporterDecl[];
  entrypoint_module: string;
  has_kernel_bpf: boolean;
  kernel_bpf_objects: Array<{ arch: string; path: string; sha256: string }>;
  signature_status: PluginSignatureStatus;
  signature_trust: PluginSignatureTrust;
  signature_key_fingerprint?: string;
  signature_message: string;
  signature_reason?: string;
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
    const sig = verifyPluginPackageSignature(pkgRoot, opts?.trustedFingerprints);
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
      has_kernel_bpf: Boolean(parsed.manifest.kernel_probes),
      kernel_bpf_objects: parsed.manifest.kernel_probes
        ? Object.entries(parsed.manifest.kernel_probes.objects)
            .filter(([, v]) => Boolean(v))
            .map(([arch, v]) => ({ arch, path: v!.path, sha256: v!.sha256 }))
        : [],
      signature_status: sig.status,
      signature_trust: sig.trust,
      ...(sig.key_fingerprint ? { signature_key_fingerprint: sig.key_fingerprint } : {}),
      signature_message: sig.message,
      ...(sig.reason ? { signature_reason: sig.reason } : {}),
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
    const sig = verifyPluginPackageSignature(pkgRoot);
    if (sig.status === 'invalid') {
      throw new Error(`plugin signature invalid: ${sig.reason ?? sig.message}`);
    }
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


export function exportExternalPackageZip(
  pluginDir: string,
  outZipPath: string,
  opts?: { signPrivateKeyPem?: string },
): {
  outPath: string;
  pluginId: string;
  version: string;
  signed: boolean;
  keyFingerprint?: string;
  fileCount: number;
  bytes: number;
} {
  const parsed = parseExternalPluginDir(pluginDir);
  const staging = fs.mkdtempSync(path.join(os.tmpdir(), 'pktpath-export-pkg-'));
  try {
    copyDirRecursive(pluginDir, staging);
    let signed = false;
    let keyFingerprint: string | undefined;
    if (opts?.signPrivateKeyPem) {
      const doc = signPluginPackageDir(staging, opts.signPrivateKeyPem);
      signed = true;
      keyFingerprint = doc.key_fingerprint;
    } else {
      const existingSig = verifyPluginPackageSignature(staging);
      if (existingSig.status === 'invalid') {
        throw new Error(`cannot export plugin with invalid signature: ${existingSig.reason ?? existingSig.message}`);
      }
      if (existingSig.status === 'verified') {
        signed = true;
        keyFingerprint = existingSig.key_fingerprint;
      }
    }
    const resolvedOut = path.resolve(outZipPath);
    const { fileCount, bytes } = createZipFromDir(staging, resolvedOut);
    return {
      outPath: resolvedOut,
      pluginId: parsed.manifest.id,
      version: parsed.manifest.version,
      signed,
      ...(keyFingerprint ? { keyFingerprint } : {}),
      fileCount,
      bytes,
    };
  } finally {
    fs.rmSync(staging, { recursive: true, force: true });
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
  if (!modulePath) return {};
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
