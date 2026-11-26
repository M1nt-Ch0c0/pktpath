import fs from 'node:fs';
import path from 'node:path';

const PLUGIN_STATE_FILE = '.plugins_state.json';

export interface PluginSockField {
  struct: string;
  field: string;
  size: number;
  role: string;
  label: string;
  summary: string;
}

export interface PluginQdisc {
  id: string;
  name: string;
  kind: string;
  mode: 'classful' | 'leaf';
  enqueue_sym: string;
  dequeue_sym?: string;
  summary: string;
}

export interface PluginDetail {
  id: string;
  file: string;
  name: string;
  version?: string;
  description?: string;
  enabled: boolean;
  sock_fields: number;
  qdiscs: number;
  sock_field_specs: PluginSockField[];
  qdisc_specs: PluginQdisc[];
  capabilities: string[];
  warnings?: string[];
  error?: string;
}

export interface PluginSlots {
  sock_used: number;
  sock_max: number;
  classful_used: number;
  classful_max: number;
  leaf_used: number;
  leaf_max: number;
  enabled_count: number;
  total_count: number;
}

interface PluginStateFile {
  disabled: Record<string, boolean>;
}

export function sanitizePluginFileName(raw: string): string {
  const base = path.basename(raw).replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^[-.]+|[-.]+$/g, '');
  if (!base) return 'plugin.json';
  return base.toLowerCase().endsWith('.json') ? base : `${base}.json`;
}

function readPluginState(pluginsDir: string): PluginStateFile {
  const p = path.join(pluginsDir, PLUGIN_STATE_FILE);
  try {
    const raw = fs.readFileSync(p, 'utf8');
    const parsed = JSON.parse(raw) as Partial<PluginStateFile>;
    if (parsed && typeof parsed.disabled === 'object' && parsed.disabled !== null) {
      return { disabled: { ...parsed.disabled } };
    }
  } catch {
    // missing or invalid state file -> empty
  }
  return { disabled: {} };
}

function writePluginState(pluginsDir: string, st: PluginStateFile): void {
  fs.mkdirSync(pluginsDir, { recursive: true });
  const p = path.join(pluginsDir, PLUGIN_STATE_FILE);
  const tmp = `${p}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify({ disabled: st.disabled ?? {} }, null, 2), 'utf8');
  fs.renameSync(tmp, p);
}

export function parseRuntimePluginManifest(fileName: string, rawText: string, enabled: boolean): PluginDetail {
  const baseFile = path.basename(fileName);
  const baseId = baseFile.replace(/\.[^.]+$/, '');
  const pd: PluginDetail = {
    id: baseId,
    file: baseFile,
    name: baseId,
    enabled,
    sock_fields: 0,
    qdiscs: 0,
    sock_field_specs: [],
    qdisc_specs: [],
    capabilities: [],
  };
  const warnings: string[] = [];

  let doc: Record<string, unknown>;
  try {
    const parsed = JSON.parse(rawText);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      pd.error = 'JSON 解析失败: root must be a JSON object';
      return pd;
    }
    doc = parsed as Record<string, unknown>;
  } catch (err) {
    pd.error = `JSON 解析失败: ${err instanceof Error ? err.message : String(err)}`;
    return pd;
  }

  if (typeof doc.id === 'string' && doc.id.trim()) pd.id = doc.id.trim();
  if (typeof doc.name === 'string' && doc.name.trim()) pd.name = doc.name.trim();
  if (typeof doc.version === 'string' && doc.version.trim()) pd.version = doc.version.trim();
  if (typeof doc.description === 'string' && doc.description.trim()) pd.description = doc.description.trim();

  if (Array.isArray(doc.sock_fields)) {
    for (const item of doc.sock_fields) {
      if (!item || typeof item !== 'object') continue;
      const sf = item as Record<string, unknown>;
      const stName = typeof sf.struct === 'string' && sf.struct.trim() ? sf.struct.trim() : 'sock';
      const fld = typeof sf.field === 'string' ? sf.field.trim() : '';
      if (!fld) {
        warnings.push('存在空的 sock_fields.field，加载时将被跳过');
        continue;
      }
      const sz = Number(sf.size);
      if (sz !== 1 && sz !== 2 && sz !== 4 && sz !== 8) {
        warnings.push(`字段 ${stName}.${fld} 的 size=${sf.size} 非法（仅支持 1/2/4/8）`);
        continue;
      }
      let role = typeof sf.role === 'string' && sf.role.trim() ? sf.role.trim().toLowerCase() : 'tag';
      const lbl = typeof sf.label === 'string' && sf.label.trim() ? sf.label.trim() : fld;
      let summary: string;
      if (role === 'tgid_fallback') {
        summary = `通过内核 BTF 动态读取 struct ${stName}.${fld} (${sz}B)，当标准归属缺失时作为进程 PID/TGID 兜底来源`;
      } else {
        role = 'tag';
        summary = `通过内核 BTF 动态读取 struct ${stName}.${fld} (${sz}B)，为每个样本附加扩展标签 [${lbl}]`;
      }
      pd.sock_field_specs.push({ struct: stName, field: fld, size: sz, role, label: lbl, summary });
      pd.capabilities.push(summary);
    }
  }

  if (Array.isArray(doc.qdiscs)) {
    for (const item of doc.qdiscs) {
      if (!item || typeof item !== 'object') continue;
      const q = item as Record<string, unknown>;
      let id = typeof q.id === 'string' ? q.id.trim() : '';
      let kind = typeof q.kind === 'string' ? q.kind.trim() : '';
      const modeRaw = typeof q.mode === 'string' ? q.mode.trim().toLowerCase() : '';
      const enq = typeof q.enqueue_sym === 'string' ? q.enqueue_sym.trim() : '';
      const deq = typeof q.dequeue_sym === 'string' ? q.dequeue_sym.trim() : '';
      let name = typeof q.name === 'string' ? q.name.trim() : '';
      if (!kind) kind = id;
      if (!id) id = kind;
      if (!name) name = `${kind.toUpperCase()} Custom Qdisc`;
      if (modeRaw !== 'classful' && modeRaw !== 'leaf') {
        warnings.push(`队列 ${id} 的 mode=${JSON.stringify(q.mode ?? '')} 非法（应为 classful 或 leaf）`);
        continue;
      }
      if (!enq) {
        warnings.push(`队列 ${id} 缺少 enqueue_sym`);
        continue;
      }
      if (modeRaw === 'leaf' && !deq) {
        warnings.push(`叶子队列 ${id} 缺少 dequeue_sym（无法计算驻留耗时）`);
        continue;
      }
      const summary = modeRaw === 'classful'
        ? `追踪自定义分层队列 ${kind.toUpperCase()} (classful)：挂钩 ${enq}，记录入队分类路径`
        : `追踪自定义叶子队列 ${kind.toUpperCase()} (leaf)：挂钩 ${enq} / ${deq}，精确测量单包排队驻留耗时`;
      pd.qdisc_specs.push({
        id,
        name,
        kind,
        mode: modeRaw,
        enqueue_sym: enq,
        ...(deq ? { dequeue_sym: deq } : {}),
        summary,
      });
      pd.capabilities.push(summary);
    }
  }

  pd.sock_fields = pd.sock_field_specs.length;
  pd.qdiscs = pd.qdisc_specs.length;
  if (pd.sock_fields === 0 && pd.qdiscs === 0 && !pd.error) {
    warnings.push('该 JSON 未声明任何有效的 sock_fields 或 qdiscs 能力');
  }
  if (warnings.length > 0) pd.warnings = warnings;
  return pd;
}

export function listRuntimePlugins(pluginsDir: string): { plugins: PluginDetail[]; slots: PluginSlots } {
  const st = readPluginState(pluginsDir);
  const plugins: PluginDetail[] = [];
  const slots: PluginSlots = {
    sock_used: 0,
    sock_max: 16,
    classful_used: 0,
    classful_max: 32,
    leaf_used: 0,
    leaf_max: 32,
    enabled_count: 0,
    total_count: 0,
  };

  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(pluginsDir, { withFileTypes: true });
  } catch {
    return { plugins, slots };
  }

  const names = entries
    .filter((e) => !e.isDirectory() && !e.name.startsWith('.') && e.name.toLowerCase().endsWith('.json'))
    .map((e) => e.name)
    .sort((a, b) => a.localeCompare(b));

  for (const name of names) {
    const enabled = !st.disabled[name];
    let pd: PluginDetail;
    try {
      const raw = fs.readFileSync(path.join(pluginsDir, name), 'utf8');
      pd = parseRuntimePluginManifest(name, raw, enabled);
    } catch (err) {
      pd = {
        id: name.replace(/\.[^.]+$/, ''),
        file: name,
        name,
        enabled,
        sock_fields: 0,
        qdiscs: 0,
        sock_field_specs: [],
        qdisc_specs: [],
        capabilities: [],
        error: err instanceof Error ? err.message : String(err),
      };
    }
    slots.total_count += 1;
    if (enabled && !pd.error) {
      slots.enabled_count += 1;
      slots.sock_used += pd.sock_field_specs.length;
      for (const q of pd.qdisc_specs) {
        if (q.mode === 'classful') slots.classful_used += 1;
        else if (q.mode === 'leaf') slots.leaf_used += 1;
      }
    }
    plugins.push(pd);
  }
  return { plugins, slots };
}

export function enabledRuntimePluginPaths(pluginsDir: string): string[] {
  const { plugins } = listRuntimePlugins(pluginsDir);
  return plugins
    .filter((p) => p.enabled && !p.error)
    .map((p) => path.join(pluginsDir, p.file));
}

function readPluginInput(body: Record<string, unknown>): { rawText: string; fileName: string } {
  const rawPath = typeof body.path === 'string' ? body.path.trim() : '';
  const content = typeof body.content === 'string' ? body.content : '';
  let fileName = typeof body.filename === 'string' ? body.filename.trim() : '';

  if (rawPath) {
    let rawText: string;
    try {
      rawText = fs.readFileSync(rawPath, 'utf8');
    } catch (err) {
      throw new Error(`读取插件文件失败: ${err instanceof Error ? err.message : String(err)}`);
    }
    if (!fileName) fileName = path.basename(rawPath);
    return { rawText, fileName };
  }
  if (content) {
    if (!fileName) fileName = 'custom_plugin.json';
    return { rawText: content, fileName };
  }
  throw new Error('missing path or content');
}

export function previewRuntimePlugin(pluginsDir: string, body: Record<string, unknown>): {
  ok: boolean;
  plugin: PluginDetail;
  slots: PluginSlots;
  error?: string;
} {
  const { rawText, fileName } = readPluginInput(body);
  const pd = parseRuntimePluginManifest(fileName, rawText, true);
  const { slots } = listRuntimePlugins(pluginsDir);
  const warnings = [...(pd.warnings ?? [])];

  if (slots.sock_used + pd.sock_field_specs.length > slots.sock_max) {
    warnings.push(`导入后 Socket 字段槽位将超出上限 (${slots.sock_used}+${pd.sock_field_specs.length} > ${slots.sock_max})`);
  }
  let clsAdd = 0;
  let leafAdd = 0;
  for (const q of pd.qdisc_specs) {
    if (q.mode === 'classful') clsAdd += 1;
    else leafAdd += 1;
  }
  if (slots.classful_used + clsAdd > slots.classful_max) {
    warnings.push(`导入后 Classful 队列槽位将超出上限 (${slots.classful_used}+${clsAdd} > ${slots.classful_max})`);
  }
  if (slots.leaf_used + leafAdd > slots.leaf_max) {
    warnings.push(`导入后 Leaf 队列槽位将超出上限 (${slots.leaf_used}+${leafAdd} > ${slots.leaf_max})`);
  }
  if (warnings.length > 0) pd.warnings = warnings;

  return {
    ok: !pd.error,
    plugin: pd,
    slots,
    ...(pd.error ? { error: pd.error } : {}),
  };
}

export function importRuntimePlugin(pluginsDir: string, body: Record<string, unknown>): {
  ok: true;
  imported: PluginDetail;
  plugins_dir: string;
  plugins: PluginDetail[];
  slots: PluginSlots;
} {
  const { rawText, fileName } = readPluginInput(body);
  const safeName = sanitizePluginFileName(fileName);
  const pd = parseRuntimePluginManifest(safeName, rawText, true);
  if (pd.error) {
    throw new Error(pd.error);
  }
  fs.mkdirSync(pluginsDir, { recursive: true });
  fs.writeFileSync(path.join(pluginsDir, safeName), rawText, 'utf8');
  const st = readPluginState(pluginsDir);
  delete st.disabled[safeName];
  writePluginState(pluginsDir, st);

  const { plugins, slots } = listRuntimePlugins(pluginsDir);
  return {
    ok: true,
    imported: pd,
    plugins_dir: pluginsDir,
    plugins,
    slots,
  };
}

export function toggleRuntimePlugin(pluginsDir: string, body: Record<string, unknown>): {
  ok: true;
  file: string;
  enabled: boolean;
  plugins: PluginDetail[];
  slots: PluginSlots;
} {
  const rawFile = typeof body.file === 'string' ? body.file.trim() : '';
  const file = path.basename(rawFile);
  if (!file || file === '.' || file === '..' || !file.toLowerCase().endsWith('.json')) {
    throw new Error('invalid plugin file');
  }
  if (!fs.existsSync(path.join(pluginsDir, file))) {
    const err = new Error(`plugin not found: ${file}`) as Error & { statusCode?: number };
    err.statusCode = 404;
    throw err;
  }
  const enabled = Boolean(body.enabled);
  const st = readPluginState(pluginsDir);
  if (enabled) delete st.disabled[file];
  else st.disabled[file] = true;
  writePluginState(pluginsDir, st);

  const { plugins, slots } = listRuntimePlugins(pluginsDir);
  return { ok: true, file, enabled, plugins, slots };
}

export function deleteRuntimePlugin(pluginsDir: string, body: Record<string, unknown>): {
  ok: true;
  deleted: string;
  plugins: PluginDetail[];
  slots: PluginSlots;
} {
  const rawFile = typeof body.file === 'string' ? body.file.trim() : '';
  const file = path.basename(rawFile);
  if (!file || file === '.' || file === '..' || !file.toLowerCase().endsWith('.json')) {
    throw new Error('invalid plugin file');
  }
  fs.rmSync(path.join(pluginsDir, file), { force: true });
  const st = readPluginState(pluginsDir);
  delete st.disabled[file];
  writePluginState(pluginsDir, st);

  const { plugins, slots } = listRuntimePlugins(pluginsDir);
  return { ok: true, deleted: file, plugins, slots };
}
