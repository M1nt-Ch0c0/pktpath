import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

export interface DialogResult {
  ok: boolean;
  cancelled?: boolean;
  unsupported?: boolean;
  path?: string;
  error?: string;
  httpStatus?: number;
}

export interface DialogHooks {
  platform?: NodeJS.Platform;
  runPowerShell?: (script: string, extraEnv: NodeJS.ProcessEnv) => Promise<string>;
  revealExplorer?: (args: string[]) => void;
  statPath?: (abs: string) => { exists: boolean; isDirectory: boolean };
  resolvePath?: (input: string) => string;
  env?: NodeJS.ProcessEnv;
}

const DEFAULT_OPEN_FILTER = 'PktPath Plugin (*.json)|*.json|All Files (*.*)|*.*';
const DEFAULT_SAVE_FILTER = 'Wireshark Capture (*.pcapng)|*.pcapng|All Files (*.*)|*.*';
const DEFAULT_OPEN_TITLE = '选择文件 - PktPath Studio';
const DEFAULT_SAVE_TITLE = '导出保存位置 - PktPath Studio';
const DEFAULT_FOLDER_TITLE = '选择 PktPath 会话文件夹';
const UTF8_NOBOM = '[System.Text.UTF8Encoding]::new($false)';

export function escapePwshSingleQuoted(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

export function sanitizeSaveFileName(name: string): string {
  const base = path.win32.basename(name).trim();
  if (base === '.' || base === '..' || base === '/' || base === '\\') return '';
  let out = '';
  for (const ch of base) {
    if ('<>:"/\\|?*'.includes(ch)) {
      out += '_';
    } else if (ch.charCodeAt(0) >= 32) {
      out += ch;
    }
  }
  return out.trim();
}

function bodyStr(body: Record<string, unknown>, key: string): string {
  const v = body[key];
  return typeof v === 'string' ? v : '';
}

function defaultStatPath(abs: string): { exists: boolean; isDirectory: boolean } {
  try {
    const st = fs.statSync(abs);
    return { exists: true, isDirectory: st.isDirectory() };
  } catch {
    return { exists: false, isDirectory: false };
  }
}

function defaultRunPowerShell(script: string, extraEnv: NodeJS.ProcessEnv): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-STA', '-Command', script],
      {
        timeout: 120_000,
        windowsHide: true,
        encoding: 'utf8',
        env: { ...process.env, ...extraEnv },
      },
      (err, stdout, stderr) => {
        if (err) {
          reject(new Error(String(stderr || err.message).trim()));
          return;
        }
        resolve(String(stdout ?? '').replace(/^\uFEFF/, ''));
      },
    );
  });
}

function defaultRevealExplorer(args: string[]): void {
  // Intentionally do not hide the process, matching Go revealPathNative
  // so Explorer comes to the foreground.
  execFile('explorer.exe', args, { windowsHide: false }, () => {});
}

function resolveHooks(hooks?: DialogHooks): Required<DialogHooks> {
  return {
    platform: hooks?.platform ?? process.platform,
    runPowerShell: hooks?.runPowerShell ?? defaultRunPowerShell,
    revealExplorer: hooks?.revealExplorer ?? defaultRevealExplorer,
    statPath: hooks?.statPath ?? defaultStatPath,
    resolvePath: hooks?.resolvePath ?? ((input: string) => path.resolve(input)),
    env: hooks?.env ?? process.env,
  };
}

function encodingPreamble(): string {
  return [
    `[Console]::OutputEncoding = ${UTF8_NOBOM}`,
    `[Console]::InputEncoding = ${UTF8_NOBOM}`,
    `$OutputEncoding = ${UTF8_NOBOM}`,
    'Add-Type -AssemblyName System.Windows.Forms',
    '[System.Windows.Forms.Application]::EnableVisualStyles()',
  ].join('\n');
}

function ownerFormBlock(): string {
  return [
    '$owner = New-Object System.Windows.Forms.Form',
    '$owner.TopMost = $true',
    '$owner.ShowInTaskbar = $false',
    '$owner.Width = 1',
    '$owner.Height = 1',
    '$owner.StartPosition = \'CenterScreen\'',
    '$owner.Opacity = 0',
    '$owner.Show()',
  ].join('\n');
}

function ownerDisposeAndEmit(): string {
  return [
    '$res = $dlg.ShowDialog($owner)',
    '$owner.Dispose()',
    'if ($res -eq [System.Windows.Forms.DialogResult]::OK) {',
    '  $chosen = $dlg.SelectedPath',
    '  if (-not $chosen) { $chosen = $dlg.FileName }',
    '  if ($chosen) { Write-Output ("@@path=" + $chosen) } else { Write-Output "@@cancelled=1" }',
    '} else {',
    '  Write-Output "@@cancelled=1"',
    '}',
  ].join('\n');
}

function resolvedExistingDir(
  raw: string,
  hooks: Required<DialogHooks>,
): string {
  const trimmed = raw.trim();
  if (!trimmed) return '';
  const abs = hooks.resolvePath(trimmed);
  const st = hooks.statPath(abs);
  if (st.exists && st.isDirectory) return abs;
  return '';
}

function defaultSaveInitialDir(hooks: Required<DialogHooks>): string {
  const up = hooks.env.USERPROFILE || hooks.env.HOME || '';
  if (!up) return '';
  const downloads = path.join(up, 'Downloads');
  const dlStat = hooks.statPath(hooks.resolvePath(downloads));
  if (dlStat.exists && dlStat.isDirectory) return hooks.resolvePath(downloads);
  const upStat = hooks.statPath(hooks.resolvePath(up));
  if (upStat.exists && upStat.isDirectory) return hooks.resolvePath(up);
  return '';
}

export function buildDialogScript(
  action: 'pick-folder' | 'save-file' | 'open-file',
  params: {
    title: string;
    initialDir: string;
    filter: string;
    fileName: string;
    defaultExt: string;
  },
): string {
  const lines = [encodingPreamble(), ownerFormBlock()];
  if (action === 'pick-folder') {
    lines.push('$dlg = New-Object System.Windows.Forms.FolderBrowserDialog');
    lines.push(`$dlg.Description = ${escapePwshSingleQuoted(params.title || DEFAULT_FOLDER_TITLE)}`);
    lines.push('$dlg.UseDescriptionForTitle = $true');
    lines.push('$dlg.ShowNewFolderButton = $true');
    if (params.initialDir) {
      lines.push(`$init = ${escapePwshSingleQuoted(params.initialDir)}`);
      lines.push('if ($init -and (Test-Path -LiteralPath $init -PathType Container)) { $dlg.SelectedPath = $init }');
    }
  } else if (action === 'open-file') {
    lines.push('$dlg = New-Object System.Windows.Forms.OpenFileDialog');
    lines.push(`$dlg.Title = ${escapePwshSingleQuoted(params.title || DEFAULT_OPEN_TITLE)}`);
    lines.push(`$dlg.Filter = ${escapePwshSingleQuoted(params.filter || DEFAULT_OPEN_FILTER)}`);
    lines.push('$dlg.Multiselect = $false');
    lines.push('$dlg.CheckFileExists = $true');
    if (params.initialDir) {
      lines.push(`$dlg.InitialDirectory = ${escapePwshSingleQuoted(params.initialDir)}`);
    }
  } else {
    lines.push('$dlg = New-Object System.Windows.Forms.SaveFileDialog');
    lines.push(`$dlg.Title = ${escapePwshSingleQuoted(params.title || DEFAULT_SAVE_TITLE)}`);
    lines.push(`$dlg.Filter = ${escapePwshSingleQuoted(params.filter || DEFAULT_SAVE_FILTER)}`);
    lines.push('$dlg.OverwritePrompt = $true');
    lines.push('$dlg.AddExtension = $true');
    if (params.fileName) {
      lines.push(`$dlg.FileName = ${escapePwshSingleQuoted(params.fileName)}`);
    }
    if (params.defaultExt) {
      lines.push(`$dlg.DefaultExt = ${escapePwshSingleQuoted(params.defaultExt)}`);
    }
    if (params.initialDir) {
      lines.push(`$dlg.InitialDirectory = ${escapePwshSingleQuoted(params.initialDir)}`);
    }
  }
  lines.push(ownerDisposeAndEmit());
  return lines.join('\n');
}

function parseDialogOutput(stdout: string): DialogResult {
  const lines = stdout.replace(/\r\n/g, '\n').split('\n');
  for (const raw of lines) {
    const ln = raw.trim();
    if (ln.startsWith('@@path=')) {
      const chosen = ln.slice('@@path='.length).trim();
      if (chosen) {
        return { ok: true, cancelled: false, path: chosen, httpStatus: 200 };
      }
    }
    if (ln === '@@cancelled=1') {
      return { ok: false, cancelled: true, path: '', httpStatus: 200 };
    }
  }
  return { ok: false, cancelled: true, path: '', httpStatus: 200 };
}

function unsupported(action: string): DialogResult {
  return {
    ok: false,
    unsupported: true,
    error: `native dialog "${action}" is only available on Windows; please enter the path manually`,
    httpStatus: 501,
  };
}

export async function handleDialogAction(
  action: 'pick-folder' | 'save-file' | 'open-file' | 'reveal',
  body: Record<string, unknown>,
  hooks?: DialogHooks,
): Promise<DialogResult> {
  const h = resolveHooks(hooks);
  if (h.platform !== 'win32') {
    return unsupported(action);
  }

  try {
    if (action === 'reveal') {
      const rawPath = bodyStr(body, 'path');
      if (!rawPath) {
        return { ok: false, error: 'missing path', httpStatus: 400 };
      }
      let abs: string;
      try {
        abs = h.resolvePath(rawPath);
      } catch (err) {
        return { ok: false, error: `invalid path: ${err instanceof Error ? err.message : String(err)}`, httpStatus: 400 };
      }
      const st = h.statPath(abs);
      if (!st.exists) {
        return { ok: false, error: `path does not exist: ${abs}`, httpStatus: 404 };
      }
      if (st.isDirectory) {
        h.revealExplorer([abs]);
      } else {
        h.revealExplorer([`/select,"${abs}"`]);
      }
      return { ok: true, path: abs, httpStatus: 200 };
    }

    const titleRaw = bodyStr(body, 'title');
    const filterRaw = bodyStr(body, 'filter');
    const initialRaw = bodyStr(body, 'initial_dir');
    let initialDir = resolvedExistingDir(initialRaw, h);
    let title = titleRaw;
    let filter = filterRaw;
    let fileName = '';
    let defaultExt = '';

    if (action === 'pick-folder') {
      title = titleRaw || DEFAULT_FOLDER_TITLE;
    } else if (action === 'open-file') {
      title = titleRaw || DEFAULT_OPEN_TITLE;
      filter = filterRaw || DEFAULT_OPEN_FILTER;
    } else {
      title = titleRaw || DEFAULT_SAVE_TITLE;
      filter = filterRaw || DEFAULT_SAVE_FILTER;
      if (!initialDir && !initialRaw.trim()) {
        initialDir = defaultSaveInitialDir(h);
      }
      fileName = sanitizeSaveFileName(bodyStr(body, 'default_name'));
      defaultExt = path.extname(fileName).replace(/^\./, '');
      if (!defaultExt) defaultExt = 'pcapng';
    }

    const script = buildDialogScript(action, { title, initialDir, filter, fileName, defaultExt });
    const extraEnv: NodeJS.ProcessEnv = {};
    if (initialDir) extraEnv.PKTPATH_INIT_DIR = initialDir;
    const stdout = await h.runPowerShell(script, extraEnv);
    return parseDialogOutput(stdout);
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err), httpStatus: 500 };
  }
}
