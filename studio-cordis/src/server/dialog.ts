import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

export interface DialogResult {
  ok: boolean;
  cancelled?: boolean;
  unsupported?: boolean;
  path?: string;
  error?: string;
}

function runPowerShell(script: string): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-STA', '-Command', script],
      { timeout: 120_000, windowsHide: true },
      (err, stdout, stderr) => {
        if (err) {
          reject(new Error(String(stderr || err.message).trim()));
          return;
        }
        resolve(String(stdout ?? '').trim());
      },
    );
  });
}

export async function handleDialogAction(
  action: 'pick-folder' | 'save-file' | 'open-file' | 'reveal',
  body: Record<string, unknown>,
): Promise<DialogResult> {
  if (process.platform !== 'win32') {
    return {
      ok: false,
      unsupported: true,
      error: `native dialog "${action}" is only available on Windows; please enter the path manually`,
    };
  }

  try {
    if (action === 'pick-folder') {
      const ps = [
        'Add-Type -AssemblyName System.Windows.Forms',
        '$d = New-Object System.Windows.Forms.FolderBrowserDialog',
        'if ($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { Write-Output $d.SelectedPath }',
      ].join('; ');
      const selected = await runPowerShell(ps);
      return selected ? { ok: true, cancelled: false, path: selected } : { ok: true, cancelled: true };
    }

    if (action === 'open-file') {
      const ps = [
        'Add-Type -AssemblyName System.Windows.Forms',
        '$d = New-Object System.Windows.Forms.OpenFileDialog',
        'if ($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { Write-Output $d.FileName }',
      ].join('; ');
      const selected = await runPowerShell(ps);
      return selected ? { ok: true, cancelled: false, path: selected } : { ok: true, cancelled: true };
    }

    if (action === 'save-file') {
      const defaultName = typeof body.default_name === 'string'
        ? body.default_name.replace(/[^a-zA-Z0-9._-]/g, '_')
        : 'report.csv';
      const ps = [
        'Add-Type -AssemblyName System.Windows.Forms',
        '$d = New-Object System.Windows.Forms.SaveFileDialog',
        `$d.FileName = '${defaultName}'`,
        'if ($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { Write-Output $d.FileName }',
      ].join('; ');
      const selected = await runPowerShell(ps);
      return selected ? { ok: true, cancelled: false, path: selected } : { ok: true, cancelled: true };
    }

    // reveal
    const target = typeof body.path === 'string' ? path.resolve(body.path) : '';
    if (!target || !fs.existsSync(target)) {
      return { ok: false, error: 'path does not exist' };
    }
    execFile('explorer.exe', [`/select,${target}`], { windowsHide: true }, () => {});
    return { ok: true, path: target };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}
