import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { CordisHost } from '../src/kernel/host.ts';
import { registerWave1Builtins } from '../src/plugins/register.ts';
import {
  buildDialogScript,
  escapePwshSingleQuoted,
  handleDialogAction,
  sanitizeSaveFileName,
} from '../src/server/dialog.ts';
import { startStudioApp } from '../src/server/app.ts';

describe('Y-AUDIT-03 Windows native dialogs + P2-13 non-Windows 501', () => {
  it('escapes PowerShell single quotes and sanitizes save-file names like Go', () => {
    assert.equal(escapePwshSingleQuoted("C:\\Users\\O'Brien\\文档"), "'C:\\Users\\O''Brien\\文档'");
    assert.equal(sanitizeSaveFileName('  report<>:"|?*.pcapng  '), 'report_______.pcapng');
    assert.equal(sanitizeSaveFileName('/tmp/../.'), '');
    assert.equal(sanitizeSaveFileName('C:\\Users\\demo\\会话:非法*.pcapng'), '会话_非法_.pcapng');
    assert.equal(sanitizeSaveFileName('会话-导出.pcapng'), '会话-导出.pcapng');
  });

  it('PowerShell scripts include UTF-8 no-BOM encoding, TopMost owner Form, and escaped params', () => {
    const initialDir = "C:\\Users\\张三\\桌面\\O'Brien 会话";
    const filter = "PktPath Plugin (*.json)|*.json|自定义 (*.zip)|*.zip";
    const title = "选择插件 zip — O'Brien";
    const script = buildDialogScript('open-file', {
      title,
      initialDir,
      filter,
      fileName: '',
      defaultExt: '',
    });
    assert.match(script, /\[Console\]::OutputEncoding = \[System\.Text\.UTF8Encoding\]::new\(\$false\)/);
    assert.match(script, /\[Console\]::InputEncoding = \[System\.Text\.UTF8Encoding\]::new\(\$false\)/);
    assert.match(script, /\$owner\.TopMost = \$true/);
    assert.match(script, /\$res = \$dlg\.ShowDialog\(\$owner\)/);
    assert.match(script, /\$owner\.Dispose\(\)/);
    assert.ok(script.includes(escapePwshSingleQuoted(initialDir)));
    assert.ok(script.includes(escapePwshSingleQuoted(filter)));
    assert.ok(script.includes(escapePwshSingleQuoted(title)));

    const folder = buildDialogScript('pick-folder', {
      title: '选择 PktPath 会话文件夹',
      initialDir,
      filter: '',
      fileName: '',
      defaultExt: '',
    });
    assert.match(folder, /FolderBrowserDialog/);
    assert.match(folder, /\[Console\]::OutputEncoding = \[System\.Text\.UTF8Encoding\]::new\(\$false\)/);
    assert.match(folder, /\$owner\.TopMost = \$true/);
  });

  it('cancel returns { ok:false, cancelled:true, path:"" } and selected Chinese paths are preserved', async () => {
    const cancelled = await handleDialogAction('pick-folder', { initial_dir: 'C:\\Users\\演示' }, {
      platform: 'win32',
      statPath: () => ({ exists: false, isDirectory: false }),
      runPowerShell: async (script) => {
        assert.match(script, /UTF8Encoding\]::new\(\$false\)/);
        return '@@cancelled=1\n';
      },
    });
    assert.deepEqual(cancelled, { ok: false, cancelled: true, path: '', httpStatus: 200 });

    const chinese = 'C:\\Users\\张三\\桌面\\会话目录';
    const picked = await handleDialogAction('open-file', {
      title: "打开 O'Brien 的插件",
      initial_dir: chinese,
      filter: 'All Files (*.*)|*.*',
    }, {
      platform: 'win32',
      statPath: (abs) => ({ exists: true, isDirectory: true }),
      resolvePath: (input) => input,
      runPowerShell: async (script, env) => {
        assert.ok(script.includes(escapePwshSingleQuoted(chinese)));
        assert.ok(script.includes(escapePwshSingleQuoted("打开 O'Brien 的插件")));
        assert.equal(env.PKTPATH_INIT_DIR, chinese);
        return `@@path=${chinese}\n`;
      },
    });
    assert.deepEqual(picked, { ok: true, cancelled: false, path: chinese, httpStatus: 200 });
  });

  it('initial_dir that is missing or a file is not passed through', async () => {
    let script = '';
    await handleDialogAction('save-file', {
      default_name: 'trace.pcapng',
      initial_dir: 'C:\\missing\\path',
    }, {
      platform: 'win32',
      env: {},
      statPath: () => ({ exists: false, isDirectory: false }),
      resolvePath: (input) => input,
      runPowerShell: async (s) => {
        script = s;
        return '@@cancelled=1\n';
      },
    });
    assert.equal(script.includes('C:\\missing\\path'), false);
    assert.match(script, /SaveFileDialog/);
    assert.match(script, /\$dlg\.FileName = 'trace\.pcapng'/);
    assert.match(script, /\$dlg\.DefaultExt = 'pcapng'/);
  });

  it('reveal uses explorer.exe <dir> for directories and /select,"file" for files', async () => {
    const calls: string[][] = [];
    const dir = await handleDialogAction('reveal', { path: 'C:\\Users\\张三\\会话' }, {
      platform: 'win32',
      resolvePath: (input) => input,
      statPath: () => ({ exists: true, isDirectory: true }),
      revealExplorer: (args) => { calls.push(args); },
    });
    assert.deepEqual(dir, { ok: true, path: 'C:\\Users\\张三\\会话', httpStatus: 200 });
    assert.deepEqual(calls[0], ['C:\\Users\\张三\\会话']);

    const file = await handleDialogAction('reveal', { path: 'C:\\Users\\张三\\会话\\manifest.json' }, {
      platform: 'win32',
      resolvePath: (input) => input,
      statPath: () => ({ exists: true, isDirectory: false }),
      revealExplorer: (args) => { calls.push(args); },
    });
    assert.deepEqual(file, { ok: true, path: 'C:\\Users\\张三\\会话\\manifest.json', httpStatus: 200 });
    assert.deepEqual(calls[1], ['/select,"C:\\Users\\张三\\会话\\manifest.json"']);

    const missing = await handleDialogAction('reveal', { path: 'C:\\nope' }, {
      platform: 'win32',
      resolvePath: (input) => input,
      statPath: () => ({ exists: false, isDirectory: false }),
      revealExplorer: (args) => { calls.push(args); },
    });
    assert.equal(missing.httpStatus, 404);
    assert.equal(missing.ok, false);
    assert.equal(calls.length, 2);
  });

  it('non-Windows (P2-13) returns 501 unsupported, matching Go dialog_other.go availability', async () => {
    for (const action of ['pick-folder', 'save-file', 'open-file', 'reveal'] as const) {
      const result = await handleDialogAction(action, { path: '/tmp', initial_dir: '/tmp' }, { platform: 'linux' });
      assert.equal(result.ok, false);
      assert.equal(result.unsupported, true);
      assert.equal(result.httpStatus, 501);
      assert.match(result.error ?? '', /only available on Windows/);
    }

    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pktpath-dialog-http-'));
    try {
      const appDir = path.join(root, 'app');
      const host = new CordisHost({
        appDir,
        sessionsRoot: path.join(appDir, 'sessions'),
        pluginsDir: path.join(appDir, 'plugins'),
        exportsDir: path.join(appDir, 'exports'),
        collectorsDir: path.join(root, 'collectors'),
        webDir: path.join(root, 'web'),
      });
      registerWave1Builtins(host);
      await host.start();
      const app = await startStudioApp({ host, listenPort: 0, autoQuitMs: 0 });
      try {
        if (process.platform !== 'win32') {
          for (const route of ['pick-folder', 'save-file', 'open-file', 'reveal']) {
            const resp = await fetch(`${app.url}/api/dialog/${route}`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ path: '/tmp', initial_dir: '/tmp' }),
            });
            assert.equal(resp.status, 501, route);
            const body = await resp.json() as { ok: boolean; unsupported?: boolean };
            assert.equal(body.ok, false);
            assert.equal(body.unsupported, true);
          }
        }
      } finally {
        await app.close();
      }
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});
