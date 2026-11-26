import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

const scriptsDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../scripts');
const repoRoot = path.resolve(scriptsDir, '../..');
const packager = path.join(repoRoot, 'scripts', 'package_preview_bundle.py');

function read(name: string): Buffer {
  return fs.readFileSync(path.join(scriptsDir, name));
}

function hasBom(buf: Buffer): boolean {
  return buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf;
}

function isCrlf(buf: Buffer): boolean {
  const text = buf.toString('binary');
  const n = (text.match(/\n/g) || []).length;
  const crlf = (text.match(/\r\n/g) || []).length;
  const bareCr = (text.match(/\r(?!\n)/g) || []).length;
  return n > 0 && crlf === n && bareCr === 0;
}

function isLf(buf: Buffer): boolean {
  return !buf.includes(0x0d);
}

/** Port of start-studio.ps1 Get-WinArgvQuoted for Linux-side verification. */
function getWinArgvQuoted(value: string): string {
  if (!/[ \t\n\v"]/.test(value)) return value;
  let out = '"';
  let slashes = 0;
  for (const ch of value) {
    if (ch === '\\') { slashes += 1; continue; }
    if (ch === '"') {
      out += '\\'.repeat(2 * slashes + 1);
      out += '"';
      slashes = 0;
      continue;
    }
    if (slashes > 0) { out += '\\'.repeat(slashes); slashes = 0; }
    out += ch;
  }
  if (slashes > 0) out += '\\'.repeat(2 * slashes);
  out += '"';
  return out;
}

describe('P1-13 / P2-12 / P2-14 launch scripts and packaging alignment', () => {
  it('keeps .ps1 UTF-8 BOM+CRLF and .cmd no-BOM+CRLF with chcp 65001', () => {
    const startCmd = read('start-studio.cmd');
    const stopCmd = read('stop-studio.cmd');
    const startPs1 = read('start-studio.ps1');
    const stopPs1 = read('stop-studio.ps1');
    const startSh = read('start-studio.sh');
    const stopSh = read('stop-studio.sh');

    assert.equal(hasBom(startPs1), true);
    assert.equal(hasBom(stopPs1), true);
    assert.equal(hasBom(startCmd), false);
    assert.equal(hasBom(stopCmd), false);
    assert.equal(isCrlf(startCmd), true);
    assert.equal(isCrlf(stopCmd), true);
    assert.equal(isCrlf(startPs1), true);
    assert.equal(isCrlf(stopPs1), true);
    assert.equal(isLf(startSh), true);
    assert.equal(isLf(stopSh), true);

    const cmdText = startCmd.toString('utf8');
    const stopCmdText = stopCmd.toString('utf8');
    assert.ok(cmdText.includes('chcp 65001 >nul'));
    assert.ok(stopCmdText.includes('chcp 65001 >nul'));
    assert.ok(cmdText.includes('collectors\\android-arm64\\pktpath'));
    assert.ok(startPs1.toString('utf8').includes('collectors\\android-arm64\\pktpath'));
    assert.ok(startSh.toString('utf8').includes('collectors/android-arm64/pktpath'));
  });

  it('Get-WinArgvQuoted handles spaces, Chinese, quotes, and trailing backslashes', () => {
    assert.equal(getWinArgvQuoted('C:\\PktPath'), 'C:\\PktPath');
    assert.equal(getWinArgvQuoted('C:\\Pkt Path\\app'), '"C:\\Pkt Path\\app"');
    assert.equal(getWinArgvQuoted('C:\\用户\\测试'), 'C:\\用户\\测试');
    assert.equal(getWinArgvQuoted('C:\\用户\\测试 目录'), '"C:\\用户\\测试 目录"');
    assert.equal(getWinArgvQuoted('C:\\say "hi"'), '"C:\\say \\"hi\\""');
    // Trailing backslash without spaces/quotes stays unquoted (quoting only kicks in for [ \\t\\n\\v"]).
    assert.equal(getWinArgvQuoted('C:\\dir\\'), 'C:\\dir\\');
    assert.equal(getWinArgvQuoted('C:\\ends\\with\\'), 'C:\\ends\\with\\');
    // Once quoted for spaces, trailing backslashes are doubled before the closing quote.
    assert.equal(getWinArgvQuoted('C:\\dir name\\'), '"C:\\dir name\\\\"');
    assert.equal(getWinArgvQuoted('C:\\用户\\测试 目录\\'), '"C:\\用户\\测试 目录\\\\"');

    const ps1 = read('start-studio.ps1').toString('utf8');
    assert.ok(ps1.includes('function Get-WinArgvQuoted([string]$Value)'));
    assert.ok(ps1.includes('CreateNoWindow') || ps1.includes('WindowStyle Hidden'));
    assert.ok(ps1.includes('--no-auto-quit'));
    assert.ok(ps1.includes('/api/app/quit'));
    assert.ok(read('start-studio.sh').toString('utf8').includes('--no-auto-quit'));
    assert.ok(read('start-studio.sh').toString('utf8').includes('FORWARD+=("$1")'));
  });

  it('write_launchers --launchers-dir copies Windows and Linux scripts with BOM/CRLF preserved', () => {
    assert.equal(fs.existsSync(packager), true);
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wei-launchers-pack-'));
    try {
      const py = `
import sys
from pathlib import Path
sys.path.insert(0, ${JSON.stringify(path.dirname(packager))})
import importlib.util
spec = importlib.util.spec_from_file_location("package_preview_bundle", ${JSON.stringify(packager)})
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
win = Path(${JSON.stringify(tmp)}) / "windows"
linux = Path(${JSON.stringify(tmp)}) / "linux"
win.mkdir()
linux.mkdir()
src = Path(${JSON.stringify(scriptsDir)})
written_win = mod.write_launchers("windows", win, src)
written_linux = mod.write_launchers("linux", linux, src)
print("WIN=" + ",".join(written_win))
print("LINUX=" + ",".join(written_linux))
`
      const r = spawnSync('python3', ['-c', py], { encoding: 'utf8', timeout: 15_000 });
      assert.equal(r.status, 0, r.stderr || r.stdout);
      assert.match(r.stdout, /WIN=start-studio\.cmd,start-studio\.ps1,stop-studio\.cmd,stop-studio\.ps1/);
      assert.match(r.stdout, /LINUX=start-studio\.sh,stop-studio\.sh/);

      const packedPs1 = fs.readFileSync(path.join(tmp, 'windows', 'start-studio.ps1'));
      const srcPs1 = read('start-studio.ps1');
      assert.equal(hasBom(packedPs1), true);
      assert.equal(isCrlf(packedPs1), true);
      assert.equal(
        crypto.createHash('sha256').update(packedPs1).digest('hex'),
        crypto.createHash('sha256').update(srcPs1).digest('hex'),
        'packaged start-studio.ps1 must be byte-identical (BOM+CRLF preserved)',
      );
      const packedCmd = fs.readFileSync(path.join(tmp, 'windows', 'start-studio.cmd'));
      assert.equal(hasBom(packedCmd), false);
      assert.equal(isCrlf(packedCmd), true);
      assert.equal(
        crypto.createHash('sha256').update(packedCmd).digest('hex'),
        crypto.createHash('sha256').update(read('start-studio.cmd')).digest('hex'),
      );
      const packedSh = fs.readFileSync(path.join(tmp, 'linux', 'start-studio.sh'));
      const packedStopSh = fs.readFileSync(path.join(tmp, 'linux', 'stop-studio.sh'));
      assert.equal(isLf(packedSh), true);
      assert.equal(isLf(packedStopSh), true);
      assert.ok((fs.statSync(path.join(tmp, 'linux', 'start-studio.sh')).mode & 0o111) !== 0);
      assert.equal(
        crypto.createHash('sha256').update(packedSh).digest('hex'),
        crypto.createHash('sha256').update(read('start-studio.sh')).digest('hex'),
      );
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
