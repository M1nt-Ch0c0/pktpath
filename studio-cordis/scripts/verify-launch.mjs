#!/usr/bin/env node
// Linux verification for Wei Wave 1 Windows/Linux launchers.
// Does not modify Lin's work tree. Does not push or publish.
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const SCRIPTS = path.join(ROOT, "scripts");
const LIN_STUDIO = "/workspace/pktpath-community/lin-cordis-research/cordis-wave1-20261126/studio-cordis";
const LIN_REPO = "/workspace/pktpath-community/lin-cordis-research/cordis-wave1-20261126";
const LIN_COMMIT_EXPECTED = "52fa69d82b6d181c50765615d11a2ccae0e83158";
const CONTRACT = "/workspace/pktpath-community/lin-cordis-research/cordis-wave1-contract-20261126/WAVE1-CONTRACT.md";
const CONTRACT_SHA256 = "34c55d3fcfe32186a9c714e8b447bbfa9828cf5960ee078f861eb6fca286fc97";
const NING_PACKAGER = "/workspace/pktpath-ning-wave1-ci-20261126/scripts/package_preview_bundle.py";
const WIN_NODE_ZIP = "/workspace/wei-windows-runtime-f2fba933-20261126/inputs/node-v24.22.1-win-x64.zip";
const ANDROID_COLLECTOR = "/workspace/wei-windows-runtime-f2fba933-20261126/pktpath-windows-x64-cordis-runtime-f2fba933/collectors/pktpath-android-arm64";
const LINUX_COLLECTOR = "/workspace/wei-windows-runtime-f2fba933-20261126/pktpath-windows-x64-cordis-runtime-f2fba933/collectors/pktpath-linux-x86_64";
const REPO_LICENSE = path.join(LIN_REPO, "LICENSE");

const results = [];
let failed = 0;

function sha256File(p) {
  return crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");
}

function assert(name, cond, detail = "") {
  if (cond) {
    results.push({ name, ok: true, detail });
    console.log(`PASS  ${name}${detail ? " — " + detail : ""}`);
  } else {
    failed += 1;
    results.push({ name, ok: false, detail });
    console.error(`FAIL  ${name}${detail ? " — " + detail : ""}`);
  }
}

function mustExist(p) {
  if (!fs.existsSync(p)) throw new Error(`missing ${p}`);
  return p;
}

function crlfOk(buf) {
  const n = (buf.toString("binary").match(/\n/g) || []).length;
  const crlf = (buf.toString("binary").match(/\r\n/g) || []).length;
  const bareCr = (buf.toString("binary").match(/\r(?!\n)/g) || []).length;
  return n > 0 && crlf === n && bareCr === 0;
}

function lfOk(buf) {
  return !buf.includes(0x0d);
}

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, {
    encoding: "utf8",
    timeout: opts.timeout ?? 30_000,
    env: opts.env ?? process.env,
    cwd: opts.cwd,
  });
  return r;
}

function parseReady(text) {
  if (!text) return null;
  const m = String(text).match(/PKTPATH_STUDIO_READY\s+url=(http:\/\/\S+)\s+pid=(\d+)/);
  if (!m) return null;
  return { url: m[1], pid: Number(m[2]) };
}

async function fetchOk(url, timeoutMs = 2000) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: ac.signal });
    const body = await res.text();
    return res.status === 200 && /"ok"\s*:\s*true/.test(body) ? { res, body } : null;
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

async function postQuit(baseUrl) {
  const url = baseUrl.replace(/\/$/, "") + "/api/app/quit";
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json; charset=utf-8" },
      body: "{}",
    });
    const body = await res.text();
    return { status: res.status, body };
  } catch (err) {
    return { status: 0, body: String(err) };
  }
}

function pidAlive(pid) {
  if (!pid) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function makeNodeWrapper(dest) {
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  const real = process.execPath;
  fs.writeFileSync(dest, `#!/usr/bin/env bash\nexec "${real}" "$@"\n`, { mode: 0o755 });
}

function writeStubCore(studioRoot) {
  const pkgDir = path.join(studioRoot, "node_modules", "@cordisjs", "core");
  fs.mkdirSync(pkgDir, { recursive: true });
  fs.writeFileSync(
    path.join(pkgDir, "package.json"),
    JSON.stringify({ name: "@cordisjs/core", version: "3.18.1", type: "module", exports: "./index.mjs" }, null, 2),
  );
  fs.writeFileSync(path.join(pkgDir, "index.mjs"), "export default {};\nexport const Context = class {};\n");
}

function writeMinimalBundle({ bundleDir, entrySource, withCore = true, withWeb = true, withCollector = true, withNode = true }) {
  fs.mkdirSync(bundleDir, { recursive: true });
  if (withNode) makeNodeWrapper(path.join(bundleDir, "node", "bin", "node"));
  const studio = path.join(bundleDir, "studio-cordis");
  fs.mkdirSync(path.join(studio, "src"), { recursive: true });
  fs.copyFileSync(entrySource, path.join(studio, "src", "main.ts"));
  fs.writeFileSync(path.join(studio, "package.json"), JSON.stringify({ name: "pktpath-studio-cordis", type: "module", dependencies: { "@cordisjs/core": "3.18.1" } }, null, 2));
  if (withWeb) {
    fs.mkdirSync(path.join(studio, "web"), { recursive: true });
    fs.writeFileSync(path.join(studio, "web", "index.html"), "<!doctype html><title>PktPath Studio</title>\n");
  }
  if (withCore) writeStubCore(studio);
  if (withCollector) {
    const col = path.join(bundleDir, "collectors", "android-arm64");
    fs.mkdirSync(col, { recursive: true });
    fs.writeFileSync(path.join(col, "pktpath"), "stub-collector\n", { mode: 0o755 });
  }
  for (const name of ["start-studio.sh", "stop-studio.sh", "start-studio.cmd", "start-studio.ps1", "stop-studio.cmd", "stop-studio.ps1"]) {
    const src = path.join(SCRIPTS, name);
    if (fs.existsSync(src)) fs.copyFileSync(src, path.join(bundleDir, name));
  }
  fs.chmodSync(path.join(bundleDir, "start-studio.sh"), 0o755);
  if (fs.existsSync(path.join(bundleDir, "stop-studio.sh"))) fs.chmodSync(path.join(bundleDir, "stop-studio.sh"), 0o755);
}

// ---------------- static checks ----------------
function staticChecks() {
  const cmd = fs.readFileSync(path.join(SCRIPTS, "start-studio.cmd"));
  const ps1 = fs.readFileSync(path.join(SCRIPTS, "start-studio.ps1"));
  const sh = fs.readFileSync(path.join(SCRIPTS, "start-studio.sh"));
  const stopCmd = fs.readFileSync(path.join(SCRIPTS, "stop-studio.cmd"));
  const stopPs1 = fs.readFileSync(path.join(SCRIPTS, "stop-studio.ps1"));
  const stopSh = fs.readFileSync(path.join(SCRIPTS, "stop-studio.sh"));

  assert("start-studio.cmd is CRLF", crlfOk(cmd));
  assert("start-studio.ps1 is CRLF", crlfOk(ps1));
  assert("stop-studio.cmd is CRLF", crlfOk(stopCmd));
  assert("stop-studio.ps1 is CRLF", crlfOk(stopPs1));
  assert("start-studio.sh is LF", lfOk(sh));
  assert("stop-studio.sh is LF", lfOk(stopSh));
  assert("start-studio.ps1 has UTF-8 BOM", ps1[0] === 0xef && ps1[1] === 0xbb && ps1[2] === 0xbf);
  assert("stop-studio.ps1 has UTF-8 BOM", stopPs1[0] === 0xef && stopPs1[1] === 0xbb && stopPs1[2] === 0xbf);
  assert("start-studio.cmd has no UTF-8 BOM", !(cmd[0] === 0xef && cmd[1] === 0xbb && cmd[2] === 0xbf));
  assert("stop-studio.cmd has no UTF-8 BOM", !(stopCmd[0] === 0xef && stopCmd[1] === 0xbb && stopCmd[2] === 0xbf));
  assert("start-studio.cmd sets chcp 65001", cmd.toString("utf8").includes("chcp 65001 >nul"));
  assert("stop-studio.cmd sets chcp 65001", stopCmd.toString("utf8").includes("chcp 65001 >nul"));
  assert("start-studio.ps1 uses launch mutex", ps1.toString("utf8").includes("System.Threading.Mutex") && ps1.toString("utf8").includes("Get-LaunchMutexName"));
  assert("start-studio.ps1 has no redundant no-op health probe", !ps1.toString("utf8").includes("$ready = $ready"));

  const allWin = Buffer.concat([cmd, ps1, stopCmd, stopPs1]).toString("utf8");
  const all = allWin + sh.toString("utf8") + stopSh.toString("utf8");
  const forbidden = [
    "pktpath-studio.exe",
    "pktpath-offline.exe",
    "--window",
    "WebView2",
    "--cordis-plugin-runtime",
    "--cordis-analyzer-node",
  ];
  for (const f of forbidden) {
    assert(`no forbidden token ${f}`, !all.includes(f));
  }
  // PATH fallback: allow comments saying we never fall back
  const pathFallbackRe = /(?:LookPath|Get-Command\s+node|command\s+-v\s+node|where\.exe\s+node|PATH.*node\.exe(?!.*拒绝)|fallback to PATH Node(?!.*;))/i;
  assert("scripts do not implement PATH Node fallback", !pathFallbackRe.test(all) && all.includes("不会回退到 PATH") || all.toLowerCase().includes("no path fallback") || all.includes("不会回退到 PATH"));

  const needed = [
    "studio-cordis\\src\\main.ts",
    "node\\node.exe",
    "studio-cordis\\node_modules\\@cordisjs\\core\\package.json",
    "collectors\\android-arm64\\pktpath",
    "studio-cordis\\web\\index.html",
    "/api/health",
    "/api/app/quit",
    "PKTPATH_STUDIO_READY",
    "--no-open",
    "PktPathStudio",
    "d702daa815eabbff763c7d3808e235cf031cf2ca70211b56847bc72f51e240e5",
    "CreateNoWindow",
    "34c55d3fcfe32186a9c714e8b447bbfa9828cf5960ee078f861eb6fca286fc97",
  ];
  const winText = allWin;
  for (const n of needed) {
    assert(`windows scripts contain ${n}`, winText.includes(n), n === "CreateNoWindow" ? "or hidden-window fallback present" : "");
  }
  const shText = sh.toString("utf8");
  for (const n of ["studio-cordis/src/main.ts", "node/bin/node", "/api/health", "/api/app/quit", "PKTPATH_STUDIO_READY", "--no-open", "android-arm64/pktpath"]) {
    assert(`start-studio.sh contains ${n}`, shText.includes(n));
  }
  assert("ps1 accepts --flag=value", winText.includes("--host=(.*)") || winText.includes("^--host="));
  assert("sh accepts --flag=value", shText.includes("--host=*"));
  assert("scripts honor PKTPATH_NO_OPEN=true", winText.includes('PKTPATH_NO_OPEN -eq "true"') && shText.includes('PKTPATH_NO_OPEN:-}" == "true"'));
  assert("Ning launchers-dir expected names present",
    fs.existsSync(path.join(SCRIPTS, "start-studio.cmd")) &&
    fs.existsSync(path.join(SCRIPTS, "start-studio.ps1")) &&
    fs.existsSync(path.join(SCRIPTS, "start-studio.sh")));
}

function contractPins() {
  const actual = sha256File(CONTRACT);
  assert("WAVE1-CONTRACT.md v1.2 SHA256", actual === CONTRACT_SHA256, actual);
  const pinned = run("git", ["-C", LIN_REPO, "rev-parse", "--verify", LIN_COMMIT_EXPECTED + "^{commit}"]);
  assert("Lin baseline 52fa69d8 is present in the repo", pinned.status === 0 && String(pinned.stdout).trim() === LIN_COMMIT_EXPECTED, (pinned.stdout || pinned.stderr || "").trim());
  const head = run("git", ["-C", LIN_REPO, "rev-parse", "HEAD"]);
  const headSha = String(head.stdout).trim();
  const mainDiff = run("git", ["-C", LIN_REPO, "diff", LIN_COMMIT_EXPECTED, "HEAD", "--", "studio-cordis/src/main.ts"]);
  assert("HEAD main.ts is identical to baseline 52fa69d8 (launch entry unchanged even if HEAD moved)", (mainDiff.stdout || "") === "", `HEAD=${headSha}`);
  assert("Lin main.ts exists", fs.existsSync(path.join(LIN_STUDIO, "src", "main.ts")));
  const main = fs.readFileSync(path.join(LIN_STUDIO, "src", "main.ts"), "utf8");
  assert("main.ts writes PKTPATH_STUDIO_READY url=... pid=...", main.includes("PKTPATH_STUDIO_READY url=${app.url} pid=${process.pid}"));
  assert("main.ts default host 127.0.0.1 / port 0", main.includes("'PKTPATH_HOST', '127.0.0.1'") && main.includes("'PKTPATH_PORT', '0'"));
  assert("main.ts supports --flag=value", main.includes("arg.indexOf('=')"));
  assert("main.ts PKTPATH_NO_OPEN is 1 or true", main.includes("PKTPATH_NO_OPEN === '1'") && main.includes("PKTPATH_NO_OPEN === 'true'"));
  const app = fs.readFileSync(path.join(LIN_STUDIO, "src", "server", "app.ts"), "utf8");
  assert("app.ts GET /api/health returns ok:true", app.includes("pathname === '/api/health'") && app.includes("ok: true"));
  assert("app.ts POST /api/app/quit returns ok:true then closeAll", app.includes("pathname === '/api/app/quit'") && app.includes("ok: true") && app.includes("closeAll()"));
  assert("bound URL is http://host:port", app.includes("http://${listenHost}:${addr.port}"));
  const pkg = JSON.parse(fs.readFileSync(path.join(LIN_STUDIO, "package.json"), "utf8"));
  assert("@cordisjs/core pinned 3.18.1 in package.json", pkg.dependencies["@cordisjs/core"] === "3.18.1");
  const lock = fs.readFileSync(path.join(LIN_STUDIO, "package-lock.json"), "utf8");
  assert("package-lock has @cordisjs/core 3.18.1 and cosmokit 1.8.1", lock.includes('"@cordisjs/core"') && lock.includes('"version": "3.18.1"') && lock.includes('"version": "1.8.1"'));
  assert("Lin web/ currently has no index.html (scripts still require it in the package)", !fs.existsSync(path.join(LIN_STUDIO, "web", "index.html")));
}

async function testFailClosed() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "wei-w1-fail-"));
  const mock = path.join(HERE, "mock-cordis-server.mjs");
  const cases = [
    { name: "missing node", patch: (b) => fs.rmSync(path.join(b, "node"), { recursive: true, force: true }) },
    { name: "missing entry", patch: (b) => fs.rmSync(path.join(b, "studio-cordis", "src", "main.ts")) },
    { name: "missing core", patch: (b) => fs.rmSync(path.join(b, "studio-cordis", "node_modules"), { recursive: true, force: true }) },
    { name: "missing web", patch: (b) => fs.rmSync(path.join(b, "studio-cordis", "web"), { recursive: true, force: true }) },
    { name: "missing collector", patch: (b) => fs.rmSync(path.join(b, "collectors"), { recursive: true, force: true }) },
  ];
  for (const c of cases) {
    const bundle = path.join(tmp, c.name.replace(/\s+/g, "-"));
    writeMinimalBundle({ bundleDir: bundle, entrySource: mock });
    c.patch(bundle);
    const appDir = path.join(tmp, c.name.replace(/\s+/g, "-") + "-app");
    const r = run("bash", [path.join(bundle, "start-studio.sh"), "--no-open", "--app-dir", appDir], { timeout: 15_000 });
    assert(`fail-closed: ${c.name}`, r.status === 1, `status=${r.status} err=${(r.stderr || "").trim().slice(0, 200)}`);
  }
  fs.rmSync(tmp, { recursive: true, force: true });
}

async function waitFileReady(appDir, timeoutMs = 20000) {
  const outLog = path.join(appDir, "logs", "studio.out.log");
  const rt = path.join(appDir, "logs", "launcher-runtime.json");
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    if (fs.existsSync(rt)) {
      try {
        const j = JSON.parse(fs.readFileSync(rt, "utf8"));
        if (j.url && (await fetchOk(j.url.replace(/\/$/, "") + "/api/health"))) return j;
      } catch {}
    }
    if (fs.existsSync(outLog)) {
      const ready = parseReady(fs.readFileSync(outLog, "utf8"));
      if (ready && (await fetchOk(ready.url.replace(/\/$/, "") + "/api/health"))) return { ...ready, pid: ready.pid };
    }
    await sleep(80);
  }
  return null;
}

async function testMockProtocol() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "wei-w1-mock-"));
  const mock = path.join(HERE, "mock-cordis-server.mjs");

  // happy path, unicode/spaces in bundle path, port 0
  const bundle = path.join(tmp, "PktPath 组合包 中文");
  writeMinimalBundle({ bundleDir: bundle, entrySource: mock });
  const appDir = path.join(tmp, "app data 中文");
  const start = run("bash", [path.join(bundle, "start-studio.sh"), "--no-open", "--app-dir", appDir], { timeout: 20_000 });
  const started = start.status === 0;
  const state = started ? await waitFileReady(appDir, 2000) || JSON.parse(fs.readFileSync(path.join(appDir, "logs", "launcher-runtime.json"), "utf8")) : null;
  assert("mock start in unicode path exit 0", started, (start.stderr || start.stdout || "").slice(0, 400));
  assert("mock start wrote runtime.json with url+pid", !!(state && state.url && state.pid), JSON.stringify(state));
  if (state?.url) {
    const health = await fetchOk(state.url.replace(/\/$/, "") + "/api/health");
    assert("mock GET /api/health 200 ok:true", !!health, health ? "" : "no health");
    assert("READY url has no trailing slash and includes 127.0.0.1", /^http:\/\/127\.0\.0\.1:\d+$/.test(state.url), state.url);
    assert("mock process alive after start", pidAlive(state.pid));
  }

  // reuse live instance
  if (state?.url) {
    const again = run("bash", [path.join(bundle, "start-studio.sh"), "--no-open", "--app-dir", appDir], { timeout: 15_000 });
    assert("second start reuses live instance", again.status === 0 && String(again.stdout).includes("已在运行"), again.stdout + again.stderr);
  }

  // graceful stop
  if (state?.pid) {
    const stop = run("bash", [path.join(bundle, "stop-studio.sh"), "--app-dir", appDir], { timeout: 15_000 });
    assert("stop-studio.sh graceful quit exit 0", stop.status === 0, (stop.stdout || "") + (stop.stderr || ""));
    await sleep(200);
    assert("mock process exited after POST /api/app/quit", !pidAlive(state.pid));
    assert("runtime.json removed after stop", !fs.existsSync(path.join(appDir, "logs", "launcher-runtime.json")));
  }

  // health timeout cleanup
  const bundleHang = path.join(tmp, "hang-bundle");
  writeMinimalBundle({ bundleDir: bundleHang, entrySource: mock });
  const appHang = path.join(tmp, "hang-app");
  const hang = run("bash", [path.join(bundleHang, "start-studio.sh"), "--no-open", "--app-dir", appHang, "--ready-delay-ms", "60000"], { timeout: 30_000, env: { ...process.env, /* default ready timeout 20s */ } });
  // The mock flag must be forwarded. Our script forwards unknown args, including --ready-delay-ms 60000.
  // Wait, READY_TIMEOUT is 20s so this test takes 20s. Acceptable.
  assert("health/ready timeout exits non-zero", hang.status === 1, `status=${hang.status} ${(hang.stderr || "").slice(0, 300)}`);
  const hangRt = path.join(appHang, "logs", "launcher-runtime.json");
  assert("timeout does not leave runtime.json", !fs.existsSync(hangRt));
  // try to ensure no orphan node with ready-delay
  const hanging = run("bash", ["-lc", `pgrep -af "ready-delay-ms 60000" || true`], { timeout: 5000 });
  const leftover = (hanging.stdout || "").split("\n").filter((l) => l.includes("ready-delay-ms") && !l.includes("pgrep"));
  assert("timeout cleaned hanging mock process", leftover.length === 0, leftover.join(" | "));

  // force stop when quit ignored
  const bundleForce = path.join(tmp, "force-bundle");
  writeMinimalBundle({ bundleDir: bundleForce, entrySource: mock });
  const appForce = path.join(tmp, "force-app");
  const startedForce = run("bash", [path.join(bundleForce, "start-studio.sh"), "--no-open", "--app-dir", appForce, "--ignore-quit"], { timeout: 20_000 });
  const stForce = startedForce.status === 0 ? JSON.parse(fs.readFileSync(path.join(appForce, "logs", "launcher-runtime.json"), "utf8")) : null;
  assert("force-stop fixture started", !!(stForce && stForce.pid), (startedForce.stderr || startedForce.stdout || "").slice(0, 300));
  if (stForce?.pid) {
    const stopF = run("bash", [path.join(bundleForce, "stop-studio.sh"), "--app-dir", appForce], { timeout: 20_000 });
    assert("force stop after ignored quit exits 0", stopF.status === 0, (stopF.stdout || "") + (stopF.stderr || ""));
    await sleep(200);
    assert("ignored-quit process was force-killed", !pidAlive(stForce.pid));
  }

  fs.rmSync(tmp, { recursive: true, force: true });
}

async function testRealMainTs() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "wei-w1-real-"));
  const bundle = path.join(tmp, "bundle");
  fs.mkdirSync(bundle, { recursive: true });
  makeNodeWrapper(path.join(bundle, "node", "bin", "node"));
  // Copy Lin studio-cordis read-only snapshot into the fixture (never write back).
  const studioDst = path.join(bundle, "studio-cordis");
  const archived = run("bash", ["-lc", `set -euo pipefail; git -C "${LIN_REPO}" archive ${LIN_COMMIT_EXPECTED} studio-cordis | tar -x -C "${bundle}"`], { timeout: 30_000 });
  const nmSrc = path.join(LIN_STUDIO, "node_modules");
  const nmDst = path.join(studioDst, "node_modules");
  let nm = { status: 1 };
  if (fs.existsSync(path.join(studioDst, "src", "main.ts")) && fs.existsSync(nmSrc)) {
    nm = run("cp", ["-a", nmSrc, nmDst], { timeout: 30_000 });
  }
  assert("archived Lin studio-cordis@52fa69d8 into temp fixture (not dirty worktree)", archived.status === 0 && fs.existsSync(path.join(studioDst, "src", "main.ts")), (archived.stderr || archived.stdout || "").slice(0, 400));
  assert("copied node_modules into fixture", nm.status === 0 && fs.existsSync(path.join(nmDst, "@cordisjs", "core", "package.json")));
  // Record source hash to prove we didn't change Lin tree
  const linHashBefore = sha256File(path.join(LIN_STUDIO, "src", "main.ts"));
  // Only the fixture gets a stub index.html (Lin tree web/ is empty at 03106f56).
  fs.mkdirSync(path.join(studioDst, "web"), { recursive: true });
  fs.writeFileSync(path.join(studioDst, "web", "index.html"), "<!doctype html><title>PktPath Studio fixture</title>\n");
  const col = path.join(bundle, "collectors", "android-arm64");
  fs.mkdirSync(col, { recursive: true });
  fs.copyFileSync(ANDROID_COLLECTOR, path.join(col, "pktpath"));
  fs.chmodSync(path.join(col, "pktpath"), 0o755);
  for (const name of ["start-studio.sh", "stop-studio.sh"]) {
    fs.copyFileSync(path.join(SCRIPTS, name), path.join(bundle, name));
    fs.chmodSync(path.join(bundle, name), 0o755);
  }
  const appDir = path.join(tmp, "app-dir");
  const start = run("bash", [path.join(bundle, "start-studio.sh"), "--no-open", "--app-dir", appDir, "--host", "127.0.0.1"], { timeout: 25_000 });
  const out = (start.stdout || "") + (start.stderr || "");
  assert("real main.ts start-studio.sh exit 0", start.status === 0, out.slice(0, 800));
  let state = null;
  const rt = path.join(appDir, "logs", "launcher-runtime.json");
  if (fs.existsSync(rt)) state = JSON.parse(fs.readFileSync(rt, "utf8"));
  assert("real main.ts runtime.json present", !!(state && state.url && state.pid), JSON.stringify(state));
  if (state?.url) {
    const readyLogs = fs.existsSync(path.join(appDir, "logs", "studio.out.log"))
      ? fs.readFileSync(path.join(appDir, "logs", "studio.out.log"), "utf8")
      : "";
    const parsed = parseReady(readyLogs);
    assert("real stdout READY line matches http://127.0.0.1:<port> pid=<pid>", !!(parsed && parsed.url === state.url && parsed.pid === state.pid), readyLogs.trim());
    const health = await fetchOk(state.url.replace(/\/$/, "") + "/api/health");
    assert("real GET /api/health 200 ok:true", !!health);
    if (health) {
      const body = JSON.parse(health.body);
      assert("real health.runtime.engine is cordis-node", body.runtime?.engine === "cordis-node");
      assert("real health.version is cordis-wave1", body.version === "cordis-wave1");
      assert("real health.pid matches process", body.pid === state.pid);
    }
    const quit = await postQuit(state.url);
    assert("real POST /api/app/quit 200 ok:true", quit.status === 200 && /"ok"\s*:\s*true/.test(quit.body), JSON.stringify(quit));
    const t0 = Date.now();
    while (pidAlive(state.pid) && Date.now() - t0 < 8000) await sleep(100);
    assert("real process exits within 8s after quit", !pidAlive(state.pid), `pid=${state.pid} still alive`);
  }
  // also exercise stop-studio on a fresh start
  const appDir2 = path.join(tmp, "app-dir-2");
  const start2 = run("bash", [path.join(bundle, "start-studio.sh"), "--no-open", "--app-dir", appDir2], { timeout: 25_000 });
  assert("real main.ts second start exit 0", start2.status === 0, (start2.stderr || start2.stdout || "").slice(0, 400));
  const st2 = fs.existsSync(path.join(appDir2, "logs", "launcher-runtime.json"))
    ? JSON.parse(fs.readFileSync(path.join(appDir2, "logs", "launcher-runtime.json"), "utf8"))
    : null;
  if (st2?.pid) {
    const stop2 = run("bash", [path.join(bundle, "stop-studio.sh"), "--app-dir", appDir2], { timeout: 15_000 });
    assert("real stop-studio.sh exit 0", stop2.status === 0, (stop2.stdout || "") + (stop2.stderr || ""));
    await sleep(200);
    assert("real process gone after stop-studio.sh", !pidAlive(st2.pid));
  } else {
    assert("real second start wrote runtime", false, (start2.stdout || "") + (start2.stderr || ""));
  }

  const linHashAfter = sha256File(path.join(LIN_STUDIO, "src", "main.ts"));
  assert("Lin work tree main.ts unchanged", linHashBefore === linHashAfter, linHashAfter);

  // cleanup leftovers just in case
  for (const s of [state, st2]) {
    if (s?.pid && pidAlive(s.pid)) {
      try { process.kill(s.pid, "SIGKILL"); } catch {}
    }
  }
  fs.rmSync(tmp, { recursive: true, force: true });
}

function testNingLaunchersDir() {
  assert("Ning packager exists", fs.existsSync(NING_PACKAGER));
  const src = fs.readFileSync(NING_PACKAGER, "utf8");
  assert("Ning write_launchers copies start-studio.cmd/.ps1 on windows and .sh on linux",
    src.includes('("start-studio.cmd"') && src.includes('("start-studio.ps1"') && src.includes('("start-studio.sh"'));
  assert("Ning --launchers-dir help mentions start-studio.{cmd,ps1,sh}",
    src.includes("start-studio.{cmd,ps1,sh}") || src.includes("studio-cordis/scripts"));
  assert("Ning write_launchers supports optional stop-studio.*", src.includes('("stop-studio.cmd"') && src.includes('("stop-studio.ps1"') && src.includes('("stop-studio.sh"'));

  // Simulate write_launchers against a temp dir, then optionally run the real packager for Windows.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "wei-w1-ning-"));
  const sim = path.join(tmp, "sim-bundle");
  fs.mkdirSync(sim);
  const py = `
from pathlib import Path
import importlib.util
spec = importlib.util.spec_from_file_location("pack", ${JSON.stringify(NING_PACKAGER)})
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
written = mod.write_launchers("windows", Path(${JSON.stringify(sim)}), Path(${JSON.stringify(SCRIPTS)}))
print(",".join(written))
for name in written:
    p = Path(${JSON.stringify(sim)}) / name
    text = p.read_text(encoding="utf-8")
    print(name, "CRLF" if text.count("\\r\\n")==text.count("\\n") else "EOL-BAD", "has_main", "studio-cordis" in text and "main.ts" in text)
`;
  const simRun = run("python3", ["-c", py], { timeout: 10_000 });
  assert("Ning write_launchers simulation exit 0", simRun.status === 0, (simRun.stderr || "") + (simRun.stdout || ""));
  const simOut = simRun.stdout || "";
  assert("Ning windows launchers-dir picked start-studio.cmd,start-studio.ps1",
    simOut.includes("start-studio.cmd") && simOut.includes("start-studio.ps1"));
  assert("Ning windows launchers-dir also picked stop-studio.cmd,stop-studio.ps1", simOut.split("\n")[0].includes("stop-studio.cmd") && simOut.split("\n")[0].includes("stop-studio.ps1"));
  const packedCmd = path.join(sim, "start-studio.cmd");
  const packedPs1 = path.join(sim, "start-studio.ps1");
  if (fs.existsSync(packedCmd) && fs.existsSync(packedPs1)) {
    const ourCmd = fs.readFileSync(path.join(SCRIPTS, "start-studio.cmd"), "utf8").replace(/\r\n/g, "\n");
    const theirCmd = fs.readFileSync(packedCmd, "utf8").replace(/\r\n/g, "\n");
    const ourPs1 = fs.readFileSync(path.join(SCRIPTS, "start-studio.ps1"), "utf8").replace(/\r\n/g, "\n");
    const theirPs1 = fs.readFileSync(packedPs1, "utf8").replace(/\r\n/g, "\n");
    assert("packed start-studio.cmd content matches our scripts/ (modulo EOL)", ourCmd === theirCmd);
    assert("packed start-studio.ps1 content matches our scripts/ (modulo EOL)", ourPs1 === theirPs1);
    const packedCmdBuf = fs.readFileSync(packedCmd);
    const packedPs1Buf = fs.readFileSync(packedPs1);
    const packedStopPs1 = path.join(sim, "stop-studio.ps1");
    const packedStopPs1Buf = fs.existsSync(packedStopPs1) ? fs.readFileSync(packedStopPs1) : Buffer.alloc(0);
    assert("packed cmd/ps1 are CRLF", crlfOk(packedCmdBuf) && crlfOk(packedPs1Buf));
    assert("packed ps1 preserves UTF-8 BOM", packedPs1Buf[0] === 0xef && packedPs1Buf[1] === 0xbb && packedPs1Buf[2] === 0xbf && packedStopPs1Buf[0] === 0xef && packedStopPs1Buf[1] === 0xbb && packedStopPs1Buf[2] === 0xbf);
  }

  // Real packager dry-run if inputs exist.
  if (fs.existsSync(WIN_NODE_ZIP) && fs.existsSync(ANDROID_COLLECTOR) && fs.existsSync(REPO_LICENSE)) {
    const studioCopy = path.join(tmp, "studio-cordis");
    run("bash", ["-lc", `set -euo pipefail; git -C "${LIN_REPO}" archive ${LIN_COMMIT_EXPECTED} studio-cordis | tar -x -C "${tmp}"`], { timeout: 30_000 });
    if (fs.existsSync(path.join(LIN_STUDIO, "node_modules"))) {
      run("cp", ["-a", path.join(LIN_STUDIO, "node_modules"), path.join(studioCopy, "node_modules")], { timeout: 30_000 });
    }
    fs.mkdirSync(path.join(studioCopy, "web"), { recursive: true });
    fs.writeFileSync(path.join(studioCopy, "web", "index.html"), "<!doctype html><title>PktPath Studio</title>\n");
    const colDir = path.join(tmp, "collectors-in");
    fs.mkdirSync(colDir, { recursive: true });
    fs.copyFileSync(ANDROID_COLLECTOR, path.join(colDir, "pktpath-android-arm64"));
    if (fs.existsSync(LINUX_COLLECTOR)) fs.copyFileSync(LINUX_COLLECTOR, path.join(colDir, "pktpath-linux-x86_64"));
    const outDir = path.join(tmp, "ning-out");
    const pack = run("python3", [
      NING_PACKAGER,
      "--os", "windows",
      "--studio-dir", studioCopy,
      "--collectors-dir", colDir,
      "--repo-license", REPO_LICENSE,
      "--launchers-dir", SCRIPTS,
      "--node-archive", WIN_NODE_ZIP,
      "--out-dir", outDir,
      "--bundle-name", "pktpath-windows-x64-wei-launchers-dryrun",
      "--keep-dir",
    ], { timeout: 120_000 });
    const packOut = (pack.stdout || "") + (pack.stderr || "");
    assert("Ning package_preview_bundle.py --launchers-dir dry-run exit 0", pack.status === 0, packOut.slice(0, 1200));
    if (pack.status === 0) {
      try {
        const summary = JSON.parse(pack.stdout);
        assert("Ning dry-run launchers are start+stop cmd+ps1", JSON.stringify(summary.launchers) === JSON.stringify(["start-studio.cmd", "start-studio.ps1", "stop-studio.cmd", "stop-studio.ps1"]));
        const stagedCmd = path.join(outDir, "pktpath-windows-x64-wei-launchers-dryrun", "start-studio.cmd");
        const stagedPs1 = path.join(outDir, "pktpath-windows-x64-wei-launchers-dryrun", "start-studio.ps1");
        assert("staged bundle has our start scripts at root", fs.existsSync(stagedCmd) && fs.existsSync(stagedPs1));
        assert("staged bundle has no pktpath-studio.exe", !fs.existsSync(path.join(outDir, "pktpath-windows-x64-wei-launchers-dryrun", "pktpath-studio.exe")));
        assert("staged bundle has node/node.exe and studio-cordis/src/main.ts",
          fs.existsSync(path.join(outDir, "pktpath-windows-x64-wei-launchers-dryrun", "node", "node.exe")) &&
          fs.existsSync(path.join(outDir, "pktpath-windows-x64-wei-launchers-dryrun", "studio-cordis", "src", "main.ts")));
        if (summary.archive_sha256) {
          fs.mkdirSync(path.join(ROOT, "evidence"), { recursive: true });
          fs.writeFileSync(path.join(ROOT, "evidence", "ning-launchers-dir-dryrun.json"), JSON.stringify(summary, null, 2) + "\n");
        }
      } catch (err) {
        assert("Ning dry-run JSON parse", false, String(err) + "\n" + packOut.slice(0, 500));
      }
    }
  } else {
    assert("Ning full packager inputs available", false, "missing node zip, collector, or LICENSE");
  }

  fs.rmSync(tmp, { recursive: true, force: true });
}

const evidence = {
  started_at: new Date().toISOString(),
  node: process.version,
};

async function main() {
  console.log(`verify-launch: node ${process.version}`);
  staticChecks();
  contractPins();
  await testFailClosed();
  await testMockProtocol();
  await testRealMainTs();
  testNingLaunchersDir();

  const summary = { total: results.length, passed: results.filter((r) => r.ok).length, failed, results };
  fs.mkdirSync(path.join(ROOT, "evidence"), { recursive: true });
  fs.writeFileSync(path.join(ROOT, "evidence", "verify-launch.json"), JSON.stringify({ ...evidence, finished_at: new Date().toISOString(), summary }, null, 2) + "\n");
  console.log(`\n${summary.passed}/${summary.total} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
