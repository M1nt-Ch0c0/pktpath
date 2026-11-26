#!/usr/bin/env node
// Test-only mock of WAVE1-CONTRACT.md v1.2 host (studio-cordis/src/main.ts).
// Not shipped in the product bundle. Implements:
//   --host/--port/--app-dir/--collectors-dir/--web-dir/--no-open and PKTPATH_* env
//   stdout ready line: PKTPATH_STUDIO_READY url=http://127.0.0.1:<port> pid=<pid>
//   GET /api/health -> 200 { ok: true, ... }
//   POST /api/app/quit -> 200 { ok: true } then exit within 5s
import http from "node:http";
import fs from "node:fs";
import path from "node:path";

function argValue(argv, flag, envName, fallback) {
  const i = argv.indexOf(flag);
  if (i >= 0) {
    if (i + 1 >= argv.length) throw new Error(`missing value for ${flag}`);
    return argv[i + 1];
  }
  if (envName && process.env[envName] != null && process.env[envName] !== "") {
    return process.env[envName];
  }
  return fallback;
}

function hasFlag(argv, flag) {
  return argv.includes(flag);
}

const argv = process.argv.slice(2);
const host = argValue(argv, "--host", "PKTPATH_HOST", "127.0.0.1");
const portRaw = argValue(argv, "--port", "PKTPATH_PORT", "0");
const appDir = argValue(argv, "--app-dir", "PKTPATH_APP_DIR", "");
const collectorsDir = argValue(argv, "--collectors-dir", "PKTPATH_COLLECTORS_DIR", "");
const webDir = argValue(argv, "--web-dir", "PKTPATH_WEB_DIR", "");
const noOpen = hasFlag(argv, "--no-open") || process.env.PKTPATH_NO_OPEN === "1";
const readyDelayMs = Number(argValue(argv, "--ready-delay-ms", "PKTPATH_MOCK_READY_DELAY_MS", "0"));
const quitDelayMs = Number(argValue(argv, "--quit-delay-ms", "PKTPATH_MOCK_QUIT_DELAY_MS", "30"));
const ignoreQuit = hasFlag(argv, "--ignore-quit") || process.env.PKTPATH_MOCK_IGNORE_QUIT === "1";
const noReadyLine = hasFlag(argv, "--no-ready-line") || process.env.PKTPATH_MOCK_NO_READY === "1";
const badHealth = hasFlag(argv, "--bad-health") || process.env.PKTPATH_MOCK_BAD_HEALTH === "1";
const crashAfterListen = hasFlag(argv, "--crash-after-listen") || false;

let quitting = false;
const startedAt = Date.now();

function healthBody(port) {
  return {
    ok: !badHealth,
    pid: process.pid,
    version: "cordis-wave1",
    runtime: {
      engine: "cordis-node",
      node_version: process.version,
      platform: process.platform,
      arch: process.arch,
      adb_path: "",
      collectors_dir: collectorsDir,
    },
    adb_missing: true,
    sessions_root: appDir ? path.join(appDir, "sessions") : "",
    plugins_dir: appDir ? path.join(appDir, "plugins") : "",
    active_clients: 0,
    kernel_plugins_active: 0,
    kernel_plugins_total: 7,
    mock: true,
    port,
  };
}

function sendJson(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url || "/", `http://${host}`);
  if (req.method === "GET" && url.pathname === "/api/health") {
    if (badHealth) {
      sendJson(res, 200, { ok: false, error: "mock unhealthy" });
      return;
    }
    sendJson(res, 200, healthBody(boundPort));
    return;
  }
  if (req.method === "POST" && url.pathname === "/api/app/quit") {
    let chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      sendJson(res, 200, { ok: true });
      if (ignoreQuit) return;
      quitting = true;
      const wait = Math.min(Math.max(quitDelayMs, 0), 5000);
      setTimeout(() => {
        server.close(() => process.exit(0));
        setTimeout(() => process.exit(0), 200).unref();
      }, wait);
    });
    return;
  }
  sendJson(res, 404, { ok: false, error: "not found" });
});

let boundPort = 0;

function onListening() {
  boundPort = server.address().port;
  const url = `http://${host}:${boundPort}`;
  const emitReady = () => {
    if (!noReadyLine) {
      process.stdout.write(`PKTPATH_STUDIO_READY url=${url} pid=${process.pid}\n`);
    }
    if (crashAfterListen) {
      setTimeout(() => process.exit(2), 20);
    }
    if (appDir) {
      try {
        fs.mkdirSync(path.join(appDir, "logs"), { recursive: true });
      } catch {}
    }
    void noOpen;
    void startedAt;
  };
  if (readyDelayMs > 0) setTimeout(emitReady, readyDelayMs);
  else emitReady();
}

server.listen(Number(portRaw), host, onListening);

for (const sig of ["SIGINT", "SIGTERM"]) {
  process.on(sig, () => {
    if (quitting) return;
    quitting = true;
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 200).unref();
  });
}
