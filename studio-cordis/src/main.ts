import { spawn } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CordisHost } from './kernel/host.ts';
import type { HostPaths } from './kernel/types.ts';
import type { BuiltinPluginDefinition } from './kernel/types.ts';
import { createAnalysisWave1Builtins } from './plugins/analysis/index.ts';
import { registerWave1Builtins } from './plugins/register.ts';
import { uiThemePlugin } from './plugins/ui/theme.ts';
import { handleSessionRoute } from './routes/session-routes.ts';
import { startStudioApp } from './server/app.ts';

export interface CliConfig {
  host: string;
  port: number;
  noOpen: boolean;
  version: string;
  paths: HostPaths;
}

function defaultAppDir(): string {
  if (process.platform === 'win32') {
    const base = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
    return path.join(base, 'PktPathStudio');
  }
  return path.join(os.homedir(), '.local', 'share', 'pktpath-studio');
}

export function parseCliArgs(argv: string[], env: NodeJS.ProcessEnv = process.env): CliConfig {
  const scriptDir = path.dirname(fileURLToPath(import.meta.url));
  const studioRoot = path.resolve(scriptDir, '..');
  const packageRoot = path.resolve(studioRoot, '..');

  const flags = new Map<string, string>();
  let noOpen = env.PKTPATH_NO_OPEN === '1' || env.PKTPATH_NO_OPEN === 'true';

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--no-open') {
      noOpen = true;
      continue;
    }
    if (arg.startsWith('--')) {
      const eq = arg.indexOf('=');
      if (eq > 2) {
        flags.set(arg.slice(2, eq), arg.slice(eq + 1));
      } else if (i + 1 < argv.length) {
        flags.set(arg.slice(2), argv[i + 1]);
        i += 1;
      }
    }
  }

  const getVal = (flag: string, envKey: string, fallback: string): string => {
    const f = flags.get(flag);
    if (f !== undefined && f !== '') return f;
    const e = env[envKey];
    if (e !== undefined && e !== '') return e;
    return fallback;
  };

  const listenHost = getVal('host', 'PKTPATH_HOST', '127.0.0.1');
  const portRaw = getVal('port', 'PKTPATH_PORT', '0');
  const port = Number.parseInt(portRaw, 10);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error(`invalid port: ${portRaw}`);
  }

  const appDir = path.resolve(getVal('app-dir', 'PKTPATH_APP_DIR', defaultAppDir()));
  const sessionsRoot = path.resolve(getVal('sessions-dir', 'PKTPATH_SESSIONS_DIR', path.join(appDir, 'sessions')));
  const pluginsDir = path.resolve(getVal('plugins-dir', 'PKTPATH_PLUGINS_DIR', path.join(appDir, 'plugins')));
  const exportsDir = path.join(appDir, 'exports');
  const collectorsDir = path.resolve(getVal('collectors-dir', 'PKTPATH_COLLECTORS_DIR', path.join(packageRoot, 'collectors')));
  const webDir = path.resolve(getVal('web-dir', 'PKTPATH_WEB_DIR', path.join(studioRoot, 'web')));
  const adbPathRaw = getVal('adb-path', 'PKTPATH_ADB_PATH', '');
  const version = getVal('version', 'PKTPATH_VERSION', 'cordis-wave1');

  return {
    host: listenHost,
    port,
    noOpen,
    version,
    paths: {
      appDir,
      sessionsRoot,
      pluginsDir,
      exportsDir,
      collectorsDir,
      webDir,
      adbPath: adbPathRaw || undefined,
    },
  };
}

function openDefaultBrowser(url: string): void {
  try {
    if (process.platform === 'win32') {
      spawn('cmd.exe', ['/c', 'start', '', url], { detached: true, stdio: 'ignore', windowsHide: true }).unref();
    } else if (process.platform === 'darwin') {
      spawn('open', [url], { detached: true, stdio: 'ignore' }).unref();
    } else {
      spawn('xdg-open', [url], { detached: true, stdio: 'ignore' }).unref();
    }
  } catch {
    // Non-fatal: user can open the printed URL manually.
  }
}

async function main(): Promise<void> {
  const cfg = parseCliArgs(process.argv.slice(2));
  const host = new CordisHost(cfg.paths, cfg.version);
  registerWave1Builtins(host);
  for (const plugin of createAnalysisWave1Builtins()) {
    host.registerBuiltin(plugin as unknown as BuiltinPluginDefinition);
  }
  host.registerBuiltin(uiThemePlugin);
  await host.start();

  const app = await startStudioApp({
    host,
    listenHost: cfg.host,
    listenPort: cfg.port,
    extraRouteHandlers: [handleSessionRoute],
    onQuitRequested: () => {
      process.exit(0);
    },
  });

  process.stdout.write(`PKTPATH_STUDIO_READY url=${app.url} pid=${process.pid}\n`);

  if (!cfg.noOpen) {
    openDefaultBrowser(app.url);
  }

  let shuttingDown = false;
  const onSignal = (): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    const forceTimer = setTimeout(() => process.exit(1), 6_000);
    forceTimer.unref();
    void app.close().finally(() => process.exit(0));
  };

  process.on('SIGINT', onSignal);
  process.on('SIGTERM', onSignal);
}

const isEntrypoint = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isEntrypoint) {
  main().catch((err: unknown) => {
    process.stderr.write(`pktpath studio-cordis failed to start: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
    process.exit(1);
  });
}
