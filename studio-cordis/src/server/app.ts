import http, { type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { CordisHost } from '../kernel/host.ts';
import type { AdbTransportService } from '../plugins/adb/android-adb.ts';
import { handleAdbRoute } from '../routes/adb-routes.ts';
import { handleKernelRoute } from '../routes/kernel-routes.ts';
import { handleDialogAction } from './dialog.ts';
import { readJsonBody, sendJson, serveWebStatic } from './http-utils.ts';

export type ExtraRouteHandler = (
  host: CordisHost,
  method: string,
  url: URL,
  req: IncomingMessage,
  res: ServerResponse,
) => Promise<boolean>;

export const DEFAULT_AUTO_QUIT_MS = 25_000;

export interface StudioAppOptions {
  host: CordisHost;
  listenHost?: string;
  listenPort?: number;
  extraRouteHandlers?: ExtraRouteHandler[];
  onQuitRequested?: () => void;
  /** Idle auto-quit timeout in ms. 0 or negative disables. Default 25000. */
  autoQuitMs?: number;
  /** Read-only probe: true while a capture is running or finalizing. */
  hasActiveCapture?: () => boolean;
}

export interface RunningStudioApp {
  readonly server: http.Server;
  readonly url: string;
  readonly port: number;
  readonly host: CordisHost;
  readonly everHadClient: boolean;
  activeClients(): number;
  close(): Promise<void>;
}

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);

function checkLoopbackGuard(
  req: IncomingMessage,
  method: string,
  parsedUrl: URL,
  boundPort: number,
): { ok: true } | { ok: false; status: number; error: string } {
  const rawHost = (req.headers.host ?? '').trim();
  if (boundPort > 0 && rawHost) {
    const hostname = parsedUrl.hostname.toLowerCase();
    if (!LOOPBACK_HOSTS.has(hostname)) {
      return { ok: false, status: 403, error: 'forbidden host' };
    }
    if (parsedUrl.port && parsedUrl.port !== String(boundPort)) {
      return { ok: false, status: 403, error: 'forbidden host port' };
    }
    const rawOrigin = typeof req.headers.origin === 'string' ? req.headers.origin.trim().toLowerCase() : '';
    if (rawOrigin && rawOrigin !== 'null' && method !== 'GET' && method !== 'HEAD') {
      const okOrigin =
        rawOrigin.startsWith('http://127.0.0.1:') ||
        rawOrigin.startsWith('http://localhost:') ||
        rawOrigin.startsWith('http://[::1]:') ||
        rawOrigin === 'http://127.0.0.1' ||
        rawOrigin === 'http://localhost';
      if (!okOrigin) {
        return { ok: false, status: 403, error: 'forbidden origin' };
      }
    }
  }
  return { ok: true };
}

export async function startStudioApp(opts: StudioAppOptions): Promise<RunningStudioApp> {
  const { host } = opts;
  const listenHost = opts.listenHost ?? '127.0.0.1';
  const listenPort = opts.listenPort ?? 0;
  const extraHandlers = opts.extraRouteHandlers ?? [];
  const autoQuitMs = opts.autoQuitMs === undefined ? DEFAULT_AUTO_QUIT_MS : opts.autoQuitMs;
  const hasActiveCapture = (): boolean => {
    try {
      return opts.hasActiveCapture?.() === true;
    } catch {
      return false;
    }
  };

  const sseClients = new Set<ServerResponse>();
  let everHadClient = false;
  const heartbeat = setInterval(() => {
    for (const client of sseClients) {
      try {
        client.write(': ping\n\n');
      } catch {
        sseClients.delete(client);
      }
    }
  }, 15_000);
  heartbeat.unref();

  let closing = false;
  let boundPort = 0;
  let server: http.Server;
  let idleTimer: ReturnType<typeof setTimeout> | undefined;
  let idlePoll: ReturnType<typeof setInterval> | undefined;

  const disarmAutoQuit = (): void => {
    if (idleTimer !== undefined) {
      clearTimeout(idleTimer);
      idleTimer = undefined;
    }
  };

  const considerAutoQuit = (): void => {
    if (closing || autoQuitMs <= 0 || !everHadClient) {
      disarmAutoQuit();
      return;
    }
    if (sseClients.size === 0 && !hasActiveCapture()) {
      if (idleTimer === undefined) {
        idleTimer = setTimeout(() => {
          idleTimer = undefined;
          if (closing || sseClients.size > 0 || hasActiveCapture()) {
            considerAutoQuit();
            return;
          }
          process.stderr.write(`pktpath studio-cordis: 0 browser tabs & 0 active captures for ${autoQuitMs}ms; auto-shutting down\n`);
          void closeAll().finally(() => {
            if (opts.onQuitRequested) opts.onQuitRequested();
          });
        }, autoQuitMs);
        idleTimer.unref();
      }
    } else {
      disarmAutoQuit();
    }
  };

  const closeAll = async (): Promise<void> => {
    if (closing) return;
    closing = true;
    disarmAutoQuit();
    if (idlePoll !== undefined) {
      clearInterval(idlePoll);
      idlePoll = undefined;
    }
    clearInterval(heartbeat);
    for (const client of sseClients) {
      try {
        client.end();
      } catch {
        // ignore
      }
    }
    sseClients.clear();
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
    await host.shutdown(5_000);
  };

  const detachSse = (res: ServerResponse): void => {
    if (!sseClients.delete(res)) return;
    considerAutoQuit();
  };

  server = http.createServer(async (req, res) => {
    const method = (req.method ?? 'GET').toUpperCase();
    let url: URL;
    try {
      url = new URL(req.url ?? '/', `http://${req.headers.host ?? '127.0.0.1'}`);
    } catch {
      sendJson(res, 400, { ok: false, error: 'invalid request URL or Host header' });
      return;
    }

    const guard = checkLoopbackGuard(req, method, url, boundPort);
    if (!guard.ok) {
      sendJson(res, guard.status, { ok: false, error: guard.error });
      return;
    }

    const pathname = url.pathname;

    try {
      if (method === 'GET' && pathname === '/api/health') {
        const snap = host.snapshot();
        const adb = host.getService<AdbTransportService>('transport.adb');
        sendJson(res, 200, {
          ok: true,
          pid: process.pid,
          version: host.version,
          runtime: {
            engine: 'cordis-node',
            node_version: process.version,
            platform: process.platform,
            arch: process.arch,
            adb_path: adb?.adbPath ?? '',
            collectors_dir: host.paths.collectorsDir,
          },
          adb_missing: adb ? adb.adbMissing : true,
          sessions_root: host.paths.sessionsRoot,
          plugins_dir: host.paths.pluginsDir,
          active_clients: sseClients.size,
          kernel_plugins_active: snap.active_plugins,
          kernel_plugins_total: snap.total_plugins,
        });
        return;
      }

      if (method === 'GET' && pathname === '/api/app/events') {
        res.writeHead(200, {
          'Content-Type': 'text/event-stream; charset=utf-8',
          'Cache-Control': 'no-cache, no-store',
          'Connection': 'keep-alive',
          'X-Accel-Buffering': 'no',
        });
        try {
          res.write(': connected\n\n');
          res.write('event: ready\ndata: {"ok":true}\n\n');
        } catch {
          return;
        }
        everHadClient = true;
        sseClients.add(res);
        considerAutoQuit();
        let detached = false;
        const onClose = (): void => {
          if (detached) return;
          detached = true;
          detachSse(res);
        };
        req.on('close', onClose);
        res.on('close', onClose);
        return;
      }

      if (method === 'POST' && pathname === '/api/app/quit') {
        sendJson(res, 200, { ok: true });
        setImmediate(() => {
          void closeAll().finally(() => {
            if (opts.onQuitRequested) {
              opts.onQuitRequested();
            }
          });
        });
        return;
      }

      if (method === 'POST' && pathname.startsWith('/api/dialog/')) {
        const action = pathname.slice('/api/dialog/'.length);
        if (action === 'pick-folder' || action === 'save-file' || action === 'open-file' || action === 'reveal') {
          const body = await readJsonBody(req);
          if (action === 'pick-folder') {
            const init = body.initial_dir;
            if (typeof init !== 'string' || init.trim() === '') {
              body.initial_dir = host.paths.sessionsRoot;
            }
          }
          const result = await handleDialogAction(action, body);
          const { httpStatus, ...payload } = result;
          const status = httpStatus ?? (payload.ok || payload.cancelled ? 200 : payload.unsupported ? 501 : 400);
          sendJson(res, status, payload);
          return;
        }
      }

      if (await handleKernelRoute(host, method, pathname, req, res)) return;
      if (await handleAdbRoute(host, method, url, req, res)) return;

      for (const handler of extraHandlers) {
        if (await handler(host, method, url, req, res)) return;
      }

      // All unlisted /api/* routes (including cut linux-ssh routes) strictly return 404.
      if (pathname.startsWith('/api/')) {
        sendJson(res, 404, { ok: false, error: `unknown API endpoint: ${method} ${pathname}` });
        return;
      }

      if (method === 'GET' && serveWebStatic(res, host.paths.webDir, pathname)) {
        return;
      }

      sendJson(res, 404, { ok: false, error: 'not found' });
    } catch (err) {
      if (!res.headersSent) {
        sendJson(res, 500, { ok: false, error: err instanceof Error ? err.message : String(err) });
      }
    }
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(listenPort, listenHost, () => {
      server.off('error', reject);
      resolve();
    });
  });

  if (autoQuitMs > 0) {
    const pollMs = Math.min(1_000, Math.max(25, Math.floor(autoQuitMs / 4)));
    idlePoll = setInterval(() => {
      considerAutoQuit();
    }, pollMs);
    idlePoll.unref();
  }

  const addr = server.address() as AddressInfo;
  boundPort = addr.port;
  const boundUrl = `http://${listenHost}:${addr.port}`;

  return {
    server,
    url: boundUrl,
    port: addr.port,
    host,
    get everHadClient() {
      return everHadClient;
    },
    activeClients: () => sseClients.size,
    close: closeAll,
  };
}
