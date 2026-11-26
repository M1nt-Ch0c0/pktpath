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

export interface StudioAppOptions {
  host: CordisHost;
  listenHost?: string;
  listenPort?: number;
  extraRouteHandlers?: ExtraRouteHandler[];
  onQuitRequested?: () => void;
}

export interface RunningStudioApp {
  readonly server: http.Server;
  readonly url: string;
  readonly port: number;
  readonly host: CordisHost;
  close(): Promise<void>;
}

export async function startStudioApp(opts: StudioAppOptions): Promise<RunningStudioApp> {
  const { host } = opts;
  const listenHost = opts.listenHost ?? '127.0.0.1';
  const listenPort = opts.listenPort ?? 0;
  const extraHandlers = opts.extraRouteHandlers ?? [];

  const sseClients = new Set<ServerResponse>();
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
  let server: http.Server;

  const closeAll = async (): Promise<void> => {
    if (closing) return;
    closing = true;
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

  server = http.createServer(async (req, res) => {
    const method = (req.method ?? 'GET').toUpperCase();
    let url: URL;
    try {
      url = new URL(req.url ?? '/', `http://${req.headers.host ?? '127.0.0.1'}`);
    } catch {
      sendJson(res, 400, { ok: false, error: 'invalid request URL or Host header' });
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
          'Cache-Control': 'no-cache',
          Connection: 'keep-alive',
        });
        res.write('event: ready\ndata: {"ok":true}\n\n');
        sseClients.add(res);
        req.on('close', () => {
          sseClients.delete(res);
        });
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
          const result = await handleDialogAction(action, body);
          sendJson(res, result.ok ? 200 : result.unsupported ? 501 : 400, result);
          return;
        }
      }

      if (await handleKernelRoute(host, method, pathname, req, res)) return;
      if (await handleAdbRoute(host, method, url, req, res)) return;

      for (const handler of extraHandlers) {
        if (await handler(host, method, url, req, res)) return;
      }

      // All unlisted /api/* routes (including all 6 removed Wave 2/3 feature routes) strictly return 404.
      if (pathname.startsWith('/api/')) {
        sendJson(res, 404, { ok: false, error: 'not found' });
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

  const addr = server.address() as AddressInfo;
  const boundUrl = `http://${listenHost}:${addr.port}`;

  return {
    server,
    url: boundUrl,
    port: addr.port,
    host,
    close: closeAll,
  };
}
