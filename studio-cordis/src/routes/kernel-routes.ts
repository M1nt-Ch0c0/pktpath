import type { IncomingMessage, ServerResponse } from 'node:http';
import type { CordisHost } from '../kernel/host.ts';
import { readJsonBody, sendJson, serveStaticFile } from '../server/http-utils.ts';

export async function handleKernelRoute(
  host: CordisHost,
  method: string,
  pathname: string,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<boolean> {
  if (method === 'GET' && pathname === '/api/kernel/state') {
    sendJson(res, 200, { ok: true, state: host.snapshot() });
    return true;
  }

  if (method === 'GET' && pathname.startsWith('/api/kernel/plugin-asset/')) {
    const rest = pathname.slice('/api/kernel/plugin-asset/'.length);
    const slash = rest.indexOf('/');
    if (slash <= 0) {
      sendJson(res, 400, { ok: false, error: 'invalid plugin asset path' });
      return true;
    }
    let pluginId: string;
    let relPath: string;
    try {
      pluginId = decodeURIComponent(rest.slice(0, slash));
      relPath = decodeURIComponent(rest.slice(slash + 1));
    } catch {
      sendJson(res, 400, { ok: false, error: 'invalid URI encoding in plugin asset path' });
      return true;
    }
    const full = host.resolvePluginAsset(pluginId, relPath);
    if (!full) {
      sendJson(res, 404, { ok: false, error: 'asset not found' });
      return true;
    }
    serveStaticFile(res, full);
    return true;
  }

  if (method !== 'POST') return false;

  if (pathname === '/api/kernel/plugins/toggle') {
    const body = await readJsonBody(req);
    const id = typeof body.id === 'string' ? body.id.trim() : '';
    const enabled = Boolean(body.enabled);
    if (!id) {
      sendJson(res, 400, { ok: false, error: 'id is required' });
      return true;
    }
    const out = await host.toggle(id, enabled);
    sendJson(res, out.ok ? 200 : 400, out);
    return true;
  }

  if (pathname === '/api/kernel/plugins/config') {
    const body = await readJsonBody(req);
    const id = typeof body.id === 'string' ? body.id.trim() : '';
    const config = body.config && typeof body.config === 'object' && !Array.isArray(body.config)
      ? (body.config as Record<string, unknown>)
      : undefined;
    if (!id || !config) {
      sendJson(res, 400, { ok: false, error: 'id and config object are required' });
      return true;
    }
    const out = await host.updateConfig(id, config);
    sendJson(res, out.ok ? 200 : 400, out);
    return true;
  }

  if (pathname === '/api/kernel/plugins/reset') {
    const body = await readJsonBody(req);
    const id = typeof body.id === 'string' ? body.id.trim() : '';
    if (!id) {
      sendJson(res, 400, { ok: false, error: 'id is required' });
      return true;
    }
    const out = await host.resetConfig(id);
    sendJson(res, out.ok ? 200 : 400, out);
    return true;
  }

  if (pathname === '/api/kernel/plugins/reload') {
    const body = await readJsonBody(req);
    const id = typeof body.id === 'string' ? body.id.trim() : '';
    if (!id) {
      sendJson(res, 400, { ok: false, error: 'id is required' });
      return true;
    }
    const out = await host.reload(id);
    sendJson(res, out.ok ? 200 : 400, out);
    return true;
  }

  if (pathname === '/api/kernel/plugins/preview') {
    const body = await readJsonBody(req);
    const sourcePath = typeof body.path === 'string' ? body.path.trim() : '';
    if (!sourcePath) {
      sendJson(res, 400, { ok: false, error: 'path is required' });
      return true;
    }
    try {
      const preview = host.previewExternal(sourcePath);
      sendJson(res, 200, { ok: true, preview });
    } catch (err) {
      sendJson(res, 400, { ok: false, error: err instanceof Error ? err.message : String(err) });
    }
    return true;
  }

  if (pathname === '/api/kernel/plugins/install') {
    const body = await readJsonBody(req);
    const sourcePath = typeof body.path === 'string' ? body.path.trim() : '';
    if (!sourcePath) {
      sendJson(res, 400, { ok: false, error: 'path is required' });
      return true;
    }
    const out = await host.installExternal(sourcePath);
    sendJson(res, out.ok ? 200 : 400, out);
    return true;
  }

  if (pathname === '/api/kernel/plugins/uninstall') {
    const body = await readJsonBody(req);
    const id = typeof body.id === 'string' ? body.id.trim() : '';
    if (!id) {
      sendJson(res, 400, { ok: false, error: 'id is required' });
      return true;
    }
    const out = await host.uninstallExternal(id);
    sendJson(res, out.ok ? 200 : 400, out);
    return true;
  }

  if (pathname === '/api/kernel/export') {
    const body = await readJsonBody(req);
    const exporterId = typeof body.exporter_id === 'string' ? body.exporter_id.trim() : '';
    const sessionId = typeof body.session_id === 'string' ? body.session_id.trim() : '';
    const outPath = typeof body.out_path === 'string' ? body.out_path : undefined;
    const params = body.params && typeof body.params === 'object' && !Array.isArray(body.params)
      ? (body.params as Record<string, unknown>)
      : {};
    if (!exporterId || !sessionId) {
      sendJson(res, 400, { ok: false, error: 'exporter_id and session_id are required' });
      return true;
    }
    try {
      const out = await host.runExport({
        exporter_id: exporterId,
        session_id: sessionId,
        out_path: outPath,
        params,
      });
      sendJson(res, out.ok ? 200 : 400, out);
    } catch (err) {
      sendJson(res, 400, { ok: false, error: err instanceof Error ? err.message : String(err) });
    }
    return true;
  }

  return false;
}
