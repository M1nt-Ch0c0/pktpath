import type { IncomingMessage, ServerResponse } from 'node:http';
import type { CordisHost } from '../kernel/host.ts';
import type { AdbTransportService } from '../plugins/adb/android-adb.ts';
import {
  CaptureBadRequestError,
  CaptureConflictError,
  CaptureStartFailedError,
  type CaptureController,
} from '../plugins/adb/capture-controller.ts';
import type { DaemonCaptureService } from '../plugins/adb/daemon.ts';
import type { CaptureSpec } from '../plugins/adb/ebpf-tc.ts';
import type { OneshotCaptureService } from '../plugins/adb/oneshot.ts';
import {
  deleteRuntimePlugin,
  importRuntimePlugin,
  listRuntimePlugins,
  previewRuntimePlugin,
  toggleRuntimePlugin,
} from '../plugins/adb/runtime-plugins.ts';
import { readJsonBody, sendJson } from '../server/http-utils.ts';

function statusCodeForError(err: unknown): number {
  if (err instanceof CaptureConflictError) return err.statusCode;
  if (err instanceof CaptureBadRequestError) return err.statusCode;
  if (err && typeof err === 'object' && 'statusCode' in err && typeof (err as { statusCode?: unknown }).statusCode === 'number') {
    return (err as { statusCode: number }).statusCode;
  }
  return 400;
}

async function resolveSerial(adb: AdbTransportService, explicit: string): Promise<string> {
  const trimmed = explicit.trim();
  if (trimmed) return trimmed;
  return adb.defaultSerial();
}

export async function handleAdbRoute(
  host: CordisHost,
  method: string,
  url: URL,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<boolean> {
  const pathname = url.pathname;

  // ---- Device-side Runtime JSON Plugins (/api/plugins*) ----
  if (method === 'GET' && pathname === '/api/plugins') {
    const { plugins, slots } = listRuntimePlugins(host.paths.pluginsDir);
    sendJson(res, 200, {
      ok: true,
      plugins_dir: host.paths.pluginsDir,
      plugins,
      slots,
    });
    return true;
  }

  if (method === 'POST' && pathname === '/api/plugins/preview') {
    try {
      const body = await readJsonBody(req);
      const out = previewRuntimePlugin(host.paths.pluginsDir, body);
      sendJson(res, 200, out);
    } catch (err) {
      sendJson(res, statusCodeForError(err), { ok: false, error: err instanceof Error ? err.message : String(err) });
    }
    return true;
  }

  if (method === 'POST' && pathname === '/api/plugins/import') {
    try {
      const body = await readJsonBody(req);
      const out = importRuntimePlugin(host.paths.pluginsDir, body);
      sendJson(res, 200, out);
    } catch (err) {
      sendJson(res, statusCodeForError(err), { ok: false, error: err instanceof Error ? err.message : String(err) });
    }
    return true;
  }

  if (method === 'POST' && pathname === '/api/plugins/toggle') {
    try {
      const body = await readJsonBody(req);
      const out = toggleRuntimePlugin(host.paths.pluginsDir, body);
      sendJson(res, 200, out);
    } catch (err) {
      sendJson(res, statusCodeForError(err), { ok: false, error: err instanceof Error ? err.message : String(err) });
    }
    return true;
  }

  if (method === 'POST' && pathname === '/api/plugins/delete') {
    try {
      const body = await readJsonBody(req);
      const out = deleteRuntimePlugin(host.paths.pluginsDir, body);
      sendJson(res, 200, out);
    } catch (err) {
      sendJson(res, statusCodeForError(err), { ok: false, error: err instanceof Error ? err.message : String(err) });
    }
    return true;
  }

  // ---- Devices & ADB ----
  if (method === 'GET' && pathname === '/api/devices') {
    const adb = host.getService<AdbTransportService>('transport.adb');
    if (!adb) {
      sendJson(res, 400, { ok: false, error: '「Android ADB 连接」插件未启用，请先在插件页启用后再使用设备与采集功能。' });
      return true;
    }
    try {
      const result = await adb.listDevices();
      sendJson(res, 200, { ok: true, ...result });
    } catch (err) {
      sendJson(res, 500, { ok: false, error: err instanceof Error ? err.message : String(err) });
    }
    return true;
  }

  if (method === 'POST' && pathname === '/api/device/prepare') {
    const adb = host.getService<AdbTransportService>('transport.adb');
    if (!adb) {
      sendJson(res, 400, { ok: false, error: '「Android ADB 连接」插件未启用，请先在插件页启用后再使用设备与采集功能。' });
      return true;
    }
    const body = await readJsonBody(req);
    const serial = await resolveSerial(adb, typeof body.serial === 'string' ? body.serial : '');
    if (!serial) {
      sendJson(res, 400, { ok: false, error: 'serial is required' });
      return true;
    }
    try {
      const info = await adb.prepareDevice(serial);
      sendJson(res, 200, { ok: true, ...info });
    } catch (err) {
      sendJson(res, 400, { ok: false, error: err instanceof Error ? err.message : String(err) });
    }
    return true;
  }

  if (method === 'GET' && pathname === '/api/device/inspect') {
    const adb = host.getService<AdbTransportService>('transport.adb');
    if (!adb) {
      sendJson(res, 400, { ok: false, error: '「Android ADB 连接」插件未启用，请先在插件页启用后再使用设备与采集功能。' });
      return true;
    }
    const serial = await resolveSerial(adb, url.searchParams.get('serial') ?? '');
    const dev = (url.searchParams.get('dev') ?? '').trim() || undefined;
    const scope = (url.searchParams.get('scope') ?? '').trim() || 'tc-egress';
    const pluginsParam = (url.searchParams.get('plugins') ?? '').trim().toLowerCase();
    const enablePlugins = !(pluginsParam === '0' || pluginsParam === 'false' || pluginsParam === 'off');
    if (!serial) {
      sendJson(res, 400, { ok: false, error: 'serial query parameter is required' });
      return true;
    }
    try {
      const info = await adb.inspectDevice(serial, dev, scope, enablePlugins);
      sendJson(res, 200, { ok: true, ...info });
    } catch (err) {
      sendJson(res, 400, { ok: false, error: err instanceof Error ? err.message : String(err) });
    }
    return true;
  }

  if (method === 'GET' && pathname === '/api/device/apps') {
    const adb = host.getService<AdbTransportService>('transport.adb');
    if (!adb) {
      sendJson(res, 400, { ok: false, error: '「Android ADB 连接」插件未启用，请先在插件页启用后再使用设备与采集功能。' });
      return true;
    }
    const serial = await resolveSerial(adb, url.searchParams.get('serial') ?? '');
    if (!serial) {
      sendJson(res, 400, { ok: false, error: 'serial query parameter is required' });
      return true;
    }
    try {
      const apps = await adb.listApps(serial);
      sendJson(res, 200, { ok: true, serial, apps });
    } catch (err) {
      sendJson(res, 400, { ok: false, error: err instanceof Error ? err.message : String(err) });
    }
    return true;
  }

  if (method === 'POST' && pathname === '/api/capture/start') {
    const body = await readJsonBody(req);
    const mode = typeof body.mode === 'string' && body.mode.trim() ? body.mode.trim().toLowerCase() : 'oneshot';
    if (mode !== 'oneshot' && mode !== 'daemon') {
      sendJson(res, 400, { ok: false, error: `unsupported capture mode "${mode}" (oneshot|daemon)` });
      return true;
    }
    try {
      if (mode === 'oneshot') {
        const oneshot = host.getService<OneshotCaptureService>('capture.mode.oneshot');
        if (!oneshot) {
          sendJson(res, 400, { ok: false, error: '短时采集功能未启用，请先在插件页同时启用「短时采集模式 (Oneshot)」和「eBPF TC / Socket 采集器」。' });
          return true;
        }
        const out = await oneshot.start({ ...(body as unknown as CaptureSpec), mode: 'oneshot' });
        sendJson(res, 200, out);
      } else {
        const daemon = host.getService<DaemonCaptureService>('capture.mode.daemon');
        if (!daemon) {
          sendJson(res, 400, { ok: false, error: '常驻录制功能未启用，请先在插件页同时启用「常驻录制模式 (Daemon)」和「eBPF TC / Socket 采集器」。' });
          return true;
        }
        const out = await daemon.start({ ...(body as unknown as CaptureSpec), mode: 'daemon' });
        sendJson(res, 200, out);
      }
    } catch (err) {
      if (err instanceof CaptureStartFailedError) {
        sendJson(res, err.statusCode, {
          ok: false,
          error: err.message,
          capture_id: err.captureId,
          log_lines: err.logLines,
          log_tail: err.logLines,
        });
        return true;
      }
      if (err instanceof CaptureConflictError) {
        sendJson(res, err.statusCode, {
          ok: false,
          error: err.message,
          ...(err.captureId ? { capture_id: err.captureId } : {}),
          ...(err.logLines ? { log_lines: err.logLines, log_tail: err.logLines } : {}),
        });
        return true;
      }
      sendJson(res, statusCodeForError(err), { ok: false, error: err instanceof Error ? err.message : String(err) });
    }
    return true;
  }

  if (method === 'POST' && pathname === '/api/capture/flush') {
    const daemon = host.getService<DaemonCaptureService>('capture.mode.daemon');
    if (!daemon) {
      sendJson(res, 400, { ok: false, error: '「常驻录制模式 (Daemon)」插件未启用，请先在插件页启用后再执行手动落盘。' });
      return true;
    }
    try {
      const out = await daemon.flush();
      sendJson(res, 200, out);
    } catch (err) {
      sendJson(res, statusCodeForError(err), { ok: false, error: err instanceof Error ? err.message : String(err) });
    }
    return true;
  }

  if (method === 'GET' && pathname === '/api/capture/status') {
    const controller = host.getService<CaptureController>('capture.controller');
    if (!controller) {
      sendJson(res, 200, {
        ok: true,
        active: false,
        status: 'idle',
        phase: 'idle',
        capture_id: '',
        serial: '',
        mode: '',
        dev: '',
        scope: '',
        elapsed_sec: 0,
        duration_sec: 0,
        log_tail: [],
        log_lines: [],
        last_session_id: '',
        session_path: '',
        error: '',
      });
      return true;
    }
    const snap = await controller.status();
    sendJson(res, 200, snap);
    return true;
  }

  if (method === 'POST' && pathname === '/api/capture/stop') {
    const controller = host.getService<CaptureController>('capture.controller');
    if (!controller) {
      sendJson(res, 400, { ok: false, error: '当前没有已启用的采集模式插件，请先在插件页启用短时采集或常驻录制插件。' });
      return true;
    }
    const out = await controller.stop();
    sendJson(res, out.ok ? 200 : 400, out);
    return true;
  }

  return false;
}
