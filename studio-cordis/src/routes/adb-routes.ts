import type { IncomingMessage, ServerResponse } from 'node:http';
import type { CordisHost } from '../kernel/host.ts';
import type { AdbTransportService } from '../plugins/adb/android-adb.ts';
import {
  CaptureBadRequestError,
  CaptureConflictError,
  type CaptureController,
} from '../plugins/adb/capture-controller.ts';
import type { DaemonCaptureService } from '../plugins/adb/daemon.ts';
import type { CaptureSpec } from '../plugins/adb/ebpf-tc.ts';
import type { OneshotCaptureService } from '../plugins/adb/oneshot.ts';
import { readJsonBody, sendJson } from '../server/http-utils.ts';

function statusCodeForError(err: unknown): number {
  if (err instanceof CaptureConflictError) return err.statusCode;
  if (err instanceof CaptureBadRequestError) return err.statusCode;
  return 400;
}

export async function handleAdbRoute(
  host: CordisHost,
  method: string,
  url: URL,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<boolean> {
  const pathname = url.pathname;

  if (method === 'GET' && pathname === '/api/devices') {
    const adb = host.getService<AdbTransportService>('transport.adb');
    if (!adb) {
      sendJson(res, 400, { ok: false, error: 'builtin.transport.android-adb plugin is disabled' });
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
      sendJson(res, 400, { ok: false, error: 'builtin.transport.android-adb plugin is disabled' });
      return true;
    }
    const body = await readJsonBody(req);
    const serial = typeof body.serial === 'string' ? body.serial.trim() : '';
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
      sendJson(res, 400, { ok: false, error: 'builtin.transport.android-adb plugin is disabled' });
      return true;
    }
    const serial = (url.searchParams.get('serial') ?? '').trim();
    const dev = (url.searchParams.get('dev') ?? '').trim() || undefined;
    const scope = (url.searchParams.get('scope') ?? '').trim() || 'all';
    if (!serial) {
      sendJson(res, 400, { ok: false, error: 'serial query parameter is required' });
      return true;
    }
    try {
      const info = await adb.inspectDevice(serial, dev, scope);
      sendJson(res, 200, { ok: true, ...info });
    } catch (err) {
      sendJson(res, 400, { ok: false, error: err instanceof Error ? err.message : String(err) });
    }
    return true;
  }

  if (method === 'GET' && pathname === '/api/device/apps') {
    const adb = host.getService<AdbTransportService>('transport.adb');
    if (!adb) {
      sendJson(res, 400, { ok: false, error: 'builtin.transport.android-adb plugin is disabled' });
      return true;
    }
    const serial = (url.searchParams.get('serial') ?? '').trim();
    if (!serial) {
      sendJson(res, 400, { ok: false, error: 'serial query parameter is required' });
      return true;
    }
    try {
      const apps = await adb.listApps(serial);
      sendJson(res, 200, { ok: true, apps });
    } catch (err) {
      sendJson(res, 400, { ok: false, error: err instanceof Error ? err.message : String(err) });
    }
    return true;
  }

  if (method === 'POST' && pathname === '/api/capture/start') {
    const body = await readJsonBody(req);
    const mode = typeof body.mode === 'string' && body.mode.trim() ? body.mode.trim() : 'oneshot';
    if (mode !== 'oneshot' && mode !== 'daemon') {
      sendJson(res, 400, { ok: false, error: `unsupported capture mode "${mode}" (oneshot|daemon)` });
      return true;
    }
    try {
      if (mode === 'oneshot') {
        const oneshot = host.getService<OneshotCaptureService>('capture.mode.oneshot');
        if (!oneshot) {
          sendJson(res, 400, { ok: false, error: 'builtin.mode.oneshot (or builtin.collector.ebpf-tc) plugin is disabled' });
          return true;
        }
        const out = await oneshot.start({ ...(body as unknown as CaptureSpec), mode: 'oneshot' });
        sendJson(res, 200, out);
      } else {
        const daemon = host.getService<DaemonCaptureService>('capture.mode.daemon');
        if (!daemon) {
          sendJson(res, 400, { ok: false, error: 'builtin.mode.daemon (or builtin.collector.ebpf-tc) plugin is disabled' });
          return true;
        }
        const out = await daemon.start({ ...(body as unknown as CaptureSpec), mode: 'daemon' });
        sendJson(res, 200, out);
      }
    } catch (err) {
      sendJson(res, statusCodeForError(err), { ok: false, error: err instanceof Error ? err.message : String(err) });
    }
    return true;
  }

  if (method === 'POST' && pathname === '/api/capture/flush') {
    const daemon = host.getService<DaemonCaptureService>('capture.mode.daemon');
    if (!daemon) {
      sendJson(res, 400, { ok: false, error: 'builtin.mode.daemon plugin is disabled' });
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
      sendJson(res, 200, { ok: true, status: 'idle' });
      return true;
    }
    const snap = await controller.status();
    sendJson(res, 200, snap);
    return true;
  }

  if (method === 'POST' && pathname === '/api/capture/stop') {
    const controller = host.getService<CaptureController>('capture.controller');
    if (!controller) {
      sendJson(res, 400, { ok: false, error: 'no capture mode plugin is active' });
      return true;
    }
    const out = await controller.stop();
    sendJson(res, out.ok ? 200 : 400, out);
    return true;
  }

  return false;
}
