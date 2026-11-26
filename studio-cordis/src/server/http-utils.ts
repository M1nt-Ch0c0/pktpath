import fs from 'node:fs';
import type { IncomingMessage, ServerResponse } from 'node:http';
import path from 'node:path';
import { stringifyJsonSafe } from '../kernel/u64-json.ts';

const MAX_BODY_BYTES = 4 * 1024 * 1024; // 4 MiB

const MIME_MAP: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
  '.csv': 'text/csv; charset=utf-8',
};

export function sendJson(res: ServerResponse, status: number, payload: unknown): void {
  const body = stringifyJsonSafe(payload);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

export function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8').trim();
      if (!raw) {
        resolve({});
        return;
      }
      try {
        const parsed: unknown = JSON.parse(raw);
        if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
          reject(new Error('request body must be a JSON object'));
          return;
        }
        resolve(parsed as Record<string, unknown>);
      } catch (err) {
        reject(new Error(`invalid JSON body: ${err instanceof Error ? err.message : String(err)}`));
      }
    });
    req.on('error', reject);
  });
}

export function serveStaticFile(res: ServerResponse, filePath: string): void {
  const ext = path.extname(filePath).toLowerCase();
  const mime = MIME_MAP[ext] ?? 'application/octet-stream';
  const data = fs.readFileSync(filePath);
  res.writeHead(200, {
    'Content-Type': mime,
    'Content-Length': data.length,
    'Cache-Control': 'no-cache',
  });
  res.end(data);
}

export function serveWebStatic(res: ServerResponse, webDir: string, pathname: string): boolean {
  if (!fs.existsSync(webDir)) return false;
  const rootReal = fs.realpathSync(webDir);
  let rel = pathname.replace(/^\/+/, '');
  if (!rel) rel = 'index.html';
  if (rel.split('/').includes('..')) return false;
  const candidate = path.resolve(rootReal, rel);
  if (!candidate.startsWith(rootReal + path.sep) && candidate !== rootReal) return false;
  if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
    const real = fs.realpathSync(candidate);
    if (!real.startsWith(rootReal + path.sep)) return false;
    serveStaticFile(res, real);
    return true;
  }
  return false;
}
