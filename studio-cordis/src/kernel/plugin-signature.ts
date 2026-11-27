// Pure-Node Ed25519 whole-package signing, verification, and ZIP packaging
// (zero third-party dependencies).
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';

export const SIGNATURE_FILE_NAME = 'signature.json';
const SIG_PAYLOAD_HEADER = 'pktpath-plugin-sig-v1';
const SHA256_RE = /^[a-f0-9]{64}$/;

export type PluginSignatureStatus = 'verified' | 'unsigned' | 'invalid';
export type PluginSignatureTrust = 'trusted_key' | 'self_declared' | 'none';

export interface PluginSignatureDoc {
  version: 1;
  algorithm: 'ed25519';
  public_key_pem: string;
  key_fingerprint: string;
  signed_at: string;
  files: Record<string, string>;
  signature: string;
}

export interface PluginSignatureResult {
  status: PluginSignatureStatus;
  trust: PluginSignatureTrust;
  key_fingerprint?: string;
  signed_at?: string;
  file_count?: number;
  message: string;
  reason?: string;
}

export function generateEd25519KeyPair(): {
  publicKeyPem: string;
  privateKeyPem: string;
  fingerprint: string;
} {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const fingerprint = computePublicKeyFingerprint(publicKeyPem);
  return { publicKeyPem, privateKeyPem, fingerprint };
}

export function computePublicKeyFingerprint(publicKeyPem: string): string {
  const keyObj = crypto.createPublicKey(publicKeyPem);
  const der = keyObj.export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex');
}

function collectPackageFileDigests(rootDir: string): Record<string, string> {
  const out: Record<string, string> = {};
  const walk = (dir: string, relPrefix: string): void => {
    const entries = fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (entry.isSymbolicLink()) {
        throw new Error(`symlink not allowed in signed plugin package: ${relPrefix}${entry.name}`);
      }
      const rel = relPrefix ? `${relPrefix}/${entry.name}` : entry.name;
      if (rel === SIGNATURE_FILE_NAME) continue;
      const abs = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(abs, rel);
      } else if (entry.isFile()) {
        const buf = fs.readFileSync(abs);
        out[rel] = crypto.createHash('sha256').update(buf).digest('hex');
      }
    }
  };
  walk(rootDir, '');
  return out;
}

function buildCanonicalPayload(files: Record<string, string>): Buffer {
  const keys = Object.keys(files).sort();
  const lines = [SIG_PAYLOAD_HEADER];
  for (const k of keys) {
    lines.push(`${files[k]}  ${k}`);
  }
  return Buffer.from(`${lines.join('\n')}\n`, 'utf8');
}

/**
 * Signs EVERY regular file in `pluginDir` (manifest.json, JS/TS entrypoint,
 * .bpf.o objects, and any helper files; excluding signature.json itself)
 * using Ed25519 and writes `signature.json` at `pluginDir` root.
 */
export function signPluginPackageDir(pluginDir: string, privateKeyPem: string): PluginSignatureDoc {
  const privKey = crypto.createPrivateKey(privateKeyPem);
  const pubKey = crypto.createPublicKey(privKey);
  const publicKeyPem = pubKey.export({ type: 'spki', format: 'pem' }).toString();
  const keyFingerprint = computePublicKeyFingerprint(publicKeyPem);

  const files = collectPackageFileDigests(pluginDir);
  if (!files['manifest.json']) {
    throw new Error('cannot sign plugin package without manifest.json');
  }

  const payload = buildCanonicalPayload(files);
  const sigBuf = crypto.sign(null, payload, privKey);
  const doc: PluginSignatureDoc = {
    version: 1,
    algorithm: 'ed25519',
    public_key_pem: publicKeyPem,
    key_fingerprint: keyFingerprint,
    signed_at: new Date().toISOString(),
    files,
    signature: sigBuf.toString('base64'),
  };
  fs.writeFileSync(path.join(pluginDir, SIGNATURE_FILE_NAME), JSON.stringify(doc, null, 2) + '\n', 'utf8');
  return doc;
}

/**
 * Verifies whole-package Ed25519 signature if `signature.json` exists.
 * Distinguishes `unsigned` vs `invalid` vs `verified`, and never conflates
 * self-declared public key verification with an official trusted key.
 */
export function verifyPluginPackageSignature(
  pluginDir: string,
  trustedFingerprints?: readonly string[],
): PluginSignatureResult {
  const sigPath = path.join(pluginDir, SIGNATURE_FILE_NAME);
  if (!fs.existsSync(sigPath)) {
    return {
      status: 'unsigned',
      trust: 'none',
      message: '插件未签名',
    };
  }

  let raw: unknown;
  try {
    raw = JSON.parse(fs.readFileSync(sigPath, 'utf8'));
  } catch (err) {
    return {
      status: 'invalid',
      trust: 'none',
      message: '签名文件损坏',
      reason: `signature.json parse error: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    return { status: 'invalid', trust: 'none', message: '签名格式无效', reason: 'signature.json must be an object' };
  }
  const doc = raw as Record<string, unknown>;
  if (doc.version !== 1 || doc.algorithm !== 'ed25519') {
    return {
      status: 'invalid',
      trust: 'none',
      message: '不支持的签名版本或算法',
      reason: `unsupported signature version/algorithm: ${String(doc.version)}/${String(doc.algorithm)}`,
    };
  }
  const pubPem = typeof doc.public_key_pem === 'string' ? doc.public_key_pem : '';
  const declaredFp = typeof doc.key_fingerprint === 'string' ? doc.key_fingerprint.trim().toLowerCase() : '';
  const sigB64 = typeof doc.signature === 'string' ? doc.signature.trim() : '';
  const declaredFiles = doc.files;

  if (!pubPem || !SHA256_RE.test(declaredFp) || !sigB64 || typeof declaredFiles !== 'object' || declaredFiles === null || Array.isArray(declaredFiles)) {
    return {
      status: 'invalid',
      trust: 'none',
      message: '签名字段缺失或格式无效',
      reason: 'missing or malformed public_key_pem, key_fingerprint, files, or signature',
    };
  }

  let pubKey: crypto.KeyObject;
  let actualFp: string;
  try {
    pubKey = crypto.createPublicKey(pubPem);
    actualFp = computePublicKeyFingerprint(pubPem);
  } catch (err) {
    return {
      status: 'invalid',
      trust: 'none',
      message: '签名公钥无效',
      reason: `invalid Ed25519 public key: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  if (actualFp !== declaredFp) {
    return {
      status: 'invalid',
      trust: 'none',
      key_fingerprint: actualFp,
      message: '公钥指纹不匹配',
      reason: `key_fingerprint mismatch: declared ${declaredFp}, actual ${actualFp}`,
    };
  }

  let actualFiles: Record<string, string>;
  try {
    actualFiles = collectPackageFileDigests(pluginDir);
  } catch (err) {
    return {
      status: 'invalid',
      trust: 'none',
      key_fingerprint: actualFp,
      message: '插件目录包含非法文件',
      reason: err instanceof Error ? err.message : String(err),
    };
  }

  const declaredMap = declaredFiles as Record<string, unknown>;
  const actualKeys = Object.keys(actualFiles).sort();
  const declaredKeys = Object.keys(declaredMap).sort();

  if (actualKeys.length !== declaredKeys.length || actualKeys.some((k, i) => k !== declaredKeys[i])) {
    const missing = declaredKeys.filter((k) => !(k in actualFiles));
    const extra = actualKeys.filter((k) => !(k in declaredMap));
    return {
      status: 'invalid',
      trust: 'none',
      key_fingerprint: actualFp,
      message: '插件文件清单与签名不一致',
      reason: `file list mismatch (missing: [${missing.join(', ')}], extra: [${extra.join(', ')}])`,
    };
  }

  const normalizedDeclared: Record<string, string> = {};
  for (const k of actualKeys) {
    const want = declaredMap[k];
    if (typeof want !== 'string' || !SHA256_RE.test(want)) {
      return {
        status: 'invalid',
        trust: 'none',
        key_fingerprint: actualFp,
        message: '签名文件摘要格式无效',
        reason: `invalid sha256 entry for ${k}`,
      };
    }
    if (actualFiles[k] !== want) {
      return {
        status: 'invalid',
        trust: 'none',
        key_fingerprint: actualFp,
        message: `文件内容已被篡改：${k}`,
        reason: `file digest mismatch for ${k}: expected ${want}, got ${actualFiles[k]}`,
      };
    }
    normalizedDeclared[k] = want;
  }

  const payload = buildCanonicalPayload(normalizedDeclared);
  let verified = false;
  try {
    const sigBuf = Buffer.from(sigB64, 'base64');
    verified = crypto.verify(null, payload, pubKey, sigBuf);
  } catch {
    verified = false;
  }

  if (!verified) {
    return {
      status: 'invalid',
      trust: 'none',
      key_fingerprint: actualFp,
      message: 'Ed25519 签名验证失败',
      reason: 'ed25519 cryptographic signature verification failed',
    };
  }

  const isTrusted = Array.isArray(trustedFingerprints)
    && trustedFingerprints.some((fp) => fp.trim().toLowerCase() === actualFp);

  return {
    status: 'verified',
    trust: isTrusted ? 'trusted_key' : 'self_declared',
    key_fingerprint: actualFp,
    signed_at: typeof doc.signed_at === 'string' ? doc.signed_at : undefined,
    file_count: actualKeys.length,
    message: isTrusted
      ? `签名完整（受信任公钥，指纹 ${actualFp.slice(0, 16)}…）`
      : `签名完整（包内公钥自验，指纹 ${actualFp.slice(0, 16)}…，非官方背书）`,
  };
}

// --- Pure-Node ZIP writer (DEFLATE / CRC32, compatible with extractZipSafe & standard unzip) ---

const CRC32_TABLE = (() => {
  const tbl = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) {
      c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    }
    tbl[n] = c >>> 0;
  }
  return tbl;
})();

function crc32(buf: Buffer): number {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i += 1) {
    c = CRC32_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

export function createZipFromDir(srcDir: string, outZipPath: string): { fileCount: number; bytes: number } {
  const entries: Array<{ rel: string; data: Buffer }> = [];
  const walk = (dir: string, prefix: string): void => {
    const items = fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name));
    for (const item of items) {
      if (item.isSymbolicLink()) {
        throw new Error(`cannot pack symlink into plugin zip: ${prefix}${item.name}`);
      }
      const rel = prefix ? `${prefix}/${item.name}` : item.name;
      const abs = path.join(dir, item.name);
      if (item.isDirectory()) {
        walk(abs, rel);
      } else if (item.isFile()) {
        entries.push({ rel, data: fs.readFileSync(abs) });
      }
    }
  };
  walk(srcDir, '');

  const localParts: Buffer[] = [];
  const cdParts: Buffer[] = [];
  let offset = 0;

  for (const entry of entries) {
    const nameBuf = Buffer.from(entry.rel, 'utf8');
    const crc = crc32(entry.data);
    const compressed = zlib.deflateRawSync(entry.data);
    const useDeflate = compressed.length < entry.data.length;
    const body = useDeflate ? compressed : entry.data;
    const method = useDeflate ? 8 : 0;

    const lfh = Buffer.alloc(30);
    lfh.writeUInt32LE(0x04034b50, 0);
    lfh.writeUInt16LE(20, 4); // version needed
    lfh.writeUInt16LE(0x0800, 6); // UTF-8 filename flag
    lfh.writeUInt16LE(method, 8);
    lfh.writeUInt16LE(0, 10); // mod time
    lfh.writeUInt16LE(0, 12); // mod date
    lfh.writeUInt32LE(crc, 14);
    lfh.writeUInt32LE(body.length, 18);
    lfh.writeUInt32LE(entry.data.length, 22);
    lfh.writeUInt16LE(nameBuf.length, 26);
    lfh.writeUInt16LE(0, 28); // extra len

    localParts.push(lfh, nameBuf, body);

    const cdh = Buffer.alloc(46);
    cdh.writeUInt32LE(0x02014b50, 0);
    cdh.writeUInt16LE(20, 4); // version made by
    cdh.writeUInt16LE(20, 6); // version needed
    cdh.writeUInt16LE(0x0800, 8); // UTF-8
    cdh.writeUInt16LE(method, 10);
    cdh.writeUInt16LE(0, 12);
    cdh.writeUInt16LE(0, 14);
    cdh.writeUInt32LE(crc, 16);
    cdh.writeUInt32LE(body.length, 20);
    cdh.writeUInt32LE(entry.data.length, 24);
    cdh.writeUInt16LE(nameBuf.length, 28);
    cdh.writeUInt16LE(0, 30); // extra len
    cdh.writeUInt16LE(0, 32); // comment len
    cdh.writeUInt16LE(0, 34); // disk start
    cdh.writeUInt16LE(0, 36); // internal attrs
    cdh.writeUInt32LE((0o100644 << 16) >>> 0, 38); // regular file POSIX mode
    cdh.writeUInt32LE(offset, 42);

    cdParts.push(cdh, nameBuf);
    offset += lfh.length + nameBuf.length + body.length;
  }

  const cdBuf = Buffer.concat(cdParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);

  const finalBuf = Buffer.concat([...localParts, cdBuf, eocd]);
  fs.mkdirSync(path.dirname(path.resolve(outZipPath)), { recursive: true });
  fs.writeFileSync(outZipPath, finalBuf);
  return { fileCount: entries.length, bytes: finalBuf.length };
}
