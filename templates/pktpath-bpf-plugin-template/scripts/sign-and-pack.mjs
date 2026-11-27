#!/usr/bin/env node
// Standalone zero-dependency helper for PktPath BPF plugins:
//   1. `keygen --out-dir ./keys`             -> generates Ed25519 keypair + fingerprint
//   2. `pack --dir . --out plugin.zip [--key ./keys/private.pem]`
//      -> updates .bpf.o sha256 in manifest.json, optionally signs whole package into signature.json, and writes .zip

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';

const SIG_FILE = 'signature.json';
const SIG_HEADER = 'pktpath-plugin-sig-v1';

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function walkFiles(rootDir) {
  const out = [];
  const walk = (dir, prefix) => {
    const items = fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name));
    for (const item of items) {
      if (item.name === '.git' || item.name === 'dist' || item.name === 'keys' || item.name === 'scripts' || item.name === 'Makefile') continue;
      if (item.isSymbolicLink()) throw new Error(`symlink not allowed: ${prefix}${item.name}`);
      const rel = prefix ? `${prefix}/${item.name}` : item.name;
      const abs = path.join(dir, item.name);
      if (item.isDirectory()) walk(abs, rel);
      else if (item.isFile()) out.push({ rel, abs });
    }
  };
  walk(rootDir, '');
  return out;
}

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i += 1) {
    c ^= buf[i];
    for (let k = 0; k < 8; k += 1) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
  }
  return (c ^ 0xffffffff) >>> 0;
}

function writeZip(files, outZip) {
  const localParts = [];
  const cdParts = [];
  let offset = 0;
  for (const { rel, data } of files) {
    const nameBuf = Buffer.from(rel, 'utf8');
    const crc = crc32(data);
    const comp = zlib.deflateRawSync(data);
    const body = comp.length < data.length ? comp : data;
    const method = comp.length < data.length ? 8 : 0;

    const lfh = Buffer.alloc(30);
    lfh.writeUInt32LE(0x04034b50, 0);
    lfh.writeUInt16LE(20, 4);
    lfh.writeUInt16LE(0x0800, 6);
    lfh.writeUInt16LE(method, 8);
    lfh.writeUInt32LE(crc, 14);
    lfh.writeUInt32LE(body.length, 18);
    lfh.writeUInt32LE(data.length, 22);
    lfh.writeUInt16LE(nameBuf.length, 26);
    localParts.push(lfh, nameBuf, body);

    const cdh = Buffer.alloc(46);
    cdh.writeUInt32LE(0x02014b50, 0);
    cdh.writeUInt16LE(20, 4);
    cdh.writeUInt16LE(20, 6);
    cdh.writeUInt16LE(0x0800, 8);
    cdh.writeUInt16LE(method, 10);
    cdh.writeUInt32LE(crc, 16);
    cdh.writeUInt32LE(body.length, 20);
    cdh.writeUInt32LE(data.length, 24);
    cdh.writeUInt16LE(nameBuf.length, 28);
    cdh.writeUInt32LE((0o100644 << 16) >>> 0, 38);
    cdh.writeUInt32LE(offset, 42);
    cdParts.push(cdh, nameBuf);
    offset += lfh.length + nameBuf.length + body.length;
  }
  const cdBuf = Buffer.concat(cdParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);
  fs.mkdirSync(path.dirname(path.resolve(outZip)), { recursive: true });
  fs.writeFileSync(outZip, Buffer.concat([...localParts, cdBuf, eocd]));
}

const args = process.argv.slice(2);
const cmd = args[0];
const getArg = (flag, def = '') => {
  const idx = args.indexOf(flag);
  return idx >= 0 && args[idx + 1] ? args[idx + 1] : def;
};

if (cmd === 'keygen') {
  const outDir = path.resolve(getArg('--out-dir', './keys'));
  fs.mkdirSync(outDir, { recursive: true });
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const fp = crypto.createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
  fs.writeFileSync(path.join(outDir, 'public.pem'), pubPem, 'utf8');
  fs.writeFileSync(path.join(outDir, 'private.pem'), privPem, { encoding: 'utf8', mode: 0o600 });
  console.log(`Generated Ed25519 keypair in ${outDir}`);
  console.log(`Public key fingerprint: ${fp}`);
} else if (cmd === 'pack') {
  const dir = path.resolve(getArg('--dir', '.'));
  const outZip = path.resolve(getArg('--out', './dist/plugin.zip'));
  const keyPath = getArg('--key', '');

  const manifestPath = path.join(dir, 'manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  if (manifest.kernel_probes?.objects) {
    for (const [arch, decl] of Object.entries(manifest.kernel_probes.objects)) {
      const objAbs = path.resolve(dir, decl.path);
      if (fs.existsSync(objAbs)) {
        decl.sha256 = sha256File(objAbs);
        console.log(`Updated ${arch} sha256: ${decl.sha256}`);
      }
    }
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n', 'utf8');
  }

  const fileList = walkFiles(dir).filter((f) => f.rel !== SIG_FILE);
  const packEntries = fileList.map((f) => ({ rel: f.rel, data: fs.readFileSync(f.abs) }));

  if (keyPath) {
    const privKey = crypto.createPrivateKey(fs.readFileSync(path.resolve(keyPath), 'utf8'));
    const pubKey = crypto.createPublicKey(privKey);
    const pubPem = pubKey.export({ type: 'spki', format: 'pem' }).toString();
    const fp = crypto.createHash('sha256').update(pubKey.export({ type: 'spki', format: 'der' })).digest('hex');
    const filesMap = {};
    for (const entry of packEntries) {
      filesMap[entry.rel] = crypto.createHash('sha256').update(entry.data).digest('hex');
    }
    const lines = [SIG_HEADER];
    for (const rel of Object.keys(filesMap).sort()) {
      lines.push(`${filesMap[rel]}  ${rel}`);
    }
    const sig = crypto.sign(null, Buffer.from(`${lines.join('\n')}\n`, 'utf8'), privKey).toString('base64');
    const sigDoc = {
      version: 1,
      algorithm: 'ed25519',
      public_key_pem: pubPem,
      key_fingerprint: fp,
      signed_at: new Date().toISOString(),
      files: filesMap,
      signature: sig,
    };
    packEntries.push({ rel: SIG_FILE, data: Buffer.from(JSON.stringify(sigDoc, null, 2) + '\n', 'utf8') });
    console.log(`Signed whole package with Ed25519 key fingerprint ${fp.slice(0, 16)}...`);
  }

  writeZip(packEntries, outZip);
  console.log(`Packed ${packEntries.length} files -> ${outZip}`);
} else {
  console.error('Usage: sign-and-pack.mjs <keygen|pack> [options]');
  process.exit(2);
}
