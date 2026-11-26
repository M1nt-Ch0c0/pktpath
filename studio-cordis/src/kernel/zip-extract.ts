// Pure-Node ZIP extractor (stored + deflate via node:zlib) with Zip-Slip,
// symlink, entry-count, and uncompressed byte-size guards.
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';

const EOCD_SIG = 0x06054b50;
const CD_SIG = 0x02014b50;
const LFH_SIG = 0x04034b50;
const MAX_ENTRIES = 512;
const MAX_TOTAL_BYTES = 32 * 1024 * 1024; // 32 MiB

export function extractZipSafe(zipPath: string, destDir: string): string[] {
  const buf = fs.readFileSync(zipPath);
  if (buf.length < 22) {
    throw new Error('invalid zip: file too small');
  }

  let eocdOffset = -1;
  const minOffset = Math.max(0, buf.length - 65557);
  for (let i = buf.length - 22; i >= minOffset; i--) {
    if (buf.readUInt32LE(i) === EOCD_SIG) {
      eocdOffset = i;
      break;
    }
  }
  if (eocdOffset < 0) {
    throw new Error('invalid zip: end-of-central-directory not found');
  }

  const totalEntries = buf.readUInt16LE(eocdOffset + 10);
  const cdSize = buf.readUInt32LE(eocdOffset + 12);
  const cdOffset = buf.readUInt32LE(eocdOffset + 16);

  if (totalEntries > MAX_ENTRIES) {
    throw new Error(`zip exceeds max entry limit (${MAX_ENTRIES})`);
  }
  if (cdOffset + cdSize > buf.length) {
    throw new Error('invalid zip: central directory out of bounds');
  }

  const rootResolved = path.resolve(destDir);
  fs.mkdirSync(rootResolved, { recursive: true });

  const extracted: string[] = [];
  let totalUncompressed = 0;
  let cursor = cdOffset;

  for (let idx = 0; idx < totalEntries; idx++) {
    if (cursor + 46 > buf.length || buf.readUInt32LE(cursor) !== CD_SIG) {
      throw new Error('invalid zip: corrupt central directory entry');
    }

    const method = buf.readUInt16LE(cursor + 10);
    const compSize = buf.readUInt32LE(cursor + 20);
    const uncompSize = buf.readUInt32LE(cursor + 24);
    const nameLen = buf.readUInt16LE(cursor + 28);
    const extraLen = buf.readUInt16LE(cursor + 30);
    const commentLen = buf.readUInt16LE(cursor + 32);
    const extAttrs = buf.readUInt32LE(cursor + 38);
    const lfhOffset = buf.readUInt32LE(cursor + 42);

    const rawName = buf.subarray(cursor + 46, cursor + 46 + nameLen).toString('utf8');
    cursor += 46 + nameLen + extraLen + commentLen;

    // Reject symlinks (POSIX mode 0120000 in upper 16 bits of external attributes)
    const unixMode = (extAttrs >>> 16) & 0o170000;
    if (unixMode === 0o120000) {
      throw new Error(`zip entry "${rawName}" is a symlink, which is not allowed`);
    }

    const norm = rawName.replaceAll('\\', '/');
    if (norm.startsWith('/') || /^[a-zA-Z]:/.test(norm) || norm.split('/').includes('..')) {
      throw new Error(`zip path traversal rejected: ${rawName}`);
    }

    const targetPath = path.resolve(rootResolved, norm);
    if (targetPath !== rootResolved && !targetPath.startsWith(rootResolved + path.sep)) {
      throw new Error(`zip path escapes destination: ${rawName}`);
    }

    if (norm.endsWith('/')) {
      fs.mkdirSync(targetPath, { recursive: true });
      continue;
    }

    if (lfhOffset + 30 > buf.length || buf.readUInt32LE(lfhOffset) !== LFH_SIG) {
      throw new Error(`invalid zip: bad local header for ${rawName}`);
    }
    const lfhNameLen = buf.readUInt16LE(lfhOffset + 26);
    const lfhExtraLen = buf.readUInt16LE(lfhOffset + 28);
    const dataStart = lfhOffset + 30 + lfhNameLen + lfhExtraLen;
    const dataEnd = dataStart + compSize;
    if (dataEnd > buf.length) {
      throw new Error(`invalid zip: data out of bounds for ${rawName}`);
    }

    totalUncompressed += uncompSize;
    if (totalUncompressed > MAX_TOTAL_BYTES) {
      throw new Error(`zip exceeds max uncompressed size (${MAX_TOTAL_BYTES} bytes)`);
    }

    const compressed = buf.subarray(dataStart, dataEnd);
    let content: Buffer;
    if (method === 0) {
      content = compressed;
    } else if (method === 8) {
      content = zlib.inflateRawSync(compressed, { maxOutputLength: MAX_TOTAL_BYTES });
    } else {
      throw new Error(`unsupported zip compression method ${method} for ${rawName}`);
    }

    if (content.length !== uncompSize) {
      throw new Error(`zip size mismatch for ${rawName}: got ${content.length}, want ${uncompSize}`);
    }

    fs.mkdirSync(path.dirname(targetPath), { recursive: true });
    fs.writeFileSync(targetPath, content);
    extracted.push(norm);
  }

  return extracted;
}
