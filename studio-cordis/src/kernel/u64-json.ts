// Safe JSON serialization preserving bigint as decimal strings so uint64 IDs
// (sample_id, object_id, ts_ns, etc.) never suffer JS Number > 2^53-1 truncation.

export function stringifyJsonSafe(value: unknown, space?: number): string {
  return JSON.stringify(
    value,
    (_key, v: unknown) => (typeof v === 'bigint' ? v.toString(10) : v),
    space,
  );
}

export function normalizeU64String(value: unknown): string {
  if (typeof value === 'bigint') {
    if (value < 0n) {
      throw new Error(`negative u64 value: ${value}`);
    }
    return value.toString(10);
  }
  if (typeof value === 'number') {
    if (!Number.isInteger(value) || value < 0 || !Number.isSafeInteger(value)) {
      throw new Error(`unsafe numeric u64 value: ${value}`);
    }
    return String(value);
  }
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!/^\d+$/.test(trimmed)) {
      throw new Error(`invalid u64 string: ${value}`);
    }
    const parsed = BigInt(trimmed);
    if (parsed > 18446744073709551615n) {
      throw new Error(`u64 overflow: ${value}`);
    }
    return parsed.toString(10);
  }
  throw new Error(`unsupported u64 value type: ${typeof value}`);
}
