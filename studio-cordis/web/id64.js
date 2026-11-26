/* Decimal uint64 helpers for Wave 1 HTTP JSON.
 * sample_id / object_id / ts_ns / first_ts_ns / last_ts_ns / skb_addr arrive as
 * decimal strings (e.g. "18446744073709551615"). Never use Number() on them.
 * CommonJS export is solely for dependency-free Node tests, not a bundle.
 */
(function (host, factory) {
  'use strict';
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else host.PktPathId64 = api;
})(typeof window === 'undefined' ? null : window, function () {
  'use strict';
  const U64_FIELDS = Object.freeze(['sample_id', 'object_id', 'ts_ns', 'first_ts_ns', 'last_ts_ns', 'skb_addr']);

  function decId(v) {
    if (v === null || v === undefined || v === '') return null;
    if (typeof v === 'bigint') return v < 0n ? null : v.toString(10);
    if (typeof v === 'number') {
      if (!Number.isFinite(v) || v < 0 || !Number.isInteger(v)) return null;
      if (v > Number.MAX_SAFE_INTEGER) return null;
      return String(v);
    }
    const s = String(v).trim();
    if (!/^\d+$/.test(s)) return null;
    return s.replace(/^0+(?=\d)/, '');
  }

  function sameId(a, b) {
    const x = decId(a);
    const y = decId(b);
    return x !== null && y !== null && x === y;
  }

  function compareId(a, b) {
    const x = decId(a);
    const y = decId(b);
    if (x === null && y === null) return 0;
    if (x === null) return -1;
    if (y === null) return 1;
    if (x.length !== y.length) return x.length < y.length ? -1 : 1;
    return x < y ? -1 : x > y ? 1 : 0;
  }

  function preserveFields(input) {
    const o = input && typeof input === 'object' && !Array.isArray(input) ? Object.assign({}, input) : {};
    for (const k of U64_FIELDS) {
      if (o[k] !== undefined && o[k] !== null && o[k] !== '') {
        const d = decId(o[k]);
        o[k] = d !== null ? d : String(o[k]);
      }
    }
    return o;
  }

  function queryValue(v) {
    const d = decId(v);
    return d !== null ? d : '';
  }

  /** Format a unix timestamp that may be a decimal-string ns/us/ms value. */
  function fmtEpoch(x) {
    if (x === null || x === undefined || x === '') return '';
    const raw = typeof x === 'bigint' ? x.toString(10) : x;
    if (typeof raw === 'string' && /^\d+$/.test(raw.trim())) {
      const s = raw.trim().replace(/^0+(?=\d)/, '');
      let msStr;
      if (s.length >= 18) msStr = s.slice(0, s.length - 6);
      else if (s.length >= 16) msStr = s.slice(0, s.length - 3);
      else if (s.length >= 13) msStr = s;
      else {
        const n = Number(s);
        const d = new Date(n > 1e12 ? n : n * 1000);
        return isNaN(d.getTime()) ? String(x) : formatDate(d);
      }
      const ms = Number(msStr.length > 15 ? msStr.slice(0, 13) : msStr);
      const d = new Date(ms);
      return isNaN(d.getTime()) ? s : formatDate(d);
    }
    if (typeof raw === 'number' && Number.isFinite(raw)) {
      const d = new Date(raw > 1e15 ? raw / 1e6 : raw > 1e12 ? raw : raw * 1000);
      return isNaN(d.getTime()) ? String(x) : formatDate(d);
    }
    const d = new Date(String(x));
    return isNaN(d.getTime()) ? String(x) : formatDate(d);
  }

  function formatDate(d) {
    const p = (n) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  }

  return { U64_FIELDS, decId, sameId, compareId, preserveFields, queryValue, fmtEpoch };
});
