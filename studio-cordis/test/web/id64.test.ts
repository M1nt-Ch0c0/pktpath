import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadBrowserScript } from './_load-browser-script.ts';

const id64 = loadBrowserScript('../../web/id64.js');

test('decId keeps decimal strings beyond MAX_SAFE_INTEGER and never uses Number', () => {
  const big = '18446744073709551615';
  assert.equal(id64.decId(big), big);
  assert.equal(id64.decId('00012'), '12');
  assert.equal(id64.decId(42), '42');
  assert.equal(id64.decId(42n), '42');
  assert.equal(id64.decId(Number.MAX_SAFE_INTEGER + 1), null);
  assert.equal(id64.decId(''), null);
  assert.equal(id64.decId('12.3'), null);
  assert.ok(id64.sameId(big, big));
  assert.ok(id64.sameId('12', 12));
  assert.equal(id64.sameId(big, '18446744073709551614'), false);
  assert.ok(id64.compareId('9', '10') < 0);
  assert.ok(id64.compareId(big, '10') > 0);
  assert.equal(id64.queryValue(big), big);
});

test('preserveFields only stringifies the contracted uint64 keys', () => {
  const got = id64.preserveFields({
    sample_id: 7,
    object_id: '18446744073709551615',
    ts_ns: 42n,
    uid: 10150,
    max_sojourn_us: 1200,
  });
  assert.equal(got.sample_id, '7');
  assert.equal(got.object_id, '18446744073709551615');
  assert.equal(got.ts_ns, '42');
  assert.equal(got.uid, 10150);
  assert.equal(got.max_sojourn_us, 1200);
});

test('fmtEpoch renders decimal-string nanosecond timestamps without Number truncation', () => {
  const text = id64.fmtEpoch('1732612800000000000');
  assert.match(text, /^\d{4}-\d{2}-\d{2} /);
  assert.equal(id64.fmtEpoch(''), '');
});
