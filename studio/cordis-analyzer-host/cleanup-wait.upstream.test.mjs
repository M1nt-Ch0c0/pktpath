import { Context } from '@cordisjs/core';
import assert from 'node:assert/strict';
import test from 'node:test';

test('stock Cordis 3.18.1 stop returns before async cleanup finishes', async () => {
  const ctx = new Context();
  let finished = false;
  ctx.plugin({
    name: 'slow-cleanup',
    apply(local) {
      local.effect(() => async () => {
        await new Promise((r) => setTimeout(r, 80));
        finished = true;
      });
    },
  });
  await ctx.start();
  await ctx.stop();
  assert.equal(finished, false, 'upstream does not await async disposers');
  await new Promise((r) => setTimeout(r, 120));
  assert.equal(finished, true);
});
