import { Context } from '@cordisjs/core';
import { attachCleanupWait } from './cleanup-wait.mjs';
import assert from 'node:assert/strict';
import test from 'node:test';

test('attachCleanupWait settles only after async disposers finish', async () => {
  const ctx = new Context();
  const cleanup = attachCleanupWait(ctx);
  let finished = false;
  const fork = ctx.plugin({
    name: 'slow-cleanup',
    apply(local) {
      local.effect(() => async () => {
        await new Promise((r) => setTimeout(r, 80));
        finished = true;
      });
    },
  });
  await ctx.start();
  const t0 = Date.now();
  fork.dispose();
  assert.equal(finished, false);
  await cleanup.wait();
  const elapsed = Date.now() - t0;
  assert.equal(finished, true);
  assert.ok(elapsed >= 70, `expected to wait for disposer, elapsed=${elapsed}`);
});

test('ctx.stop plus wait covers root shutdown', async () => {
  const ctx = new Context();
  const cleanup = attachCleanupWait(ctx);
  let finished = false;
  ctx.plugin({
    name: 'slow-stop',
    apply(local) {
      local.effect(() => async () => {
        await new Promise((r) => setTimeout(r, 80));
        finished = true;
      });
    },
  });
  await ctx.start();
  await ctx.stop();
  assert.equal(finished, false);
  await cleanup.wait();
  assert.equal(finished, true);
});
