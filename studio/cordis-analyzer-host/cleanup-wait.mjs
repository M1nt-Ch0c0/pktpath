// DSH-style wait: official Cordis 3.18.1 Scope.reset fires async disposers
// without awaiting them. This host tracks those promises and exposes wait().
// This is a small self-maintained host patch, not a vendored DeepSeek Harness tree.
import { Context } from '@cordisjs/core';

export function attachCleanupWait(ctx) {
  let proto = Object.getPrototypeOf(ctx.scope);
  while (proto && !Object.prototype.hasOwnProperty.call(proto, 'reset')) {
    proto = Object.getPrototypeOf(proto);
  }
  if (!proto) throw new Error('cordis Scope.reset not found');
  if (proto.reset._pktpathCleanupWait) return proto.reset._pktpathCleanupWait;

  const pending = new Set();
  const original = proto.reset;
  function reset() {
    this.isActive = false;
    this.disposables = this.disposables.splice(0).filter((dispose) => {
      if (this.uid !== null && dispose[Context.static] === this) return true;
      const done = Promise.resolve().then(() => dispose());
      pending.add(done);
      const tracked = done.catch((reason) => {
        this.context.emit(this.ctx, 'internal/error', reason);
        return reason;
      });
      tracked.finally(() => pending.delete(done));
      return false;
    });
  }
  const api = {
    wait: async () => {
      while (pending.size) {
        await Promise.allSettled([...pending]);
      }
    },
    size: () => pending.size,
  };
  reset._pktpathCleanupWait = api;
  // Preserve any extra fields on the original if present; we replace behavior
  // with the official 3.18.1 filter plus tracking. original is kept for tests.
  reset._pktpathOriginalReset = original;
  proto.reset = reset;
  return api;
}
