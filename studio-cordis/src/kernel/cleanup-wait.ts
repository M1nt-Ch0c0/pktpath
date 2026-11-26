// Self-maintained host patch: official Cordis 3.18.1 Scope.reset fires async
// disposers without awaiting them. This tracks those promises so shutdown,
// disable, reload, and uninstall await cleanup deterministically.
import { Context } from '@cordisjs/core';

export interface CleanupWaitHandle {
  wait(): Promise<string[]>;
  size(): number;
}

type ResetFn = ((this: Record<string, unknown>) => void) & {
  _pktpathCleanupWait?: CleanupWaitHandle;
  _pktpathOriginalReset?: (this: Record<string, unknown>) => void;
};

export function attachCleanupWait(ctx: Context): CleanupWaitHandle {
  let proto: Record<string, unknown> | null = Object.getPrototypeOf(ctx.scope) as Record<string, unknown> | null;
  while (proto && !Object.prototype.hasOwnProperty.call(proto, 'reset')) {
    proto = Object.getPrototypeOf(proto) as Record<string, unknown> | null;
  }
  if (!proto) {
    throw new Error('cordis Scope.reset not found');
  }
  const existing = proto.reset as ResetFn;
  if (existing._pktpathCleanupWait) {
    return existing._pktpathCleanupWait;
  }

  const pending = new Set<Promise<unknown>>();
  const errors: string[] = [];
  const original = existing;

  const reset: ResetFn = function reset(this: Record<string, unknown>) {
    this.isActive = false;
    const disposables = this.disposables as Array<(() => unknown) & Record<symbol, unknown>>;
    const selfUid = this.uid;
    const context = this.context as { emit(c: unknown, event: string, reason: unknown): void };
    const selfCtx = this.ctx;

    this.disposables = disposables.splice(0).filter((dispose) => {
      if (selfUid !== null && dispose[Context.static as unknown as symbol] === this) {
        return true;
      }
      const done = Promise.resolve().then(() => dispose());
      pending.add(done);
      const tracked = done.catch((reason: unknown) => {
        errors.push(reason instanceof Error ? reason.message : String(reason));
        context.emit(selfCtx, 'internal/error', reason);
        return reason;
      });
      tracked.finally(() => {
        pending.delete(done);
      });
      return false;
    });
  };

  const api: CleanupWaitHandle = {
    wait: async () => {
      while (pending.size > 0) {
        await Promise.allSettled([...pending]);
      }
      return errors.splice(0);
    },
    size: () => pending.size,
  };

  reset._pktpathCleanupWait = api;
  reset._pktpathOriginalReset = original;
  proto.reset = reset;
  return api;
}
