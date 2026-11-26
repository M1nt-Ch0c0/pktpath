import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

/**
 * Loads a classic browser IIFE script from studio-cordis/web/ in the current
 * V8 realm via vm.runInThisContext so tests work identically whether
 * package.json declares "type": "module" or not, keep native Object prototypes
 * for assert.deepStrictEqual, and leave browser <script> sources untouched.
 */
export function loadBrowserScript(relFromTestWeb: string): any {
  const absPath = path.resolve(import.meta.dirname, relFromTestWeb);
  const code = fs.readFileSync(absPath, 'utf-8');
  const mod = { exports: {} as any };
  const wrapper = vm.runInThisContext(
    `(function(module, exports, window) {\n${code}\n})`,
    { filename: absPath },
  );
  wrapper(mod, mod.exports, undefined);
  return mod.exports;
}
