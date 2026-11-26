import type { CordisHost } from '../kernel/host.ts';
import type { BuiltinPlugin } from '../kernel/types.ts';
import { androidAdbPlugin } from './adb/android-adb.ts';
import { daemonModePlugin } from './adb/daemon.ts';
import { ebpfTcPlugin } from './adb/ebpf-tc.ts';
import { oneshotModePlugin } from './adb/oneshot.ts';

export const ADB_BUILTIN_PLUGINS: readonly BuiltinPlugin[] = [
  androidAdbPlugin,
  ebpfTcPlugin,
  oneshotModePlugin,
  daemonModePlugin,
];

/**
 * Registers Lin's 4 ADB/capture built-in plugins (android-adb, ebpf-tc, oneshot, daemon)
 * plus any additional built-in plugins (e.g., Shan's 6 offline/analysis/export built-ins
 * and Rui's optional ui.theme when merged).
 */
export function registerWave1Builtins(
  host: CordisHost,
  extraBuiltins: readonly BuiltinPlugin[] = [],
): void {
  for (const plugin of ADB_BUILTIN_PLUGINS) {
    host.registerBuiltin(plugin);
  }
  for (const plugin of extraBuiltins) {
    host.registerBuiltin(plugin);
  }
}
