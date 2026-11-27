import type { BuiltinPlugin } from '../../kernel/types.ts';
import {
  getOrCreateCaptureController,
  type CaptureStatusSnapshot,
  type CaptureStateKind,
} from './capture-controller.ts';
import type { CaptureSpec } from './ebpf-tc.ts';

export interface OneshotCaptureService {
  start(spec: CaptureSpec): Promise<{ ok: true; capture_id: string; status: 'running'; mode: 'oneshot'; remote_pid: number }>;
  status(): Promise<CaptureStatusSnapshot>;
  stop(): Promise<{ ok: boolean; status: CaptureStateKind; session_id?: string; session_dir?: string; error?: string }>;
}

export const oneshotModePlugin: BuiltinPlugin = {
  meta: {
    id: 'builtin.mode.oneshot',
    name: '短时采集模式 (Oneshot)',
    version: '1.0.0',
    description: '启动单次定时/手动停止的 Android 设备采集，并在结束后自动拉取会话至本地。',
    category: 'collector',
    icon: 'play-circle',
    builtin: true,
    capabilities: ['capture.mode.oneshot'],
    provides: ['capture.mode.oneshot'],
    requires: ['collector.ebpf'],
    usedBy: ['短时采集'],
    tags: ['capture', 'oneshot'],
  },
  schema: {
    fields: [
      {
        key: 'cleanup_remote',
        label: '拉取后清理设备临时目录',
        type: 'boolean',
        default: true,
      },
    ],
  },
  apply(ctx, cfg) {
    const cleanupRemote = cfg.cleanup_remote !== false;
    const controller = getOrCreateCaptureController(ctx.host);

    const service: OneshotCaptureService = {
      async start(spec: CaptureSpec) {
        const res = await controller.start({ ...spec, mode: 'oneshot' }, { cleanupRemote });
        return { ...res, mode: 'oneshot' };
      },
      status: () => controller.status(),
      stop: () => controller.stop(),
    };

    ctx.onDispose(async () => {
      await controller.abortForMode('oneshot');
    });

    ctx.provide('capture.mode.oneshot', service);
    ctx.registerExtension('capture.mode', {
      id: 'oneshot',
      plugin_id: 'builtin.mode.oneshot',
      name: '短时采集 (Oneshot)',
      description: '单次短时采集并在完成后自动拉回本地会话。',
    });
  },
};
