import type { BuiltinPlugin } from '../../kernel/types.ts';
import {
  getOrCreateCaptureController,
  type CaptureStatusSnapshot,
  type CaptureStateKind,
} from './capture-controller.ts';
import type { CaptureSpec } from './ebpf-tc.ts';

export interface DaemonCaptureService {
  start(spec: CaptureSpec): Promise<{ ok: true; capture_id: string; status: 'running'; mode: 'daemon'; remote_pid: number }>;
  flush(): Promise<{ ok: true; capture_id: string; signal: 'SIGUSR1'; remote_pid: number; flush_count: number }>;
  status(): Promise<CaptureStatusSnapshot>;
  stop(): Promise<{ ok: boolean; status: CaptureStateKind; session_id?: string; session_dir?: string; error?: string }>;
}

export const daemonModePlugin: BuiltinPlugin = {
  meta: {
    id: 'builtin.mode.daemon',
    name: '常驻录制模式 (Daemon)',
    version: '1.0.0',
    description: '在 Android 设备上启动常驻环形缓冲采集，支持手动 SIGUSR1 flush 落盘与停止拉回。',
    category: 'collector',
    icon: 'activity',
    builtin: true,
    capabilities: ['capture.mode.daemon', 'capture.flush'],
    provides: ['capture.mode.daemon'],
    requires: ['collector.ebpf'],
    tags: ['capture', 'daemon', 'flush'],
  },
  schema: {
    fields: [
      {
        key: 'default_trigger',
        label: '默认触发条件',
        type: 'string',
        default: 'sojourn_us>50000',
      },
      {
        key: 'default_pre_window_sec',
        label: '默认触发前窗口（秒）',
        type: 'number',
        default: 5,
        min: 1,
        max: 60,
      },
      {
        key: 'default_post_window_sec',
        label: '默认触发后窗口（秒）',
        type: 'number',
        default: 5,
        min: 1,
        max: 60,
      },
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
    const defaultTrigger = typeof cfg.default_trigger === 'string' && cfg.default_trigger.trim()
      ? cfg.default_trigger.trim()
      : 'sojourn_us>50000';
    const defaultPre = typeof cfg.default_pre_window_sec === 'number' && cfg.default_pre_window_sec > 0
      ? Math.floor(cfg.default_pre_window_sec)
      : 5;
    const defaultPost = typeof cfg.default_post_window_sec === 'number' && cfg.default_post_window_sec > 0
      ? Math.floor(cfg.default_post_window_sec)
      : 5;
    const controller = getOrCreateCaptureController(ctx.host);

    const service: DaemonCaptureService = {
      async start(spec: CaptureSpec) {
        const merged: CaptureSpec = {
          ...spec,
          mode: 'daemon',
          trigger: spec.trigger ?? defaultTrigger,
          pre_window_sec: spec.pre_window_sec ?? defaultPre,
          post_window_sec: spec.post_window_sec ?? defaultPost,
        };
        const res = await controller.start(merged, { cleanupRemote });
        return { ...res, mode: 'daemon' };
      },
      flush: () => controller.flush(),
      status: () => controller.status(),
      stop: () => controller.stop(),
    };

    ctx.onDispose(async () => {
      await controller.abortForMode('daemon');
    });

    ctx.provide('capture.mode.daemon', service);
    ctx.registerExtension('capture.mode', {
      id: 'daemon',
      plugin_id: 'builtin.mode.daemon',
      name: '常驻录制 (Daemon)',
      description: '常驻环形缓冲采集，支持按需 SIGUSR1 flush 落盘。',
      supports_flush: true,
    });
  },
};
