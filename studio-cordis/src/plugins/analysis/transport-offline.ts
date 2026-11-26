// Builtin plugin: builtin.transport.offline
// Provides the `session.provider` service backed by SessionStore and registers
// the offline session-dir transport extension.

import { SessionStore } from './session-store.ts'
import type { AnalysisHostLike, BuiltinPlugin, PluginContext } from './types.ts'

export function createOfflineTransportPlugin(store?: SessionStore): BuiltinPlugin {
  return {
    meta: {
      id: 'builtin.transport.offline',
      name: '离线会话目录',
      version: '2.0.0',
      author: 'PktPath',
      description: '读取本地已采集的 PktPath 会话目录（manifest.json + *.pktb），提供会话列表、概览、单包详情与分析缓存。',
      category: 'transport',
      icon: '📂',
      builtin: true,
      capabilities: [
        '浏览 sessionsRoot 与已打开的外部会话目录',
        '支持跨重启磁盘分析结果缓存与只读目录自动降级',
      ],
      provides: ['transport.offline', 'session.provider'],
      tags: ['offline', 'session', 'disk'],
    },
    schema: {
      fields: [
        {
          key: 'enable_disk_cache',
          label: '启用分析结果磁盘持久化缓存',
          type: 'boolean',
          default: true,
        },
      ],
    },
    apply(ctx: PluginContext, cfg: Record<string, unknown>): void {
      const maybeHost = ctx.host as unknown as Partial<AnalysisHostLike>
      const validHost =
        typeof maybeHost.snapshot === 'function' && typeof maybeHost.runAnalyzers === 'function'
          ? (maybeHost as AnalysisHostLike)
          : undefined
      const activeStore = store ?? new SessionStore(ctx.host.paths, validHost)
      if (store && validHost) {
        activeStore.bindHost(validHost)
      }
      ctx.provide('transport.offline', { ...cfg, store: activeStore })
      ctx.provide('session.provider', activeStore)
      ctx.registerExtension('transport', {
        id: 'offline',
        plugin_id: 'builtin.transport.offline',
        name: '离线会话目录',
        description: '从本地磁盘打开或浏览 PktPath 会话目录',
        priority: 10,
      })
    },
  }
}

export const offlineTransportPlugin: BuiltinPlugin = createOfflineTransportPlugin()
