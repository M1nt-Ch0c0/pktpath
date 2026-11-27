// Builtin plugin: builtin.transport.offline
// Provides the `session.provider` service backed by SessionStore and registers
// the offline session-dir transport extension.

import { SessionStore } from './session-store.ts'
import type { AnalysisHostLike, BuiltinPlugin, PluginContext } from './types.ts'

export function createOfflineTransportPlugin(store?: SessionStore): BuiltinPlugin {
  return {
    meta: {
      id: 'builtin.transport.offline',
      name: '本地会话存储与加载',
      version: '2.0.0',
      author: 'PktPath',
      description: '管理所有本地会话目录（含手机采集拉回的会话与手动打开的目录），提供会话列表、概览、单包详情与分析缓存。',
      category: 'transport',
      icon: '📂',
      builtin: true,
      capabilities: [
        '管理所有本地会话（含手机采集回传落盘与手动打开的目录）',
        '支持跨重启磁盘分析结果缓存与只读目录自动降级',
      ],
      provides: ['transport.offline', 'session.provider'],
      required: true,
      usedBy: ['会话列表与概览', '打开本地会话', '手机采集回传落盘', '会话导出'],
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
        name: '本地会话存储与加载',
        description: '管理本地会话目录（含手机采集拉回的会话与手动打开的目录）',
        priority: 10,
      })
    },
  }
}

export const offlineTransportPlugin: BuiltinPlugin = createOfflineTransportPlugin()
