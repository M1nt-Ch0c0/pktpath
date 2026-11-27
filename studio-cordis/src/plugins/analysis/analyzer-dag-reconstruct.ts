// Builtin plugin: builtin.analyzer.dag-reconstruct
// Ported 1:1 from studio/pkg/plugins/analyzers.go (dagReconstructAnalyzer).

import type { AnalyzerInput, AnalyzerOutput, AnalyzerRegistration, BuiltinPlugin, PluginContext } from './types.ts'

function readBool(cfg: Record<string, unknown>, key: string, fallback: boolean): boolean {
  const v = cfg[key]
  return typeof v === 'boolean' ? v : fallback
}

export const dagReconstructPlugin: BuiltinPlugin = {
  meta: {
    id: 'builtin.analyzer.dag-reconstruct',
    name: '路径 DAG 重建',
    version: '2.0.0',
    author: 'PktPath',
    description: '配对队列入出队事件，重建多分支路径与血缘。',
    category: 'analyzer',
    icon: '🕸️',
    builtin: true,
    capabilities: [
      '计算队列 P50 / P95 / P99 驻留耗时',
      '识别 SKB Clone / Copy / Expand 多分支流转',
    ],
    provides: ['analyzer.dag'],
    usedBy: ['会话分析洞察'],
    tags: ['dag', 'sojourn', 'clone'],
  },
  schema: {
    fields: [
      {
        key: 'highlight_multi_branch',
        label: '在会话顶部汇总多分支派生样本',
        type: 'boolean',
        default: true,
      },
    ],
  },
  apply(ctx: PluginContext, cfg: Record<string, unknown>): void {
    const highlight = readBool(cfg, 'highlight_multi_branch', true)
    ctx.provide('analyzer.dag', { ...cfg })

    const reg: AnalyzerRegistration = {
      id: 'dag-reconstruct',
      plugin_id: 'builtin.analyzer.dag-reconstruct',
      name: '路径 DAG 重建',
      description: '配对队列入出队事件，重建多分支路径与血缘。',
      run(input: AnalyzerInput): AnalyzerOutput {
        const out: AnalyzerOutput = { insights: [], kpis: [], notes: [] }
        if (!highlight || !input.overview) return out
        const rawSamples = input.overview['samples']
        if (!Array.isArray(rawSamples)) return out

        const multiIDs: string[] = []
        for (const item of rawSamples) {
          if (typeof item !== 'object' || item === null) continue
          const row = item as Record<string, unknown>
          const bc = typeof row['branch_count'] === 'number' ? row['branch_count'] : 0
          if (bc > 1 && row['sample_id'] !== undefined) {
            multiIDs.push(String(row['sample_id']))
          }
        }
        if (multiIDs.length > 0) {
          const capped = multiIDs.slice(0, 10)
          out.insights.push({
            id: 'dag.multi_branch',
            plugin_id: 'builtin.analyzer.dag-reconstruct',
            analyzer_id: 'dag-reconstruct',
            severity: 'info',
            title: '存在 SKB 多分支派生',
            summary: `共 ${capped.length} 个样本发生 Clone / Copy / Expand 派生。`,
            detail: `共 ${capped.length} 个样本发生 Clone / Copy / Expand 派生。`,
            metric: `${capped.length} 样本`,
            sample_ids: capped,
          })
        }

        // Wave 3: attribute external .bpf.o plugin hits by plugin_id
        const extPlugins = input.overview['external_bpf_plugins']
        if (Array.isArray(extPlugins) && extPlugins.length > 0) {
          for (const raw of extPlugins) {
            if (typeof raw !== 'object' || raw === null) continue
            const p = raw as Record<string, unknown>
            const pluginId = typeof p['plugin_id'] === 'string' ? p['plugin_id'] : ''
            const hitCount = typeof p['hit_count'] === 'number' ? p['hit_count'] : 0
            if (!pluginId || hitCount <= 0) continue
            const sampleIds = Array.isArray(p['sample_ids'])
              ? (p['sample_ids'] as unknown[]).map((x) => String(x)).slice(0, 10)
              : []
            const summary = `外置 eBPF 插件 ${pluginId} 命中 ${hitCount} 次（涉及 ${sampleIds.length} 条样本）。`
            out.insights.push({
              id: `dag.external_bpf.${pluginId}`,
              plugin_id: 'builtin.analyzer.dag-reconstruct',
              analyzer_id: 'dag-reconstruct',
              severity: 'info',
              title: `外置 eBPF 插件命中：${pluginId}`,
              summary,
              detail: summary,
              metric: `${hitCount} 次命中`,
              sample_ids: sampleIds,
            })
          }
        }
        return out
      },
    }
    ctx.registerExtension('analyzer', reg)
  },
}
