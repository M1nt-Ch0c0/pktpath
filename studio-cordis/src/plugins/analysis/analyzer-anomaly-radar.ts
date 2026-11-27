// Builtin plugin: builtin.analyzer.anomaly-radar
// Ported 1:1 from studio/pkg/plugins/analyzers.go (anomalyRadarAnalyzer).
// Shares the unified AnalyzerInput/AnalyzerOutput contract with external analyzers.

import type { AnalyzerInput, AnalyzerOutput, AnalyzerRegistration, BuiltinPlugin, PluginContext } from './types.ts'

function readNum(cfg: Record<string, unknown>, key: string, fallback: number): number {
  const v = cfg[key]
  if (typeof v === 'number' && Number.isFinite(v)) return v
  if (typeof v === 'string' && v.trim() !== '') {
    const n = Number(v)
    if (Number.isFinite(n)) return n
  }
  return fallback
}

export const anomalyRadarPlugin: BuiltinPlugin = {
  meta: {
    id: 'builtin.analyzer.anomaly-radar',
    name: '异常雷达',
    version: '2.0.0',
    author: 'PktPath',
    description: '标出高排队时延、丢包和驱动重排样本。',
    category: 'analyzer',
    icon: '📡',
    builtin: true,
    capabilities: [
      '按阈值检测慢队列与长尾样本',
      '汇总丢包（DROP）与驱动 BUSY 重排（Requeue）',
    ],
    provides: ['analyzer.anomaly-radar'],
    usedBy: ['异常雷达诊断'],
    tags: ['diagnostics', 'anomaly', 'radar'],
  },
  schema: {
    fields: [
      {
        key: 'sojourn_warn_ms',
        label: '驻留警告阈值 (ms)',
        type: 'number',
        default: 5,
        min: 0.1,
        max: 5000,
      },
      {
        key: 'sojourn_crit_ms',
        label: '驻留严重阈值 (ms)',
        type: 'number',
        default: 25,
        min: 0.5,
        max: 10000,
      },
      {
        key: 'drop_warn_count',
        label: '丢包告警条数',
        type: 'number',
        default: 1,
        min: 1,
        max: 10000,
      },
      {
        key: 'requeue_warn_count',
        label: '重排告警次数',
        type: 'number',
        default: 1,
        min: 1,
        max: 10000,
      },
    ],
  },
  apply(ctx: PluginContext, cfg: Record<string, unknown>): void {
    const warnMs = readNum(cfg, 'sojourn_warn_ms', 5)
    let critMs = readNum(cfg, 'sojourn_crit_ms', 25)
    if (critMs < warnMs) critMs = warnMs
    const dropThresh = Math.trunc(readNum(cfg, 'drop_warn_count', 1))
    const reqThresh = Math.trunc(readNum(cfg, 'requeue_warn_count', 1))

    ctx.provide('analyzer.anomaly-radar', { ...cfg })

    const reg: AnalyzerRegistration = {
      id: 'anomaly-radar',
      plugin_id: 'builtin.analyzer.anomaly-radar',
      name: '异常雷达',
      description: '标出高排队时延、丢包和驱动重排样本。',
      run(input: AnalyzerInput): AnalyzerOutput {
        const out: AnalyzerOutput = { insights: [], kpis: [], notes: [] }
        const ov = input.overview
        if (!ov || typeof ov['stats'] !== 'object' || ov['stats'] === null) return out

        const st = ov['stats'] as Record<string, unknown>
        const rawSamples = Array.isArray(ov['samples']) ? (ov['samples'] as Array<Record<string, unknown>>) : []

        const slow: Array<{ id: string; ms: number }> = []
        let maxMs = 0
        for (const s of rawSamples) {
          const maxSojUs = typeof s['max_sojourn_us'] === 'number' ? s['max_sojourn_us'] : 0
          const ms = maxSojUs / 1000.0
          if (ms > maxMs) maxMs = ms
          if (ms >= warnMs && s['sample_id'] !== undefined) {
            slow.push({ id: String(s['sample_id']), ms })
          }
        }
        slow.sort((a, b) => b.ms - a.ms)

        let hotQueue = ''
        let hotP95Ms = 0
        const queues = Array.isArray(st['queues']) ? (st['queues'] as Array<Record<string, unknown>>) : []
        for (const q of queues) {
          const p95 = q['p95_us']
          if (typeof p95 === 'number' && p95 / 1000.0 > hotP95Ms) {
            hotP95Ms = p95 / 1000.0
            hotQueue = typeof q['label'] === 'string' ? q['label'] : ''
          }
        }

        if (slow.length > 0) {
          const sev = maxMs >= critMs ? 'critical' : 'warn'
          const topIDs = slow.slice(0, 8).map((x) => x.id)
          const qHint = hotQueue !== '' ? `，最慢队列 ${hotQueue} (P95=${hotP95Ms.toFixed(2)} ms)` : ''
          const summary = `${slow.length} 个样本驻留 ≥ ${warnMs.toFixed(1)} ms（峰值 ${maxMs.toFixed(2)} ms${qHint}）。`
          out.insights.push({
            id: 'radar.high_sojourn',
            plugin_id: 'builtin.analyzer.anomaly-radar',
            analyzer_id: 'anomaly-radar',
            severity: sev,
            title: '队列排队时延偏高',
            summary,
            detail: summary,
            metric: `峰值 ${maxMs.toFixed(2)} ms`,
            sample_ids: topIDs,
          })
        }

        const endpoints =
          typeof st['endpoints'] === 'object' && st['endpoints'] !== null
            ? (st['endpoints'] as Record<string, unknown>)
            : {}
        const drops = typeof endpoints['DROP'] === 'number' ? endpoints['DROP'] : 0
        if (drops >= dropThresh) {
          const dropIDs: string[] = []
          for (const s of rawSamples) {
            if (s['endpoint'] === 'DROP' && s['sample_id'] !== undefined && dropIDs.length < 8) {
              dropIDs.push(String(s['sample_id']))
            }
          }
          const summary = `共 ${drops} 条分支在协议栈或队列中丢弃。`
          out.insights.push({
            id: 'radar.drops',
            plugin_id: 'builtin.analyzer.anomaly-radar',
            analyzer_id: 'anomaly-radar',
            severity: 'critical',
            title: '发现内核丢包 (DROP)',
            summary,
            detail: summary,
            metric: `${drops} 丢包`,
            sample_ids: dropIDs,
          })
        }

        const requeueCount = typeof st['requeue_count'] === 'number' ? st['requeue_count'] : 0
        const reqGso = typeof st['requeue_gso_count'] === 'number' ? st['requeue_gso_count'] : 0
        const reqBadTxq = typeof st['requeue_bad_txq_count'] === 'number' ? st['requeue_bad_txq_count'] : 0
        if (requeueCount >= reqThresh) {
          const reqIDs: string[] = []
          for (const s of rawSamples) {
            if (s['requeued'] === true && s['sample_id'] !== undefined && reqIDs.length < 8) {
              reqIDs.push(String(s['sample_id']))
            }
          }
          const summary = `共 ${requeueCount} 次 NETDEV_TX_BUSY 重排（GSO=${reqGso} / BadTXQ=${reqBadTxq}）。`
          out.insights.push({
            id: 'radar.requeue',
            plugin_id: 'builtin.analyzer.anomaly-radar',
            analyzer_id: 'anomaly-radar',
            severity: 'warn',
            title: '驱动发包重排 (Requeue)',
            summary,
            detail: summary,
            metric: `${requeueCount} 次`,
            sample_ids: reqIDs,
          })
        }

        if (out.insights.length === 0 && rawSamples.length > 0) {
          const summary = `共 ${rawSamples.length} 个样本，最大驻留 ${maxMs.toFixed(2)} ms（阈值 ${warnMs.toFixed(1)} ms），无丢包与重排。`
          out.insights.push({
            id: 'radar.healthy',
            plugin_id: 'builtin.analyzer.anomaly-radar',
            analyzer_id: 'anomaly-radar',
            severity: 'ok',
            title: '未触发异常阈值',
            summary,
            detail: summary,
            metric: `峰值 ${maxMs.toFixed(2)} ms`,
          })
        }

        let tone: 'ok' | 'warn' | 'bad' = 'ok'
        let statusLabel = '正常'
        if (drops >= dropThresh || maxMs >= critMs) {
          tone = 'bad'
          statusLabel = '存在瓶颈/丢包'
        } else if (slow.length > 0 || requeueCount >= reqThresh) {
          tone = 'warn'
          statusLabel = '时延波动'
        }
        out.kpis.push({
          plugin_id: 'builtin.analyzer.anomaly-radar',
          analyzer_id: 'anomaly-radar',
          label: '异常雷达评估',
          value: statusLabel,
          sub: `峰值 ${maxMs.toFixed(2)} ms · 丢包 ${drops} · 重排 ${requeueCount}`,
          tone,
        })
        return out
      },
    }
    ctx.registerExtension('analyzer', reg)
  },
}
