// Builtin plugin: builtin.exporter.csv-report
// Ported 1:1 from studio/pkg/plugins/exporters.go (csvReportExporter).
// Enforces WAVE1-CONTRACT.md v1.2 safety rules:
// - Default path when omitted: <exportsDir>/<sanitized_session_id>-report.<ext>
// - Hard-forbids writing inside session_dir (protects raw session directory)
// - Refuses FIFO pipes and atomic-writes output.

import fs from 'node:fs'
import path from 'node:path'
import { writeFileAtomic } from './session-store.ts'
import type { BuiltinPlugin, ExporterInput, ExporterOutput, ExporterRegistration, PluginContext } from './types.ts'

function csvEscape(cell: string): string {
  if (cell.includes(',') || cell.includes('"') || cell.includes('\n') || cell.includes('\r')) {
    return '"' + cell.replaceAll('"', '""') + '"'
  }
  return cell
}

function fmtUsMs(us: unknown): string {
  if (typeof us !== 'number' || !Number.isFinite(us)) return '—'
  return (us / 1000.0).toFixed(3)
}

function canonicalizeNearestExisting(targetPath: string, depth = 0): string {
  const abs = path.resolve(targetPath)
  if (depth > 16) return abs
  const missing: string[] = []
  let cur = abs
  while (true) {
    try {
      const real = fs.realpathSync(cur)
      return missing.length > 0 ? path.join(real, ...missing.reverse()) : real
    } catch {
      try {
        const lst = fs.lstatSync(cur)
        if (lst.isSymbolicLink()) {
          const linkTarget = path.resolve(path.dirname(cur), fs.readlinkSync(cur))
          const resolved = canonicalizeNearestExisting(linkTarget, depth + 1)
          return missing.length > 0 ? path.join(resolved, ...missing.reverse()) : resolved
        }
      } catch {
        // cur does not exist yet; walk up to nearest existing ancestor
      }
      const parent = path.dirname(cur)
      if (parent === cur) return abs
      missing.push(path.basename(cur))
      cur = parent
    }
  }
}

export function isPathInsideDir(targetPath: string, dirPath: string): boolean {
  const absTarget = canonicalizeNearestExisting(targetPath)
  const absDir = canonicalizeNearestExisting(dirPath)
  const rel = path.relative(absDir, absTarget)
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel))
}

export function validateExportOutPath(outPath: string, sessionDir: string): string {
  const abs = path.resolve(outPath)
  if (sessionDir && isPathInsideDir(abs, sessionDir)) {
    throw new Error(`refusing to write export inside session_dir: ${abs}`)
  }
  try {
    if (fs.existsSync(abs)) {
      const lst = fs.lstatSync(abs)
      if (lst.isFIFO()) throw new Error(`refusing to export to FIFO pipe: ${abs}`)
      if (lst.isDirectory()) throw new Error(`export target is a directory: ${abs}`)
    }
  } catch (err) {
    if (err instanceof Error && (err.message.includes('FIFO') || err.message.includes('directory'))) {
      throw err
    }
  }
  return abs
}

export const csvReportExporterPlugin: BuiltinPlugin = {
  meta: {
    id: 'builtin.exporter.csv-report',
    name: '表格 / Markdown 报告',
    version: '2.0.0',
    author: 'PktPath',
    description: '将样本与队列耗时导出为 CSV 表格或 Markdown 摘要报告。',
    category: 'exporter',
    icon: '📑',
    builtin: true,
    capabilities: [
      '导出带 UTF-8 BOM 的 Excel 兼容 CSV 样本明细',
      '导出含队列分位与样本明细的 Markdown 报告',
    ],
    provides: ['exporter.csv-report'],
    tags: ['csv', 'markdown', 'report'],
  },
  schema: {
    fields: [
      {
        key: 'format',
        label: '导出格式',
        type: 'select',
        default: 'csv',
        options: [
          { value: 'csv', label: 'CSV 表格 (.csv)' },
          { value: 'markdown', label: 'Markdown 报告 (.md)' },
        ],
      },
      {
        key: 'max_rows',
        label: '最多导出行数（0 为全部）',
        type: 'number',
        default: 0,
        min: 0,
        max: 100000,
      },
    ],
  },
  apply(ctx: PluginContext, cfg: Record<string, unknown>): void {
    const cfgFormat = cfg['format'] === 'markdown' ? 'markdown' : 'csv'
    const cfgMaxRows = typeof cfg['max_rows'] === 'number' && Number.isFinite(cfg['max_rows']) ? Math.trunc(cfg['max_rows']) : 0
    const ext = cfgFormat === 'markdown' ? '.md' : '.csv'

    ctx.provide('exporter.csv-report', { ...cfg })

    const reg: ExporterRegistration = {
      id: 'csv-report',
      plugin_id: 'builtin.exporter.csv-report',
      name: '表格 / Markdown 报告',
      description: '导出样本明细或摘要报告',
      default_ext: ext,
      async run(input: ExporterInput): Promise<ExporterOutput> {
        const ov = input.overview
        if (!ov) {
          return { ok: false, out_path: '', summary: '', error: '会话数据尚未加载' }
        }
        const format =
          input.params && (input.params['format'] === 'markdown' || input.params['format'] === 'csv')
            ? (input.params['format'] as 'csv' | 'markdown')
            : cfgFormat
        const maxRows =
          input.params && typeof input.params['max_rows'] === 'number' && Number.isFinite(input.params['max_rows'])
            ? Math.trunc(input.params['max_rows'] as number)
            : cfgMaxRows
        const useExt = format === 'markdown' ? '.md' : '.csv'

        const safeSessionId = input.session_id.replace(/[^a-zA-Z0-9._-]/g, '_') || 'session'
        let rawOutPath = typeof input.out_path === 'string' ? input.out_path.trim() : ''
        if (!rawOutPath) {
          fs.mkdirSync(ctx.host.paths.exportsDir, { recursive: true })
          rawOutPath = path.join(ctx.host.paths.exportsDir, `${safeSessionId}-report${useExt}`)
        }
        const outPath = validateExportOutPath(rawOutPath, input.session_dir)

        let samples = Array.isArray(ov['samples']) ? (ov['samples'] as Array<Record<string, unknown>>) : []
        if (maxRows > 0 && samples.length > maxRows) {
          samples = samples.slice(0, maxRows)
        }

        if (format === 'markdown') {
          const lines: string[] = []
          lines.push(`# PktPath 诊断报告 — ${input.session_id}\n`)
          const st = typeof ov['stats'] === 'object' && ov['stats'] !== null ? (ov['stats'] as Record<string, unknown>) : undefined
          if (st) {
            lines.push(`- Scope: \`${String(st['scope'] ?? '')}\` · 模式: \`${String(st['mode'] ?? '')}\` · 抽样: \`${String(st['sample_rate'] ?? '')}\``)
            const sc = (st['samples'] ?? {}) as Record<string, unknown>
            const br = (st['branches'] ?? {}) as Record<string, unknown>
            const eps = (st['endpoints'] ?? {}) as Record<string, unknown>
            lines.push(
              `- 样本: **${Number(sc['total'] ?? 0)}** · 分支: **${Number(br['total'] ?? 0)}**（完整 ${Number(br['complete'] ?? 0)} / 缺失 ${Number(br['incomplete'] ?? 0)}）`,
            )
            lines.push(`- 丢包: **${Number(eps['DROP'] ?? 0)}** · 重排: **${Number(st['requeue_count'] ?? 0)}**\n`)
            const queues = Array.isArray(st['queues']) ? (st['queues'] as Array<Record<string, unknown>>) : []
            if (queues.length > 0) {
              lines.push('## 队列分位\n')
              lines.push('| 队列 | 类型 | 次数 | P50(ms) | P95(ms) | P99(ms) | Max(ms) |')
              lines.push('|---|---|---:|---:|---:|---:|---:|')
              for (const q of queues) {
                lines.push(
                  `| ${String(q['label'] ?? '')} | ${String(q['kind'] ?? '')} | ${Number(q['paired_n'] ?? 0)} | ${fmtUsMs(q['p50_us'])} | ${fmtUsMs(q['p95_us'])} | ${fmtUsMs(q['p99_us'])} | ${fmtUsMs(q['max_us'])} |`,
                )
              }
              lines.push('')
            }
          }
          lines.push(`## 样本明细 (${samples.length})\n`)
          lines.push('| # | 进程 | 协议 | 源 -> 目的 | 长度 | 最大驻留(ms) | 终点 | 路径 |')
          lines.push('|---:|---|---|---|---:|---:|---|---|')
          for (const s of samples) {
            const maxSojMs = ((typeof s['max_sojourn_us'] === 'number' ? s['max_sojourn_us'] : 0) / 1000.0).toFixed(3)
            lines.push(
              `| ${String(s['sample_id'] ?? '')} | ${String(s['comm'] ?? '')} | ${String(s['proto'] ?? '')} | ${String(s['src'] ?? '')} -> ${String(s['dst'] ?? '')} | ${String(s['pkt_len'] ?? '0')} | ${maxSojMs} | ${String(s['endpoint'] ?? '')} | \`${String(s['path_sig'] ?? '')}\` |`,
            )
          }
          writeFileAtomic(outPath, lines.join('\n') + '\n')
          return {
            ok: true,
            out_path: outPath,
            summary: `已导出 Markdown 报告（${samples.length} 条）`,
            details: { rows: samples.length, format: 'markdown' },
          }
        }

        const header = [
          'sample_id', 'uid', 'tgid', 'comm', 'proto', 'src', 'dst',
          'pkt_len', 'max_sojourn_ms', 'total_ms', 'endpoint', 'completeness', 'branches', 'requeued', 'path_sig',
        ]
        const csvLines: string[] = [header.join(',')]
        for (const s of samples) {
          const maxSojMs = ((typeof s['max_sojourn_us'] === 'number' ? s['max_sojourn_us'] : 0) / 1000.0).toFixed(3)
          const totalMs = ((typeof s['total_us'] === 'number' ? s['total_us'] : 0) / 1000.0).toFixed(3)
          const row = [
            String(s['sample_id'] ?? ''),
            s['uid'] !== null && s['uid'] !== undefined ? String(s['uid']) : '',
            s['tgid'] !== null && s['tgid'] !== undefined ? String(s['tgid']) : '',
            String(s['comm'] ?? ''),
            String(s['proto'] ?? ''),
            String(s['src'] ?? ''),
            String(s['dst'] ?? ''),
            String(s['pkt_len'] ?? '0'),
            maxSojMs,
            totalMs,
            String(s['endpoint'] ?? ''),
            String(s['completeness'] ?? ''),
            String(s['branch_count'] ?? 0),
            String(Boolean(s['requeued'])),
            String(s['path_sig'] ?? ''),
          ]
          csvLines.push(row.map(csvEscape).join(','))
        }
        const bom = Buffer.from([0xef, 0xbb, 0xbf])
        const body = Buffer.from(csvLines.join('\n') + '\n', 'utf8')
        writeFileAtomic(outPath, Buffer.concat([bom, body]))
        return {
          ok: true,
          out_path: outPath,
          summary: `已导出 CSV（${samples.length} 条）`,
          details: { rows: samples.length, format: 'csv' },
        }
      },
    }
    ctx.registerExtension('exporter', reg)
  },
}
