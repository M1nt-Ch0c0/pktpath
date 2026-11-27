// Builtin plugin: builtin.exporter.redact (Tier 2 required)
// Ported 1:1 from studio/pkg/plugins/exporters.go (redactExporter) with v1.2 safety rules.

import fs from 'node:fs'
import path from 'node:path'
import { redactSession } from './export/redact.ts'
import { isPathInsideDir } from './exporter-csv-report.ts'
import type { BuiltinPlugin, ExporterInput, ExporterOutput, ExporterRegistration, PluginContext } from './types.ts'

export const redactExporterPlugin: BuiltinPlugin = {
  meta: {
    id: 'builtin.exporter.redact',
    name: '隐私脱敏',
    version: '2.0.0',
    author: 'PktPath',
    description: '匿名化 IP、端口、UID 和包头后另存会话目录。',
    category: 'exporter',
    icon: '🛡️',
    builtin: true,
    capabilities: [
      '保留流关联与队列耗时，替换真实 IP、端口、UID 与包头',
      '另存为可独立打开的脱敏会话目录，绝不改动原会话',
    ],
    provides: ['exporter.redact'],
    usedBy: ['隐私脱敏导出'],
    tags: ['privacy', 'redact'],
  },
  schema: {
    fields: [
      {
        key: 'default_key',
        label: '脱敏盐值 Key',
        description: '相同 Key 对同一 IP 始终生成一致的匿名地址。',
        type: 'string',
        placeholder: '留空自动随机',
      },
    ],
  },
  apply(ctx: PluginContext, cfg: Record<string, unknown>): void {
    const defKey = typeof cfg['default_key'] === 'string' ? cfg['default_key'].trim() : ''

    ctx.provide('exporter.redact', { ...cfg })

    const reg: ExporterRegistration = {
      id: 'redact',
      plugin_id: 'builtin.exporter.redact',
      name: '隐私脱敏',
      description: '生成脱敏会话目录',
      async run(input: ExporterInput): Promise<ExporterOutput> {
        const key =
          typeof input.params?.['key'] === 'string' && (input.params['key'] as string).trim() !== ''
            ? (input.params['key'] as string).trim()
            : defKey
        const safeSessionId = input.session_id.replace(/[^a-zA-Z0-9._-]/g, '_') || 'session'
        let rawOutDir = typeof input.out_path === 'string' ? input.out_path.trim() : ''
        if (!rawOutDir) {
          fs.mkdirSync(ctx.host.paths.exportsDir, { recursive: true })
          rawOutDir = path.join(ctx.host.paths.exportsDir, `${safeSessionId}_redacted`)
        }
        const outDir = path.resolve(rawOutDir)
        if (input.session_dir && isPathInsideDir(outDir, input.session_dir)) {
          throw new Error(`refusing to write redacted session inside session_dir: ${outDir}`)
        }
        redactSession(input.session_dir, outDir, key)
        return {
          ok: true,
          out_path: outDir,
          is_directory: true,
          summary: '已生成脱敏会话目录',
          details: { is_directory: true },
        }
      },
    }
    ctx.registerExtension('exporter', reg)
  },
}
