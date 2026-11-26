// Builtin plugin: builtin.exporter.pcapng (Tier 2 required)
// Ported 1:1 from studio/pkg/plugins/exporters.go (pcapngExporter) with v1.2 safety rules.

import fs from 'node:fs'
import path from 'node:path'
import { exportPcapng } from './export/pcapng.ts'
import { validateExportOutPath } from './exporter-csv-report.ts'
import type { BuiltinPlugin, ExporterInput, ExporterOutput, ExporterRegistration, PluginContext } from './types.ts'

export const pcapngExporterPlugin: BuiltinPlugin = {
  meta: {
    id: 'builtin.exporter.pcapng',
    name: 'Wireshark 导出',
    version: '2.0.0',
    author: 'PktPath',
    description: '导出带队列路径注释的 .pcapng 文件。',
    category: 'exporter',
    icon: '🦈',
    builtin: true,
    capabilities: [
      '导出 Wireshark 可直接打开的多 IDB .pcapng',
      '支持导出前对 IP、端口、MAC 与负载脱敏',
    ],
    provides: ['exporter.pcapng'],
    tags: ['pcapng', 'wireshark'],
  },
  schema: {
    fields: [
      {
        key: 'redact_by_default',
        label: '导出时默认脱敏 IP 与端口',
        type: 'boolean',
        default: false,
      },
      {
        key: 'default_key',
        label: '默认脱敏 Key',
        type: 'string',
        placeholder: '留空自动随机',
      },
    ],
  },
  apply(ctx: PluginContext, cfg: Record<string, unknown>): void {
    const defRedact = cfg['redact_by_default'] === true
    const defKey = typeof cfg['default_key'] === 'string' ? cfg['default_key'].trim() : ''

    ctx.provide('exporter.pcapng', { ...cfg })

    const reg: ExporterRegistration = {
      id: 'pcapng',
      plugin_id: 'builtin.exporter.pcapng',
      name: 'Wireshark 导出',
      description: '导出 Wireshark .pcapng',
      default_ext: '.pcapng',
      async run(input: ExporterInput): Promise<ExporterOutput> {
        const redact = typeof input.params?.['redact'] === 'boolean' ? (input.params['redact'] as boolean) : defRedact
        const key =
          typeof input.params?.['key'] === 'string' && (input.params['key'] as string).trim() !== ''
            ? (input.params['key'] as string).trim()
            : defKey
        const safeSessionId = input.session_id.replace(/[^a-zA-Z0-9._-]/g, '_') || 'session'
        let rawOutPath = typeof input.out_path === 'string' ? input.out_path.trim() : ''
        if (!rawOutPath) {
          fs.mkdirSync(ctx.host.paths.exportsDir, { recursive: true })
          rawOutPath = path.join(ctx.host.paths.exportsDir, `${safeSessionId}.pcapng`)
        }
        const outPath = validateExportOutPath(rawOutPath, input.session_dir)
        const n = exportPcapng(input.session_dir, outPath, redact, key)
        return {
          ok: true,
          out_path: outPath,
          summary: `已导出 ${n} 个包 (.pcapng)`,
          details: { exported_packets: n, redact },
        }
      },
    }
    ctx.registerExtension('exporter', reg)
  },
}
