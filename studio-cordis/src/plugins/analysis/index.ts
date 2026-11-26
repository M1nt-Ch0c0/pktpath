export * from './types.ts'
export * from './wire/consts.ts'
export * from './wire/wire.ts'
export * from './reconstruct/index.ts'
export * from './session-store.ts'
export * from './transport-offline.ts'
export * from './analyzer-dag-reconstruct.ts'
export * from './analyzer-anomaly-radar.ts'
export * from './exporter-csv-report.ts'
export * from './export/redact.ts'
export * from './export/pcapng.ts'
export * from './exporter-pcapng.ts'
export * from './exporter-redact.ts'

import { anomalyRadarPlugin } from './analyzer-anomaly-radar.ts'
import { dagReconstructPlugin } from './analyzer-dag-reconstruct.ts'
import { csvReportExporterPlugin } from './exporter-csv-report.ts'
import { pcapngExporterPlugin } from './exporter-pcapng.ts'
import { redactExporterPlugin } from './exporter-redact.ts'
import type { SessionStore } from './session-store.ts'
import { createOfflineTransportPlugin, offlineTransportPlugin } from './transport-offline.ts'
import type { BuiltinPlugin } from './types.ts'

export function createAnalysisTier1Builtins(store?: SessionStore): BuiltinPlugin[] {
  return [
    store ? createOfflineTransportPlugin(store) : offlineTransportPlugin,
    dagReconstructPlugin,
    anomalyRadarPlugin,
    csvReportExporterPlugin,
  ]
}

export function createAnalysisWave1Builtins(store?: SessionStore): BuiltinPlugin[] {
  return [
    ...createAnalysisTier1Builtins(store),
    pcapngExporterPlugin,
    redactExporterPlugin,
  ]
}

export const ANALYSIS_TIER1_BUILTINS: BuiltinPlugin[] = [
  offlineTransportPlugin,
  dagReconstructPlugin,
  anomalyRadarPlugin,
  csvReportExporterPlugin,
]

export const ANALYSIS_WAVE1_BUILTINS: BuiltinPlugin[] = [
  ...ANALYSIS_TIER1_BUILTINS,
  pcapngExporterPlugin,
  redactExporterPlugin,
]
