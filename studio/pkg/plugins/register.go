// Package plugins implements all first-class built-in plugins for PktPath Studio v2.0.
// Following the DSH/Cordis "everything is a plugin" architecture, transports,
// eBPF collectors, visual kernel extensions, post-analyzers, exporters, and UI themes
// are all registered as hot-reloadable plugins with visual config schemas.
package plugins

import "pktpath/studio/pkg/kernel"

// RegisterAllBuiltins registers all 11 first-class built-in plugins on k.
func RegisterAllBuiltins(k *kernel.Kernel) {
	// 1. Target Transports
	k.RegisterBuiltin(&androidADBTransport{}, true)
	k.RegisterBuiltin(&linuxSSHTransport{}, true)
	k.RegisterBuiltin(&offlineSessionTransport{}, true)

	// 2. Collectors & Visual Dynamic Kernel Extensions
	k.RegisterBuiltin(&ebpfTCCollector{}, true)
	k.RegisterBuiltin(&kernelExtBuilder{}, true)

	// 3. Post-Analyzers
	k.RegisterBuiltin(&dagReconstructAnalyzer{}, true)
	k.RegisterBuiltin(&anomalyRadarAnalyzer{}, true)

	// 4. Exporters
	k.RegisterBuiltin(&pcapngExporter{}, true)
	k.RegisterBuiltin(&redactExporter{}, true)
	k.RegisterBuiltin(&csvReportExporter{}, true)

	// 5. UI & Appearance
	k.RegisterBuiltin(&uiThemePlugin{}, true)
}
