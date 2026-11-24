package plugins

import "pktpath/studio/pkg/kernel"

// RegisterAllBuiltins registers all 13 first-class built-in plugins on k.
func RegisterAllBuiltins(k *kernel.Kernel) {
	// 1. Transports (where packets/sessions come from)
	k.RegisterBuiltin(&androidADBTransport{}, true)
	k.RegisterBuiltin(&linuxSSHTransport{}, true)
	k.RegisterBuiltin(&offlineSessionTransport{}, true)

	// 2. Collectors & Kernel Extensions (what gets observed)
	k.RegisterBuiltin(&ebpfTCCollector{}, true)
	k.RegisterBuiltin(&kernelExtBuilder{}, true)

	// 3. Capture Modes (how capture runs / triggers)
	k.RegisterBuiltin(&oneshotModePlugin{}, true)
	k.RegisterBuiltin(&daemonModePlugin{}, true)

	// 4. Post-Analyzers (how traces are interpreted)
	k.RegisterBuiltin(&dagReconstructAnalyzer{}, true)
	k.RegisterBuiltin(&anomalyRadarAnalyzer{}, true)

	// 5. Exporters (how results leave Studio)
	k.RegisterBuiltin(&pcapngExporter{}, true)
	k.RegisterBuiltin(&redactExporter{}, true)
	k.RegisterBuiltin(&csvReportExporter{}, true)

	// 6. UI Theme
	k.RegisterBuiltin(&uiThemePlugin{}, true)
}
