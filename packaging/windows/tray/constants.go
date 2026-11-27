package main

import "time"

// Official bundled Node v24.22.1 win-x64 node.exe SHA256 (WAVE1-CONTRACT v1.2).
const OfficialNodeExeSHA256 = "d702daa815eabbff763c7d3808e235cf031cf2ca70211b56847bc72f51e240e5"

const (
	AppDirName      = "PktPathStudio"
	DefaultHost     = "127.0.0.1"
	HealthPath      = "/api/health"
	QuitPath        = "/api/app/quit"
	ReadyPrefix     = "PKTPATH_STUDIO_READY"
	RuntimeFileName = "launcher-runtime.json"
	OutLogName      = "studio.out.log"
	ErrLogName      = "studio.err.log"

	// TrayWindowClass is the fixed Win32 class name. The NSIS installer
	// locates a running tray host with FindWindow and sends WM_CLOSE so
	// an upgrade or uninstall can gracefully stop the backend first.
	TrayWindowClass = "PktPathStudioTrayWindowClass"

	MutexNamePrefix = "Local\\PktPathStudioTray-"

	SkipNodeHashEnv = "PKTPATH_SKIP_NODE_HASH"
	AppDirEnv       = "PKTPATH_APP_DIR"
	LocalAppDataEnv = "LOCALAPPDATA"
)

const (
	ReadyTimeout  = 20 * time.Second
	QuitWait      = 8 * time.Second
	HealthWait    = 1500 * time.Millisecond
	ForceKillWait = 3 * time.Second
	ProbeWait     = 8 * time.Second
)

// Relative paths of fail-closed required files, from the install root.
const (
	RelNodeExe          = "node/node.exe"
	RelEntry            = "studio-cordis/src/main.ts"
	RelWebIndex         = "studio-cordis/web/index.html"
	RelCordisCore       = "studio-cordis/node_modules/@cordisjs/core/package.json"
	RelAndroidCollector = "collectors/android-arm64/pktpath"
	RelCollectorsDir    = "collectors"
	RelWebDir           = "studio-cordis/web"
)
