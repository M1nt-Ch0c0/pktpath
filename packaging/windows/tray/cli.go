package main

import (
	"os"
	"path/filepath"
	"strings"
)

// TrayOptions are the tray-host command-line / environment options.
type TrayOptions struct {
	InstallDir string
	AppDir     string
	SkipHash   bool
	NoOpen     bool
}

func ParseTrayArgs(argv []string, env func(string) string, executable string) TrayOptions {
	opt := TrayOptions{}
	if env != nil {
		opt.AppDir = strings.TrimSpace(env(AppDirEnv))
		opt.SkipHash = envTruthy(env(SkipNodeHashEnv))
		opt.NoOpen = envTruthy(env("PKTPATH_NO_OPEN"))
	}
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--app-dir" && i+1 < len(argv):
			i++
			opt.AppDir = argv[i]
		case strings.HasPrefix(a, "--app-dir="):
			opt.AppDir = strings.TrimPrefix(a, "--app-dir=")
		case a == "--install-dir" && i+1 < len(argv):
			i++
			opt.InstallDir = argv[i]
		case strings.HasPrefix(a, "--install-dir="):
			opt.InstallDir = strings.TrimPrefix(a, "--install-dir=")
		case a == "--no-open":
			opt.NoOpen = true
		case a == "--skip-node-hash":
			opt.SkipHash = true
		}
	}
	if opt.InstallDir == "" && executable != "" {
		opt.InstallDir = filepath.Dir(executable)
	}
	if opt.AppDir == "" {
		opt.AppDir = DefaultAppDir()
	}
	return opt
}

func currentExecutable() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		return resolved
	}
	return exe
}
