package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Paths captures the install root, data directories, and required binaries.
type Paths struct {
	InstallDir  string
	AppDir      string
	SessionsDir string
	LogsDir     string
	RuntimePath string
	OutLog      string
	ErrLog      string
	Node        string
	Entry       string
	WebDir      string
	Collectors  string
}

// DefaultAppDir returns %LOCALAPPDATA%\PktPathStudio on Windows, or a
// comparable per-user data directory on other platforms (used by tests).
func DefaultAppDir() string {
	if v := strings.TrimSpace(os.Getenv(AppDirEnv)); v != "" {
		return v
	}
	if runtime.GOOS == "windows" {
		base := strings.TrimSpace(os.Getenv(LocalAppDataEnv))
		if base == "" {
			home, _ := os.UserHomeDir()
			base = filepath.Join(home, "AppData", "Local")
		}
		return filepath.Join(base, AppDirName)
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "share", "pktpath-studio")
}

// ResolvePaths builds the full path set. appDir empty falls back to DefaultAppDir.
func ResolvePaths(installDir, appDir string) Paths {
	installDir = filepath.Clean(installDir)
	if strings.TrimSpace(appDir) == "" {
		appDir = DefaultAppDir()
	}
	appDir = filepath.Clean(appDir)
	logs := filepath.Join(appDir, "logs")
	return Paths{
		InstallDir:  installDir,
		AppDir:      appDir,
		SessionsDir: filepath.Join(appDir, "sessions"),
		LogsDir:     logs,
		RuntimePath: filepath.Join(logs, RuntimeFileName),
		OutLog:      filepath.Join(logs, OutLogName),
		ErrLog:      filepath.Join(logs, ErrLogName),
		Node:        filepath.Join(installDir, filepath.FromSlash(RelNodeExe)),
		Entry:       filepath.Join(installDir, filepath.FromSlash(RelEntry)),
		WebDir:      filepath.Join(installDir, filepath.FromSlash(RelWebDir)),
		Collectors:  filepath.Join(installDir, filepath.FromSlash(RelCollectorsDir)),
	}
}

type missingFile struct {
	Rel string
	Msg string
}

var requiredFiles = []missingFile{
	{RelNodeExe, "缺少随包 Node（node\\node.exe），拒绝启动，不会回退到 PATH。"},
	{RelEntry, "缺少 Studio 入口（studio-cordis\\src\\main.ts），拒绝启动。"},
	{RelWebIndex, "缺少前端页面（studio-cordis\\web\\index.html），拒绝启动。"},
	{RelCordisCore, "缺少 @cordisjs/core（studio-cordis\\node_modules\\@cordisjs\\core\\package.json），拒绝启动。"},
	{RelAndroidCollector, "缺少 Android 采集器（collectors\\android-arm64\\pktpath），拒绝启动。"},
}

// ValidateInstall fail-closes if any required file is missing. It never
// falls back to a PATH-resolved node. Hash checking is skipped when
// skipHash is true or PKTPATH_SKIP_NODE_HASH=1 (tests / debug only).
func ValidateInstall(p Paths, skipHash bool) error {
	for _, req := range requiredFiles {
		path := filepath.Join(p.InstallDir, filepath.FromSlash(req.Rel))
		st, err := os.Stat(path)
		if err != nil || st.IsDir() {
			return &LaunchError{Code: "missing", Message: req.Msg, Path: path}
		}
	}
	if skipHash || envTruthy(os.Getenv(SkipNodeHashEnv)) {
		return nil
	}
	sum, err := sha256File(p.Node)
	if err != nil {
		return &LaunchError{Code: "hash", Message: "无法读取随包 node\\node.exe 以校验 SHA256，拒绝启动，不会回退到 PATH。", Path: p.Node}
	}
	if !strings.EqualFold(sum, OfficialNodeExeSHA256) {
		return &LaunchError{
			Code:    "hash",
			Message: "随包 node\\node.exe 的 SHA256 与官方 Node v24.22.1 win-x64 不一致，拒绝启动，不会回退到 PATH。",
			Path:    p.Node,
		}
	}
	return nil
}

// LaunchError is a user-facing Chinese error from the tray host.
type LaunchError struct {
	Code    string
	Message string
	Path    string
}

func (e *LaunchError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

func sha256File(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func envTruthy(v string) bool {
	s := strings.ToLower(strings.TrimSpace(v))
	return s == "1" || s == "true" || s == "yes" || s == "on"
}

// MutexName returns Local\PktPathStudioTray-<first 16 hex of sha256(normalized appDir)>.
func MutexName(appDir string) string {
	return MutexNamePrefix + appDirHash(appDir)
}

func appDirHash(appDir string) string {
	norm := strings.ToLower(strings.TrimRight(strings.TrimSpace(appDir), `\/`))
	norm = strings.ReplaceAll(norm, "/", string(os.PathSeparator))
	sum := sha256.Sum256([]byte(norm))
	return hex.EncodeToString(sum[:])[:16]
}

// BuildNodeArgs returns the argv (excluding the node executable) used to
// start the bundled studio-cordis entry.
func BuildNodeArgs(p Paths, host string, port int) []string {
	if host == "" {
		host = DefaultHost
	}
	return []string{
		p.Entry,
		"--host", host,
		"--port", fmt.Sprintf("%d", port),
		"--app-dir", p.AppDir,
		"--collectors-dir", p.Collectors,
		"--web-dir", p.WebDir,
		"--no-open",
		"--no-auto-quit",
	}
}
