package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildNodeArgs(t *testing.T) {
	p := ResolvePaths(`/opt/PktPath Studio`, `/tmp/data dir/PktPathStudio`)
	args := BuildNodeArgs(p, "", 0)
	joined := strings.Join(args, "\x00")
	want := []string{
		"--host", "127.0.0.1",
		"--port", "0",
		"--app-dir", p.AppDir,
		"--collectors-dir", p.Collectors,
		"--web-dir", p.WebDir,
		"--no-open",
		"--no-auto-quit",
	}
	for i := 0; i+1 < len(want); i += 2 {
		if !strings.Contains(joined, want[i]+"\x00"+want[i+1]) && want[i] != "--no-open" && want[i] != "--no-auto-quit" {
			// flags without values checked below
		}
	}
	if args[0] != p.Entry {
		t.Fatalf("first arg should be entry, got %q", args[0])
	}
	got := map[string]string{}
	flags := map[string]bool{}
	for i := 1; i < len(args); i++ {
		if args[i] == "--no-open" || args[i] == "--no-auto-quit" {
			flags[args[i]] = true
			continue
		}
		if strings.HasPrefix(args[i], "--") && i+1 < len(args) {
			got[args[i]] = args[i+1]
			i++
		}
	}
	if got["--host"] != "127.0.0.1" || got["--port"] != "0" {
		t.Fatalf("host/port = %q %q", got["--host"], got["--port"])
	}
	if got["--app-dir"] != p.AppDir {
		t.Fatalf("app-dir = %q", got["--app-dir"])
	}
	if got["--collectors-dir"] != p.Collectors {
		t.Fatalf("collectors-dir = %q", got["--collectors-dir"])
	}
	if got["--web-dir"] != p.WebDir {
		t.Fatalf("web-dir = %q", got["--web-dir"])
	}
	if !flags["--no-open"] || !flags["--no-auto-quit"] {
		t.Fatalf("missing no-open/no-auto-quit: %v %v", flags, args)
	}
}

func TestMutexNameStableAndNormalized(t *testing.T) {
	a := MutexName(`C:\Users\张三\AppData\Local\PktPathStudio`)
	b := MutexName(`C:\Users\张三\AppData\Local\PktPathStudio\`)
	c := MutexName(`c:\users\张三\appdata\local\pktpathstudio`)
	if !strings.HasPrefix(a, MutexNamePrefix) {
		t.Fatalf("prefix: %s", a)
	}
	if a != b || a != c {
		t.Fatalf("normalization failed: %s / %s / %s", a, b, c)
	}
	if len(strings.TrimPrefix(a, MutexNamePrefix)) != 16 {
		t.Fatalf("hash length: %s", a)
	}
}

func TestValidateInstallFailClosed(t *testing.T) {
	root := t.TempDir()
	app := filepath.Join(t.TempDir(), "app data")
	p := ResolvePaths(root, app)
	err := ValidateInstall(p, true)
	if err == nil {
		t.Fatal("expected missing-file error")
	}
	le, ok := err.(*LaunchError)
	if !ok || le.Code != "missing" || !strings.Contains(le.Message, "内置运行环境") {
		t.Fatalf("expected node missing message, got %#v", err)
	}

	// Create files one by one and confirm each missing message.
	order := []struct {
		rel string
		msg string
	}{
		{RelNodeExe, "内置运行环境"},
		{RelEntry, "主程序文件"},
		{RelWebIndex, "界面文件"},
		{RelCordisCore, "核心组件"},
		{RelAndroidCollector, "手机采集组件"},
	}
	for i, step := range order {
		if err := ValidateInstall(p, true); err == nil || !strings.Contains(err.Error(), step.msg) {
			t.Fatalf("step %d: want %q in %v", i, step.msg, err)
		}
		path := filepath.Join(root, filepath.FromSlash(step.rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := ValidateInstall(p, true); err != nil {
		t.Fatalf("all files present, skip hash: %v", err)
	}

	// Wrong hash must fail when skip is false, and must not use PATH.
	err = ValidateInstall(p, false)
	if err == nil || !strings.Contains(err.Error(), "已损坏或被修改") {
		t.Fatalf("expected hash mismatch, got %v", err)
	}

	// Official hash of the tiny fixture file, then it should pass.
	sum := sha256.Sum256([]byte("x"))
	if hex.EncodeToString(sum[:]) == OfficialNodeExeSHA256 {
		t.Fatal("fixture unexpectedly matches official hash")
	}

	t.Setenv(SkipNodeHashEnv, "1")
	if err := ValidateInstall(p, false); err != nil {
		t.Fatalf("PKTPATH_SKIP_NODE_HASH=1 should skip: %v", err)
	}
}

func TestDefaultAppDirEnvOverride(t *testing.T) {
	want := filepath.Join(t.TempDir(), "custom app")
	t.Setenv(AppDirEnv, want)
	if got := DefaultAppDir(); got != want {
		t.Fatalf("DefaultAppDir=%q want %q", got, want)
	}
}
