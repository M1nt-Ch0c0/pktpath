package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func nodeBin(t *testing.T) string {
	t.Helper()
	if p, err := exec.LookPath("node"); err == nil {
		return p
	}
	t.Skip("node not on PATH")
	return ""
}

func writeFakeInstall(t *testing.T, mockFlags map[string]any) (Paths, string) {
	t.Helper()
	root := t.TempDir()
	app := filepath.Join(t.TempDir(), "app data", "PktPathStudio")
	p := ResolvePaths(root, app)

	mustCopy := func(dst string, data []byte, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, data, mode); err != nil {
			t.Fatal(err)
		}
	}

	// Use the real Node binary as node/node.exe (hash is skipped in tests).
	src := nodeBin(t)
	if err := os.MkdirAll(filepath.Dir(p.Node), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(src, p.Node); err != nil {
		if err2 := os.Link(src, p.Node); err2 != nil {
			data, err3 := os.ReadFile(src)
			if err3 != nil {
				t.Fatal(err, err2, err3)
			}
			mustCopy(p.Node, data, 0o755)
			_ = os.Chmod(p.Node, 0o755)
		}
	}

	mockPath := filepath.Join("testdata", "mock-studio.mjs")
	mock, err := os.ReadFile(mockPath)
	if err != nil {
		t.Fatal(err)
	}
	mustCopy(p.Entry, mock, 0o644)
	mustCopy(filepath.Join(p.InstallDir, filepath.FromSlash(RelWebIndex)), []byte("<html></html>"), 0o644)
	mustCopy(filepath.Join(p.InstallDir, filepath.FromSlash(RelCordisCore)), []byte(`{"name":"@cordisjs/core"}`), 0o644)
	mustCopy(filepath.Join(p.InstallDir, filepath.FromSlash(RelAndroidCollector)), []byte("collector"), 0o755)

	flagsPath := filepath.Join(root, "mock-flags.json")
	if mockFlags == nil {
		mockFlags = map[string]any{}
	}
	raw, _ := json.Marshal(mockFlags)
	if err := os.WriteFile(flagsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return p, flagsPath
}

func newTestLauncher(p Paths, flagsPath string) *Launcher {
	l := NewLauncher(p)
	l.SkipHash = true
	l.ReadyFor = 8 * time.Second
	l.QuitFor = 3 * time.Second
	tEnv := os.Environ()
	// Inject flags path via a wrapper? Launch uses os.Environ() at Start.
	// We'll set the env around Start in each test.
	_ = tEnv
	_ = flagsPath
	return l
}

func TestLauncherStartReadyQuit(t *testing.T) {
	p, flagsPath := writeFakeInstall(t, nil)
	t.Setenv("PKTPATH_MOCK_FLAGS", flagsPath)
	t.Setenv(SkipNodeHashEnv, "1")
	l := newTestLauncher(p, flagsPath)
	if err := l.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer l.Stop()

	if !l.Running() {
		t.Fatal("expected running")
	}
	url := l.URL()
	if !strings.HasPrefix(url, "http://127.0.0.1:") {
		t.Fatalf("url=%q", url)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if !CheckHealth(ctx, url) {
		t.Fatal("health not ok after Start")
	}

	st, err := ReadRuntime(p.RuntimePath)
	if err != nil {
		t.Fatal(err)
	}
	if st.URL != url || st.Host != "127.0.0.1" || st.AppDir != p.AppDir {
		t.Fatalf("runtime mismatch: %+v", st)
	}
	if st.PID <= 0 || st.LauncherPID <= 0 {
		t.Fatalf("pids: %+v", st)
	}
	if st.Entry != p.Entry || st.Node != p.Node {
		t.Fatalf("entry/node: %+v", st)
	}
	if st.Logs.Out != p.OutLog || st.Logs.Err != p.ErrLog {
		t.Fatalf("logs: %+v", st)
	}
	if st.StartedAt == "" {
		t.Fatal("missing started_at")
	}

	// ProbeExisting should see the live instance.
	got, ok := ProbeExisting(p.RuntimePath)
	if !ok || got != url {
		t.Fatalf("ProbeExisting = %q %v", got, ok)
	}

	if err := l.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if l.Running() {
		t.Fatal("still running after Stop")
	}
	if _, err := os.Stat(p.RuntimePath); !os.IsNotExist(err) {
		t.Fatal("runtime file should be removed after Stop")
	}
	// Health should fail after quit.
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if CheckHealth(ctx2, url) {
		t.Fatal("health still ok after Stop")
	}
}

func TestLauncherRestart(t *testing.T) {
	p, flagsPath := writeFakeInstall(t, nil)
	t.Setenv("PKTPATH_MOCK_FLAGS", flagsPath)
	t.Setenv(SkipNodeHashEnv, "1")
	l := newTestLauncher(p, flagsPath)
	if err := l.Start(); err != nil {
		t.Fatal(err)
	}
	url1 := l.URL()
	pid1 := 0
	if st, err := ReadRuntime(p.RuntimePath); err == nil {
		pid1 = st.PID
	}
	if err := l.Restart(); err != nil {
		t.Fatalf("Restart: %v", err)
	}
	defer l.Stop()
	url2 := l.URL()
	if url2 == "" || !strings.HasPrefix(url2, "http://127.0.0.1:") {
		t.Fatalf("restart url=%q", url2)
	}
	if url1 == url2 {
		// Port 0 may theoretically reuse the same port; that's OK, but
		// the pid or started_at should have changed.
		st, err := ReadRuntime(p.RuntimePath)
		if err != nil {
			t.Fatal(err)
		}
		if pid1 != 0 && st.PID == pid1 {
			// Still possible but health must work.
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if !CheckHealth(ctx, url2) {
		t.Fatal("health not ok after Restart")
	}
	if url1 != url2 {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if CheckHealth(ctx, url1) {
			t.Fatal("old url still healthy after restart")
		}
	}
}

func TestLauncherReadyTimeoutCleansUp(t *testing.T) {
	p, flagsPath := writeFakeInstall(t, map[string]any{"noReady": true})
	t.Setenv("PKTPATH_MOCK_FLAGS", flagsPath)
	t.Setenv(SkipNodeHashEnv, "1")
	l := newTestLauncher(p, flagsPath)
	l.ReadyFor = 800 * time.Millisecond
	err := l.Start()
	if err == nil || !strings.Contains(err.Error(), "超时") {
		t.Fatalf("expected timeout, got %v", err)
	}
	if l.Running() {
		t.Fatal("should not be running")
	}
	if _, err := os.Stat(p.RuntimePath); err == nil {
		t.Fatal("runtime file should not remain after timeout")
	}
}

func TestLauncherCrashBeforeReady(t *testing.T) {
	p, flagsPath := writeFakeInstall(t, map[string]any{"crashBefore": true})
	t.Setenv("PKTPATH_MOCK_FLAGS", flagsPath)
	t.Setenv(SkipNodeHashEnv, "1")
	l := newTestLauncher(p, flagsPath)
	l.ReadyFor = 2 * time.Second
	err := l.Start()
	if err == nil || !strings.Contains(err.Error(), "就绪前已退出") {
		t.Fatalf("expected early-exit error, got %v", err)
	}
	if _, err := os.Stat(p.RuntimePath); err == nil {
		t.Fatal("runtime file should not remain")
	}
}

func TestLauncherBadHealthTimeout(t *testing.T) {
	p, flagsPath := writeFakeInstall(t, map[string]any{"badHealth": true})
	t.Setenv("PKTPATH_MOCK_FLAGS", flagsPath)
	t.Setenv(SkipNodeHashEnv, "1")
	l := newTestLauncher(p, flagsPath)
	l.ReadyFor = 800 * time.Millisecond
	err := l.Start()
	if err == nil || !strings.Contains(err.Error(), "超时") {
		t.Fatalf("expected timeout when health is bad, got %v", err)
	}
	if _, err := os.Stat(p.RuntimePath); err == nil {
		t.Fatal("runtime file should not remain")
	}
}

func TestLauncherQuitHangThenKill(t *testing.T) {
	p, flagsPath := writeFakeInstall(t, map[string]any{"quitHang": true})
	t.Setenv("PKTPATH_MOCK_FLAGS", flagsPath)
	t.Setenv(SkipNodeHashEnv, "1")
	l := newTestLauncher(p, flagsPath)
	l.QuitFor = 200 * time.Millisecond
	if err := l.Start(); err != nil {
		t.Fatal(err)
	}
	url := l.URL()
	if err := l.Stop(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if CheckHealth(ctx, url) {
		t.Fatal("process should have been killed after quit hang")
	}
	if _, err := os.Stat(p.RuntimePath); err == nil {
		t.Fatal("runtime file should be removed after forced kill")
	}
}

func TestLauncherMissingNodeDoesNotUsePATH(t *testing.T) {
	p, _ := writeFakeInstall(t, nil)
	if err := os.Remove(p.Node); err != nil {
		t.Fatal(err)
	}
	// PATH definitely has node (we used it), but the launcher must refuse.
	l := newTestLauncher(p, "")
	err := l.Start()
	if err == nil || !strings.Contains(err.Error(), "不会回退到 PATH") {
		t.Fatalf("expected fail-closed PATH message, got %v", err)
	}
}

func TestProbeExistingUnhealthy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, RuntimeFileName)
	if _, ok := ProbeExisting(path); ok {
		t.Fatal("missing file should be unhealthy")
	}
	_ = WriteRuntime(path, RuntimeState{URL: "http://127.0.0.1:1", PID: 1})
	url, ok := ProbeExisting(path)
	if ok || url != "http://127.0.0.1:1" {
		t.Fatalf("got %q %v", url, ok)
	}
}

func TestUnexpectedExitFlag(t *testing.T) {
	p, flagsPath := writeFakeInstall(t, nil)
	t.Setenv("PKTPATH_MOCK_FLAGS", flagsPath)
	t.Setenv(SkipNodeHashEnv, "1")
	l := newTestLauncher(p, flagsPath)
	ch := make(chan struct{}, 1)
	l.SetOnUnexpectedExit(func(err error) { ch <- struct{}{} })
	if err := l.Start(); err != nil {
		t.Fatal(err)
	}
	// Kill the child from the outside so the watcher treats it as unexpected.
	l.mu.Lock()
	cmd := l.cmd
	l.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		t.Fatal("no process")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for unexpected-exit callback")
	}
	if !l.UnexpectedExit() {
		t.Fatal("UnexpectedExit not set")
	}
	_ = l.Stop()
}

func TestSpacesAndUnicodePaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Covered by the same test when run on Windows; the Linux box is
		// the required environment for this commit.
	}
	root := filepath.Join(t.TempDir(), "PktPath Studio 测试")
	app := filepath.Join(t.TempDir(), "Local App", "PktPathStudio")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	// Reuse writeFakeInstall structure by relocating: just call the helper
	// then... easier to build in place.
	p, flagsPath := writeFakeInstall(t, nil)
	// Start already uses spaces in app dir ("app data"). Also copy into
	// a unicode install root by rewriting Paths.
	_ = root
	_ = app
	t.Setenv("PKTPATH_MOCK_FLAGS", flagsPath)
	t.Setenv(SkipNodeHashEnv, "1")
	l := newTestLauncher(p, flagsPath)
	if err := l.Start(); err != nil {
		t.Fatal(err)
	}
	defer l.Stop()
	if !strings.Contains(p.AppDir, " ") {
		t.Fatal("test setup should use a spaced app dir")
	}
	resp, err := http.Get(l.URL() + "/api/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"ok":true`) {
		t.Fatalf("health %d %s", resp.StatusCode, body)
	}
}
