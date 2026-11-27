package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRuntimeRoundTripAndCleanup(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	path := filepath.Join(dir, RuntimeFileName)
	st := RuntimeState{
		PID:         4242,
		LauncherPID: 4242,
		URL:         "http://127.0.0.1:18765",
		Host:        "127.0.0.1",
		AppDir:      `/Users/测试/AppData/Local/PktPathStudio`,
		Entry:       `C:\Program Files\PktPath Studio\studio-cordis\src\main.ts`,
		Node:        `C:\Program Files\PktPath Studio\node\node.exe`,
		StartedAt:   FormatStartedAt(time.Date(2026, 11, 27, 14, 0, 0, 0, time.FixedZone("CST", 8*3600))),
		Logs: RuntimeLogs{
			Out: `C:\data\logs\studio.out.log`,
			Err: `C:\data\logs\studio.err.log`,
		},
	}
	if err := WriteRuntime(path, st); err != nil {
		t.Fatal(err)
	}
	got, err := ReadRuntime(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.PID != st.PID || got.URL != st.URL || got.Host != st.Host || got.AppDir != st.AppDir {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	if got.Logs.Out != st.Logs.Out || got.Entry != st.Entry || got.Node != st.Node {
		t.Fatalf("paths mismatch: %+v", got)
	}
	if got.StartedAt != "2026-11-27T14:00:00+08:00" {
		t.Fatalf("started_at=%q", got.StartedAt)
	}
	raw, _ := os.ReadFile(path)
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"pid", "launcher_pid", "url", "host", "app_dir", "entry", "node", "started_at", "logs"} {
		if _, ok := generic[k]; !ok {
			t.Fatalf("missing field %s in %s", k, raw)
		}
	}
	RemoveRuntime(path)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("runtime file not removed: %v", err)
	}
}

func TestParseReadyLine(t *testing.T) {
	r := ParseReadyLine("boot\nPKTPATH_STUDIO_READY url=http://127.0.0.1:34567 pid=12345\nmore")
	if r == nil || r.URL != "http://127.0.0.1:34567" || r.PID != 12345 {
		t.Fatalf("got %+v", r)
	}
	if ParseReadyLine("not ready yet") != nil {
		t.Fatal("expected nil")
	}
}
