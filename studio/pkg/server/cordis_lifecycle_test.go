package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCordisF02HTTPExistingToggleConfigResetReloadAndNegativeGates(t *testing.T) {
	path := os.Getenv("PKTPATH_TEST_CORDIS_HOST")
	if path == "" {
		t.Skip("controlled Node host required")
	}
	s := New(Options{AppDir: t.TempDir(), CordisPluginHost: path})
	defer s.Shutdown(context.Background())
	h := s.kernel.Host().LifecycleHost
	if h == nil {
		t.Fatal("candidate not wired")
	}
	wait := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := h.WaitActive(ctx, "builtin.collector.ebpf-tc", "builtin.collector.kernel-ext", "builtin.mode.oneshot", "builtin.mode.daemon"); err != nil {
			t.Fatal(err)
		}
	}
	wait()
	post := func(route, body string) {
		t.Helper()
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", route, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		s.Handler().ServeHTTP(w, r)
		var data map[string]json.RawMessage
		json.Unmarshal(w.Body.Bytes(), &data)
		if w.Code != 200 || string(data["ok"]) != "true" {
			t.Fatalf("%s status=%d %s", route, w.Code, w.Body.String())
		}
		if _, ok := data["state"]; !ok {
			t.Fatal("state removed")
		}
	}
	id := `"id":"builtin.collector.ebpf-tc"`
	post("/api/kernel/plugins/toggle", `{`+id+`,"enabled":false}`)
	if s.kernel.Collector() != nil || len(s.kernel.CaptureModes()) != 0 {
		t.Fatal("HTTP disable bypassed owner")
	}
	post("/api/kernel/plugins/toggle", `{`+id+`,"enabled":true}`)
	wait()
	post("/api/kernel/plugins/config", `{`+id+`,"config":{"capture_hdr_bytes":64}}`)
	wait()
	if s.kernel.Collector().CaptureHdrBytes != 64 {
		t.Fatal("config not effective")
	}
	post("/api/kernel/plugins/reset", `{`+id+`}`)
	wait()
	if s.kernel.Collector().CaptureHdrBytes != 96 {
		t.Fatal("reset not effective")
	}
	post("/api/kernel/plugins/reload", `{`+id+`}`)
	wait()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/api/kernel/state", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"lifecycle_host"`) {
		t.Fatal("no graph diagnostics")
	}
	if s.cap != nil || s.http != nil {
		t.Fatal("metadata-only candidate changed capture/listener")
	}
}
func TestCordisF02DisabledZeroNodeAndNoConfigRewrite(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "plugins_config.json")
	original := []byte(`{"version":2,"plugins":{}}`)
	os.WriteFile(config, original, 0600)
	sentinel := filepath.Join(dir, "must not run node")
	called := filepath.Join(dir, "node-called")
	os.WriteFile(sentinel, []byte("#!/bin/sh\nprintf called > '"+called+"'\nexit 91\n"), 0700)
	s := New(Options{AppDir: dir, CordisPluginNode: sentinel})
	defer s.Shutdown(context.Background())
	if s.kernel.Host().LifecycleHost != nil || s.kernel.Collector() == nil {
		t.Fatal("Node path alone enabled candidate/broke default")
	}
	if _, err := os.Stat(called); !os.IsNotExist(err) {
		t.Fatal("disabled candidate probed runtime")
	}
	after, _ := os.ReadFile(config)
	if string(after) != string(original) {
		t.Fatal("default rewrote config")
	}
	if s.cap != nil || s.http != nil {
		t.Fatal("capture/listener unexpectedly started")
	}
}
func TestCordisF02ExplicitMissingNodeErrorsNoGoReplay(t *testing.T) {
	s := New(Options{AppDir: t.TempDir(), CordisPluginHost: "not-executed.mjs", CordisPluginNode: filepath.Join(t.TempDir(), "nonexistent-node")})
	defer s.Shutdown(context.Background())
	if s.kernel.Host().LifecycleHost == nil || s.kernel.Collector() != nil || len(s.kernel.CaptureModes()) != 0 {
		t.Fatal("explicit candidate failure silently ran Go Apply")
	}
	if !s.kernel.IsPluginActive("builtin.transport.offline") {
		t.Fatal("unselected Go path broken")
	}
	if s.cap != nil || s.http != nil {
		t.Fatal("capture/listener unexpectedly started")
	}
}
