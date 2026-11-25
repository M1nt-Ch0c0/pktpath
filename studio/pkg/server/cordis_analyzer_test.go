package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestF01LegacyAndCurrentMutationEntrypoints(t *testing.T) {
	// No packages are activated, so the fake absent runtime must never be probed.
	s := New(Options{AppDir: t.TempDir(), CordisAnalyzerHost: "not-started.mjs", CordisAnalyzerNode: "not-started-node"})
	defer s.Shutdown(context.Background())
	h := s.kernel.Host().AnalyzerHost
	if h == nil {
		t.Fatal("candidate option not wired")
	}
	end, err := h.ProtectPackageMutation()
	if err != nil {
		t.Fatal(err)
	}
	defer end()
	for _, route := range []string{"/api/plugins/import", "/api/plugins/delete", "/api/kernel/plugins/install", "/api/kernel/plugins/uninstall"} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest("POST", route, strings.NewReader(`{"id":"fixture","content":"{}","filename":"fixture.json"}`))
		request.Header.Set("Content-Type", "application/json")
		s.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "leased") {
			t.Fatalf("%s bypassed package admission: %d %s", route, recorder.Code, recorder.Body.String())
		}
	}
	if s.cap != nil || s.http != nil {
		t.Fatal("candidate unexpectedly owns capture/listener")
	}
}
func TestF01DisabledCandidateZeroNodeAndNoConfigRewrite(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "plugins_config.json")
	original := []byte(`{"version":2,"plugins":{}}`)
	if err := os.WriteFile(config, original, 0600); err != nil {
		t.Fatal(err)
	}
	// Supplying a Node path alone is not opt-in and cannot execute this sentinel.
	sentinel := filepath.Join(dir, "must not run node")
	called := filepath.Join(dir, "node-called")
	_ = os.WriteFile(sentinel, []byte("#!/bin/sh\nprintf called > '"+called+"'\nexit 91\n"), 0700)
	s := New(Options{AppDir: dir, CordisAnalyzerNode: sentinel})
	defer s.Shutdown(context.Background())
	if s.kernel.Host().AnalyzerHost != nil {
		t.Fatal("Node path alone enabled candidate")
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/api/kernel/state", nil))
	if w.Code != 200 || strings.Contains(w.Body.String(), `"analyzer_host"`) {
		t.Fatal("default API exposed active candidate")
	}
	if _, err := os.Stat(called); !os.IsNotExist(err) {
		t.Fatal("disabled path probed Node")
	}
	after, _ := os.ReadFile(config)
	if string(after) != string(original) {
		t.Fatalf("disabled candidate rewrote config: %s", after)
	}
	if s.cap != nil || s.http != nil {
		t.Fatal("default test started capture/listener")
	}
}
