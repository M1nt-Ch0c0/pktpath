package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCordisF031AHTTPIncompatibleStartupVisibleNoNode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plugins_config.json")
	raw := []byte("{\"version\":99,\"plugins\":{}}\n")
	os.WriteFile(path, raw, 0600)
	marker := filepath.Join(dir, "node-was-started")
	node := filepath.Join(dir, "node-sentinel")
	os.WriteFile(node, []byte("#!/bin/sh\nprintf started > '"+marker+"'\nexit 99\n"), 0700)
	s := New(Options{AppDir: dir, CordisPluginHost: "never-loaded.mjs", CordisPluginNode: node, CordisConfigTransactions: true})
	defer s.Shutdown(context.Background())
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/api/kernel/state", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"config_compatibility"`) || !strings.Contains(w.Body.String(), `"incompatible-config"`) {
		t.Fatalf("startup error was swallowed without API diagnostics: %d %s", w.Code, w.Body.String())
	}
	r := httptest.NewRequest("POST", "/api/kernel/plugins/reset", strings.NewReader(`{"id":"builtin.collector.ebpf-tc"}`))
	r.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	var response map[string]json.RawMessage
	json.Unmarshal(w.Body.Bytes(), &response)
	if w.Code != 400 || string(response["ok"]) != "false" || response["state"] == nil {
		t.Fatalf("Reset hid incompatible startup: %d %s", w.Code, w.Body.String())
	}
	if s.kernel.Collector() != nil || len(s.kernel.Host().LifecycleHost.Snapshot().ConfigOperations) != 0 {
		t.Fatal("bad config still activated collector/admitted transaction")
	}
	b, _ := os.ReadFile(path)
	if !bytes.Equal(raw, b) {
		t.Fatal("HTTP error rewrote future file")
	}
	if _, e := os.Stat(marker); !os.IsNotExist(e) {
		t.Fatal("startup probed Node")
	}
	if s.cap != nil || s.http != nil {
		t.Fatal("capture/listener touched")
	}
}
